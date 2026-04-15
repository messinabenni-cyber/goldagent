"""IAX2 protocol probing — Asterisk Inter-Asterisk eXchange v2 (RFC 5456).

Why IAX2 matters to a VoIP pentest:
  * Asterisk's native trunking protocol — present on ~40 % of Asterisk
    deployments in the field (less common behind SBCs but very common in
    greenfield Asterisk installs and small-ISP VoIP platforms).
  * Authentication bypass / username enumeration parallel to SIP REGISTER:
    a NEW message with a bogus username returns a different response than
    one with a real username.  This is the IAX2 analogue of the classic SIP
    407-vs-404 oracle (CVE-2009-2351, and rediscovered several times).
  * POKE is the IAX2 equivalent of SIP OPTIONS — a reachability probe that
    authenticated endpoints don't require auth for.  Receiving PONG proves
    an IAX2 speaker is present even when the port isn't in the banner.

Packet layout (RFC 5456 §8.1, full frame):
    bit  meaning
     0   F (1 = full frame, 0 = mini)
     1-15 source call number
    16   R (retransmission flag)
    17-31 destination call number
    32-63 timestamp (ms)
    64-71 outbound sequence number (OSeqno)
    72-79 inbound sequence number (ISeqno)
    80-87 frame type (IAX control, DTMF, voice, ...)
    88    C (1 = raw, 0 = subclass-byte)
    89-95 subclass (extended or single-byte — bit 88 flags 7-bit vs 32-bit)
    ...   IE (information elements) for control frames

For POKE / NEW we only need Full frames (F=1) with frame-type=IAX control
(frame_type=0x06) and subclass identifying the command:
    0x1E  POKE
    0x03  PONG
    0x04  ACK
    0x05  HANGUP
    0x06  REJECT
    0x0B  AUTHREQ     (IAX2 auth challenge)
    0x0C  AUTHREP     (IAX2 auth response)
    0x08  NEW         (registration / call setup)

Information Element (IE) format (§8.6.x):
    uint8  IE-ID
    uint8  length
    bytes  value

Common IEs we send/parse:
    0x06  USERNAME
    0x0E  AUTHMETHODS
    0x0F  CHALLENGE
    0x1A  CAUSE
    0x1B  IAX-UNKNOWN
    0x28  CAUSECODE

No third-party dependencies.  Pure stdlib (struct + socket).
"""
from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass, field


IAX2_PORT = 4569
FRAME_TYPE_IAX = 0x06

SUBCLASS_NEW      = 0x01
SUBCLASS_HANGUP   = 0x05
SUBCLASS_REJECT   = 0x06
SUBCLASS_ACCEPT   = 0x07
SUBCLASS_ACK      = 0x04
SUBCLASS_INVAL    = 0x0A
SUBCLASS_AUTHREQ  = 0x0B
SUBCLASS_AUTHREP  = 0x0C
SUBCLASS_REGREQ   = 0x0D
SUBCLASS_REGAUTH  = 0x0E
SUBCLASS_REGACK   = 0x0F
SUBCLASS_REGREJ   = 0x10
SUBCLASS_PING     = 0x02
SUBCLASS_PONG     = 0x03
SUBCLASS_POKE     = 0x1E

IE_CALLED_NUMBER = 0x01
IE_CALLING_NUMBER = 0x02
IE_USERNAME       = 0x06
IE_PASSWORD       = 0x07
IE_CAPABILITY     = 0x08
IE_FORMAT         = 0x09
IE_VERSION        = 0x0B
IE_AUTHMETHODS    = 0x0E
IE_CHALLENGE      = 0x0F
IE_MD5RESULT      = 0x10
IE_CAUSE          = 0x16
IE_CAUSECODE      = 0x28
IE_DATETIME       = 0x1F


def _pack_ie(ie_id: int, value: bytes) -> bytes:
    return bytes([ie_id, len(value)]) + value


def _parse_ies(data: bytes) -> dict[int, bytes]:
    """Parse TLV-style IEs from an IAX2 frame payload."""
    out: dict[int, bytes] = {}
    i = 0
    while i + 2 <= len(data):
        ie_id = data[i]
        length = data[i + 1]
        if i + 2 + length > len(data):
            break
        out[ie_id] = data[i + 2:i + 2 + length]
        i += 2 + length
    return out


def _build_full_frame(
    source_call: int,
    dest_call: int,
    timestamp_ms: int,
    oseqno: int,
    iseqno: int,
    frame_type: int,
    subclass: int,
    ies: bytes = b"",
) -> bytes:
    """Construct a full IAX2 frame.  Subclass encoded as a single byte
    (bit 88=0 in §8.1), which is the common case for control frames.
    """
    # Source call (bit 0 = F = 1 for full frame)
    src = 0x8000 | (source_call & 0x7FFF)
    # Dest call (bit 16 = R = retransmission = 0)
    dst = dest_call & 0x7FFF
    header = struct.pack(
        "!HHIBBBB",
        src,
        dst,
        timestamp_ms & 0xFFFFFFFF,
        oseqno & 0xFF,
        iseqno & 0xFF,
        frame_type & 0xFF,
        subclass & 0xFF,
    )
    return header + ies


def _parse_full_frame(pkt: bytes) -> dict | None:
    """Return None if packet isn't a full IAX2 frame."""
    if len(pkt) < 12:
        return None
    # bit 0 of the first byte = F flag
    if (pkt[0] & 0x80) == 0:
        return None  # mini frame
    src = struct.unpack("!H", pkt[0:2])[0] & 0x7FFF
    dst = struct.unpack("!H", pkt[2:4])[0] & 0x7FFF
    ts = struct.unpack("!I", pkt[4:8])[0]
    oseq = pkt[8]
    iseq = pkt[9]
    ftype = pkt[10]
    subclass = pkt[11]
    ies = _parse_ies(pkt[12:])
    return {
        "source_call": src,
        "dest_call": dst,
        "timestamp": ts,
        "oseqno": oseq,
        "iseqno": iseq,
        "frame_type": ftype,
        "subclass": subclass,
        "ies": ies,
        "raw": pkt,
    }


@dataclass
class IAX2ProbeResult:
    target: str
    port: int = IAX2_PORT
    iax2_detected: bool = False
    pong_received: bool = False
    server_info: str = ""
    round_trip_ms: float = 0.0
    error: str | None = None
    raw_response: bytes = b""


def probe_poke(
    host: str,
    port: int = IAX2_PORT,
    timeout: float = 3.0,
    traffic_log=None,
) -> IAX2ProbeResult:
    """Send an IAX2 POKE and wait for a PONG.  POKE is unauthenticated —
    a PONG confirms an IAX2 speaker is live, regardless of registration.
    """
    result = IAX2ProbeResult(target=host, port=port)
    start = time.monotonic()

    source_call = random.randint(1, 0x7FFE)
    frame = _build_full_frame(
        source_call=source_call,
        dest_call=0,
        timestamp_ms=0,
        oseqno=0,
        iseqno=0,
        frame_type=FRAME_TYPE_IAX,
        subclass=SUBCLASS_POKE,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.bind(("", 0))
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", frame)
        sock.sendto(frame, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return result
        result.round_trip_ms = (time.monotonic() - start) * 1000
        result.raw_response = data
        if traffic_log:
            traffic_log.log("IN", f"{host}:{port}", data)
        parsed = _parse_full_frame(data)
        if not parsed:
            return result
        result.iax2_detected = (parsed["frame_type"] == FRAME_TYPE_IAX)
        if parsed["subclass"] == SUBCLASS_PONG:
            result.pong_received = True
        # IAX2 responses to POKE sometimes carry CAUSE IE with server text
        cause = parsed["ies"].get(IE_CAUSE)
        if cause:
            result.server_info = cause.decode("utf-8", errors="replace").strip()
    except OSError as exc:
        result.error = f"socket error: {exc}"
    finally:
        sock.close()
    return result


def _probe_username(
    host: str,
    port: int,
    username: str,
    timeout: float,
    traffic_log=None,
) -> tuple[bool, str]:
    """Send a NEW with the given username.  Returns (exists, evidence).

    Oracle:
      * REJECT with "No authority found" / cause-code 31 — username does not exist
      * AUTHREQ with AUTHMETHODS IE  — username exists, awaiting credentials
      * REGAUTH                      — username is a registration peer
      * No response                  — timeout or behind ACL
    """
    source_call = random.randint(1, 0x7FFE)
    ies = (
        _pack_ie(IE_VERSION, b"\x00\x02")
        + _pack_ie(IE_USERNAME, username.encode("utf-8"))
        + _pack_ie(IE_CAPABILITY, b"\x00\x00\x00\x04")  # ulaw
        + _pack_ie(IE_FORMAT, b"\x00\x00\x00\x04")
        + _pack_ie(IE_CALLED_NUMBER, b"100")
    )
    frame = _build_full_frame(
        source_call=source_call,
        dest_call=0,
        timestamp_ms=0,
        oseqno=0,
        iseqno=0,
        frame_type=FRAME_TYPE_IAX,
        subclass=SUBCLASS_NEW,
        ies=ies,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.bind(("", 0))
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", frame)
        sock.sendto(frame, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return False, "no response"
        if traffic_log:
            traffic_log.log("IN", f"{host}:{port}", data)
        parsed = _parse_full_frame(data)
        if not parsed:
            return False, "non-IAX2 response"

        subclass = parsed["subclass"]
        # Politely hang up the half-opened dialog so we don't leave the
        # peer holding a call-leg in its state table.
        dest_call = parsed["source_call"]
        hangup = _build_full_frame(
            source_call=source_call,
            dest_call=dest_call,
            timestamp_ms=0,
            oseqno=1,
            iseqno=1,
            frame_type=FRAME_TYPE_IAX,
            subclass=SUBCLASS_HANGUP,
        )
        try:
            sock.sendto(hangup, (host, port))
        except OSError:
            pass

        if subclass == SUBCLASS_AUTHREQ:
            authmethods = parsed["ies"].get(IE_AUTHMETHODS, b"")
            return True, f"AUTHREQ, authmethods={authmethods.hex()}"
        if subclass == SUBCLASS_REGAUTH:
            return True, "REGAUTH — registration peer"
        if subclass == SUBCLASS_REJECT:
            cause = parsed["ies"].get(IE_CAUSE, b"").decode("utf-8", errors="replace")
            return False, f"REJECT: {cause}"
        if subclass == SUBCLASS_ACCEPT:
            return True, "ACCEPT — call accepted without auth (!)"
        return False, f"subclass=0x{subclass:02x}"
    except OSError as exc:
        return False, f"socket error: {exc}"
    finally:
        sock.close()


@dataclass
class IAX2EnumResult:
    target: str
    port: int = IAX2_PORT
    users_tested: int = 0
    users_found: list[tuple[str, str]] = field(default_factory=list)
    unauthenticated_accept: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0


def enumerate_usernames(
    host: str,
    usernames: list[str],
    port: int = IAX2_PORT,
    timeout: float = 1.5,
    rate: float = 10.0,
    traffic_log=None,
) -> IAX2EnumResult:
    """Probe each username via NEW and classify the response.

    Caller is responsible for sizing the wordlist — 1000 usernames at
    10 pps takes ~100 seconds.  Uses a shared RateLimiter via the utils
    module if the caller wants stricter pacing.
    """
    from .utils import RateLimiter

    result = IAX2EnumResult(target=host, port=port)
    start = time.monotonic()
    rl = RateLimiter(rate)

    for username in usernames:
        rl.wait()
        exists, evidence = _probe_username(host, port, username, timeout, traffic_log)
        result.users_tested += 1
        if exists:
            result.users_found.append((username, evidence))
            if "without auth" in evidence:
                result.unauthenticated_accept.append(username)

    result.elapsed_s = time.monotonic() - start
    return result


def build_findings(
    poke_result: IAX2ProbeResult | None,
    enum_result: IAX2EnumResult | None,
) -> list[dict]:
    """Convert IAX2 probe results into findings entries."""
    out: list[dict] = []
    if poke_result and poke_result.pong_received:
        out.append({
            "id": "iax2.exposed",
            "severity": "low",
            "host": poke_result.target,
            "title": f"IAX2 service exposed on UDP/{poke_result.port}",
            "detail": (
                f"Target responded to IAX2 POKE with PONG "
                f"({poke_result.round_trip_ms:.0f} ms). "
                f"{('Server info: ' + poke_result.server_info) if poke_result.server_info else ''}"
            ),
            "remediation": (
                "If IAX2 trunking is not in active use, disable it in "
                "modules.conf (noload chan_iax2.so for Asterisk). If required, "
                "restrict access to known trunk peers via permit/deny in "
                "iax.conf or an upstream firewall."
            ),
        })
    if enum_result and enum_result.users_found:
        users = ", ".join(u for u, _ in enum_result.users_found[:10])
        out.append({
            "id": "iax2.enum",
            "severity": "medium",
            "host": enum_result.target,
            "title": f"IAX2 username enumeration ({len(enum_result.users_found)} users)",
            "detail": (
                f"IAX2 NEW oracle revealed {len(enum_result.users_found)} valid "
                f"username(s): {users}"
                f"{' ...' if len(enum_result.users_found) > 10 else ''}. "
                f"{enum_result.users_tested} total usernames probed."
            ),
            "remediation": (
                "Enable IAX2 uniform-response mode where available (Asterisk: "
                "set 'delayreject=yes' in iax.conf so rejects return identical "
                "timing regardless of whether the username exists). Rate-limit "
                "IAX2 auth attempts per source IP at the firewall."
            ),
        })
    if enum_result and enum_result.unauthenticated_accept:
        users = ", ".join(enum_result.unauthenticated_accept[:10])
        out.append({
            "id": "iax2.anon_accept",
            "severity": "critical",
            "host": enum_result.target,
            "title": "IAX2 accepts calls without authentication",
            "detail": (
                f"IAX2 NEW from our source was ACCEPTED for users: {users}. "
                "This allows anonymous call placement via IAX2 — the same toll-fraud "
                "class as SIP anonymous-INVITE but on UDP/4569."
            ),
            "remediation": (
                "Enforce IAX2 authentication: set 'auth=md5' or 'auth=rsa' for "
                "every peer in iax.conf and remove any 'context=default' that "
                "permits outbound calls. Audit for peers with 'type=user' and "
                "no secret."
            ),
        })
    return out
