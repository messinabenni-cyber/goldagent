"""DTMF for IVR traversal — SIP-INFO method.

The PoC call places an INVITE, gets a 200 OK, then sends DTMF to traverse
the dial plan (e.g. "press 9 for an outside line"). SIP-INFO is the
out-of-band method that works without a media stream — perfect for the
signalling-only PoC.

RFC 4733 (DTMF in RTP) is omitted from this build because we don't stream
media. If you need it, the audio-streaming live-call module from earlier
versions can be reintroduced.
"""
from __future__ import annotations

import random
import socket


DTMF_DIGITS = set("0123456789*#ABCD")


def build_info_dtmf_body(digit: str, duration_ms: int = 160) -> str:
    """Build the application/dtmf-relay body for a SIP INFO request.

    duration_ms is clamped to [10, 10000]ms. Values outside that range are
    either rejected by strict PBX parsers or interpreted as a stuck key.
    """
    if digit not in DTMF_DIGITS:
        raise ValueError(f"Unsupported DTMF digit: {digit!r}")
    if not isinstance(duration_ms, int) or duration_ms < 10:
        duration_ms = 160
    duration_ms = min(duration_ms, 10000)
    return f"Signal={digit}\r\nDuration={duration_ms}\r\n"


def send_sip_info_dtmf(
    sock: socket.socket,
    remote: tuple[str, int],
    *,
    request_uri: str,
    from_uri: str,
    to_uri: str,
    call_id: str,
    cseq: int,
    from_tag: str,
    to_tag: str,
    local_ip: str,
    local_port: int,
    digit: str,
    duration_ms: int = 160,
    user_agent: str = "VoIPScan/3.0",
) -> int:
    """Send one DTMF digit as an in-dialog SIP INFO request.

    Returns the CSeq used. Caller must increment for the next in-dialog
    request (BYE, re-INVITE, etc.).
    """
    body = build_info_dtmf_body(digit, duration_ms)
    branch = f"z9hG4bK-dtmf-{random.randrange(0, 1 << 32):08x}"
    lines = [
        f"INFO {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f"From: <{from_uri}>;tag={from_tag}",
        f"To: <{to_uri}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} INFO",
        f"Contact: <sip:{local_ip}:{local_port}>",
        f"User-Agent: {user_agent}",
        "Content-Type: application/dtmf-relay",
        f"Content-Length: {len(body)}",
        "",
        body,
    ]
    msg = "\r\n".join(lines).encode("utf-8")
    sock.sendto(msg, remote)
    return cseq
