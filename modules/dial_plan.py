"""Dial-plan intelligence — auto-probe common outside-line / international
prefixes when the user-supplied number doesn't route.

Real-world PBXes almost always sit behind a dial-plan transform:
  - Outside-line selector (e.g. 9 or 0 to seize a trunk)
  - International access code (00 in EU/most-of-world, 011 in NANP)
  - Sometimes both combined (e.g. 900447700900123)
  - Sometimes neither (modern E.164 direct)

This module generates candidate dial strings in order of modernity (most
likely to work first) and provides a lightweight INVITE probe that classifies
each candidate as: ROUTED / REJECTED / AUTH-REQUIRED / TIMEOUT. The probe
CANCELs before the target phone actually rings, so the user's mobile doesn't
chirp during dial-plan discovery — only the final "real" call rings it.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from . import sip
from .utils import local_ip_for, rand_call_id, rand_tag


# Status codes the PBX returns when dial plan rejected the number:
_DIALPLAN_REJECTED = {404, 484, 488, 500, 503, 603, 604}
# Provisional responses that indicate routing succeeded:
_ROUTED_PROVISIONALS = {100, 180, 183}
# Anything 2xx is a bullseye (rare during a 1s probe because the callee hasn't
# picked up yet — they wouldn't even have started ringing).


@dataclass
class ProbeResult:
    candidate: str
    status: str           # 'routed' | 'rejected' | 'auth' | 'timeout'
    status_code: int | None
    reason: str
    rtt_ms: float


def generate_candidates(
    original: str,
    outside_prefixes: list[str] | None = None,
    intl_access_codes: list[str] | None = None,
    custom_prefix: str | None = None,
) -> list[str]:
    """Return dial-string candidates in priority order.

    The FIRST entry is always the user's original number (they know their
    target best). After that we try modern E.164 variations, then
    outside-line prefixes, then international access codes, then combinations.
    Duplicates are removed while preserving order.
    """
    outside_prefixes = outside_prefixes if outside_prefixes is not None else ["9", "0"]
    intl_access_codes = intl_access_codes if intl_access_codes is not None else ["00", "011"]

    # Derive a normalized "digits" form (strip +, spaces, dashes, parens).
    digits = "".join(c for c in original if c.isdigit())
    is_intl_looking = original.startswith("+") or len(digits) >= 11

    out: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        if s and s not in seen:
            out.append(s)
            seen.add(s)

    # 0) User's override prefix if they supplied one
    if custom_prefix:
        _add(custom_prefix + (original.lstrip("+") if original.startswith("+") else original))
        _add(custom_prefix + digits)

    # 1) Exactly what the user typed
    _add(original)

    # 2) E.164-normalized
    if is_intl_looking:
        _add("+" + digits)
        _add(digits)

    # 3) Outside-line prefix + original
    for p in outside_prefixes:
        _add(p + original)

    # 4) Outside-line + E.164 with +
    for p in outside_prefixes:
        _add(p + "+" + digits)

    # 5) International access code + digits (no +)
    if is_intl_looking:
        for iac in intl_access_codes:
            _add(iac + digits)

    # 6) Outside-line + international access code + digits
    if is_intl_looking:
        for p in outside_prefixes:
            for iac in intl_access_codes:
                _add(p + iac + digits)

    # 7) Last-ditch: just the digits (some PBXes strip everything non-digit)
    _add(digits)

    return out


def probe_candidate(
    pbx_host: str,
    candidate: str,
    pbx_port: int = 5060,
    from_user: str = "1000",
    timeout: float = 1.5,
    traffic_log=None,
) -> ProbeResult:
    """Send one INVITE, watch for 1.5s, CANCEL if it routed. Classifies the
    PBX's response. CANCEL ensures the target phone doesn't actually ring."""
    local_ip = local_ip_for(pbx_host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(min(timeout, 1.0))
    s.bind(("", 0))
    local_port = s.getsockname()[1]

    call_id = rand_call_id()
    tag_from = rand_tag()
    request_uri = f"sip:{candidate}@{pbx_host}"
    branch = "z9hG4bK-probe-" + rand_tag(8)

    # Build a minimal INVITE with tiny SDP (we're not going to stream)
    sdp = (
        "v=0\r\n"
        f"o=probe 0 0 IN IP4 {local_ip}\r\n"
        "s=probe\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
    )
    invite_lines = [
        f"INVITE {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        f'From: "dialplan-probe" <sip:{from_user}@{local_ip}>;tag={tag_from}',
        f"To: <sip:{candidate}@{pbx_host}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:{from_user}@{local_ip}:{local_port}>",
        "User-Agent: voip-demo/1.0 (dialplan-probe)",
        "Content-Type: application/sdp",
        f"Content-Length: {len(sdp)}",
        "",
    ]
    invite = ("\r\n".join(invite_lines) + "\r\n" + sdp).encode("utf-8")

    t0 = time.monotonic()
    if traffic_log:
        traffic_log.log("OUT", f"{pbx_host}:{pbx_port}", invite)
    try:
        s.sendto(invite, (pbx_host, pbx_port))
    except OSError as e:
        s.close()
        return ProbeResult(candidate, "timeout", None, f"send failed: {e}", 0.0)

    deadline = time.monotonic() + timeout
    final: sip.SipResponse | None = None
    to_tag: str | None = None
    classification: str = "timeout"
    status_code: int | None = None
    reason: str = "no response"

    while time.monotonic() < deadline:
        try:
            s.settimeout(max(0.05, deadline - time.monotonic()))
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            break
        except OSError:
            break
        if traffic_log:
            traffic_log.log("IN", f"{pbx_host}:{pbx_port}", data)
        resp = sip.parse_response(data)
        if not resp:
            continue
        to_hdr = resp.headers.get("to", "")
        if ";tag=" in to_hdr:
            to_tag = to_hdr.split(";tag=", 1)[1].split(";")[0].split(",")[0].strip()
        status_code, reason = resp.status_code, resp.reason

        if resp.status_code in _ROUTED_PROVISIONALS:
            classification = "routed"
            final = resp
            break  # Dialplan engaged — good enough to call it a winner
        if resp.is_auth_required:
            classification = "auth"
            final = resp
            break
        if resp.status_code in _DIALPLAN_REJECTED:
            classification = "rejected"
            final = resp
            break
        if 200 <= resp.status_code < 300:
            classification = "routed"
            final = resp
            break
        # other codes: note but keep listening briefly
        final = resp

    rtt_ms = (time.monotonic() - t0) * 1000.0

    # Always CANCEL to clean up so the target doesn't ring
    if classification == "routed":
        cancel_lines = [
            f"CANCEL {request_uri} SIP/2.0",
            # CANCEL uses the SAME branch as the INVITE it cancels (RFC 3261 §9.1)
            f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport",
            "Max-Forwards: 70",
            f'From: "dialplan-probe" <sip:{from_user}@{local_ip}>;tag={tag_from}',
            f"To: <sip:{candidate}@{pbx_host}>"
            + (f";tag={to_tag}" if to_tag else ""),
            f"Call-ID: {call_id}",
            "CSeq: 1 CANCEL",
            "Content-Length: 0",
            "",
        ]
        cancel = ("\r\n".join(cancel_lines) + "\r\n").encode("utf-8")
        try:
            if traffic_log:
                traffic_log.log("OUT", f"{pbx_host}:{pbx_port}", cancel)
            s.sendto(cancel, (pbx_host, pbx_port))
            # Drain any remaining responses briefly
            s.settimeout(0.3)
            try:
                while True:
                    s.recvfrom(65535)
            except (socket.timeout, OSError):
                pass
        except OSError:
            pass

    s.close()

    if classification == "timeout" and final and final.status_code:
        # We got SOME response but didn't fit our buckets — record the code
        status_code = final.status_code
        reason = final.reason

    return ProbeResult(candidate, classification, status_code, reason, rtt_ms)


def find_working_prefix(
    pbx_host: str,
    call_to: str,
    pbx_port: int = 5060,
    from_user: str = "1000",
    custom_prefix: str | None = None,
    extra_candidates: list[str] | None = None,
    timeout: float = 1.5,
    rate_per_second: float = 20.0,
    traffic_log=None,
) -> tuple[str | None, list[ProbeResult]]:
    """Try each candidate dial string; return (winner, all_attempts).

    If none route, winner is None and the operator should inspect the probe
    log to see what response each candidate got (often reveals the correct
    format — e.g. every attempt returns 484 Address Incomplete means you need
    more digits; every attempt returns 403 means the trunk doesn't permit
    international).
    """
    candidates = generate_candidates(call_to, custom_prefix=custom_prefix)
    if extra_candidates:
        for c in extra_candidates:
            if c not in candidates:
                candidates.append(c)
    interval = 1.0 / rate_per_second if rate_per_second > 0 else 0
    results: list[ProbeResult] = []
    winner: str | None = None
    last = 0.0
    for c in candidates:
        if interval:
            now = time.monotonic()
            delta = now - last
            if delta < interval:
                time.sleep(interval - delta)
        last = time.monotonic()
        pr = probe_candidate(
            pbx_host, c, pbx_port=pbx_port,
            from_user=from_user, timeout=timeout,
            traffic_log=traffic_log,
        )
        results.append(pr)
        if pr.status == "routed":
            winner = c
            break
    return winner, results


def format_probe_table(results: list[ProbeResult]) -> str:
    """Render probe results as a table for the report / console."""
    if not results:
        return "  (no candidates tried)"
    rows = ["  " + f"{'Candidate':<22} {'Status':<10} {'Code':<6} {'RTT':<8} Reason",
            "  " + "─" * 70]
    for pr in results:
        code = str(pr.status_code) if pr.status_code else "-"
        rows.append(
            f"  {pr.candidate:<22} {pr.status:<10} {code:<6} "
            f"{pr.rtt_ms:>6.0f}ms {pr.reason[:24]}"
        )
    return "\n".join(rows)
