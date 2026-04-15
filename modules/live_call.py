"""Real call flow: INVITE → ringing → 200 OK → ACK → RTP stream → BYE.

Unlike modules/call_test.py (which tears the call down immediately on 200 OK
as a signaling-only PoC), this module keeps the call up with actual RTP audio
so the callee's phone rings, they answer, and hear the supplied audio. This
is the client-demo module — use only with explicit authorization.
"""
from __future__ import annotations

import random
import socket
import threading
import time
from dataclasses import dataclass, field

from . import dtmf, recording, rtp, sip
from .control import controller
from .events import bus
from .utils import local_ip_for, rand_call_id, rand_tag


@dataclass
class LiveCallResult:
    success: bool
    status_code: int | None
    reason: str
    codec: str
    duration_s: float
    rtp_packets_sent: int
    audio_source: str
    sip_trace: list[str] = field(default_factory=list)
    evidence: str = ""
    hangup_side: str = "local"  # 'local', 'remote', 'timeout', 'interrupted'
    dtmf_sent: list[str] = field(default_factory=list)
    recording: dict | None = None   # recording summary if enabled


def place_live_call(
    pbx_host: str,
    call_to: str,
    call_from: str,
    audio_payload,                  # dict {"PCMU": bytes, "PCMA": bytes, "label": str}
                                    #   or legacy bytes (treated as PCMU only)
    audio_label: str | None = None, # legacy; ignored if audio_payload is a dict
    pbx_port: int = 5060,
    username: str | None = None,
    password: str | None = None,
    hold_seconds: float = 1800.0,   # 30 min default — you control hangup
    ring_timeout_s: float = 45.0,
    timeout: float = 5.0,
    traffic_log=None,
    caller_id_name: str = "Pentest Demo",
    on_answered=None,     # callback(remote_media, effective_hold_seconds)
    on_heartbeat=None,    # callback(elapsed_s, max_hold_s, rtp_pkts_sent)
    dtmf_sequence: str | None = None,   # e.g. "0" or "p1000,1234,#"
    dtmf_digit_ms: int = 200,
    record_path: str | None = None,     # if set, write received audio to WAV
    stop_event: threading.Event | None = None,  # per-call hangup signal (call_manager)
) -> LiveCallResult:
    # Normalize audio payload to a codec dict
    if isinstance(audio_payload, (bytes, bytearray)):
        audio_payload = {"PCMU": bytes(audio_payload),
                         "PCMA": bytes(audio_payload),
                         "label": audio_label or "legacy-ulaw"}
    elif not isinstance(audio_payload, dict):
        raise TypeError(
            "audio_payload must be bytes or a dict of {codec: bytes, ...}"
        )
    audio_label = audio_payload.get("label", audio_label or "unknown")
    """Place a real call to `call_to` via `pbx_host`, stream `ulaw_payload`
    for `hold_seconds` once the callee answers, then BYE. Returns a result
    summary suitable for reporting."""
    local_ip = local_ip_for(pbx_host)

    # SIP socket (bound port used in Contact + Via)
    sip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sip_sock.settimeout(timeout)
    sip_sock.bind(("", 0))
    sip_local_port = sip_sock.getsockname()[1]

    # RTP socket
    rtp_sock, rtp_local_port = rtp.bind_rtp_socket()

    trace: list[str] = []
    t_start = time.monotonic()

    def _send(msg: bytes) -> None:
        if traffic_log:
            traffic_log.log("OUT", f"{pbx_host}:{pbx_port}", msg)
        sip_sock.sendto(msg, (pbx_host, pbx_port))

    def _recv(timeout_left: float) -> sip.SipResponse | bytes | None:
        sip_sock.settimeout(max(0.1, timeout_left))
        try:
            data, _ = sip_sock.recvfrom(65535)
        except socket.timeout:
            return None
        if traffic_log:
            traffic_log.log("IN", f"{pbx_host}:{pbx_port}", data)
        # Could be a request (BYE from callee) or a response
        try:
            head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        except Exception:
            return None
        if head.startswith("SIP/2.0"):
            return sip.parse_response(data)
        return data  # raw request (we only care about BYE)

    call_id = rand_call_id()
    tag_from = rand_tag()
    request_uri = f"sip:{call_to}@{pbx_host}"

    sdp = rtp.build_sdp_offer(local_ip, rtp_local_port)

    # ---- 1) Initial INVITE ----
    invite = _build_invite(
        method_cseq=1,
        uri=request_uri,
        from_user=call_from,
        to_user=call_to,
        host=pbx_host, port=pbx_port,
        local_ip=local_ip, local_port=sip_local_port,
        call_id=call_id, from_tag=tag_from,
        sdp=sdp,
        caller_id_name=caller_id_name,
    )
    _send(invite)
    trace.append(f"> INVITE sip:{call_to}@{pbx_host}  (Caller-ID: {call_from!r})")
    bus.emit("call.invite", {
        "pbx": pbx_host, "call_to": call_to, "call_from": call_from,
    })

    final: sip.SipResponse | None = None
    to_tag: str | None = None
    reached_ringing = False
    auth_attempted = False
    # RFC 3261 §9.1: CANCEL must carry the same CSeq as the INVITE it cancels.
    # Track the CSeq of the most-recently-sent INVITE so timeout-CANCEL is correct.
    last_invite_cseq = 1

    _TRACE_CAP = 500   # bound memory: drop oldest entries if trace grows huge

    ring_deadline = t_start + ring_timeout_s
    while time.monotonic() < ring_deadline:
        remaining = ring_deadline - time.monotonic()
        item = _recv(remaining)
        if item is None:
            continue
        if not isinstance(item, sip.SipResponse):
            continue
        resp = item
        if len(trace) >= _TRACE_CAP:
            trace = trace[-(_TRACE_CAP // 2):]   # keep the most recent half
        trace.append(f"< {resp.status_code} {resp.reason}")
        to_hdr = resp.headers.get("to", "")
        if ";tag=" in to_hdr:
            # RFC 3261: tag parameter ends at next ';' or end of field-value.
            raw_tag = to_hdr.split(";tag=", 1)[1]
            to_tag = raw_tag.split(";")[0].split(",")[0].strip()

        if resp.status_code in (100, 180, 183):
            reached_ringing = reached_ringing or resp.status_code in (180, 183)
            if resp.status_code == 180:
                bus.emit("call.ringing", {"pbx": pbx_host})
            continue

        if resp.is_auth_required and not auth_attempted:
            if not (username and password):
                final = resp
                break
            auth_attempted = True
            # RFC 3261 §8.1.3.1: ACK is only sent for 2xx final responses to
            # INVITE.  401/407 are non-2xx finals — do NOT send ACK here.
            hdr_name = "Proxy-Authorization" if resp.status_code == 407 else "Authorization"
            auth_header = sip.build_auth_header(
                username, password, "INVITE", request_uri, resp.auth_params,
                header_name=hdr_name,
            )
            invite2 = _build_invite(
                method_cseq=2,
                uri=request_uri,
                from_user=call_from, to_user=call_to,
                host=pbx_host, port=pbx_port,
                local_ip=local_ip, local_port=sip_local_port,
                call_id=call_id, from_tag=tag_from,
                sdp=sdp,
                caller_id_name=caller_id_name,
                auth_header=auth_header,
            )
            _send(invite2)
            last_invite_cseq = 2          # CANCEL must match this CSeq
            trace.append("> INVITE (auth)")
            continue

        # Anything else ends ringing
        final = resp
        break

    if not final or not (200 <= final.status_code < 300):
        # Didn't answer — send CANCEL if no final response received (RFC 3261 §9.1)
        if final is None:
            try:
                cancel = _build_cancel(
                    request_uri, call_from, call_to, pbx_host, pbx_port,
                    local_ip, sip_local_port, call_id,
                    last_invite_cseq,   # must match the most-recent INVITE
                    tag_from, to_tag)
                _send(cancel)
                trace.append("> CANCEL (ring timeout)")
            except Exception:
                pass
        duration = time.monotonic() - t_start
        rtp_sock.close()
        sip_sock.close()
        if final is None:
            reason = "no final response"
            status = None
        else:
            reason = f"{final.status_code} {final.reason}"
            status = final.status_code
        return LiveCallResult(
            success=False, status_code=status, reason=reason,
            codec="", duration_s=duration, rtp_packets_sent=0,
            audio_source=audio_label, sip_trace=trace,
            evidence=f"Callee did not answer. Last state: {reason}. "
                     f"Ringing reached: {reached_ringing}",
            hangup_side="timeout" if final is None else "remote",
        )

    # ---- 2) 200 OK — parse SDP, send ACK, start RTP ----
    remote_media = rtp.parse_sdp_answer(final.body)
    if not remote_media:
        # 200 OK without media — can't stream; still send ACK + BYE
        ack = _build_ack(request_uri, call_from, call_to, pbx_host, pbx_port,
                         local_ip, sip_local_port, call_id,
                         _cseq_from(final) or 1, tag_from, to_tag)
        _send(ack); trace.append("> ACK")
        bye = _build_bye(request_uri, call_from, call_to, pbx_host, pbx_port,
                         local_ip, sip_local_port, call_id, 3, tag_from, to_tag)
        _send(bye); trace.append("> BYE (no SDP)")
        rtp_sock.close(); sip_sock.close()
        return LiveCallResult(
            success=True, status_code=200, reason="OK",
            codec="(no-sdp)", duration_s=time.monotonic() - t_start,
            rtp_packets_sent=0, audio_source=audio_label, sip_trace=trace,
            evidence="200 OK received but no parseable SDP in answer.",
            hangup_side="local",
        )

    # ACK the 200 OK (same CSeq number as the INVITE it answers)
    invite_cseq = _cseq_from(final) or 1
    ack = _build_ack(request_uri, call_from, call_to, pbx_host, pbx_port,
                     local_ip, sip_local_port, call_id, invite_cseq, tag_from, to_tag)
    _send(ack)
    trace.append(f"> ACK — call established, streaming {remote_media.codec} to "
                 f"{remote_media.ip}:{remote_media.port}")
    bus.emit("call.answered", {
        "pbx": pbx_host,
        "call_from": call_from,
        "call_to": call_to,
        "codec": remote_media.codec,
        "remote_ip": remote_media.ip,
        "remote_port": remote_media.port,
    })

    # ---- 3) Shared RTP state (SSRC spans DTMF + audio for clean sessions) ----
    shared_ssrc = random.randint(0, 0xFFFFFFFF)
    shared_seq = random.randint(0, 0xFFFF)
    shared_ts = random.randint(0, 0xFFFFFFFF)

    # ---- 3a) Optional: start recording the far-end audio ----
    recorder: recording.RtpRecorder | None = None
    if record_path:
        recorder = recording.RtpRecorder(
            sock=rtp_sock, wav_path=record_path,
            codec=remote_media.codec,
        )
        recorder.start()
        trace.append(f"* recording to {record_path}")

    # ---- 3b) Optional: send DTMF before audio streaming begins ----
    dtmf_digits_sent: list[str] = []
    if dtmf_sequence:
        trace.append(f"> DTMF sequence: {dtmf_sequence!r}")
        sender = dtmf.DtmfSender(
            sock=rtp_sock,
            remote_ip=remote_media.ip,
            remote_port=remote_media.port,
            payload_type=101,
            ssrc=shared_ssrc,
            seq_start=shared_seq,
            ts_start=shared_ts,
        )
        try:
            sender.send_sequence(dtmf_sequence, digit_ms=dtmf_digit_ms)
        except Exception as e:
            trace.append(f"! DTMF error: {e}")
        dtmf_digits_sent = sender.digits_sent
        shared_seq = sender.seq
        shared_ts = sender.ts
        trace.append(f"> DTMF done: sent {len(dtmf_digits_sent)} digit(s)")

    # ---- 3c) Start audio streaming ----
    codec_bytes = audio_payload.get(remote_media.codec)
    if codec_bytes is None:
        codec_bytes = audio_payload.get("PCMU", b"")
        trace.append(f"! remote chose {remote_media.codec}; falling back "
                     f"to PCMU payload (audio may be distorted)")
    streamer = rtp.RtpStreamer(
        sock=rtp_sock,
        remote_ip=remote_media.ip,
        remote_port=remote_media.port,
        payload_type=remote_media.payload_type,
        ulaw_payload=codec_bytes,
    )
    # Inherit shared RTP state so DTMF → audio transitions cleanly
    streamer._ssrc_override = shared_ssrc
    streamer._seq_override = shared_seq
    streamer._ts_override = shared_ts
    streamer.start()

    # Watch for BYE from remote during hold. User can end the call three ways:
    #   1. Hang up their mobile  → PBX forwards BYE to us        (hangup_side="remote")
    #   2. Press Ctrl+C          → KeyboardInterrupt caught here (hangup_side="interrupted")
    #   3. --hold timer expires  → we send BYE                   (hangup_side="local")
    hangup_side = "local"
    # hold_seconds <= 0 means "indefinite, capped at 1 hour safety"
    effective_hold = hold_seconds if hold_seconds > 0 else 3600
    hold_deadline = time.monotonic() + effective_hold
    heartbeat_interval = 10.0   # seconds between "call active" status prints
    next_heartbeat = time.monotonic() + heartbeat_interval
    call_answered_at = time.monotonic()

    if on_answered:
        try:
            on_answered(remote_media, effective_hold)
        except Exception:
            pass

    try:
        while time.monotonic() < hold_deadline and not streamer.stop:
            # GUI / external controller can signal hangup via the event;
            # per-call stop_event (from call_manager) takes precedence for
            # individual call teardown without affecting other concurrent calls.
            if controller.call_hangup.is_set() or (stop_event and stop_event.is_set()):
                trace.append("! hangup signal from controller — ending call")
                hangup_side = "controller"
                break
            remaining = hold_deadline - time.monotonic()
            item = _recv(min(remaining, 1.0))
            if isinstance(item, (bytes, bytearray)):
                try:
                    head = item.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                except Exception:
                    head = ""
                if head.startswith("BYE "):
                    trace.append("< BYE (callee hung up)")
                    _send(_build_200_ok_for_request(item, local_ip, sip_local_port))
                    trace.append("> 200 OK (to BYE)")
                    hangup_side = "remote"
                    break
                elif head and not head.startswith("SIP/"):
                    # In-dialog request that is not BYE (e.g. re-INVITE, INFO, OPTIONS)
                    # RFC 3261: respond 405 Method Not Allowed so remote stack cleans up.
                    method_token = head.split(" ", 1)[0]
                    trace.append(f"< {method_token} (in-dialog, responding 405)")
                    try:
                        _send(_build_405_for_request(item, local_ip, sip_local_port))
                    except Exception:
                        pass
            # Progress heartbeat (lets the operator see the call is live)
            if time.monotonic() >= next_heartbeat:
                elapsed = time.monotonic() - call_answered_at
                bus.emit("call.heartbeat", {
                    "duration_s": round(elapsed, 1),
                    "max_hold_s": effective_hold,
                    "rtp_packets_sent": streamer.packets_sent,
                    "rtp_packets_received": (recorder.packets_received
                                             if recorder else 0),
                })
                if on_heartbeat:
                    try:
                        on_heartbeat(elapsed, effective_hold, streamer.packets_sent)
                    except Exception:
                        pass
                next_heartbeat += heartbeat_interval
    except KeyboardInterrupt:
        trace.append("! Ctrl+C pressed — ending call from local side")
        hangup_side = "interrupted"
    finally:
        # Guaranteed cleanup regardless of how the hold loop exited
        streamer.stop = True
        streamer.join(timeout=1.0)
        if recorder:
            recorder.stop = True
            recorder.join(timeout=1.5)

    duration_call = time.monotonic() - call_answered_at
    bus.emit("call.ended", {
        "hangup_side": hangup_side,
        "duration_s": round(duration_call, 2),
        "rtp_packets_sent": streamer.packets_sent,
    })

    if hangup_side in ("local", "interrupted", "controller"):
        bye = _build_bye(request_uri, call_from, call_to, pbx_host, pbx_port,
                         local_ip, sip_local_port, call_id,
                         invite_cseq + 1, tag_from, to_tag)
        _send(bye)
        tag_suffix = {"interrupted": " (interrupted)",
                      "controller": " (GUI hangup)"}.get(hangup_side, "")
        trace.append(f"> BYE{tag_suffix}")
        # Wait briefly for the 200 OK to BYE (proper SIP cleanup; also gives
        # the remote's stack time to process the datagram on loopback tests).
        bye_deadline = time.monotonic() + 1.5
        while time.monotonic() < bye_deadline:
            item = _recv(bye_deadline - time.monotonic())
            if isinstance(item, sip.SipResponse):
                trace.append(f"< {item.status_code} {item.reason} (to BYE)")
                break

    rtp_sock.close()
    sip_sock.close()

    duration = time.monotonic() - t_start
    rec_summary = recorder.summary() if recorder else None
    extra_evidence = ""
    if dtmf_digits_sent:
        extra_evidence += (
            f" DTMF sent: {''.join(dtmf_digits_sent)!r}.")
    if rec_summary:
        extra_evidence += (
            f" Recording: {rec_summary['audio_seconds']}s of "
            f"{rec_summary['codec']} audio ({rec_summary['audio_packets']} "
            f"pkts, {rec_summary['lost_packets']} lost) → "
            f"{rec_summary['wav_path']}.")
    return LiveCallResult(
        success=True,
        status_code=200,
        reason="OK",
        codec=remote_media.codec,
        duration_s=duration,
        rtp_packets_sent=streamer.packets_sent,
        audio_source=audio_label,
        sip_trace=trace,
        evidence=(f"Call answered ({remote_media.codec}). Streamed "
                  f"{streamer.packets_sent} RTP packets for "
                  f"{duration:.1f}s to {remote_media.ip}:{remote_media.port}. "
                  f"Audio source: {audio_label}. "
                  f"Hang-up side: {hangup_side}.{extra_evidence}"),
        hangup_side=hangup_side,
        dtmf_sent=dtmf_digits_sent,
        recording=rec_summary,
    )


# ---- helpers ----

def _cseq_from(resp: sip.SipResponse) -> int | None:
    try:
        return int(resp.headers.get("cseq", "").split()[0])
    except (ValueError, IndexError):
        return None


def _build_invite(
    method_cseq: int,
    uri: str, from_user: str, to_user: str,
    host: str, port: int, local_ip: str, local_port: int,
    call_id: str, from_tag: str, sdp: str,
    caller_id_name: str = "Pentest Demo",
    auth_header: str | None = None,
) -> bytes:
    from_line = (f'From: "{caller_id_name}" <sip:{from_user}@{local_ip}>'
                 f';tag={from_tag}')
    lines = [
        f"INVITE {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK-{from_tag};rport",
        "Max-Forwards: 70",
        from_line,
        f"To: <sip:{to_user}@{host}>",
        f"Call-ID: {call_id}",
        f"CSeq: {method_cseq} INVITE",
        f"Contact: <sip:{from_user}@{local_ip}:{local_port}>",
        "User-Agent: voip-demo/1.0 (authorized-test)",
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS",
    ]
    if auth_header:
        lines.append(auth_header)
    lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(sdp)}")
    lines.append("")
    return ("\r\n".join(lines) + "\r\n" + sdp).encode("utf-8")


def _build_ack(uri: str, from_user: str, to_user: str,
               host: str, port: int, local_ip: str, local_port: int,
               call_id: str, cseq: int, from_tag: str, to_tag: str | None) -> bytes:
    to_header = f"To: <sip:{to_user}@{host}>"
    if to_tag:
        to_header += f";tag={to_tag}"
    lines = [
        f"ACK {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK-ack-{from_tag};rport",
        "Max-Forwards: 70",
        f'From: <sip:{from_user}@{local_ip}>;tag={from_tag}',
        to_header,
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} ACK",
        f"Contact: <sip:{from_user}@{local_ip}:{local_port}>",
        "Content-Length: 0",
        "",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _build_bye(uri: str, from_user: str, to_user: str,
               host: str, port: int, local_ip: str, local_port: int,
               call_id: str, cseq: int, from_tag: str, to_tag: str | None) -> bytes:
    to_header = f"To: <sip:{to_user}@{host}>"
    if to_tag:
        to_header += f";tag={to_tag}"
    lines = [
        f"BYE {uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK-bye-{from_tag};rport",
        "Max-Forwards: 70",
        f'From: <sip:{from_user}@{local_ip}>;tag={from_tag}',
        to_header,
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} BYE",
        "Content-Length: 0",
        "",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _build_200_ok_for_request(request_bytes: bytes, local_ip: str,
                              local_port: int) -> bytes:
    """Echo back a 200 OK for a received in-dialog request (e.g. BYE)."""
    head, _, _ = request_bytes.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="replace").split("\r\n")
    keep: list[str] = ["SIP/2.0 200 OK"]
    for ln in lines[1:]:
        lo = ln.lower()
        if (lo.startswith("via:") or lo.startswith("from:")
                or lo.startswith("to:") or lo.startswith("call-id:")
                or lo.startswith("cseq:")):
            keep.append(ln)
    keep.append("Content-Length: 0")
    keep.append("")
    return ("\r\n".join(keep) + "\r\n").encode("utf-8")


def _build_cancel(uri: str, from_user: str, to_user: str,
                  host: str, port: int, local_ip: str, local_port: int,
                  call_id: str, cseq: int, from_tag: str,
                  to_tag: str | None) -> bytes:
    """Build a CANCEL to withdraw an in-progress INVITE (RFC 3261 §9.1).

    The CANCEL MUST share the same branch token, Call-ID, From, To, and CSeq
    sequence number as the INVITE so the server can match and cancel it.
    """
    to_header = f"To: <sip:{to_user}@{host}>"
    if to_tag:
        to_header += f";tag={to_tag}"
    lines = [
        f"CANCEL {uri} SIP/2.0",
        # Same branch as the INVITE Via header — server matches on this.
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch=z9hG4bK-{from_tag};rport",
        "Max-Forwards: 70",
        f'From: <sip:{from_user}@{local_ip}>;tag={from_tag}',
        to_header,
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} CANCEL",
        "Content-Length: 0",
        "",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _build_405_for_request(request_bytes: bytes, local_ip: str,
                           local_port: int) -> bytes:
    """Build a 405 Method Not Allowed response to an in-dialog SIP request.

    Used to cleanly reject re-INVITE, INFO, and other in-dialog methods we
    don't implement.  Echoes Via/From/To/Call-ID/CSeq from the incoming
    request so the remote stack can correlate the response.
    """
    head, _, _ = request_bytes.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="replace").split("\r\n")
    keep: list[str] = ["SIP/2.0 405 Method Not Allowed"]
    for ln in lines[1:]:
        lo = ln.lower()
        if (lo.startswith("via:") or lo.startswith("from:")
                or lo.startswith("to:") or lo.startswith("call-id:")
                or lo.startswith("cseq:")):
            keep.append(ln)
    keep.append("Allow: INVITE, ACK, CANCEL, BYE, OPTIONS")
    keep.append("Content-Length: 0")
    keep.append("")
    return ("\r\n".join(keep) + "\r\n").encode("utf-8")
