"""SIP extension enumeration.

Uses REGISTER as the primary probe (most reliable across PBXes), OPTIONS as
a secondary tiebreaker, and INVITE to detect anonymous-call acceptance.
Three-pass adaptive sweep: coarse → cluster fill → iterative frontier expansion
until convergence.
"""
from __future__ import annotations

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import sip
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag

log = logging.getLogger(__name__)

_MAX_RANGE = 10_000   # cap any single range expansion to prevent runaway sweeps
_MAX_RESULTS = 5_000  # cap accumulated hits to prevent unbounded memory use

# Adaptive rate limiter — starts fast, backs off when 429/503 detected.
# Shared across threads; .wait() is GIL-safe for a single float mutation.
import threading as _threading
_rate_limited = False
_rate_limited_lock = _threading.Lock()


# ---------------------------------------------------------------------------
# Special / feature-code extensions (probed first — highest hit rate)
# ---------------------------------------------------------------------------

SPECIAL_EXTENSIONS: list[str] = [
    # Operator / reception shortcuts
    "0", "9", "00", "000", "0000",
    # Two-digit extensions — common on small PBXes and direct-dial offices
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
    "30", "31", "32", "33", "40", "41", "50", "51",
    "60", "70", "80", "90", "91", "95", "99",
    # Zero-padded operator shortcuts
    "01", "09", "001", "0001",
    # Asterisk dial-plan context labels
    "s", "i", "h", "t",
    # Role aliases (all major PBX brands)
    "operator", "reception", "info", "support", "sales", "helpdesk",
    "voicemail", "vm", "vmail", "conference", "conf", "meeting",
    "anonymous", "guest", "default", "trunk", "external",
    "fax", "efax", "it", "hr", "accounts", "finance", "ceo", "admin",
    "security", "reception1", "reception2",
    # Asterisk feature codes
    "*43", "*97", "*98", "*60", "*65", "*69", "*70", "*72", "*73",
    "*74", "*76", "*78", "*79",
    # Common IVR / auto-attendant / voicemail pilot numbers
    "1", "2", "3", "8", "99", "999", "9999",
    "1000", "2000", "3000", "4000", "5000", "6000", "7000", "8000", "9000",
    "100", "200", "300", "400", "500", "600", "700", "800", "900",
    # SIP echo / test extensions seen on many open PBXes
    "echo", "test", "demo", "9998", "9997", "4747",
    # Common conference bridge extensions
    "8500", "8600", "8700", "6001", "6500",
    # Parking / pickup
    "70", "700", "701", "702", "710", "711",
]


# ---------------------------------------------------------------------------
# Per-platform dial-plan ranges
# ---------------------------------------------------------------------------

# Ranges are probed in order: coarse step first, then fill passes.
# 10-99 is explicitly included because 2-digit extensions are entirely absent
# from the prior implementation and represent a real SMB deployment pattern.

DIALPLAN_RANGES: dict[str, list[tuple[int, int]]] = {
    # FreePBX defaults: 4-digit (1000+) is most common, 3-digit also used
    "FreePBX":     [(10, 99), (100, 999), (1000, 6999)],
    # Raw Asterisk: anything goes — sweep broadly
    "Asterisk":    [(10, 99), (100, 999), (1000, 9999)],
    # Grandstream UCM6xxx: factory defaults 1000-1099; larger sites go higher
    "Grandstream": [(10, 99), (100, 799), (1000, 6999)],
    # 3CX: 3-digit style (100-899) and some 4-digit
    "3CX":         [(10, 99), (100, 899), (1000, 1999)],
    # Kamailio / OpenSIPS / FreeSWITCH: generic SIP — sweep broadly
    "Kamailio":    [(10, 99), (100, 999), (1000, 9999)],
    "OpenSIPS":    [(10, 99), (100, 999), (1000, 9999)],
    "FreeSWITCH":  [(10, 99), (100, 999), (1000, 9999)],
    # Mitel / ShoreTel: 3-digit and low 4-digit
    "Mitel":       [(10, 99), (100, 499), (1000, 4999)],
    # Sangoma (NetBorder / Vega): similar to FreePBX
    "Sangoma":     [(10, 99), (100, 999), (1000, 6999)],
    # Fallback for unrecognised fingerprints
    "default":     [(10, 99), (100, 999), (1000, 6999)],
}


@dataclass
class ExtensionResult:
    extension: str
    exists: bool
    auth_required: bool = False
    open_register: bool = False        # 200 OK to unauth REGISTER
    anonymous_invite: bool = False     # 100/180/200 to unauth INVITE
    evidence: str = ""


# ---------------------------------------------------------------------------
# Range expansion
# ---------------------------------------------------------------------------

def expand_ext_range(spec: str) -> list[str]:
    """Accept '1000-1099' or '100,200,300' or 'file:path' or comma-separated mix."""
    if spec.startswith("file:"):
        import os as _os
        raw_path = spec[5:]
        if _os.path.isabs(raw_path) or ".." in raw_path.split(_os.sep):
            raise ValueError(f"Unsafe file path rejected: {raw_path!r}")
        with open(raw_path) as f:
            return [l.strip() for l in f
                    if l.strip() and not l.startswith("#")]

    if "," in spec:
        out: list[str] = []
        for part in spec.split(","):
            out.extend(expand_ext_range(part.strip()))
        if len(out) > _MAX_RANGE:
            raise ValueError(
                f"Combined extension list expands to {len(out)} entries (max {_MAX_RANGE}). "
                "Split into smaller batches."
            )
        return out

    if "-" in spec:
        a, b = spec.split("-", 1)
        try:
            lo, hi = int(a), int(b)
        except ValueError:
            return [spec]
        count = hi - lo + 1
        if count > _MAX_RANGE:
            raise ValueError(
                f"Extension range {spec!r} expands to {count} entries "
                f"(max {_MAX_RANGE}). Split into smaller ranges."
            )
        return [str(i) for i in range(lo, hi + 1)]

    return [spec]


# ---------------------------------------------------------------------------
# Response classification
# ---------------------------------------------------------------------------

def _classify(resp: sip.SipResponse, method: str, ext: str) -> ExtensionResult:
    """Map a SIP response code to an ExtensionResult.

    RFC-correct mappings (prior code had 603 and 403 wrong):
      401/407 → exists, auth challenge
      200     → exists, open (register/invite accepted without auth)
      100/180/183 → exists, ringing/trying
      403     → exists, forbidden (extension known but rejected — auth type issue)
      405     → exists, method not allowed (server recognised the extension URI)
      480     → exists, temporarily unavailable
      486     → exists, busy here
      487     → exists, request terminated
      603     → exists, declined (callee explicitly rejected — real extension)
      404     → does not exist
      604     → does not exist anywhere (RFC 4458)
      485     → ambiguous (multiple choices — address exists)
      Other   → assume exists (conservative — avoids false negatives)
    """
    code = resp.status_code
    ev = f"{method} -> {code} {resp.reason}"

    if code in (401, 407):
        return ExtensionResult(ext, exists=True, auth_required=True, evidence=ev)

    if code == 200:
        return ExtensionResult(
            ext, exists=True,
            open_register=(method == "REGISTER"),
            anonymous_invite=(method == "INVITE"),
            evidence=ev,
        )

    if code in (100, 180, 183):
        return ExtensionResult(
            ext, exists=True,
            anonymous_invite=(method == "INVITE"),
            evidence=ev,
        )

    if code == 403:
        # Forbidden — server knows this extension but won't allow it
        return ExtensionResult(ext, exists=True, auth_required=True,
                               evidence=ev + " (forbidden)")

    if code == 405:
        # Method Not Allowed — server recognised the extension URI
        return ExtensionResult(ext, exists=True,
                               evidence=ev + " (method N/A)")

    if code in (480, 487):
        # Temporarily Unavailable / Request Terminated — extension is real
        return ExtensionResult(ext, exists=True,
                               evidence=ev + " (temp unavail)")

    if code == 486:
        return ExtensionResult(ext, exists=True, evidence=ev + " (busy)")

    if code == 603:
        # Decline — callee explicitly rejected the request; extension is real
        return ExtensionResult(ext, exists=True, evidence=ev + " (declined)")

    if code in (404, 410, 604):
        return ExtensionResult(ext, exists=False, evidence=ev)

    if code == 501:
        return ExtensionResult(ext, exists=False, evidence=ev + " (method not supported)")

    # 500, 488, 485, and everything else — conservative: assume exists
    return ExtensionResult(ext, exists=True,
                           evidence=ev + " (ambiguous)")


# ---------------------------------------------------------------------------
# Single-extension probe
# ---------------------------------------------------------------------------

def probe(
    host: str,
    ext: str,
    port: int = 5060,
    method: str = "REGISTER",
    local_ip: str | None = None,
    timeout: float = 3.0,
    traffic_log=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
    retries: int = 1,
    header_ip: str | None = None,
    extra_headers: list[str] | None = None,
) -> ExtensionResult:
    """Probe a single extension. Retries once on timeout (catches UDP loss).

    Supports REGISTER, INVITE, and OPTIONS. OPTIONS targets sip:{ext}@{host}
    so each extension gets its own probe (unlike the server-level OPTIONS in
    sip.options_probe).
    """
    global _rate_limited

    if not local_ip:
        local_ip = source_ip if source_ip else local_ip_for(host)
    call_id = rand_call_id()
    tag = rand_tag()

    if use_tls:
        tcp = True
    transport = "TLS" if use_tls else ("TCP" if tcp else "UDP")

    if method == "REGISTER":
        request_uri = f"sip:{host}"
        extras = ["Expires: 30"]
        body = ""
    elif method == "INVITE":
        request_uri = f"sip:{ext}@{host}"
        extras = []
        body = (
            "v=0\r\n"
            f"o=scanner 0 0 IN IP4 {local_ip}\r\n"
            "s=voip-scan\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
    else:  # OPTIONS — extension-targeted, not server-level
        request_uri = f"sip:{ext}@{host}"
        extras = ["Accept: application/sdp"]
        body = ""

    all_extras = (extras or []) + (extra_headers or [])
    msg = sip.build_message(
        method, request_uri,
        from_user=ext, to_user=ext,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
        body=body, extra_headers=all_extras if all_extras else None,
        transport=transport,
        header_ip=header_ip,
    )

    data: bytes | None = None
    for attempt in range(retries + 1):
        if tcp:
            data = sip.send_and_recv_tcp(msg, host, port, timeout=timeout,
                                          use_tls=use_tls,
                                          traffic_log=traffic_log)
        else:
            data = sip.send_and_recv(msg, host, port, 0, timeout,
                                      traffic_log=traffic_log)
        if data:
            break
        if attempt < retries:
            # Brief pause before retry; avoids hammering on UDP loss
            time.sleep(0.15 * (attempt + 1))
            # Rebuild with fresh call-id so server doesn't treat as duplicate
            call_id = rand_call_id()
            tag = rand_tag()
            msg = sip.build_message(
                method, request_uri,
                from_user=ext, to_user=ext,
                host=host, port=port,
                local_ip=local_ip, local_port=0,
                call_id=call_id, cseq=1, from_tag=tag,
                body=body, extra_headers=extras,
                transport=transport,
            )

    if not data:
        return ExtensionResult(ext, exists=False, evidence="no response")

    resp = sip.parse_response(data)
    if not resp:
        return ExtensionResult(ext, exists=False, evidence="unparseable response")

    # Rate-limit detection — back off to protect the scan and the target
    if resp.status_code in (429, 503):
        with _rate_limited_lock:
            _rate_limited = True
        time.sleep(2.0 + attempt * 1.0)   # per-thread backoff
        return ExtensionResult(ext, exists=True,
                               evidence=f"{method} -> {resp.status_code} (rate-limited)")

    if _rate_limited:
        # Another thread detected rate-limiting; honour a brief cooldown
        time.sleep(0.5)

    return _classify(resp, method, ext)


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------

def sweep(
    host: str,
    extensions: list[str],
    port: int = 5060,
    method: str = "REGISTER",
    timeout: float = 3.0,
    max_workers: int = 20,
    traffic_log=None,
    progress_cb=None,   # Callable[[bool], None] — called with hit=True/False
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
    retries: int = 1,
    max_results: int = _MAX_RESULTS,
    header_ip: str | None = None,
    extra_headers: list[str] | None = None,
) -> list[ExtensionResult]:
    """Parallel sweep over a list of extension candidates. Returns only hits.

    Caps accumulated results at *max_results* (default 5 000) to bound memory
    use when scanning very large extension spaces.  A warning is emitted if the
    cap is reached.  Partial results are returned on KeyboardInterrupt.
    """
    hits: list[ExtensionResult] = []
    _capped = False

    def _probe(ext: str) -> ExtensionResult:
        return probe(host, ext, port=port, method=method,
                     timeout=timeout, traffic_log=traffic_log,
                     source_ip=source_ip, tcp=tcp, use_tls=use_tls,
                     retries=retries,
                     header_ip=header_ip,
                     extra_headers=extra_headers)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_probe, e): e for e in extensions}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    hit = r.exists
                    if hit:
                        if len(hits) >= max_results:
                            if not _capped:
                                _capped = True
                                log.warning(
                                    "sweep: max_results cap of %d reached — "
                                    "truncating remaining hits", max_results
                                )
                        else:
                            hits.append(r)
                    if progress_cb:
                        progress_cb(hit)
                except Exception as _exc:
                    if progress_cb:
                        progress_cb(False)
                    # Log unexpected errors so they're visible in traffic log
                    if traffic_log:
                        traffic_log.log("ERR", f"{host}:probe", str(_exc).encode())
                    continue
    except KeyboardInterrupt:
        log.warning(
            "sweep: interrupted — returning %d partial result(s) found so far",
            len(hits),
        )

    return sorted(hits, key=lambda r: (len(r.extension), r.extension))


def adaptive_sweep(
    host: str,
    port: int,
    low: int,
    high: int,
    coarse_step: int = 10,
    fill_radius: int = 11,
    max_fill_passes: int = 4,
    timeout: float = 3.0,
    max_workers: int = 20,
    traffic_log=None,
    progress_cb=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
    force_full_enum: bool = False,
    max_results: int = _MAX_RESULTS,
) -> list[ExtensionResult]:
    """Multi-pass adaptive sweep: coarse scan + iterative frontier expansion.

    Pass 1 — coarse: probe every coarse_step-th extension across [low, high].
    Passes 2-N — fill: for each newly discovered extension, probe ±fill_radius
    neighbours that haven't been seen yet. Repeat with the *new* hits as the
    frontier until no new hits are found or max_fill_passes is exhausted.

    This converges on dense clusters (e.g. 1000-1049 all active) in O(cluster)
    rather than O(range) probes while still covering the full coarse grid.

    Zero-padded extensions (e.g. 001, 0100) are not covered here — include them
    in SPECIAL_EXTENSIONS sweeps before calling this function.

    If high-low > _MAX_RANGE a warning is logged and the range is capped at
    low+_MAX_RANGE unless *force_full_enum* is True.

    Partial results are returned on KeyboardInterrupt.
    """
    span = high - low
    if span > _MAX_RANGE:
        if force_full_enum:
            log.warning(
                "adaptive_sweep: range %d-%d spans %d extensions (> %d cap); "
                "proceeding because force_full_enum=True",
                low, high, span, _MAX_RANGE,
            )
        else:
            capped_high = low + _MAX_RANGE
            log.warning(
                "adaptive_sweep: range %d-%d spans %d extensions (> %d cap); "
                "capping at %d. Pass force_full_enum=True to override.",
                low, high, span, _MAX_RANGE, capped_high,
            )
            high = capped_high

    by_ext: dict[str, ExtensionResult] = {}

    try:
        coarse_cands = [str(n) for n in range(low, high + 1, coarse_step)]
        coarse_hits = sweep(host, coarse_cands, port=port,
                            timeout=timeout, max_workers=max_workers,
                            traffic_log=traffic_log, progress_cb=progress_cb,
                            source_ip=source_ip, tcp=tcp, use_tls=use_tls,
                            max_results=max_results)
        by_ext = {r.extension: r for r in coarse_hits}

        # Iterative fill: frontier = newly found extensions this round
        frontier: set[str] = {r.extension for r in coarse_hits}

        for _pass in range(max_fill_passes):
            if not frontier:
                break

            fill: set[int] = set()
            for ext_str in frontier:
                try:
                    n = int(ext_str)
                except ValueError:
                    continue
                for delta in range(-fill_radius, fill_radius + 1):
                    nb = n + delta
                    if low <= nb <= high and str(nb) not in by_ext:
                        fill.add(nb)

            if not fill:
                break

            fill_cands = [str(n) for n in sorted(fill)]
            new_frontier: set[str] = set()
            for r in sweep(host, fill_cands, port=port, timeout=timeout,
                           max_workers=max_workers, traffic_log=traffic_log,
                           progress_cb=progress_cb,
                           source_ip=source_ip, tcp=tcp, use_tls=use_tls,
                           max_results=max(0, max_results - len(by_ext))):
                if r.extension not in by_ext:
                    by_ext[r.extension] = r
                    new_frontier.add(r.extension)

            frontier = new_frontier   # only expand around brand-new hits next pass

    except KeyboardInterrupt:
        log.warning(
            "adaptive_sweep: interrupted — returning %d partial result(s) found so far",
            len(by_ext),
        )

    return sorted(by_ext.values(),
                  key=lambda r: (len(r.extension), r.extension))


def probe_invite_acceptance(
    host: str,
    extensions: list[str],
    port: int = 5060,
    timeout: float = 3.0,
    max_workers: int = 20,
    traffic_log=None,
    progress_cb=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
) -> dict[str, ExtensionResult]:
    """INVITE-probe a set of extensions to capture anonymous-call acceptance."""
    results = sweep(host, extensions, port=port, method="INVITE",
                    timeout=timeout, max_workers=max_workers,
                    traffic_log=traffic_log, progress_cb=progress_cb,
                    source_ip=source_ip, tcp=tcp, use_tls=use_tls)
    return {r.extension: r for r in results}


def ranges_for_fingerprint(fp: str) -> list[tuple[int, int]]:
    return DIALPLAN_RANGES.get(fp, DIALPLAN_RANGES["default"])
