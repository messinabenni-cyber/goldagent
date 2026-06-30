"""SIP extension enumeration.

Uses REGISTER as the primary probe (most reliable across PBXes) and INVITE
as the secondary to detect anonymous-call acceptance (the toll-fraud
precondition). Dial-plan ranges are tuned for FreePBX / Asterisk / Grandstream
deployments — extensions cluster in 1000-1999, 100-999, 2000-2999.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import sip
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag


_MAX_RANGE = 10_000   # cap any single range expansion to prevent runaway sweeps


# Special / feature-code extensions seen on the target platforms
SPECIAL_EXTENSIONS: list[str] = [
    # Operator / reception shortcuts (highest hit rate — probed first)
    "0", "9", "00", "000", "0000",
    # Asterisk dial-plan context labels
    "s", "i", "h", "t",
    # Role aliases common across all PBX brands
    "operator", "reception", "info", "support", "sales", "helpdesk",
    "voicemail", "vm", "conference", "conf", "meeting",
    "anonymous", "guest", "default", "trunk",
    "fax", "it", "hr", "accounts", "finance", "ceo", "admin",
    # Asterisk feature codes
    "*43", "*97", "*98", "*60", "*65", "*69", "*70", "*72", "*73",
    # Common round-number targets
    "1", "2", "3", "99", "999", "9999",
]

# Per-fingerprint dial-plan ranges (probed in coarse + fill passes).
# 100-5000 covers the vast majority of real deployments and completes
# significantly faster than sweeping to 9999.
DIALPLAN_RANGES: dict[str, list[tuple[int, int]]] = {
    "FreePBX":     [(100, 5000)],
    "Asterisk":    [(100, 5000)],
    "Grandstream": [(100, 5000)],
    "3CX":         [(100, 5000)],
    "Kamailio":    [(100, 5000)],
    "OpenSIPS":    [(100, 5000)],
    "FreeSWITCH":  [(100, 5000)],
    "default":     [(100, 5000)],
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
) -> ExtensionResult:
    if not local_ip:
        # Prefer caller-supplied public/reflexive IP for SIP headers
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
    else:   # INVITE
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

    msg = sip.build_message(
        method, request_uri,
        from_user=ext, to_user=ext,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
        body=body, extra_headers=extras,
        transport=transport,
    )
    if tcp:
        data = sip.send_and_recv_tcp(msg, host, port, timeout=timeout,
                                      use_tls=use_tls, traffic_log=traffic_log)
    else:
        data = sip.send_and_recv(msg, host, port, 0, timeout,
                                  traffic_log=traffic_log)
    if not data:
        return ExtensionResult(ext, exists=False, evidence="no response")
    resp = sip.parse_response(data)
    if not resp:
        return ExtensionResult(ext, exists=False, evidence="unparseable response")

    evidence = f"{method} -> {resp.status_code} {resp.reason}"
    if resp.status_code in (401, 407):
        return ExtensionResult(ext, exists=True, auth_required=True, evidence=evidence)
    if resp.status_code == 200:
        return ExtensionResult(
            ext, exists=True,
            open_register=(method == "REGISTER"),
            anonymous_invite=(method == "INVITE"),
            evidence=evidence,
        )
    if resp.status_code in (100, 180, 183):
        return ExtensionResult(
            ext, exists=True,
            anonymous_invite=(method == "INVITE"),
            evidence=evidence,
        )
    if resp.status_code in (404, 403, 603, 604):
        return ExtensionResult(ext, exists=False, evidence=evidence)
    # Ambiguous (486, 488, 500, 503, ...): assume exists
    return ExtensionResult(ext, exists=True,
                            evidence=evidence + " (ambiguous)")


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
    progress_cb=None,   # Callable[[bool], None] — called with hit=True/False per result
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
) -> list[ExtensionResult]:
    """Parallel sweep over a list of extension candidates. Returns only hits."""
    hits: list[ExtensionResult] = []

    def _probe(ext: str) -> ExtensionResult:
        return probe(host, ext, port=port, method=method,
                     timeout=timeout, traffic_log=traffic_log,
                     source_ip=source_ip, tcp=tcp, use_tls=use_tls)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_probe, e): e for e in extensions}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                hit = r.exists
                if hit:
                    hits.append(r)
                if progress_cb:
                    progress_cb(hit)
            except Exception:
                if progress_cb:
                    progress_cb(False)
                continue
    return sorted(hits, key=lambda r: (len(r.extension), r.extension))


def adaptive_sweep(
    host: str,
    port: int,
    low: int,
    high: int,
    coarse_step: int = 10,
    fill_radius: int = 9,
    timeout: float = 3.0,
    max_workers: int = 20,
    traffic_log=None,
    progress_cb=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
) -> list[ExtensionResult]:
    """Two-pass sweep: every Nth extension first, then ±radius around each hit.

    Typical 5-10x speedup over a full sweep — real dial plans cluster.
    """
    coarse_cands = [str(n) for n in range(low, high + 1, coarse_step)]
    coarse_hits = sweep(host, coarse_cands, port=port,
                        timeout=timeout, max_workers=max_workers,
                        traffic_log=traffic_log, progress_cb=progress_cb,
                        source_ip=source_ip, tcp=tcp, use_tls=use_tls)
    by_ext = {r.extension: r for r in coarse_hits}

    fill: set[int] = set()
    for r in coarse_hits:
        try:
            n = int(r.extension)
        except ValueError:
            continue
        for delta in range(-fill_radius, fill_radius + 1):
            nb = n + delta
            if low <= nb <= high and str(nb) not in by_ext:
                fill.add(nb)

    if fill:
        fill_cands = [str(n) for n in sorted(fill)]
        for r in sweep(host, fill_cands, port=port, timeout=timeout,
                       max_workers=max_workers, traffic_log=traffic_log,
                       progress_cb=progress_cb,
                       source_ip=source_ip, tcp=tcp, use_tls=use_tls):
            by_ext[r.extension] = r

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
