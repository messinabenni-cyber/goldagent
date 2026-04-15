"""Extension enumeration + PBX fingerprinting + auto-discovery."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import ami_attack, sip
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag


# Dial-plan profiles per fingerprinted PBX. (low, high) ranges sampled first
# at coarse step=10, then filled in ±9 around hits for efficiency.
DIALPLAN_PROFILES: dict[str, list[tuple[int, int]]] = {
    "Asterisk":      [(1000, 9999), (100, 999)],
    "FreePBX":       [(1000, 9999), (100, 999)],
    "FreeSWITCH":    [(1000, 9999)],
    "Kamailio":      [(1000, 9999), (100, 999)],
    "OpenSIPS":      [(1000, 9999), (100, 999)],
    "3CX":           [(100, 9999)],
    "Cisco CUCM":    [(1000, 9999), (10000, 19999)],
    "Cisco":         [(1000, 9999), (100, 999)],
    "Avaya":         [(1000, 9999), (10000, 19999)],
    "Mitel":         [(1000, 9999)],
    "Grandstream":   [(100, 9999)],
    "Panasonic":     [(100, 999)],
    # Phone vendors usually aren't PBXes; if they answer SIP anyway, probe small
    "Yealink":       [(100, 999)],
    "Polycom":       [(100, 999)],
    "Snom":          [(100, 999)],
    "default":       [(100, 9999)],
}


# Non-numeric aliases + feature codes seen on common PBXes.
# Intentionally excludes emergency numbers (911/112/999) — we never probe those.
# Per-vendor credential list files. Keys match values returned by
# `fingerprint()`. When running cred spray, lists matching the detected
# fingerprint are merged with the generic list.
VENDOR_CRED_FILES: dict[str, str] = {
    "Cisco":        "creds_cisco.txt",
    "Cisco CUCM":   "creds_cisco.txt",
    "Polycom":      "creds_polycom.txt",
    "Yealink":      "creds_yealink.txt",
    "Grandstream":  "creds_grandstream.txt",
    "Avaya":        "creds_avaya.txt",
    "Mitel":        "creds_mitel.txt",
}


SPECIAL_EXTENSIONS: list[str] = [
    # Role aliases
    "operator", "reception", "frontdesk", "lobby",
    "info", "support", "sales", "help", "helpdesk",
    "fax", "faxserver",
    # Voicemail / conferences
    "voicemail", "vm", "conference", "conf", "meetme",
    # Asterisk feature codes
    "*43",        # echo test
    "*97",        # my voicemail
    "*98",        # voicemail login
    "*60",        # SAY time
    "*65",        # SAY extension
    # Special Asterisk dial-plan labels
    "s", "i", "h", "t",
    # Generic default targets
    "anonymous", "guest", "default", "trunk",
    "0", "00", "000",
]


@dataclass
class ExtensionResult:
    extension: str
    exists: bool
    auth_required: bool
    open_register: bool = False        # 200 OK to REGISTER without creds
    anonymous_invite: bool = False     # 100/180/200 to INVITE without creds
    evidence: str = ""


# PBX fingerprint patterns — matches against Server / User-Agent
PBX_SIGNATURES = [
    ("Asterisk",      re.compile(r"Asterisk", re.I)),
    ("FreeSWITCH",    re.compile(r"FreeSWITCH", re.I)),
    ("Kamailio",      re.compile(r"Kamailio|OpenSER|SER", re.I)),
    ("OpenSIPS",      re.compile(r"OpenSIPS", re.I)),
    ("3CX",           re.compile(r"3CX", re.I)),
    ("Cisco CUCM",    re.compile(r"Cisco.*CUCM|CUCM", re.I)),
    ("Cisco",         re.compile(r"Cisco", re.I)),
    ("Avaya",         re.compile(r"Avaya", re.I)),
    ("Mitel",         re.compile(r"Mitel", re.I)),
    ("Grandstream",   re.compile(r"Grandstream", re.I)),
    ("Yealink",       re.compile(r"Yealink", re.I)),
    ("Polycom",       re.compile(r"Polycom|PolycomVoIP", re.I)),
    ("Panasonic",     re.compile(r"Panasonic", re.I)),
    ("Snom",          re.compile(r"snom", re.I)),
]


def fingerprint(banner: str) -> str:
    if not banner:
        return "unknown"
    for name, rx in PBX_SIGNATURES:
        if rx.search(banner):
            return name
    return banner.split("/")[0] if "/" in banner else banner[:40]


def enumerate_extension(
    host: str,
    ext: str,
    port: int = 5060,
    method: str = "REGISTER",
    local_ip: str | None = None,
    local_port: int = 0,
    timeout: float = 3.0,
    traffic_log=None,
) -> ExtensionResult:
    """Probe one extension using REGISTER or INVITE.

    Response interpretation (PBX-dependent but usually reliable):
      401/407 -> extension exists, auth required
      200 OK  -> extension exists, open / no auth required (!)
      100/180/183/200 to INVITE -> existing extension reachable w/o auth
      404/403 -> no such extension (or blocked)
    """
    if not local_ip:
        local_ip = local_ip_for(host)
    call_id = rand_call_id()
    tag = rand_tag()
    uri = f"sip:{host}"
    body = ""
    extras: list[str] = []
    if method == "REGISTER":
        # REGISTER is sent to the registrar (the server)
        request_uri = f"sip:{host}"
        extras = ["Expires: 30"]
    else:  # INVITE
        request_uri = f"sip:{ext}@{host}"
        # Minimal SDP so the PBX doesn't 488 us on missing media
        sdp = (
            "v=0\r\n"
            f"o=scanner 0 0 IN IP4 {local_ip}\r\n"
            "s=voip-scan\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        body = sdp

    msg = sip.build_message(
        method,
        request_uri,
        from_user=ext,
        to_user=ext,
        host=host,
        port=port,
        local_ip=local_ip,
        local_port=local_port or 0,
        call_id=call_id,
        cseq=1,
        from_tag=tag,
        body=body,
        extra_headers=extras,
    )
    data = sip.send_and_recv(msg, host, port, local_port, timeout, traffic_log=traffic_log)
    if not data:
        return ExtensionResult(ext, exists=False, auth_required=False,
                               evidence="no response")
    resp = sip.parse_response(data)
    if not resp:
        return ExtensionResult(ext, exists=False, auth_required=False,
                               evidence="unparseable response")

    evidence = f"{method} -> {resp.status_code} {resp.reason}"
    if resp.status_code in (401, 407):
        return ExtensionResult(ext, exists=True, auth_required=True,
                               evidence=evidence)
    if resp.status_code == 200:
        return ExtensionResult(
            ext, exists=True, auth_required=False,
            open_register=(method == "REGISTER"),
            anonymous_invite=(method == "INVITE"),
            evidence=evidence,
        )
    if resp.status_code in (100, 180, 183):
        # Provisional means the PBX is working the call — extension exists,
        # anonymous INVITE likely accepted. Not auth-required (no 401).
        return ExtensionResult(
            ext, exists=True, auth_required=False,
            anonymous_invite=(method == "INVITE"),
            evidence=evidence,
        )
    if resp.status_code in (404, 403, 603, 604):
        return ExtensionResult(ext, exists=False, auth_required=False,
                               evidence=evidence)
    # 486/488/500/503 etc. are ambiguous — call it "probably exists"
    return ExtensionResult(ext, exists=True, auth_required=False,
                           evidence=evidence + " (ambiguous)")


def enumerate_range(
    host: str,
    extensions: list[str],
    port: int = 5060,
    method: str = "REGISTER",
    timeout: float = 3.0,
    rate_per_second: float = 20,
    traffic_log=None,
) -> list[ExtensionResult]:
    rate = RateLimiter(rate_per_second)
    local_ip = local_ip_for(host)
    found: list[ExtensionResult] = []
    for ext in extensions:
        rate.wait()
        r = enumerate_extension(
            host, ext, port=port, method=method,
            local_ip=local_ip, timeout=timeout, traffic_log=traffic_log,
        )
        if r.exists:
            found.append(r)
    return found


def enumerate_range_parallel(
    host: str,
    extensions: list[str],
    port: int = 5060,
    method: str = "REGISTER",
    timeout: float = 3.0,
    max_workers: int = 20,
    traffic_log=None,
) -> list[ExtensionResult]:
    """Parallel extension enumeration using ThreadPoolExecutor.

    Up to 10-20× faster than serial enumerate_range() for large ranges.
    No explicit rate limiting — concurrency is bounded by max_workers.
    Suitable for pentest engagements where speed is preferred.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    local_ip = local_ip_for(host)
    found: list[ExtensionResult] = []
    found_lock = __import__("threading").Lock()

    def _probe(ext: str) -> ExtensionResult:
        return enumerate_extension(
            host, ext, port=port, method=method,
            local_ip=local_ip, timeout=timeout, traffic_log=traffic_log,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(_probe, ext): ext for ext in extensions}
        from concurrent.futures import as_completed
        for fut in as_completed(future_map):
            try:
                r = fut.result()
                if r.exists:
                    with found_lock:
                        found.append(r)
            except Exception:
                pass

    return sorted(found, key=lambda r: (len(r.extension), r.extension))


def subscribe_enumerate(
    host: str,
    extensions: list[str],
    port: int = 5060,
    timeout: float = 3.0,
    max_workers: int = 10,
    traffic_log=None,
) -> list[ExtensionResult]:
    """SUBSCRIBE-based extension enumeration (RFC 6665).

    Sends SUBSCRIBE with Event: message-summary (MWI) to each extension.
    200/202 → exists and MWI enabled
    489 Bad Event → exists but MWI unsupported (try presence)
    404 → does not exist

    Less noisy than REGISTER on some PBXes since SUBSCRIBE is expected
    from softphones probing for voicemail notifications.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    local_ip = local_ip_for(host)
    found: list[ExtensionResult] = []

    def _subscribe_probe(ext: str) -> ExtensionResult:
        resp = sip.subscribe_probe(
            host, ext, event_type="message-summary",
            port=port, local_ip=local_ip, timeout=timeout,
            traffic_log=traffic_log,
        )
        if not resp:
            return ExtensionResult(ext, exists=False, auth_required=False,
                                   evidence="no response to SUBSCRIBE")
        code = resp.status_code
        evidence = f"SUBSCRIBE → {code} {resp.reason}"
        if code in (200, 202):
            return ExtensionResult(ext, exists=True, auth_required=False,
                                   evidence=evidence)
        if code == 401:
            return ExtensionResult(ext, exists=True, auth_required=True,
                                   evidence=evidence)
        if code == 489:
            # Bad Event — extension exists but event unsupported
            return ExtensionResult(ext, exists=True, auth_required=False,
                                   evidence=evidence + " (event unsupported, ext exists)")
        if code in (404, 403, 604):
            return ExtensionResult(ext, exists=False, auth_required=False,
                                   evidence=evidence)
        # 481, 500, etc — ambiguous
        return ExtensionResult(ext, exists=True, auth_required=False,
                               evidence=evidence + " (ambiguous)")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_subscribe_probe, ext): ext for ext in extensions}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r.exists:
                    found.append(r)
            except Exception:
                pass

    return sorted(found, key=lambda r: (len(r.extension), r.extension))


_MAX_EXT_RANGE = 10_000   # cap per-call expansion to prevent DoS / accidental sweeps


def expand_ext_range(spec: str) -> list[str]:
    """Accept '1000-1099' or '100,200,300' or 'file:path'.

    Raises ValueError when any numeric range exceeds _MAX_EXT_RANGE entries.
    Raises FileNotFoundError (with a clear message) when file: path is missing.
    Rejects file: paths that contain '..' or are absolute, to prevent traversal.
    """
    if spec.startswith("file:"):
        raw_path = spec[5:]
        # Path traversal guard: reject absolute paths and anything with '..'
        import os as _os
        if _os.path.isabs(raw_path) or ".." in raw_path.split(_os.sep):
            raise ValueError(
                f"Unsafe file path rejected: {raw_path!r}. "
                "Use a relative path within the project directory."
            )
        try:
            with open(raw_path) as f:
                return [l.strip() for l in f
                        if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Extension list file not found: {raw_path!r}"
            )
    # Comma-separated list may contain ranges: "1000-1099,2000-2099,operator"
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
        if count > _MAX_EXT_RANGE:
            raise ValueError(
                f"Extension range {spec!r} expands to {count} entries "
                f"(max {_MAX_EXT_RANGE}). Split into smaller ranges."
            )
        return [str(i) for i in range(lo, hi + 1)]
    return [spec]


def ranges_for_fingerprint(fingerprint: str) -> list[tuple[int, int]]:
    """Return the dial-plan numeric ranges to probe based on the detected PBX."""
    return DIALPLAN_PROFILES.get(fingerprint, DIALPLAN_PROFILES["default"])


def cred_files_for_fingerprint(fingerprint: str,
                               wordlists_dir: str) -> list[str]:
    """Return paths to vendor-specific credential files that apply to the
    detected fingerprint. Always returns at least the generic default file."""
    import os
    result = [os.path.join(wordlists_dir, "default_credentials.txt")]
    vendor_file = VENDOR_CRED_FILES.get(fingerprint)
    if vendor_file:
        result.append(os.path.join(wordlists_dir, vendor_file))
    return [p for p in result if os.path.isfile(p)]


@dataclass
class AutoEnumResult:
    """Bundle of everything `auto_enumerate` discovered + how it was found."""
    extensions: list[ExtensionResult]          # per-ext enumeration results
    ami: ami_attack.AmiResult | None           # whether AMI pwned the PBX
    fingerprint: str                            # detected PBX
    ranges_probed: list[tuple[int, int]]
    specials_probed: list[str]
    method: str = "auto"                       # 'ami' | 'sweep' | 'ami+sweep'


def adaptive_sweep(
    host: str,
    port: int,
    low: int,
    high: int,
    coarse_step: int = 10,
    fill_radius: int = 9,
    method: str = "REGISTER",
    timeout: float = 3.0,
    rate_per_second: float = 50.0,
    traffic_log=None,
) -> list[ExtensionResult]:
    """Two-pass sweep: probe every `coarse_step`-th extension, then fill
    ±fill_radius around each hit. Typical speedup ~5-10× over full sweep
    for real dial plans which tend to cluster extensions together."""
    # Phase A — coarse
    coarse_candidates = [str(n) for n in range(low, high + 1, coarse_step)]
    coarse_hits = enumerate_range(
        host, coarse_candidates, port=port, method=method,
        timeout=timeout, rate_per_second=rate_per_second,
        traffic_log=traffic_log,
    )
    hits_by_ext: dict[str, ExtensionResult] = {r.extension: r for r in coarse_hits}

    # Phase B — fill ±fill_radius around each hit (dedup + skip already-probed)
    fill_numbers: set[int] = set()
    for r in coarse_hits:
        try:
            n = int(r.extension)
        except ValueError:
            continue
        for delta in range(-fill_radius, fill_radius + 1):
            neighbor = n + delta
            if low <= neighbor <= high and str(neighbor) not in hits_by_ext:
                fill_numbers.add(neighbor)
    fill_candidates = [str(n) for n in sorted(fill_numbers)]
    if fill_candidates:
        fill_hits = enumerate_range(
            host, fill_candidates, port=port, method=method,
            timeout=timeout, rate_per_second=rate_per_second,
            traffic_log=traffic_log,
        )
        for r in fill_hits:
            hits_by_ext[r.extension] = r

    return sorted(
        hits_by_ext.values(),
        key=lambda r: (len(r.extension), r.extension),
    )


def probe_extensions_invite(
    host: str,
    extensions: list[str],
    port: int = 5060,
    timeout: float = 3.0,
    rate_per_second: float = 50.0,
    traffic_log=None,
) -> dict[str, ExtensionResult]:
    """INVITE-probe a set of extensions to see which accept anonymous calls.
    Returns a dict keyed by extension."""
    results = enumerate_range(
        host, extensions, port=port, method="INVITE",
        timeout=timeout, rate_per_second=rate_per_second,
        traffic_log=traffic_log,
    )
    return {r.extension: r for r in results}


def auto_enumerate(
    host: str,
    port: int = 5060,
    fingerprint: str = "default",
    *,
    try_ami: bool = True,
    ami_port: int = 5038,
    ami_cred_pairs: list[tuple[str, str]] | None = None,
    custom_ranges: list[tuple[int, int]] | None = None,
    include_specials: bool = True,
    coarse_step: int = 10,
    fill_radius: int = 9,
    timeout: float = 3.0,
    rate_per_second: float = 50.0,
    traffic_log=None,
) -> AutoEnumResult:
    """End-to-end extension discovery — no wordlist required.

    Strategy (in order):
      1. Try AMI with default/weak credentials. On success: dump the literal
         extension list. Fastest + most complete path — no guessing.
      2. Adaptive numeric sweep of the dial-plan ranges appropriate for the
         detected PBX. REGISTER for speed (or custom_ranges override).
      3. Probe special aliases + feature codes (`operator`, `*43`, `s`, etc.).
      4. For every numeric/special hit, also INVITE-probe to capture
         anonymous-call acceptance.

    Returns an AutoEnumResult with the unified list + provenance.
    """
    ami_result: ami_attack.AmiResult | None = None
    discovered: dict[str, ExtensionResult] = {}
    ranges_used: list[tuple[int, int]] = []
    specials_used: list[str] = []
    method = "sweep"

    # ---- 1) AMI pwn ----
    if try_ami:
        ami_result = ami_attack.attack(
            host, port=ami_port,
            cred_pairs=ami_cred_pairs,
            timeout=timeout, traffic_log=traffic_log,
        )
        if ami_result.success and ami_result.extensions:
            method = "ami"
            # Seed with ground-truth from AMI
            for ext in ami_result.extensions:
                discovered[ext] = ExtensionResult(
                    extension=ext, exists=True, auth_required=False,
                    evidence=f"AMI dump: {ami_result.evidence}",
                )

    # ---- 2) Adaptive numeric sweep (skip if AMI produced a big list already) ----
    ranges_used = custom_ranges if custom_ranges else ranges_for_fingerprint(fingerprint)
    if method == "sweep" or (ami_result and not ami_result.extensions):
        for low, high in ranges_used:
            hits = adaptive_sweep(
                host, port, low, high,
                coarse_step=coarse_step, fill_radius=fill_radius,
                method="REGISTER",
                timeout=timeout, rate_per_second=rate_per_second,
                traffic_log=traffic_log,
            )
            for r in hits:
                if r.extension not in discovered:
                    discovered[r.extension] = r
        if ami_result and ami_result.success and discovered:
            method = "ami+sweep"

    # ---- 3) Specials ----
    if include_specials:
        specials_used = list(SPECIAL_EXTENSIONS)
        special_hits = enumerate_range(
            host, specials_used, port=port, method="REGISTER",
            timeout=timeout, rate_per_second=rate_per_second,
            traffic_log=traffic_log,
        )
        for r in special_hits:
            if r.extension not in discovered:
                discovered[r.extension] = r

    # ---- 4) INVITE-probe every hit to capture anonymous-call acceptance ----
    if discovered:
        invite_map = probe_extensions_invite(
            host, list(discovered.keys()),
            port=port, timeout=timeout,
            rate_per_second=rate_per_second,
            traffic_log=traffic_log,
        )
        for ext, inv in invite_map.items():
            existing = discovered[ext]
            # Merge: anonymous_invite / open_register flags combine
            existing.anonymous_invite = existing.anonymous_invite or inv.anonymous_invite
            existing.open_register = existing.open_register or inv.open_register
            # auth_required is true iff BOTH methods returned 401, but for
            # reporting we prefer "weakest" view → false if either method got
            # through without auth
            existing.auth_required = existing.auth_required and inv.auth_required
            # Combine evidence so the report shows how we classified it
            existing.evidence = f"{existing.evidence}; {inv.evidence}"

    extensions = sorted(
        discovered.values(),
        key=lambda r: (len(r.extension), r.extension),
    )

    return AutoEnumResult(
        extensions=extensions,
        ami=ami_result,
        fingerprint=fingerprint,
        ranges_probed=ranges_used,
        specials_probed=specials_used,
        method=method,
    )
