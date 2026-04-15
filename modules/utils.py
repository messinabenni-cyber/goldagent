"""Shared helpers: rate limiting, logging, identity generation."""
from __future__ import annotations

import hashlib
import os
import random
import socket
import string
import threading
import time
from dataclasses import dataclass, field


def rand_tag(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def rand_call_id() -> str:
    return f"{rand_tag(16)}@voip-scan"


def rand_branch() -> str:
    # RFC 3261 requires z9hG4bK prefix for Via branches
    return "z9hG4bK-" + rand_tag(16)


def local_ip_for(target: str) -> str:
    """Return the local IP the kernel would pick to reach `target`."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def md5hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


@dataclass
class RateLimiter:
    """Thread-safe rate limiter (packets per second). Multiple threads may
    share a single RateLimiter — the lock serializes their scheduling so
    the combined output rate stays close to `rate`.

    Audit note: previous versions were not thread-safe, so
    concurrent discovery workers could exceed `rate` proportionally to
    the number of threads."""
    rate: float
    _last: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def wait(self) -> None:
        if self.rate <= 0:
            return
        interval = 1.0 / self.rate
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < interval:
                sleep_for = interval - delta
            else:
                sleep_for = 0.0
            # Record the *scheduled* next time so back-to-back callers chain
            self._last = now + sleep_for
        if sleep_for > 0:
            time.sleep(sleep_for)


class TrafficLog:
    """Append every outbound SIP datagram + response to a log file."""

    def __init__(self, path: str | None):
        self.path = path
        # Traffic log contains raw SIP including Authorization: headers, captured
        # nonces, and cracked credentials. Open owner-only (0o600) so shared-host
        # backups/syncs can't leak credentials to other users.
        self._fh = None
        if path:
            import os as _os
            flags = _os.O_WRONLY | _os.O_CREAT | _os.O_APPEND
            fd = _os.open(path, flags, 0o600)
            self._fh = _os.fdopen(fd, "a", encoding="utf-8")

    def log(self, direction: str, peer: str, payload: bytes) -> None:
        if not self._fh:
            return
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        header = f"\n=== {ts} {direction} {peer} ===\n"
        try:
            body = payload.decode("utf-8", errors="replace")
        except Exception:
            body = repr(payload)
        self._fh.write(header + body + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def severity_score(findings: list[dict]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        out[f.get("severity", "info")] = out.get(f.get("severity", "info"), 0) + 1
    return out


def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
