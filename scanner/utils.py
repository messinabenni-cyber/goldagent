"""Small helpers used across the scanner. No external deps."""
from __future__ import annotations

import hashlib
import os
import random
import socket
import string
import time
from pathlib import Path


def md5hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def rand_tag(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def rand_call_id() -> str:
    return f"{rand_tag(24)}@scanner"


def rand_branch() -> str:
    return f"z9hG4bK-{rand_tag(16)}"


def hash_file(path: str) -> str:
    """SHA-256 of a file's bytes — for scope-of-work audit hashing."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def local_ip_for(remote_host: str) -> str:
    """Return the local IP the kernel would use to reach remote_host.

    Uses connectionless UDP so it works even when remote_host doesn't accept
    connections — connect() on a UDP socket only sets the route, doesn't
    transmit anything.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((remote_host, 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class RateLimiter:
    """Token-bucket-ish rate limiter. Call .wait() before every operation.

    Thread-safe by virtue of the GIL — only mutates a float.
    """

    def __init__(self, rate_per_second: float):
        self.interval = 1.0 / max(rate_per_second, 0.1)
        self._next = time.monotonic()

    def wait(self) -> None:
        now = time.monotonic()
        sleep_for = self._next - now
        if sleep_for > 0:
            time.sleep(sleep_for)
        self._next = max(self._next + self.interval, now + self.interval)


class TrafficLog:
    """Append-only signalling trace. One file per scan run.

    Format is human-readable; each entry is:
        === <ISO timestamp> <OUT|IN> <peer> ===
        <payload bytes decoded as utf-8 with replacement>
    """

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def log(self, direction: str, peer: str, payload: bytes) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        text = payload.decode("utf-8", errors="replace")
        self._fh.write(f"\n=== {ts} {direction} {peer} ===\n{text}\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


def severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        severity.lower(), 99
    )


def severity_counts(findings: list[dict]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in out:
            out[sev] += 1
    return out
