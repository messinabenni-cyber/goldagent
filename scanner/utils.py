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


# ---------------------------------------------------------------------------
# Terminal colours + live progress
# ---------------------------------------------------------------------------

import sys as _sys
import threading as _threading


class Colours:
    """ANSI escape codes. Degrades to empty strings when stdout is not a TTY."""

    def __init__(self, force: bool | None = None):
        on = _sys.stdout.isatty() if force is None else force
        self.RED    = "\033[91m" if on else ""
        self.GREEN  = "\033[92m" if on else ""
        self.YELLOW = "\033[93m" if on else ""
        self.CYAN   = "\033[96m" if on else ""
        self.BOLD   = "\033[1m"  if on else ""
        self.DIM    = "\033[2m"  if on else ""
        self.RESET  = "\033[0m"  if on else ""

    def for_severity(self, sev: str) -> str:
        return {
            "critical": self.RED + self.BOLD,
            "high":     self.RED,
            "medium":   self.YELLOW,
            "low":      self.GREEN,
            "info":     self.CYAN,
        }.get(sev.lower(), "")


class Progress:
    """Thread-safe in-place terminal progress counter.

    Pass `prog.tick` as the `progress_cb` argument to enumeration sweeps.
    Call `prog.close()` when done to emit a trailing newline.
    """

    def __init__(self, label: str, total: int, col: "Colours | None" = None):
        self._label = label
        self._total = max(total, 1)
        self._done  = 0
        self._hits  = 0
        self._col   = col
        self._tty   = _sys.stdout.isatty()
        self._lock  = _threading.Lock()

    def tick(self, hit: bool = False) -> None:
        with self._lock:
            self._done += 1
            if hit:
                self._hits += 1
            self._draw()

    def _draw(self) -> None:
        if not self._tty:
            return
        pct    = int(100 * self._done / self._total)
        bw     = 26
        filled = min(bw, int(bw * self._done / self._total))
        bar    = "=" * filled + (">" if filled < bw else "") + " " * max(0, bw - filled - 1)
        c = self._col
        g, r = (c.GREEN, c.RESET) if c else ("", "")
        hits_str = f"  hits:{g}{self._hits}{r}" if self._hits else ""
        _sys.stdout.write(
            f"\r  {self._label}: [{bar}] {self._done}/{self._total} ({pct}%)"
            f"{hits_str}    "
        )
        _sys.stdout.flush()

    def close(self) -> None:
        if self._tty:
            _sys.stdout.write("\n")
            _sys.stdout.flush()
