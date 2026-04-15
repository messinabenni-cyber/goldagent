"""Real-time SIP traffic anomaly detection.

Consumes events from the event bus and identifies suspicious patterns that
indicate toll fraud, enumeration, credential attacks, and downgrade attempts.

Detections (with thresholds):
  INVITE flood           — >20 INVITEs in 10 s          → CRITICAL
  Nonce reuse            — same nonce seen twice          → HIGH
  Extension scan         — >50 distinct extensions in 30s → HIGH
  Anonymous call surge   — >5 anon INVITE successes in 60s→ CRITICAL
  Credential spray       — same password on >5 extensions → HIGH
  New anon extension     — any continuous.new_anon event  → MEDIUM
  Codec negotiation fail — >10 codec mismatches           → LOW
  BYE flood              — >15 BYEs in 10 s              → HIGH
  CANCEL flood           — >10 CANCELs in 10 s           → HIGH
  Failed-auth ratio      — >80% of auth attempts fail     → HIGH
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from queue import Queue, Empty

from .events import bus


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    type: str
    severity: str          # "low" | "medium" | "high" | "critical"
    description: str
    evidence: dict
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Thresholds — collected here so they are easy to tune
# ---------------------------------------------------------------------------

_INVITE_FLOOD_LIMIT    = 20     # INVITEs
_INVITE_FLOOD_WINDOW   = 10.0   # seconds

_EXT_SCAN_LIMIT        = 50     # distinct extensions
_EXT_SCAN_WINDOW       = 30.0   # seconds

_ANON_SURGE_LIMIT      = 5      # successful anonymous INVITEs
_ANON_SURGE_WINDOW     = 60.0   # seconds  (same as default window_seconds)

_CRED_SPRAY_LIMIT      = 5      # distinct extensions per password

_CODEC_FAIL_LIMIT      = 10     # cumulative mismatches

_BYE_FLOOD_LIMIT      = 15     # BYE messages
_BYE_FLOOD_WINDOW     = 10.0   # seconds

_CANCEL_FLOOD_LIMIT   = 10     # CANCEL messages
_CANCEL_FLOOD_WINDOW  = 10.0   # seconds

_AUTH_FAIL_RATIO_LIMIT = 0.80  # fraction of auth attempts that fail
_AUTH_FAIL_MIN_SAMPLE  = 20    # minimum attempts before ratio check fires


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class TrafficAnalyzer:
    """Subscribe to the event bus and emit anomaly.detected events."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()

        # --- sliding-window state ---
        # Each deque entry is a float timestamp (or a small tuple where noted).

        # INVITE flood: timestamps of all INVITE events
        self._invite_times: deque[float] = deque()

        # Nonce reuse: maps nonce → first-seen timestamp
        self._seen_nonces: dict[str, float] = {}

        # Extension scan: (timestamp, extension) pairs
        self._scanned_exts: deque[tuple[float, str]] = deque()

        # Anonymous call surge: timestamps of successful anonymous INVITEs
        self._anon_success_times: deque[float] = deque()

        # Credential spray: password → set of extensions attempted
        self._password_exts: dict[str, set[str]] = defaultdict(set)

        # Codec failures: simple counter (no sliding window — cumulative)
        self._codec_fail_count: int = 0
        self._codec_anomaly_emitted: bool = False

        # BYE flood: timestamps of BYE events
        self._bye_times: deque[float] = deque()

        # CANCEL flood: timestamps of CANCEL events
        self._cancel_times: deque[float] = deque()

        # Auth fail ratio: (total_attempts, failed_attempts)
        self._auth_total: int = 0
        self._auth_failed: int = 0
        self._auth_ratio_anomaly_emitted: bool = False

        # --- anomaly store ---
        self._anomalies: list[Anomaly] = []

        # --- bus subscription & thread control ---
        self._queue: Queue | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Subscribe to the bus and start the background consumer thread."""
        if self._thread is not None and self._thread.is_alive():
            return  # already running

        self._stop_event.clear()
        self._queue = bus.subscribe(replay_history=False)

        self._thread = threading.Thread(
            target=self._consume,
            name="traffic-analyzer",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the consumer thread to exit and unsubscribe from the bus."""
        self._stop_event.set()
        if self._queue is not None:
            bus.unsubscribe(self._queue)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def get_anomalies(self, since: float | None = None) -> list[Anomaly]:
        """Return a thread-safe snapshot of recorded anomalies.

        Args:
            since: If given, only return anomalies whose timestamp >= since.
        """
        with self._lock:
            if since is None:
                return list(self._anomalies)
            return [a for a in self._anomalies if a.timestamp >= since]

    # ------------------------------------------------------------------
    # Internal — bus consumer
    # ------------------------------------------------------------------

    def _consume(self) -> None:
        """Background thread: drain the queue and analyse each event."""
        assert self._queue is not None
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=0.25)
            except Empty:
                continue
            try:
                anomalies = self._analyse_event(event)
            except Exception:
                # Robust: never let a bad event kill the thread
                continue
            for anomaly in anomalies:
                with self._lock:
                    self._anomalies.append(anomaly)
                bus.emit("anomaly.detected", {
                    "type": anomaly.type,
                    "severity": anomaly.severity,
                    "description": anomaly.description,
                    "evidence": anomaly.evidence,
                    "timestamp": anomaly.timestamp,
                })

    # ------------------------------------------------------------------
    # Core detection logic
    # ------------------------------------------------------------------

    def _analyse_event(self, event: dict) -> list[Anomaly]:
        """Inspect a single bus event and return any triggered anomalies."""
        anomalies: list[Anomaly] = []
        now = event.get("timestamp", time.time())
        etype = event.get("type", "")
        data = event.get("data", {})

        # ---------------------------------------------------------------
        # 1. INVITE flood  — >20 INVITEs in 10 seconds → CRITICAL
        # ---------------------------------------------------------------
        if etype in ("sip.invite", "sip.request") and data.get("method", "").upper() == "INVITE" or etype == "sip.invite":
            with self._lock:
                self._invite_times.append(now)
                # Drop entries older than the flood window
                cutoff = now - _INVITE_FLOOD_WINDOW
                while self._invite_times and self._invite_times[0] < cutoff:
                    self._invite_times.popleft()
                count = len(self._invite_times)

            if count > _INVITE_FLOOD_LIMIT:
                anomalies.append(Anomaly(
                    type="invite_flood",
                    severity="critical",
                    description=(
                        f"INVITE flood detected: {count} INVITEs in the last "
                        f"{_INVITE_FLOOD_WINDOW:.0f} seconds."
                    ),
                    evidence={
                        "invite_count": count,
                        "window_seconds": _INVITE_FLOOD_WINDOW,
                        "threshold": _INVITE_FLOOD_LIMIT,
                    },
                    timestamp=now,
                ))

        # ---------------------------------------------------------------
        # 2. Nonce reuse  — same nonce seen twice → HIGH (downgrade indicator)
        # ---------------------------------------------------------------
        if etype in ("sip.auth_challenge", "sip.www_authenticate", "sip.response"):
            nonce = data.get("nonce") or data.get("www_authenticate", {}).get("nonce")
            if nonce:
                with self._lock:
                    first_seen = self._seen_nonces.get(nonce)
                    if first_seen is None:
                        self._seen_nonces[nonce] = now
                    else:
                        anomalies.append(Anomaly(
                            type="nonce_reuse",
                            severity="high",
                            description=(
                                f"Nonce reuse detected: nonce '{nonce[:16]}…' "
                                "was replayed — possible downgrade or replay attack."
                            ),
                            evidence={
                                "nonce": nonce,
                                "first_seen": first_seen,
                                "replayed_at": now,
                                "delta_s": round(now - first_seen, 3),
                            },
                            timestamp=now,
                        ))

        # ---------------------------------------------------------------
        # 3. Extension scan  — >50 distinct extensions probed in 30 s → HIGH
        # ---------------------------------------------------------------
        if etype in ("enumeration.found", "enumeration.probed",
                     "sip.options", "sip.invite", "sip.register"):
            ext = (data.get("extension") or data.get("user")
                   or data.get("to") or data.get("username"))
            if ext:
                with self._lock:
                    self._scanned_exts.append((now, str(ext)))
                    cutoff = now - _EXT_SCAN_WINDOW
                    while self._scanned_exts and self._scanned_exts[0][0] < cutoff:
                        self._scanned_exts.popleft()
                    distinct = len({e for _, e in self._scanned_exts})

                if distinct > _EXT_SCAN_LIMIT:
                    anomalies.append(Anomaly(
                        type="extension_scan",
                        severity="high",
                        description=(
                            f"Extension scan detected: {distinct} distinct extensions "
                            f"probed in the last {_EXT_SCAN_WINDOW:.0f} seconds."
                        ),
                        evidence={
                            "distinct_extensions": distinct,
                            "window_seconds": _EXT_SCAN_WINDOW,
                            "threshold": _EXT_SCAN_LIMIT,
                            "sample": list({e for _, e in self._scanned_exts})[:10],
                        },
                        timestamp=now,
                    ))

        # ---------------------------------------------------------------
        # 4. Anonymous call surge  — >5 anon INVITE successes in 60 s → CRITICAL
        # ---------------------------------------------------------------
        is_anon_success = (
            etype in ("call.answered", "call.success", "multicall.update")
            and data.get("state") in ("active", "ended")
            and (
                data.get("anonymous") is True
                or str(data.get("extension", "")).lower() in ("anonymous", "")
                or str(data.get("username", "")).lower() == "anonymous"
            )
        )
        if is_anon_success:
            with self._lock:
                self._anon_success_times.append(now)
                cutoff = now - _ANON_SURGE_WINDOW
                while self._anon_success_times and self._anon_success_times[0] < cutoff:
                    self._anon_success_times.popleft()
                count = len(self._anon_success_times)

            if count > _ANON_SURGE_LIMIT:
                anomalies.append(Anomaly(
                    type="anonymous_call_surge",
                    severity="critical",
                    description=(
                        f"Anonymous call surge: {count} successful anonymous INVITEs "
                        f"in {_ANON_SURGE_WINDOW:.0f} s — likely toll fraud."
                    ),
                    evidence={
                        "anon_success_count": count,
                        "window_seconds": _ANON_SURGE_WINDOW,
                        "threshold": _ANON_SURGE_LIMIT,
                    },
                    timestamp=now,
                ))

        # ---------------------------------------------------------------
        # 5. Credential spray  — same password tried on >5 extensions → HIGH
        # ---------------------------------------------------------------
        if etype in ("auth.attempt", "sip.register", "auth_test.attempt",
                     "auth_test.result"):
            password = data.get("password") or data.get("credential")
            extension = data.get("extension") or data.get("username") or data.get("user")
            if password and extension:
                with self._lock:
                    self._password_exts[str(password)].add(str(extension))
                    ext_count = len(self._password_exts[str(password)])

                if ext_count > _CRED_SPRAY_LIMIT:
                    anomalies.append(Anomaly(
                        type="credential_spray",
                        severity="high",
                        description=(
                            f"Credential spray detected: password tried against "
                            f"{ext_count} different extensions."
                        ),
                        evidence={
                            "password_hint": str(password)[:2] + "***",
                            "extension_count": ext_count,
                            "threshold": _CRED_SPRAY_LIMIT,
                            "extensions_sample": list(
                                self._password_exts[str(password)]
                            )[:10],
                        },
                        timestamp=now,
                    ))

        # ---------------------------------------------------------------
        # 6. New anon extension  — any continuous.new_anon event → MEDIUM
        # ---------------------------------------------------------------
        if etype == "continuous.new_anon":
            extension = data.get("extension") or data.get("user") or "unknown"
            anomalies.append(Anomaly(
                type="new_anon_extension",
                severity="medium",
                description=(
                    f"New anonymous extension registered: '{extension}'. "
                    "May indicate a misconfiguration or rogue device."
                ),
                evidence=dict(data),
                timestamp=now,
            ))

        # ---------------------------------------------------------------
        # 7. Multiple codec negotiation failures  — >10 mismatches → LOW
        # ---------------------------------------------------------------
        if etype in ("rtp.codec_mismatch", "call.codec_fail",
                     "sip.codec_mismatch", "sdp.codec_mismatch"):
            with self._lock:
                self._codec_fail_count += 1
                count = self._codec_fail_count
                already_emitted = self._codec_anomaly_emitted
                if count > _CODEC_FAIL_LIMIT and not already_emitted:
                    self._codec_anomaly_emitted = True

            if count > _CODEC_FAIL_LIMIT and not already_emitted:
                anomalies.append(Anomaly(
                    type="codec_negotiation_failures",
                    severity="low",
                    description=(
                        f"Excessive codec negotiation failures: {count} mismatches "
                        "recorded. May indicate incompatible or forced codec lists."
                    ),
                    evidence={
                        "mismatch_count": count,
                        "threshold": _CODEC_FAIL_LIMIT,
                        "latest_event_data": data,
                    },
                    timestamp=now,
                ))

        # ---------------------------------------------------------------
        # 8. BYE flood  — >15 BYEs in 10 s → HIGH
        # ---------------------------------------------------------------
        if etype == "sip.bye" or (etype == "sip.request" and data.get("method", "").upper() == "BYE"):
            with self._lock:
                self._bye_times.append(now)
                cutoff = now - _BYE_FLOOD_WINDOW
                while self._bye_times and self._bye_times[0] < cutoff:
                    self._bye_times.popleft()
                count = len(self._bye_times)
            if count > _BYE_FLOOD_LIMIT:
                anomalies.append(Anomaly(
                    type="bye_flood",
                    severity="high",
                    description=(
                        f"BYE flood detected: {count} BYE messages in "
                        f"{_BYE_FLOOD_WINDOW:.0f} s — possible call teardown attack or "
                        "automated hangup of legitimate calls (eavesdropping disruption)."
                    ),
                    evidence={
                        "bye_count": count,
                        "window_seconds": _BYE_FLOOD_WINDOW,
                        "threshold": _BYE_FLOOD_LIMIT,
                    },
                    timestamp=now,
                ))

        # ---------------------------------------------------------------
        # 9. CANCEL flood  — >10 CANCELs in 10 s → HIGH
        # ---------------------------------------------------------------
        if etype == "sip.cancel" or (etype == "sip.request" and data.get("method", "").upper() == "CANCEL"):
            with self._lock:
                self._cancel_times.append(now)
                cutoff = now - _CANCEL_FLOOD_WINDOW
                while self._cancel_times and self._cancel_times[0] < cutoff:
                    self._cancel_times.popleft()
                count = len(self._cancel_times)
            if count > _CANCEL_FLOOD_LIMIT:
                anomalies.append(Anomaly(
                    type="cancel_flood",
                    severity="high",
                    description=(
                        f"CANCEL flood detected: {count} CANCEL messages in "
                        f"{_CANCEL_FLOOD_WINDOW:.0f} s — possible denial-of-service "
                        "or automated call-disruption attack."
                    ),
                    evidence={
                        "cancel_count": count,
                        "window_seconds": _CANCEL_FLOOD_WINDOW,
                        "threshold": _CANCEL_FLOOD_LIMIT,
                    },
                    timestamp=now,
                ))

        # ---------------------------------------------------------------
        # 10. Failed-auth ratio  — >80% of auth attempts fail → HIGH (once)
        # ---------------------------------------------------------------
        if etype in ("auth.attempt", "auth_test.attempt", "auth_test.result",
                     "sip.register", "sip.auth_challenge"):
            failed = (
                data.get("success") is False
                or data.get("result") in ("fail", "failed", "rejected")
                or data.get("status_code") in (401, 403, 407)
            )
            with self._lock:
                self._auth_total += 1
                if failed:
                    self._auth_failed += 1
                total = self._auth_total
                fail_count = self._auth_failed
                already = self._auth_ratio_anomaly_emitted
                ratio = fail_count / total if total > 0 else 0.0
                if (total >= _AUTH_FAIL_MIN_SAMPLE
                        and ratio >= _AUTH_FAIL_RATIO_LIMIT
                        and not already):
                    self._auth_ratio_anomaly_emitted = True
            if (total >= _AUTH_FAIL_MIN_SAMPLE
                    and ratio >= _AUTH_FAIL_RATIO_LIMIT
                    and not already):
                anomalies.append(Anomaly(
                    type="high_auth_failure_rate",
                    severity="high",
                    description=(
                        f"High authentication failure rate: {fail_count}/{total} "
                        f"auth attempts failed ({ratio:.0%}). Indicates active "
                        "credential brute-force or enumeration activity."
                    ),
                    evidence={
                        "total_attempts": total,
                        "failed_attempts": fail_count,
                        "failure_ratio": round(ratio, 3),
                        "threshold_ratio": _AUTH_FAIL_RATIO_LIMIT,
                        "min_sample": _AUTH_FAIL_MIN_SAMPLE,
                    },
                    timestamp=now,
                ))

        return anomalies


# ---------------------------------------------------------------------------
# Module-level singleton — imported by gui/server.py or other consumers
# ---------------------------------------------------------------------------
traffic_analyzer = TrafficAnalyzer()
