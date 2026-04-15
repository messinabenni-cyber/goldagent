"""HTTP + SSE server for the VoIP pentest GUI tool.

Endpoints
---------
GET  /                     → serve gui/ui.html
GET  /api/events           → SSE stream (text/event-stream)
GET  /api/status           → current scan state as JSON
POST /api/start            → start scan (JSON body = config dict)
POST /api/stop             → set controller.scan_cancel
POST /api/hangup           → set controller.call_hangup
POST /api/scope-upload     → save raw text body as reports/scope-{ts}.txt
GET  /api/download/html    → report.html from report_dir
GET  /api/download/json    → report.json from report_dir
GET  /api/download/txt     → report.txt from report_dir
GET  /api/download/wav     → first .wav in report_dir
GET  /api/download/pcap   → traffic.pcap (libpcap, for Wireshark)

Uses only Python stdlib.  ThreadingHTTPServer for concurrent SSE + API.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue

# Ensure the repo root is importable regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.call_manager import call_mgr
from modules.control import controller
from modules.events import bus

# ---------------------------------------------------------------------------
# API keys / global config (persisted in memory; set via /api/config)
# ---------------------------------------------------------------------------
_api_config: dict = {
    "shodan_key": os.environ.get("SHODAN_API_KEY", ""),
    "censys_id": os.environ.get("CENSYS_API_ID", ""),
    "censys_secret": os.environ.get("CENSYS_API_SECRET", ""),
    "anthropic_key": os.environ.get("ANTHROPIC_API_KEY", ""),
    "user_agent": "VoIPScan-Pro/2.0",
    "use_stun": True,
    "use_tls": False,
    "stun_host": "stun.l.google.com",
}
_api_config_lock = threading.Lock()

# ---------------------------------------------------------------------------
# OSINT cache  (per-IP, populated on demand)
# ---------------------------------------------------------------------------
_osint_cache: dict[str, dict] = {}   # ip → OsintResult.__dict__
_osint_lock = threading.Lock()

# ---------------------------------------------------------------------------
# AI Advisor cache (populated after scan completes)
# ---------------------------------------------------------------------------
_advisor_result: dict | None = None
_advisor_lock = threading.Lock()

# ---------------------------------------------------------------------------
# AI Fuzzer state
# ---------------------------------------------------------------------------
_fuzzer_result: dict | None = None
_fuzzer_thread: threading.Thread | None = None
_fuzzer_stop: threading.Event = threading.Event()
_fuzzer_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Traffic analyser singleton (lazy-started)
# ---------------------------------------------------------------------------
_analyzer: object | None = None   # TrafficAnalyzer instance, started on first /api/anomalies
_analyzer_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Module-level scan state
# ---------------------------------------------------------------------------

_state: dict = {
    "status": "idle",          # idle | scanning | done | error | cancelled
    "phase": None,
    "hosts_found": 0,
    "extensions_found": 0,
    "creds_found": 0,
    "findings": 0,
    "report_dir": None,
    "call_active": False,
    "call_ext": None,
    "call_target": None,
    "call_duration": 0.0,
    "error": None,
    # Multi-call: extensions the scanner discovered + their attack paths
    "discovered_extensions": [],  # [{extension, pbx_host, pbx_port, anonymous_invite,
                                  #   open_register, auth_required, username, password}]
}
_state_lock = threading.Lock()

# Cache the most-recently-prepared audio payload so manual calls don't need
# the operator to re-enter audio config.
_audio_payload_cache: dict | None = None
_audio_payload_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Continuous / persistent scan state
# ---------------------------------------------------------------------------
_continuous_stop_event: threading.Event | None = None
_continuous_thread: threading.Thread | None = None
_last_scan_report: dict | None = None   # populated when run_scan finishes
_last_scan_config: dict | None = None
_continuous_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GUI_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_GUI_DIR)


def _snapshot() -> dict:
    """Return a shallow copy of _state under the lock."""
    with _state_lock:
        return dict(_state)


def _set_state(**kwargs: object) -> None:
    """Update _state fields under the lock."""
    with _state_lock:
        _state.update(kwargs)


# ---------------------------------------------------------------------------
# Background scan thread
# ---------------------------------------------------------------------------

def _run_scan_thread(config: dict) -> None:
    """Outer thread: subscribes to the bus, starts run_scan in an inner
    thread, then drains the event queue updating _state until the inner
    thread finishes.  The two-thread pattern is required because run_scan()
    is blocking.
    """
    # Import here so the server module can be imported without the whole
    # scan stack being loaded at import time.
    from gui.runner import run_scan  # noqa: PLC0415

    # Reset controller flags from any previous run.
    controller.reset()

    # Subscribe to the event bus *before* starting the inner thread so we
    # don't miss early events.
    event_q: Queue = bus.subscribe(replay_history=False)

    # Initialise per-run counters.
    _set_state(
        phase=None,
        hosts_found=0,
        extensions_found=0,
        creds_found=0,
        findings=0,
        report_dir=None,
        call_active=False,
        call_ext=None,
        call_target=None,
        call_duration=0.0,
        error=None,
    )

    result_box: list = []       # inner thread writes result here
    exc_box: list = []          # inner thread writes exception here

    def _inner() -> None:
        try:
            result = run_scan(config)
            result_box.append(result)
        except Exception as exc:  # noqa: BLE001
            exc_box.append(exc)

    inner = threading.Thread(target=_inner, name="scan-inner", daemon=True)
    inner.start()

    # Drain event queue while the inner thread is alive, and for a short
    # period afterward to catch any final events.
    while inner.is_alive() or not event_q.empty():
        try:
            event = event_q.get(timeout=0.1)
        except Empty:
            continue

        etype = event.get("type", "")
        data = event.get("data", {})

        # Cache audio payload when scanner prepares it so manual calls can
        # reuse the same audio without re-building it.
        if etype == "audio.prepared":
            # The runner emits metadata only; we can't cache bytes from here.
            # The payload bytes are built in _handle_calls_launch on demand.
            pass

        # Update _state based on event type.
        with _state_lock:
            if etype == "scan.start":
                _state["report_dir"] = data.get("report_dir")

            elif etype == "phase":
                _state["phase"] = data.get("name")
                if data.get("name") == "live_call":
                    _state["call_target"] = data.get("target")
                    _state["call_ext"] = data.get("via_ext")

            elif etype == "discovery.host_found":
                _state["hosts_found"] += 1

            elif etype == "enum.extension":
                _state["extensions_found"] += 1

            elif etype == "spray.hit":
                _state["creds_found"] += 1

            elif etype == "vuln.found":
                _state["findings"] += 1

            elif etype == "call.answered":
                _state["call_active"] = True
                _state["call_duration"] = 0.0

            elif etype == "call.heartbeat":
                _state["call_duration"] = float(data.get("duration_s", 0))

            elif etype == "call.ended":
                _state["call_active"] = False
                _state["call_duration"] = float(data.get("duration_s", 0))

            elif etype == "scan.done":
                _state["hosts_found"] = data.get("hosts", _state["hosts_found"])
                _state["findings"] = data.get("findings", _state["findings"])
                if data.get("report_dir"):
                    _state["report_dir"] = data["report_dir"]

            elif etype == "attack_matrix":
                # Populate the discovered_extensions list so the GUI can build
                # the launch dropdown and the call_manager can target them.
                host = data.get("host", "")
                pbx_port = _state.get("port", 5060) or 5060
                new_exts: list[dict] = []
                # Extensions from enumeration
                for e in data.get("extensions", []):
                    new_exts.append({
                        "extension": e.get("extension", ""),
                        "pbx_host": host,
                        "pbx_port": pbx_port,
                        "anonymous_invite": bool(e.get("anonymous_invite")),
                        "open_register": bool(e.get("open_register")),
                        "auth_required": bool(e.get("auth_required")),
                        "username": None,
                        "password": None,
                    })
                # Credentials found — overlay username/password
                cred_map: dict[str, dict] = {
                    c["extension"]: c
                    for c in data.get("credentials_found", [])
                }
                for entry in new_exts:
                    cred = cred_map.get(entry["extension"])
                    if cred:
                        entry["username"] = cred.get("username")
                        entry["password"] = cred.get("password")
                # Merge into _state (replace entries for this host)
                existing = [e for e in _state["discovered_extensions"]
                            if e["pbx_host"] != host]
                _state["discovered_extensions"] = existing + new_exts

            elif etype == "scan.error":
                _state["error"] = data.get("reason", "unknown error")

    # Inner thread finished — determine final status.
    inner.join()
    bus.unsubscribe(event_q)

    if exc_box:
        _set_state(status="error", error=str(exc_box[0]))
    elif controller.scan_cancel.is_set():
        _set_state(status="cancelled")
    elif result_box and isinstance(result_box[0], dict) and result_box[0].get("error"):
        _set_state(status="error", error=result_box[0]["error"])
    else:
        _set_state(status="done")
        # Save the completed report so continuous scan can reference it
        global _last_scan_report, _last_scan_config
        with _continuous_lock:
            if result_box:
                _last_scan_report = result_box[0]
            _last_scan_config = config


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class _Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the VoIP pentest GUI."""

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D102
        # Suppress default stderr logging; uncomment to re-enable:
        # print(f"[server] {self.address_string()} - {fmt % args}")
        pass

    # ------------------------------------------------------------------
    # Shared response helpers
    # ------------------------------------------------------------------

    def _send_cors_headers(self) -> None:
        for k, v in _CORS_HEADERS.items():
            self.send_header(k, v)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message: str, status: int = 400) -> None:
        self._send_json({"error": message}, status=status)

    _MAX_BODY = 4 * 1024 * 1024   # 4 MiB — prevents OOM from malicious clients

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return b""
        if length > self._MAX_BODY:
            # Drain and reject rather than leaving socket in a broken state.
            self.rfile.read(min(length, self._MAX_BODY))
            raise ValueError(f"Request body too large ({length} bytes)")
        return self.rfile.read(length)

    # ------------------------------------------------------------------
    # OPTIONS (preflight)
    # ------------------------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    # ------------------------------------------------------------------
    # GET routing
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path == "/":
            self._serve_ui()
        elif path == "/api/events":
            self._handle_events()
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/calls":
            self._handle_calls_list()
        elif path == "/api/continuous/status":
            self._handle_continuous_status()
        elif path == "/api/download/html":
            self._serve_report_file("report.html", "text/html")
        elif path == "/api/download/json":
            self._serve_report_file("report.json", "application/json")
        elif path == "/api/download/txt":
            self._serve_report_file("report.txt", "text/plain")
        elif path == "/api/download/wav":
            self._serve_report_wav()
        elif path == "/api/download/pdf":
            self._serve_report_file("report.html", "text/html")
        elif path == "/api/download/hashcat":
            self._serve_report_file("sip_hashes_hashcat.txt", "text/plain",
                                    "sip_hashes_hashcat.txt")
        elif path == "/api/download/john":
            self._serve_report_file("sip_hashes_john.txt", "text/plain",
                                    "sip_hashes_john.txt")
        elif path == "/api/download/pcap":
            self._serve_report_file("traffic.pcap",
                                    "application/vnd.tcpdump.pcap",
                                    "traffic.pcap")
        elif path.startswith("/api/osint/"):
            ip = path[len("/api/osint/"):]
            self._handle_osint(ip)
        elif path == "/api/ai/analyse":
            self._handle_ai_analyse()
        elif path == "/api/ai/advisor":
            self._handle_ai_advisor_get()
        elif path == "/api/ai/fuzz/status":
            self._handle_fuzz_status()
        elif path == "/api/anomalies":
            self._handle_anomalies()
        elif path == "/api/config":
            self._handle_config_get()
        elif path == "/api/persistence/status":
            self._handle_persistence_status()
        elif path == "/api/risk-score":
            self._handle_risk_score()
        else:
            self._send_error_json("not found", 404)

    # ------------------------------------------------------------------
    # POST routing
    # ------------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path == "/api/start":
            self._handle_start()
        elif path == "/api/stop":
            self._handle_stop()
        elif path == "/api/hangup":
            self._handle_hangup()
        elif path == "/api/scope-upload":
            self._handle_scope_upload()
        elif path == "/api/calls/launch":
            self._handle_calls_launch()
        elif path == "/api/calls/hangup":
            self._handle_calls_hangup()
        elif path == "/api/calls/hangup-all":
            self._handle_calls_hangup_all()
        elif path == "/api/calls/clear":
            self._handle_calls_clear()
        elif path == "/api/continuous/start":
            self._handle_continuous_start()
        elif path == "/api/continuous/stop":
            self._handle_continuous_stop()
        elif path == "/api/config":
            self._handle_config_post()
        elif path == "/api/ai/analyse":
            self._handle_ai_analyse_post()
        elif path == "/api/ai/fuzz/start":
            self._handle_fuzz_start()
        elif path == "/api/ai/fuzz/stop":
            self._handle_fuzz_stop()
        elif path == "/api/persistence/start":
            self._handle_persistence_start()
        elif path == "/api/persistence/stop":
            self._handle_persistence_stop()
        else:
            self._send_error_json("not found", 404)

    # ------------------------------------------------------------------
    # Handler implementations
    # ------------------------------------------------------------------

    def _serve_ui(self) -> None:
        """Serve gui/ui.html."""
        ui_path = os.path.join(_GUI_DIR, "ui.html")
        try:
            with open(ui_path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send_error_json("ui.html not found", 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _handle_status(self) -> None:
        """GET /api/status → current _state as JSON."""
        self._send_json(_snapshot())

    def _handle_events(self) -> None:
        """GET /api/events → SSE stream.

        Protocol
        --------
        Every message is formatted as::

            data: <json>\n\n

        (No ``event:`` line — the client uses the ``type`` field in the JSON.)

        On connect:
          1. Send a synthetic ``{"type": "state", "data": <current _state>}``.
          2. Replay all bus history.
          3. Forward live events until the client disconnects.

        A comment (``:``) heartbeat is sent every 15 s to keep the connection
        alive through proxies.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self._send_cors_headers()
        self.end_headers()

        def _write_sse(payload: dict) -> bool:
            """Serialise *payload* as an SSE data frame.  Returns False if the
            socket is broken."""
            line = "data: " + json.dumps(payload) + "\n\n"
            try:
                self.wfile.write(line.encode())
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False

        # --- 1. Immediate state snapshot ---
        if not _write_sse({"type": "state", "data": _snapshot()}):
            return

        # --- 2. Subscribe with history replay ---
        q: Queue = bus.subscribe(replay_history=True)

        last_heartbeat = time.monotonic()

        try:
            while True:
                now = time.monotonic()

                # Heartbeat comment every 15 s
                if now - last_heartbeat >= 15:
                    try:
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
                        last_heartbeat = now
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return

                # Drain the queue (non-blocking burst, then one blocking read)
                try:
                    event = q.get(timeout=1.0)
                except Empty:
                    continue

                # Forward the event to the client
                payload = {"type": event.get("type", ""), "data": event.get("data", {})}
                if not _write_sse(payload):
                    return

        finally:
            bus.unsubscribe(q)

    def _handle_start(self) -> None:
        """POST /api/start — start a scan in a background thread."""
        try:
            raw = self._read_body()
        except ValueError as exc:
            self._send_error_json(str(exc), 413)
            return
        try:
            config = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            self._send_error_json(f"invalid JSON: {exc}")
            return

        # TOCTOU-safe: check-and-set status atomically.
        with _state_lock:
            if _state["status"] == "scanning":
                self._send_json({"error": "scan already running"}, status=409)
                return
            _state["status"] = "scanning"
            # Invalidate stale caches so the new scan starts clean.
            # Done under _state_lock so no subscriber can see half-state.
            global _last_scan_report, _last_scan_config
            _last_scan_report = None
            _last_scan_config = None

        # Clear event history so new SSE clients get a clean slate for
        # this scan (existing connected clients are unaffected — they are
        # subscribed directly to the bus and get live events).
        # This is safe to call outside the lock — clear_history() is
        # internally serialised and racing SSE subscribers will at worst
        # replay a few extra events.
        bus.clear_history()

        # Invalidate the audio payload cache so a fresh scan re-builds it
        # (needed if audio config changed between scans).
        with _audio_payload_lock:
            global _audio_payload_cache
            _audio_payload_cache = None

        t = threading.Thread(
            target=_run_scan_thread,
            args=(config,),
            name="scan-outer",
            daemon=True,
        )
        t.start()
        self._send_json({"ok": True})

    def _handle_stop(self) -> None:
        """POST /api/stop — signal the running scan to cancel."""
        controller.scan_cancel.set()
        self._send_json({"ok": True})

    def _handle_hangup(self) -> None:
        """POST /api/hangup — signal the current live call to end."""
        controller.call_hangup.set()
        self._send_json({"ok": True})

    def _handle_scope_upload(self) -> None:
        """POST /api/scope-upload — save raw text body as a scope file."""
        try:
            raw = self._read_body()
        except ValueError as exc:
            self._send_error_json(str(exc), 413)
            return
        reports_dir = os.path.join(_REPO_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"scope-{timestamp}.txt"
        filepath = os.path.join(reports_dir, filename)
        try:
            with open(filepath, "wb") as fh:
                fh.write(raw)
        except OSError as exc:
            self._send_error_json(f"could not save scope file: {exc}", 500)
            return
        self._send_json({"path": filepath})

    # ------------------------------------------------------------------
    # Multi-call control endpoints
    # ------------------------------------------------------------------

    def _handle_calls_list(self) -> None:
        """GET /api/calls — snapshot of all active/completed calls."""
        self._send_json({"calls": call_mgr.get_all()})

    def _handle_calls_launch(self) -> None:
        """POST /api/calls/launch — start a call via the call_manager.

        Body (JSON):
          pbx_host       str   required — target PBX IP/hostname
          extension      str   required — source extension (call-from)
          target         str   required — destination number/URI
          pbx_port       int   optional, default 5060
          username       str   optional — creds for authenticated INVITE
          password       str   optional
          hold_seconds   float optional, default 300
          caller_id_name str   optional
          dtmf_sequence  str   optional
        """
        try:
            raw = self._read_body()
        except ValueError as exc:
            self._send_error_json(str(exc), 413)
            return
        try:
            req = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            self._send_error_json(f"invalid JSON: {exc}")
            return

        pbx_host = req.get("pbx_host", "")
        extension = str(req.get("extension", ""))
        target = str(req.get("target", ""))
        if not pbx_host:
            self._send_error_json("pbx_host is required")
            return
        if not extension:
            self._send_error_json("extension is required")
            return
        if not target:
            self._send_error_json("target is required")
            return

        # Build or reuse audio payload
        global _audio_payload_cache
        with _audio_payload_lock:
            if _audio_payload_cache is None:
                from modules import audio as _audio
                _audio_payload_cache = _audio.build_payload()

        call_id = call_mgr.launch(
            pbx_host=pbx_host,
            call_to=target,
            call_from=extension,
            audio_payload=_audio_payload_cache,
            pbx_port=int(req.get("pbx_port", 5060)),
            username=req.get("username") or None,
            password=req.get("password") or None,
            hold_seconds=float(req.get("hold_seconds", 300.0)),
            timeout=float(req.get("timeout", 5.0)),
            caller_id_name=req.get("caller_id_name", "Pentest Demo"),
            dtmf_sequence=req.get("dtmf_sequence") or None,
        )
        self._send_json({"ok": True, "call_id": call_id})

    def _handle_calls_hangup(self) -> None:
        """POST /api/calls/hangup — hang up one specific call by call_id."""
        try:
            raw = self._read_body()
        except ValueError as exc:
            self._send_error_json(str(exc), 413)
            return
        try:
            req = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            self._send_error_json(f"invalid JSON: {exc}")
            return
        call_id = req.get("call_id", "")
        if not call_id:
            self._send_error_json("call_id is required")
            return
        found = call_mgr.hangup(call_id)
        self._send_json({"ok": True, "found": found})

    def _handle_calls_hangup_all(self) -> None:
        """POST /api/calls/hangup-all — terminate every active call."""
        count = call_mgr.hangup_all()
        self._send_json({"ok": True, "count": count})

    def _handle_calls_clear(self) -> None:
        """POST /api/calls/clear — remove ended/failed calls from the registry."""
        count = call_mgr.clear_ended()
        self._send_json({"ok": True, "removed": count})

    # ------------------------------------------------------------------
    # Continuous scan
    # ------------------------------------------------------------------

    def _handle_continuous_status(self) -> None:
        """GET /api/continuous/status — is the continuous scan running?"""
        global _continuous_thread
        with _continuous_lock:
            running = (_continuous_thread is not None
                       and _continuous_thread.is_alive())
        self._send_json({"running": running})

    def _handle_continuous_start(self) -> None:
        """POST /api/continuous/start — start the continuous re-probe loop."""
        global _continuous_stop_event, _continuous_thread
        try:
            body = self._read_body()
        except ValueError as exc:
            self._send_error_json(str(exc), 413)
            return
        cfg_override: dict = {}
        if body:
            try:
                cfg_override = json.loads(body)
            except json.JSONDecodeError:
                pass

        with _continuous_lock:
            if _continuous_thread and _continuous_thread.is_alive():
                self._send_json({"ok": False, "reason": "already running"})
                return
            if not _last_scan_report:
                self._send_json({
                    "ok": False,
                    "reason": "no completed scan — run a full scan first"
                })
                return
            interval_s = float(cfg_override.get("interval_s", 300))
            config = dict(_last_scan_config or {})
            config.update(cfg_override)
            report = _last_scan_report
            stop_ev = threading.Event()
            _continuous_stop_event = stop_ev

            def _run_continuous() -> None:
                from gui.runner import run_continuous_scan  # noqa: PLC0415
                run_continuous_scan(config, report, stop_ev, interval_s)

            t = threading.Thread(target=_run_continuous,
                                 name="continuous-scan", daemon=True)
            _continuous_thread = t
            t.start()

        bus.emit("continuous.started", {"interval_s": interval_s})
        self._send_json({"ok": True, "interval_s": interval_s})

    def _handle_continuous_stop(self) -> None:
        """POST /api/continuous/stop — halt the continuous re-probe loop."""
        global _continuous_stop_event, _continuous_thread
        with _continuous_lock:
            running = (_continuous_thread is not None
                       and _continuous_thread.is_alive())
            if _continuous_stop_event:
                _continuous_stop_event.set()
        self._send_json({"ok": True, "was_running": running})

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _handle_config_get(self) -> None:
        """GET /api/config — return current API key config (keys masked)."""
        with _api_config_lock:
            safe = {k: ("*" * 6 + v[-4:] if len(v) > 8 else ("set" if v else ""))
                    if k.endswith("_key") or k.endswith("_secret") or k.endswith("_id")
                    else v
                    for k, v in _api_config.items()}
            safe["has_shodan"] = bool(_api_config.get("shodan_key"))
            safe["has_censys"] = bool(_api_config.get("censys_id"))
            safe["has_anthropic"] = bool(_api_config.get("anthropic_key"))
        self._send_json(safe)

    def _handle_config_post(self) -> None:
        """POST /api/config — update API key config."""
        try:
            raw = self._read_body()
        except ValueError as exc:
            self._send_error_json(str(exc), 413)
            return
        try:
            new_cfg = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            self._send_error_json(f"invalid JSON: {exc}")
            return
        with _api_config_lock:
            for k in ("shodan_key", "censys_id", "censys_secret",
                      "anthropic_key", "user_agent", "use_stun",
                      "use_tls", "stun_host"):
                if k in new_cfg:
                    _api_config[k] = new_cfg[k]
        self._send_json({"ok": True})

    # ------------------------------------------------------------------
    # OSINT
    # ------------------------------------------------------------------

    def _handle_osint(self, ip: str) -> None:
        """GET /api/osint/{ip} — run OSINT lookup (cached)."""
        ip = ip.strip()
        if not ip:
            self._send_error_json("ip required", 400)
            return
        with _osint_lock:
            cached = _osint_cache.get(ip)
        if cached:
            self._send_json(cached)
            return
        try:
            from modules.osint import run_osint
            with _api_config_lock:
                sk = _api_config.get("shodan_key", "")
                ci = _api_config.get("censys_id", "")
                cs = _api_config.get("censys_secret", "")
            result = run_osint(ip, shodan_key=sk or None,
                               censys_id=ci or None,
                               censys_secret=cs or None)
            data = result.__dict__ if hasattr(result, "__dict__") else {}
            with _osint_lock:
                _osint_cache[ip] = data
            self._send_json(data)
        except ImportError:
            self._send_json({"error": "osint module not available", "ip": ip})
        except Exception as exc:  # noqa: BLE001
            self._send_error_json(str(exc), 500)

    # ------------------------------------------------------------------
    # AI Advisor
    # ------------------------------------------------------------------

    def _handle_ai_advisor_get(self) -> None:
        """GET /api/ai/advisor — return cached advisor result."""
        with _advisor_lock:
            result = _advisor_result
        if result is None:
            self._send_json({"ready": False,
                             "message": "Run a scan first to generate AI advice"})
        else:
            self._send_json({"ready": True, **result})

    def _handle_ai_analyse(self) -> None:
        """GET /api/ai/analyse — trigger AI analysis of last scan."""
        self._handle_ai_analyse_post()

    def _handle_ai_analyse_post(self) -> None:
        """POST /api/ai/analyse — trigger AI analysis of last scan."""
        global _advisor_result
        with _continuous_lock:
            report = _last_scan_report
        if not report:
            self._send_error_json("no scan report available", 400)
            return
        try:
            from modules.ai_advisor import analyse_scan
            with _api_config_lock:
                ak = _api_config.get("anthropic_key", "")
            result = analyse_scan(report, api_key=ak or None)
            data = result.__dict__ if hasattr(result, "__dict__") else {}
            with _advisor_lock:
                _advisor_result = data
            bus.emit("ai.advice_ready", {"recommendations": data.get("recommendations", [])[:3]})
            self._send_json({"ok": True, **data})
        except ImportError:
            self._send_error_json("ai_advisor module not available", 503)
        except Exception as exc:  # noqa: BLE001
            self._send_error_json(str(exc), 500)

    # ------------------------------------------------------------------
    # AI Fuzzer
    # ------------------------------------------------------------------

    def _handle_fuzz_status(self) -> None:
        """GET /api/ai/fuzz/status — get fuzzer state."""
        with _fuzzer_lock:
            running = _fuzzer_thread is not None and _fuzzer_thread.is_alive()
            result = _fuzzer_result
        self._send_json({"running": running, "result": result})

    def _handle_fuzz_start(self) -> None:
        """POST /api/ai/fuzz/start — start LLM-guided fuzzer."""
        global _fuzzer_thread, _fuzzer_result, _fuzzer_stop
        try:
            raw = self._read_body()
            cfg = json.loads(raw) if raw else {}
        except Exception:
            cfg = {}
        with _fuzzer_lock:
            if _fuzzer_thread and _fuzzer_thread.is_alive():
                self._send_json({"ok": False, "reason": "already running"})
                return
            _fuzzer_stop = threading.Event()
            _fuzzer_result = None
        snap = _snapshot()
        host = cfg.get("host") or snap.get("target", "")
        port = int(cfg.get("port", snap.get("port", 5060)))
        with _api_config_lock:
            ak = _api_config.get("anthropic_key", "")

        def _do_fuzz() -> None:
            global _fuzzer_result
            try:
                from modules.ai_fuzzer import run_ai_fuzzer
                result = run_ai_fuzzer(host, port=port, api_key=ak or None,
                                       max_probes=int(cfg.get("max_probes", 500)))
                data = result.__dict__ if hasattr(result, "__dict__") else {}
                with _fuzzer_lock:
                    _fuzzer_result = data
                bus.emit("ai.fuzz_done", data)
            except Exception as exc:  # noqa: BLE001
                with _fuzzer_lock:
                    _fuzzer_result = {"error": str(exc)}
                bus.emit("ai.fuzz_done", {"error": str(exc)})

        t = threading.Thread(target=_do_fuzz, name="ai-fuzzer", daemon=True)
        with _fuzzer_lock:
            _fuzzer_thread = t
        t.start()
        self._send_json({"ok": True, "host": host, "port": port})

    def _handle_fuzz_stop(self) -> None:
        """POST /api/ai/fuzz/stop."""
        with _fuzzer_lock:
            _fuzzer_stop.set()
        self._send_json({"ok": True})

    # ------------------------------------------------------------------
    # Call Persistence
    # ------------------------------------------------------------------

    def _handle_persistence_status(self) -> None:
        """GET /api/persistence/status."""
        try:
            from modules.call_manager import persistence_engine
            self._send_json(persistence_engine.status())
        except (ImportError, AttributeError):
            self._send_json({"running": False, "error": "persistence not available"})

    def _handle_persistence_start(self) -> None:
        """POST /api/persistence/start — start auto-redial engine."""
        try:
            raw = self._read_body()
            cfg = json.loads(raw) if raw else {}
        except Exception:
            cfg = {}
        try:
            from modules.call_manager import persistence_engine
            from modules import audio as _audio
            with _audio_payload_lock:
                global _audio_payload_cache
                if _audio_payload_cache is None:
                    _audio_payload_cache = _audio.build_payload()
                payload = _audio_payload_cache
            snap = _snapshot()
            extensions = cfg.get("extensions") or snap.get("discovered_extensions", [])
            if not extensions:
                self._send_error_json("no extensions available", 400)
                return
            target = cfg.get("target") or snap.get("call_target") or ""
            if not target:
                self._send_error_json("target number required", 400)
                return
            persistence_engine.start(
                extensions=extensions,
                target=target,
                audio_payload=payload,
                pbx_host=cfg.get("pbx_host", extensions[0].get("pbx_host", "")),
                pbx_port=int(cfg.get("pbx_port", 5060)),
                hold_seconds=float(cfg.get("hold_seconds", 30.0)),
                redial_delay_s=float(cfg.get("redial_delay_s", 5.0)),
            )
            self._send_json({"ok": True})
        except ImportError:
            self._send_error_json("persistence engine not available", 503)
        except Exception as exc:  # noqa: BLE001
            self._send_error_json(str(exc), 500)

    def _handle_persistence_stop(self) -> None:
        """POST /api/persistence/stop."""
        try:
            from modules.call_manager import persistence_engine
            persistence_engine.stop()
            self._send_json({"ok": True})
        except (ImportError, AttributeError):
            self._send_json({"ok": True})

    # ------------------------------------------------------------------
    # Traffic Anomaly Detection
    # ------------------------------------------------------------------

    def _handle_anomalies(self) -> None:
        """GET /api/anomalies — return recent traffic anomalies."""
        global _analyzer
        with _analyzer_lock:
            if _analyzer is None:
                try:
                    from modules.traffic_analyzer import TrafficAnalyzer
                    _analyzer = TrafficAnalyzer()
                    _analyzer.start()
                except ImportError:
                    self._send_json({"anomalies": [],
                                     "error": "traffic_analyzer not available"})
                    return
            analyser = _analyzer
        try:
            anomalies = analyser.get_anomalies()
            self._send_json({
                "anomalies": [
                    {"type": a.type, "severity": a.severity,
                     "description": a.description,
                     "evidence": a.evidence,
                     "timestamp": a.timestamp}
                    for a in anomalies
                ]
            })
        except Exception as exc:  # noqa: BLE001
            self._send_error_json(str(exc), 500)

    # ------------------------------------------------------------------
    # Risk Score
    # ------------------------------------------------------------------

    def _handle_risk_score(self) -> None:
        """GET /api/risk-score — compute risk score from last scan."""
        with _continuous_lock:
            report = _last_scan_report
        if not report:
            self._send_json({"score": 0, "rating": "UNKNOWN",
                             "factors": ["No scan completed yet"]})
            return
        try:
            from modules.reporter import calculate_risk_score
            self._send_json(calculate_risk_score(report))
        except (ImportError, AttributeError):
            # Inline fallback scorer
            score = 0
            factors = []
            for h in report.get("hosts", []):
                if any(e.get("anonymous_invite") for e in h.get("extensions", [])):
                    score += 40; factors.append("Anonymous INVITE accepted — unauthenticated calls possible")
                if h.get("credentials_found"):
                    score += 30; factors.append("Credentials cracked via dictionary attack")
                for v in h.get("vuln_findings", []):
                    if v.get("severity") == "critical":
                        score += 20; factors.append(f"Critical vulnerability: {v.get('title')}")
                    elif v.get("severity") == "high":
                        score += 10; factors.append(f"High vulnerability: {v.get('title')}")
            score = min(score, 100)
            rating = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
            self._send_json({"score": score, "rating": rating, "factors": factors})

    def _serve_report_file(self, filename: str, content_type: str,
                            download_name: str | None = None) -> None:
        """Serve a named file from _state['report_dir'] (path-traversal safe)."""
        report_dir = _snapshot().get("report_dir")
        if not report_dir:
            self._send_error_json("no report directory (scan not yet run)", 404)
            return
        # Reject any filename containing separators / NUL / traversal tokens.
        if ("/" in filename or "\\" in filename or "\x00" in filename
                or filename in ("", ".", "..")):
            self._send_error_json("invalid filename", 400)
            return
        filepath = os.path.abspath(os.path.join(report_dir, filename))
        report_abs = os.path.abspath(report_dir) + os.sep
        if not filepath.startswith(report_abs):
            self._send_error_json("path outside report directory", 403)
            return
        self._stream_file(filepath, content_type, download_name or filename)

    def _serve_report_wav(self) -> None:
        """Serve the first .wav file directly inside _state['report_dir'] — never
        follows symlinks (O_NOFOLLOW not portable on macOS for listdir, so we
        reject any entry whose realpath escapes the dir)."""
        report_dir = _snapshot().get("report_dir")
        if not report_dir:
            self._send_error_json("no report directory (scan not yet run)", 404)
            return
        report_abs = os.path.abspath(report_dir)
        wav_path: str | None = None
        try:
            for entry in sorted(os.listdir(report_dir)):
                # Only accept simple basenames, not path-like entries
                if "/" in entry or "\\" in entry or entry.startswith("."):
                    continue
                if not entry.lower().endswith(".wav"):
                    continue
                candidate = os.path.abspath(os.path.join(report_abs, entry))
                # Realpath check defeats symlinks pointing outside report_dir
                resolved = os.path.realpath(candidate)
                if not resolved.startswith(report_abs + os.sep):
                    continue
                # Only follow regular files
                if not os.path.isfile(resolved):
                    continue
                wav_path = resolved
                break
        except OSError:
            pass
        if wav_path is None:
            self._send_error_json("no .wav file found in report directory", 404)
            return
        self._stream_file(wav_path, "audio/wav", os.path.basename(wav_path))

    def _stream_file(
        self, filepath: str, content_type: str, download_name: str
    ) -> None:
        """Stream *filepath* to the client as a download."""
        try:
            size = os.path.getsize(filepath)
        except OSError:
            self._send_error_json(f"{download_name} not found", 404)
            return
        # Sanitise the filename: strip any embedded quotes/CR/LF so the
        # Content-Disposition header can't be poisoned.
        safe_name = (download_name
                     .replace('"', '_').replace('\r', '').replace('\n', ''))
        try:
            with open(filepath, "rb") as fh:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(size))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{safe_name}"',
                )
                self._send_cors_headers()
                self.end_headers()
                # Stream in 64 KiB chunks.
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def _install_signal_handlers() -> None:
    """Gracefully stop the continuous scan thread on SIGTERM/SIGINT."""
    def _handler(signum: int, frame: object) -> None:
        with _continuous_lock:
            if _continuous_stop_event:
                _continuous_stop_event.set()
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, _handler)
    except (OSError, ValueError):
        pass   # may fail inside a non-main thread; safe to ignore


def start(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Start the GUI HTTP server in a daemon thread and return the server.

    The server runs in the background; call ``server.shutdown()`` to stop it.

    Example::

        server = start()
        # ... do other work ...
        server.shutdown()
    """
    _install_signal_handlers()
    server = ThreadingHTTPServer((host, port), _Handler)
    server.allow_reuse_address = True
    t = threading.Thread(target=server.serve_forever, daemon=True, name="gui-http")
    t.start()
    return server


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VoIP pentest GUI server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    srv = start(args.host, args.port)
    print(f"[server] Listening on http://{args.host}:{args.port}/")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[server] Shutting down.")
        srv.shutdown()
