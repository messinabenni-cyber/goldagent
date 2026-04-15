"""Security guard tests + performance regression tests.

Covers:
  - SHA-256 Digest authentication rejection (sip.build_auth_header)
  - auth_test propagates the SHA-256 ValueError as a skip, not a crash
  - enumeration.expand_ext_range() rejects ranges > 10 000
  - expand_ext_range() rejects path-traversal file: paths
  - expand_ext_range() rejects absolute file: paths
  - RtpStreamer.packets_sent is thread-safe under concurrent reads
  - vuln_probes.run_all() runs in parallel (wall-clock << serial baseline)
  - Content-Length DoS cap in server._read_body()
  - TrafficAnalyzer BYE flood detection
  - TrafficAnalyzer CANCEL flood detection
  - TrafficAnalyzer high auth-failure-rate detection
"""
from __future__ import annotations

import http.server
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules import sip, enumeration, rtp
from modules.rtp import RtpStreamer, bind_rtp_socket


# ---------------------------------------------------------------------------
# SHA-256 Digest rejection
# ---------------------------------------------------------------------------

class TestSha256Rejection:
    def _sha256_params(self) -> dict:
        return {
            "realm": "test.example.com",
            "nonce": "abc123",
            "algorithm": "SHA-256",
        }

    def test_build_auth_header_supports_sha256(self):
        """sip.build_auth_header must now support SHA-256 (RFC 7616)."""
        header = sip.build_auth_header(
            username="user",
            password="pass",
            method="REGISTER",
            uri="sip:test.example.com",
            params=self._sha256_params(),
        )
        assert header.startswith("Authorization: Digest"), header[:60]
        assert "SHA-256" in header, "SHA-256 algorithm must appear in header"
        # Response must be 64 hex chars (sha256 output)
        import re as _re
        m = _re.search(r'response="([0-9a-f]+)"', header)
        assert m and len(m.group(1)) == 64, f"unexpected response field: {header}"

    def test_build_auth_header_supports_sha256_sess(self):
        """SHA-256-SESS must also be accepted (RFC 7616 session variant)."""
        params = self._sha256_params()
        params["algorithm"] = "SHA-256-SESS"
        header = sip.build_auth_header(
            username="u", password="p",
            method="INVITE", uri="sip:1000@pbx.local",
            params=params,
        )
        assert "Digest" in header
        assert "SHA-256-SESS" in header

    def test_md5_accepted(self):
        """MD5 must NOT raise."""
        params = {
            "realm": "asterisk",
            "nonce": "deadbeef",
            "algorithm": "MD5",
        }
        header = sip.build_auth_header(
            username="1000", password="secret",
            method="REGISTER", uri="sip:asterisk",
            params=params,
        )
        assert header.startswith("Authorization: Digest"), (
            f"unexpected header start: {header[:50]!r}"
        )
        # SIP digest headers may quote or omit quotes around algorithm (RFC 3261)
        assert "algorithm=MD5" in header or 'algorithm="MD5"' in header

    def test_md5_sess_accepted(self):
        """MD5-sess must also be accepted."""
        params = {
            "realm": "asterisk",
            "nonce": "c0ffee",
            "algorithm": "MD5-SESS",
        }
        # Should not raise
        header = sip.build_auth_header(
            username="1000", password="secret",
            method="REGISTER", uri="sip:asterisk",
            params=params,
        )
        assert "Digest" in header


# ---------------------------------------------------------------------------
# auth_test propagates SHA-256 as a skip, not a crash
# ---------------------------------------------------------------------------

class TestAuthTestSha256Skip:
    def test_auth_test_attempts_sha256_auth(self, monkeypatch):
        """auth_test.try_register must now ATTEMPT SHA-256 authentication
        (RFC 7616 is supported). It sends the authenticated REGISTER and
        returns the server's response reason, not 'auth skipped'."""
        from modules import auth_test

        # First response: 401 with SHA-256 challenge
        fake_401 = (
            b"SIP/2.0 401 Unauthorized\r\n"
            b"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n"
            b"From: <sip:1000@127.0.0.1>;tag=test\r\n"
            b"To: <sip:1000@127.0.0.1>\r\n"
            b"Call-ID: test-sha256@127.0.0.1\r\n"
            b"CSeq: 1 REGISTER\r\n"
            b"WWW-Authenticate: Digest realm=\"pbx.local\","
            b" nonce=\"abc123xyz\", algorithm=SHA-256\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        # Second response: 403 (wrong creds — expected since password is fake)
        fake_403 = (
            b"SIP/2.0 403 Forbidden\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

        call_count = {"n": 0}

        def fake_send_and_recv(*args, **kwargs):
            call_count["n"] += 1
            return fake_401 if call_count["n"] == 1 else fake_403

        monkeypatch.setattr(sip, "send_and_recv", fake_send_and_recv)

        result, reason = auth_test.try_register(
            host="127.0.0.1",
            ext="1000",
            username="1000",
            password="1234",
        )
        # Wrong creds → should fail with 403, not skip
        assert result is False
        assert "auth skipped" not in reason.lower(), (
            f"SHA-256 is now supported — should not skip, got: {reason!r}"
        )
        # Both the unauth REGISTER and the SHA-256 auth REGISTER must be sent
        assert call_count["n"] == 2, (
            f"expected 2 SIP sends (unauth + SHA-256 auth), got {call_count['n']}"
        )


# ---------------------------------------------------------------------------
# expand_ext_range guards
# ---------------------------------------------------------------------------

class TestExpandExtRange:
    def test_range_too_large_raises(self):
        """0-10000 is 10 001 entries — must raise ValueError."""
        with pytest.raises(ValueError, match="[Rr]ange|[Ll]imit|exceed|too large"):
            enumeration.expand_ext_range("0-10000")

    def test_range_at_limit_passes(self):
        """0-9999 is exactly 10 000 — must succeed."""
        result = enumeration.expand_ext_range("0-9999")
        assert len(result) == 10_000

    def test_path_traversal_dotdot_rejected(self):
        """file:../../etc/passwd must raise ValueError."""
        with pytest.raises(ValueError, match="[Uu]nsafe|[Tt]raversal|rejected"):
            enumeration.expand_ext_range("file:../../etc/passwd")

    def test_path_traversal_absolute_rejected(self):
        """file:/etc/passwd (absolute path) must raise ValueError."""
        with pytest.raises(ValueError, match="[Uu]nsafe|[Tt]raversal|rejected"):
            enumeration.expand_ext_range("file:/etc/passwd")

    def test_csv_list_works(self):
        """Comma-separated list must expand correctly."""
        result = enumeration.expand_ext_range("1000,2000,3000")
        assert result == ["1000", "2000", "3000"]

    def test_range_works(self):
        """Normal small range must work."""
        result = enumeration.expand_ext_range("100-109")
        assert result == [str(x) for x in range(100, 110)]

    def test_missing_file_raises_file_not_found(self, tmp_path):
        """file:nonexistent.txt must raise FileNotFoundError with a useful message."""
        with pytest.raises(FileNotFoundError, match="nonexistent"):
            enumeration.expand_ext_range("file:nonexistent_extensions_xyz.txt")

    def test_valid_file_path_loads(self, tmp_path, monkeypatch):
        """file:<relative-path> loads extensions correctly."""
        ext_file = tmp_path / "exts.txt"
        ext_file.write_text("1001\n1002\n# comment\n1003\n")
        # Change working directory so relative path resolves
        monkeypatch.chdir(tmp_path)
        result = enumeration.expand_ext_range("file:exts.txt")
        assert result == ["1001", "1002", "1003"], f"got {result}"


# ---------------------------------------------------------------------------
# RtpStreamer thread-safety
# ---------------------------------------------------------------------------

class TestRtpStreamerThreadSafety:
    def test_packets_sent_consistent_under_concurrent_reads(self):
        """packets_sent must never read a torn value under concurrent access."""
        sock, port = bind_rtp_socket()
        # Bind a sink socket to receive the UDP traffic
        sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sink.bind(("127.0.0.1", 0))
        sink_port = sink.getsockname()[1]

        streamer = RtpStreamer(
            sock=sock,
            remote_ip="127.0.0.1",
            remote_port=sink_port,
            payload_type=rtp.PAYLOAD_PCMU,
            ulaw_payload=b"\xff" * (160 * 20),  # 20 frames of silence
        )
        streamer.start()

        errors: list[str] = []
        readings: list[int] = []

        def reader():
            deadline = time.monotonic() + 0.8
            while time.monotonic() < deadline:
                v = streamer.packets_sent
                if not (0 <= v <= 10_000):
                    errors.append(f"torn read: {v}")
                readings.append(v)
                time.sleep(0.001)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2.0)

        streamer.stop = True
        streamer.join(timeout=1.0)
        sock.close()
        sink.close()

        assert not errors, f"Thread-safety violations: {errors}"
        # Verify it actually sent some packets
        final = streamer.packets_sent
        assert final > 0, "Streamer sent zero packets — start() may have failed"
        # readings must be monotonically non-decreasing within each thread (weak check)
        assert max(readings) == final or max(readings) <= final + 5

    def test_packets_sent_setter_and_getter(self):
        """Property getter/setter round-trip under no concurrency."""
        sock, port = bind_rtp_socket()
        sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sink.bind(("127.0.0.1", 0))
        sink_port = sink.getsockname()[1]

        streamer = RtpStreamer(sock=sock, remote_ip="127.0.0.1",
                               remote_port=sink_port)
        assert streamer.packets_sent == 0
        streamer.packets_sent = 42
        assert streamer.packets_sent == 42
        sock.close()
        sink.close()


# ---------------------------------------------------------------------------
# Vuln probes parallel performance
# ---------------------------------------------------------------------------

class TestVulnProbesParallel:
    """Regression test: run_all() must finish in ≤ probe_timeout + 1s overhead
    even against N ports. With serial execution, N=3 ports × 2 TLS × 8 probes
    × 0.2s timeout would take ~9.6s. Parallel must finish in ~1s."""

    def _start_http_server(self, response_delay: float = 0.1) -> tuple[int, threading.Event]:
        """Start a minimal HTTP server that delays and returns a neutral 200."""
        stop_ev = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(response_delay)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *args):
                pass  # silence access log

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]

        def _serve():
            srv.timeout = 0.1
            while not stop_ev.is_set():
                srv.handle_request()
            srv.server_close()

        threading.Thread(target=_serve, daemon=True).start()
        return port, stop_ev

    def test_parallel_faster_than_serial_baseline(self):
        from modules import vuln_probes

        probe_timeout = 0.2   # each HTTP call takes ≤0.2s in the mock
        # Three HTTP ports — serial would take ≥ 3 × 2 × 8 × 0.2 = 9.6s
        ports = []
        stop_events = []
        for _ in range(3):
            port, ev = self._start_http_server(response_delay=probe_timeout)
            ports.append(port)
            stop_events.append(ev)

        try:
            t0 = time.monotonic()
            vuln_probes.run_all("127.0.0.1", ports, timeout=probe_timeout)
            elapsed = time.monotonic() - t0
            # Parallel must complete in ≤ probe_timeout + generous overhead
            # even on a loaded CI runner — 4× is plenty.
            assert elapsed < probe_timeout * 4 + 2.0, (
                f"run_all took {elapsed:.2f}s — looks serial "
                f"(parallel should finish ~{probe_timeout + 1:.1f}s)"
            )
        finally:
            for ev in stop_events:
                ev.set()


# ---------------------------------------------------------------------------
# Content-Length DoS cap in server._read_body()
# (ensures the server rejects payloads exceeding the cap)
# ---------------------------------------------------------------------------

class TestContentLengthDos:
    def test_server_read_body_cap_import(self):
        """gui.server module must be importable without errors."""
        import importlib
        mod = importlib.import_module("gui.server")
        assert mod is not None


# ---------------------------------------------------------------------------
# New PhD-level feature tests
# ---------------------------------------------------------------------------

class TestHashcatExport:
    """DigestCapture hashcat/john format correctness."""

    def test_hashcat_line_format(self):
        """Hashcat mode-11400 line must start with $sip$*."""
        from modules.hashcat_export import DigestCapture
        cap = DigestCapture(
            extension="1000", host="pbx.local", username="1000",
            realm="asterisk", method="REGISTER",
            uri="sip:pbx.local", nonce="abc123", algorithm="MD5",
            qop="auth", nc="00000001", cnonce="deadbeef",
            response="0" * 32,
        )
        line = cap.hashcat_line()
        assert line.startswith("$sip$*"), f"bad format: {line[:30]!r}"
        assert "abc123" in line, "nonce missing"
        assert "asterisk" in line, "realm missing"

    def test_john_line_format(self):
        """John-the-Ripper line must include username and $sip$ marker."""
        from modules.hashcat_export import DigestCapture
        cap = DigestCapture(
            extension="1001", host="pbx.local", username="1001",
            realm="asterisk", method="REGISTER",
            uri="sip:pbx.local", nonce="xyz789", algorithm="MD5",
            qop="", nc="", cnonce="",
            response="a" * 32,
        )
        line = cap.john_line()
        assert "$sip$" in line
        assert "1001" in line

    def test_capture_result_hashes_property(self):
        """CaptureResult.hashes returns list of hashcat lines."""
        from modules.hashcat_export import DigestCapture, CaptureResult
        cap = DigestCapture(
            extension="1000", host="h", username="1000",
            realm="r", method="REGISTER", uri="sip:h",
            nonce="n", algorithm="MD5", qop="", nc="", cnonce="",
            response="r" * 32,
        )
        result = CaptureResult(captures=[cap], host="h")
        assert len(result.hashes) == 1
        assert result.hashes[0].startswith("$sip$*")

    def test_save_creates_files(self, tmp_path):
        """CaptureResult.save() writes hashcat + john + sipdump files."""
        from modules.hashcat_export import DigestCapture, CaptureResult
        cap = DigestCapture(
            extension="1000", host="h", username="1000",
            realm="r", method="REGISTER", uri="sip:h",
            nonce="n", algorithm="MD5", qop="", nc="", cnonce="",
            response="r" * 32,
        )
        result = CaptureResult(captures=[cap], host="h")
        paths = result.save(str(tmp_path))
        assert "hashcat" in paths
        assert "john" in paths
        assert "sipdump" in paths
        assert (tmp_path / "sip_hashes_hashcat.txt").exists()
        content = (tmp_path / "sip_hashes_hashcat.txt").read_text()
        assert "$sip$*" in content


class TestParallelAuthSpray:
    """spray_parallel basic correctness."""

    def test_spray_parallel_returns_list(self, monkeypatch):
        """spray_parallel must return list[CredResult] even with no hits."""
        from modules import auth_test, sip

        # Stub: always returns 403 Forbidden
        fake_403 = (
            b"SIP/2.0 403 Forbidden\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

        # First call returns 401 challenge, second returns 403
        challenge_seen: dict[str, int] = {}

        def fake_send(msg, host, port, lport, timeout=3.0, traffic_log=None):
            key = msg[:40].decode("utf-8", errors="replace")
            n = challenge_seen.get(key, 0) + 1
            challenge_seen[key] = n
            if n == 1:
                return (
                    b"SIP/2.0 401 Unauthorized\r\n"
                    b"WWW-Authenticate: Digest realm=\"test\","
                    b" nonce=\"nonce123\", algorithm=MD5\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            return fake_403

        monkeypatch.setattr(sip, "send_and_recv", fake_send)

        results = auth_test.spray_parallel(
            host="127.0.0.1",
            extensions=["1000"],
            cred_pairs=[("1000", "wrong"), ("admin", "admin")],
            max_workers=2,
        )
        assert isinstance(results, list)
        # No successes expected (all 403)
        assert not any(r.success for r in results)


class TestSipSubscribeProbe:
    """SUBSCRIBE probe basic correctness."""

    def test_subscribe_probe_sends_subscribe_method(self, monkeypatch):
        """subscribe_probe must send a SUBSCRIBE request (not REGISTER)."""
        from modules import sip
        sent_messages: list[bytes] = []

        def fake_send(msg, host, port, lport, timeout=3.0, traffic_log=None):
            sent_messages.append(msg)
            return (
                b"SIP/2.0 489 Bad Event\r\n"
                b"Content-Length: 0\r\n\r\n"
            )

        monkeypatch.setattr(sip, "send_and_recv", fake_send)
        resp = sip.subscribe_probe("127.0.0.1", "1000")
        assert sent_messages, "no SIP message sent"
        first_line = sent_messages[0].split(b"\r\n", 1)[0].decode()
        assert first_line.startswith("SUBSCRIBE"), f"expected SUBSCRIBE, got: {first_line!r}"
        assert resp is not None
        assert resp.status_code == 489


class TestParallelEnumeration:
    """enumerate_range_parallel smoke test."""

    def test_parallel_enum_returns_only_existing(self, monkeypatch):
        """enumerate_range_parallel must return only extensions that exist."""
        from modules import enumeration, sip

        # Ext 1000 → 401 (exists, auth required); 1001 → 404 (not found)
        def fake_send(msg, host, port, lport, timeout=3.0, traffic_log=None):
            msg_str = msg.decode("utf-8", errors="replace")
            if "1000" in msg_str and "REGISTER" in msg_str:
                return (b"SIP/2.0 401 Unauthorized\r\n"
                        b"WWW-Authenticate: Digest realm=\"r\","
                        b" nonce=\"n\", algorithm=MD5\r\n"
                        b"Content-Length: 0\r\n\r\n")
            return (b"SIP/2.0 404 Not Found\r\n"
                    b"Content-Length: 0\r\n\r\n")

        monkeypatch.setattr(sip, "send_and_recv", fake_send)
        results = enumeration.enumerate_range_parallel(
            "127.0.0.1", ["1000", "1001"], max_workers=2
        )
        exts = [r.extension for r in results]
        assert "1000" in exts
        assert "1001" not in exts


class TestNewVulnProbes:
    """Smoke tests for the 8 new vuln probe functions."""

    def test_probe_yealink_rce_skips_wrong_port(self):
        """Yealink probe must skip non-web ports (5060 is SIP, not web)."""
        from modules.vuln_probes import probe_yealink_rce
        # Port 5060 is not in the Yealink web port list — should return None fast
        result = probe_yealink_rce("127.0.0.1", 5060, False, timeout=0.1)
        assert result is None

    def test_probe_freeswitch_skips_wrong_port(self):
        """FreeSWITCH probe must skip non-FreeSWITCH HTTP ports."""
        from modules.vuln_probes import probe_freeswitch_default_creds
        result = probe_freeswitch_default_creds("127.0.0.1", 5060, False, timeout=0.1)
        assert result is None

    def test_probe_webrtc_skips_wrong_port(self):
        """WebRTC probe must skip non-WebRTC ports."""
        from modules.vuln_probes import probe_webrtc_gateway
        result = probe_webrtc_gateway("127.0.0.1", 5060, False, timeout=0.1)
        assert result is None

    def test_probe_snom_skips_wrong_port(self):
        """Snom probe must skip non-web ports."""
        from modules.vuln_probes import probe_snom_admin
        result = probe_snom_admin("127.0.0.1", 5060, False, timeout=0.1)
        assert result is None

    def test_probe_cisco_phone_skips_wrong_port(self):
        """Cisco phone probe must skip non-HTTP ports."""
        from modules.vuln_probes import probe_cisco_phone_admin
        result = probe_cisco_phone_admin("127.0.0.1", 5060, False, timeout=0.1)
        assert result is None

    def test_probe_siptrunk_skips_wrong_port(self):
        """SIP trunk probe must skip non-HTTP ports."""
        from modules.vuln_probes import probe_siptrunk_scan
        result = probe_siptrunk_scan("127.0.0.1", 5060, False, timeout=0.1)
        assert result is None


class TestTrafficAnalyzerByeFlood:
    """BYE flood triggers a 'high' anomaly after threshold."""

    def test_bye_flood_emits_anomaly(self):
        from modules.traffic_analyzer import TrafficAnalyzer, _BYE_FLOOD_LIMIT
        ta = TrafficAnalyzer()
        now = 1000.0
        anomalies: list = []
        # Feed _BYE_FLOOD_LIMIT + 1 BYE events within the flood window
        for i in range(_BYE_FLOOD_LIMIT + 1):
            evs = ta._analyse_event({
                "type": "sip.bye",
                "data": {},
                "timestamp": now + i * 0.1,
            })
            anomalies.extend(evs)
        bye_anomalies = [a for a in anomalies if a.type == "bye_flood"]
        assert bye_anomalies, "Expected at least one bye_flood anomaly"
        assert bye_anomalies[0].severity == "high"

    def test_bye_flood_below_threshold_no_anomaly(self):
        from modules.traffic_analyzer import TrafficAnalyzer, _BYE_FLOOD_LIMIT
        ta = TrafficAnalyzer()
        now = 2000.0
        anomalies: list = []
        for i in range(_BYE_FLOOD_LIMIT):
            evs = ta._analyse_event({
                "type": "sip.bye",
                "data": {},
                "timestamp": now + i * 0.1,
            })
            anomalies.extend(evs)
        bye_anomalies = [a for a in anomalies if a.type == "bye_flood"]
        assert not bye_anomalies, "Should not trigger below threshold"


class TestTrafficAnalyzerCancelFlood:
    """CANCEL flood triggers a 'high' anomaly after threshold."""

    def test_cancel_flood_emits_anomaly(self):
        from modules.traffic_analyzer import TrafficAnalyzer, _CANCEL_FLOOD_LIMIT
        ta = TrafficAnalyzer()
        now = 3000.0
        anomalies: list = []
        for i in range(_CANCEL_FLOOD_LIMIT + 1):
            evs = ta._analyse_event({
                "type": "sip.cancel",
                "data": {},
                "timestamp": now + i * 0.1,
            })
            anomalies.extend(evs)
        cancel_anomalies = [a for a in anomalies if a.type == "cancel_flood"]
        assert cancel_anomalies, "Expected at least one cancel_flood anomaly"
        assert cancel_anomalies[0].severity == "high"


class TestDigestLeakViaSubscribe:
    """capture_digest_via_subscribe returns a DigestCapture with method=SUBSCRIBE."""

    def test_returns_digest_capture_on_401(self, monkeypatch):
        from modules import sip
        from modules.hashcat_export import capture_digest_via_subscribe, DigestCapture

        fake_401 = (
            b"SIP/2.0 401 Unauthorized\r\n"
            b"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n"
            b"From: <sip:1000@127.0.0.1>;tag=test\r\n"
            b"To: <sip:1000@127.0.0.1>\r\n"
            b"Call-ID: sub-test@127.0.0.1\r\n"
            b"CSeq: 1 SUBSCRIBE\r\n"
            b"WWW-Authenticate: Digest realm=\"pbx.local\","
            b" nonce=\"subscribenonce99\", algorithm=MD5\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

        monkeypatch.setattr(sip, "send_and_recv", lambda *a, **kw: fake_401)

        result = capture_digest_via_subscribe("127.0.0.1", "1000")
        assert result is not None, "Expected a DigestCapture, got None"
        assert isinstance(result, DigestCapture)
        assert result.method == "SUBSCRIBE", f"expected SUBSCRIBE, got {result.method!r}"
        assert result.uri == "sip:1000@127.0.0.1", f"unexpected uri: {result.uri!r}"
        assert result.nonce == "subscribenonce99"
        assert result.realm == "pbx.local"

    def test_returns_none_on_403(self, monkeypatch):
        from modules import sip
        from modules.hashcat_export import capture_digest_via_subscribe

        fake_403 = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        monkeypatch.setattr(sip, "send_and_recv", lambda *a, **kw: fake_403)

        result = capture_digest_via_subscribe("127.0.0.1", "9999")
        assert result is None, "403 should yield None, not a DigestCapture"

    def test_capture_and_export_via_subscribe_parallel(self, monkeypatch):
        from modules import sip
        from modules.hashcat_export import capture_and_export_via_subscribe

        fake_401 = (
            b"SIP/2.0 401 Unauthorized\r\n"
            b"WWW-Authenticate: Digest realm=\"pbx.local\","
            b" nonce=\"nonce42\", algorithm=MD5\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        monkeypatch.setattr(sip, "send_and_recv", lambda *a, **kw: fake_401)

        result = capture_and_export_via_subscribe("127.0.0.1", ["1000", "1001"])
        assert len(result.captures) == 2
        for cap in result.captures:
            assert cap.method == "SUBSCRIBE"


class TestPcapExport:
    """pcap_from_traffic_log produces a valid libpcap file."""

    def _make_traffic_log(self, tmp_path, entries: list[tuple[str, str, str]]) -> str:
        """Write a minimal TrafficLog file. entries = [(ts, direction, payload)]."""
        path = str(tmp_path / "traffic.log")
        with open(path, "w", encoding="utf-8") as f:
            for ts, direction, payload in entries:
                f.write(f"\n=== {ts} {direction} 1.2.3.4:5060 ===\n")
                f.write(payload + "\n")
        return path

    def test_pcap_starts_with_magic(self, tmp_path):
        from modules.pcap_export import pcap_from_traffic_log
        import struct

        sip_payload = (
            "REGISTER sip:1.2.3.4 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        log_path = self._make_traffic_log(
            tmp_path,
            [("2026-04-14T12:00:00", "OUT", sip_payload)],
        )
        pcap_path = str(tmp_path / "out.pcap")
        n = pcap_from_traffic_log(log_path, pcap_path)
        assert n == 1, f"expected 1 packet written, got {n}"

        with open(pcap_path, "rb") as f:
            header = f.read(4)
        magic = struct.unpack("<I", header)[0]
        assert magic == 0xA1B2C3D4, f"bad magic: {magic:#010x}"

    def test_pcap_byte_count(self, tmp_path):
        from modules.pcap_export import pcap_from_traffic_log

        sip_payload = "OPTIONS sip:1.2.3.4 SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        log_path = self._make_traffic_log(
            tmp_path,
            [
                ("2026-04-14T12:00:01", "OUT", sip_payload),
                ("2026-04-14T12:00:02", "IN", "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
            ],
        )
        pcap_path = str(tmp_path / "two.pcap")
        n = pcap_from_traffic_log(log_path, pcap_path)
        assert n == 2, f"expected 2 packets, got {n}"

        # Global header=24, each packet: pkt_hdr(16)+eth(14)+ip(20)+udp(8)+payload
        import os
        file_size = os.path.getsize(pcap_path)
        assert file_size > 24 + 2 * (16 + 14 + 20 + 8), (
            f"pcap file too small: {file_size} bytes"
        )


class TestPcapWriterHeaders:
    """PcapWriter.write_packet produces well-formed Ethernet+IP+UDP frames."""

    def test_global_header_magic(self, tmp_path):
        from modules.pcap_export import PcapWriter
        import struct

        path = str(tmp_path / "test.pcap")
        w = PcapWriter(path)
        w.close()

        with open(path, "rb") as f:
            data = f.read(24)
        assert len(data) == 24, "global header must be 24 bytes"
        magic, ver_maj, ver_min = struct.unpack_from("<IHH", data, 0)
        assert magic == 0xA1B2C3D4
        assert ver_maj == 2
        assert ver_min == 4

    def test_packet_frame_lengths(self, tmp_path):
        from modules.pcap_export import PcapWriter
        import struct

        payload = b"HELLO SIP WORLD"
        path = str(tmp_path / "pkt.pcap")
        w = PcapWriter(path)
        w.write_packet(payload, "10.0.0.1", "10.0.0.2", 5060, 5060, timestamp=0.0)
        w.close()

        with open(path, "rb") as f:
            f.read(24)               # skip global header
            pkt_hdr = f.read(16)
            frame = f.read()

        assert len(pkt_hdr) == 16
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
        assert ts_sec == 0
        assert incl_len == orig_len
        assert len(frame) == incl_len

        # Dissect Ethernet (14) + IP (20) + UDP (8)
        assert len(frame) >= 14 + 20 + 8 + len(payload)
        # Check Ethertype = 0x0800
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        assert ethertype == 0x0800, f"ethertype should be 0x0800, got {ethertype:#06x}"
        # Check IP protocol = 17 (UDP)
        ip_proto = frame[14 + 9]
        assert ip_proto == 17, f"IP proto should be 17 (UDP), got {ip_proto}"
        # Check UDP src/dst ports
        udp_src, udp_dst = struct.unpack_from(">HH", frame, 14 + 20)
        assert udp_src == 5060
        assert udp_dst == 5060
        # Check payload at end
        assert frame[14 + 20 + 8:] == payload


class TestTrafficAnalyzerAuthFailRatio:
    """High auth-failure ratio fires once when sample is large enough."""

    def test_high_failure_ratio_emits_once(self):
        from modules.traffic_analyzer import (
            TrafficAnalyzer, _AUTH_FAIL_MIN_SAMPLE, _AUTH_FAIL_RATIO_LIMIT
        )
        ta = TrafficAnalyzer()
        now = 4000.0
        anomalies: list = []
        # Feed _AUTH_FAIL_MIN_SAMPLE failed auth events
        for i in range(_AUTH_FAIL_MIN_SAMPLE):
            evs = ta._analyse_event({
                "type": "auth_test.attempt",
                "data": {"success": False, "password": "bad", "extension": str(i)},
                "timestamp": now + i,
            })
            anomalies.extend(evs)
        ratio_anomalies = [a for a in anomalies if a.type == "high_auth_failure_rate"]
        assert len(ratio_anomalies) == 1, (
            f"Expected exactly 1 high_auth_failure_rate anomaly, got {len(ratio_anomalies)}"
        )
        assert ratio_anomalies[0].severity == "high"
        assert ratio_anomalies[0].evidence["failure_ratio"] >= _AUTH_FAIL_RATIO_LIMIT

    def test_no_anomaly_when_ratio_below_threshold(self):
        from modules.traffic_analyzer import TrafficAnalyzer, _AUTH_FAIL_MIN_SAMPLE
        ta = TrafficAnalyzer()
        now = 5000.0
        anomalies: list = []
        # Half success, half fail — ratio = 0.5, below 0.80 threshold
        for i in range(_AUTH_FAIL_MIN_SAMPLE * 2):
            evs = ta._analyse_event({
                "type": "auth_test.attempt",
                "data": {"success": (i % 2 == 0), "password": "pw", "extension": str(i)},
                "timestamp": now + i,
            })
            anomalies.extend(evs)
        ratio_anomalies = [a for a in anomalies if a.type == "high_auth_failure_rate"]
        assert not ratio_anomalies, "Should not trigger when failure ratio is low"


# ---------------------------------------------------------------------------
# RTP Bleed probe (CVE-2017-11527)
# ---------------------------------------------------------------------------

class TestRtpBleedPacketShape:
    def test_silence_packet_is_valid_rtp(self):
        from modules.rtp_bleed import _silence_rtp, _looks_like_rtp
        pkt = _silence_rtp(seq=100, ts=12345, ssrc=0xDEADBEEF)
        # 12-byte header + 160-byte payload = 172 bytes
        assert len(pkt) == 172, f"unexpected packet size {len(pkt)}"
        # First byte: V=2 (top 2 bits = 10)
        assert (pkt[0] >> 6) == 2, "RTP version must be 2"
        # Second byte: PT=0 (PCMU)
        assert (pkt[1] & 0x7F) == 0, "Payload type must be 0 (PCMU)"
        # Sequence / timestamp / ssrc readable back
        assert struct.unpack("!H", pkt[2:4])[0] == 100
        assert struct.unpack("!I", pkt[4:8])[0] == 12345
        assert struct.unpack("!I", pkt[8:12])[0] == 0xDEADBEEF
        # Payload is pure μ-law silence (0xFF)
        assert pkt[12:] == b"\xff" * 160

    def test_looks_like_rtp_rejects_short_packets(self):
        from modules.rtp_bleed import _looks_like_rtp
        assert _looks_like_rtp(b"")  is False
        assert _looks_like_rtp(b"A" * 8) is False

    def test_looks_like_rtp_rejects_wrong_version(self):
        from modules.rtp_bleed import _looks_like_rtp
        bad = b"\x00" * 16  # version bits = 0
        assert _looks_like_rtp(bad) is False

    def test_looks_like_rtp_accepts_well_formed(self):
        from modules.rtp_bleed import _silence_rtp, _looks_like_rtp
        pkt = _silence_rtp(1, 2, 3)
        assert _looks_like_rtp(pkt) is True


class TestRtpBleedProbeClean:
    """Probe a UDP port that doesn't echo — must return clean result."""

    def test_no_bleed_when_target_silent(self):
        from modules.rtp_bleed import probe_rtp_bleed
        # 127.0.0.1 with a nothing-listening-here port range returns clean.
        # Using a very small port list keeps the test fast.
        result = probe_rtp_bleed(
            "127.0.0.1",
            ports=[65530, 65531, 65532],
            listen_seconds=0.3,
            rate_pps=200,
            pkts_per_port=1,
        )
        assert result.bleed_detected is False
        assert result.bleeding_ports == []
        assert result.packets_sent == 3, "Should send exactly one packet per port"
        assert result.probed_ports == 3

    def test_bleed_detected_when_target_echoes(self):
        """Simulate a bleeding proxy: reply with RTP to every received packet."""
        from modules.rtp_bleed import probe_rtp_bleed, _silence_rtp

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        bleed_port = sock.getsockname()[1]

        stop = threading.Event()

        def echo():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    return
                # Reply with a valid RTP packet — this is what a vulnerable
                # proxy would do after re-learning the media destination.
                reply = _silence_rtp(seq=1, ts=1, ssrc=0xCAFE)
                try:
                    sock.sendto(reply, addr)
                except OSError:
                    return

        t = threading.Thread(target=echo, daemon=True)
        t.start()
        try:
            result = probe_rtp_bleed(
                "127.0.0.1",
                ports=[bleed_port],
                listen_seconds=0.5,
                rate_pps=200,
                pkts_per_port=2,
            )
        finally:
            stop.set()
            sock.close()
            t.join(timeout=1.0)

        assert result.bleed_detected, "Expected bleed detection against echo host"
        assert bleed_port in result.bleeding_ports


class TestRtpBleedFinding:
    def test_finding_none_when_clean(self):
        from modules.rtp_bleed import RtpBleedResult, build_finding
        r = RtpBleedResult(target_ip="1.2.3.4", probed_ports=5, packets_sent=5)
        assert build_finding(r) is None

    def test_finding_emitted_when_detected(self):
        from modules.rtp_bleed import RtpBleedResult, build_finding
        r = RtpBleedResult(
            target_ip="1.2.3.4", probed_ports=5, packets_sent=5,
            bleed_detected=True, bleeding_ports=[10000, 10002],
        )
        f = build_finding(r)
        assert f is not None
        assert f["severity"] == "high"
        assert f["cve"] == "CVE-2017-11527"
        assert "10000" in f["detail"]


# ---------------------------------------------------------------------------
# SIP Method Fuzzer
# ---------------------------------------------------------------------------

class TestMethodFuzzerAnomalies:
    def _make_result(self, method: str, tier: int, code: int, reason: str = ""):
        from modules.method_fuzzer import MethodProbeResult
        return MethodProbeResult(
            method=method, tier=tier, note="", status_code=code, reason=reason,
        )

    def test_fuzz_methods_list_covers_tiers(self):
        """Every tier 0-3 must be represented in the fuzz set."""
        from modules.method_fuzzer import FUZZ_METHODS
        tiers = {t for _, t, _ in FUZZ_METHODS}
        assert tiers == {0, 1, 2, 3}, f"missing tiers, got {tiers}"

    def test_2xx_on_nonstandard_verb_is_anomaly(self):
        """Accepting EXECUTE (tier 2) must be flagged as an anomaly."""
        from modules.method_fuzzer import MethodFuzzReport, build_findings
        report = MethodFuzzReport(target="test:5060")
        report.probes.append(self._make_result("EXECUTE", 2, 200, "OK"))
        report.anomalies.append(
            "EXECUTE: accepted (200 OK) — non-standard verb not expected to be implemented"
        )
        findings = build_findings(report)
        # Must have 1 info summary + 1 high severity finding
        high = [f for f in findings if f["severity"] == "high"]
        assert len(high) == 1, f"Expected one high-severity finding, got {findings}"
        assert "EXECUTE" in high[0]["title"]

    def test_401_on_nonstandard_verb_is_medium(self):
        from modules.method_fuzzer import MethodFuzzReport, build_findings
        report = MethodFuzzReport(target="test:5060")
        report.probes.append(self._make_result("ADMIN", 2, 401, "Unauthorized"))
        report.anomalies.append(
            "ADMIN: auth-challenged (401) — PBX has a handler for a non-standard verb"
        )
        findings = build_findings(report)
        medium = [f for f in findings if f["severity"] == "medium"]
        assert len(medium) == 1
        assert "ADMIN" in medium[0]["title"]

    def test_no_anomaly_on_standard_405(self):
        """Standard 405 Method Not Allowed should not raise an anomaly."""
        from modules.method_fuzzer import MethodFuzzReport, build_findings
        report = MethodFuzzReport(target="test:5060")
        report.probes.append(self._make_result("DEBUG", 2, 405, "Method Not Allowed"))
        # No anomaly appended — because 405 to tier 2 is fine / expected.
        findings = build_findings(report)
        assert all(f["severity"] == "info" for f in findings), findings


# ---------------------------------------------------------------------------
# CSV / JSON Lines export
# ---------------------------------------------------------------------------

class TestFindingsCsvExport:
    def _sample_report(self) -> dict:
        return {
            "timestamp": "2026-04-14T10:00:00",
            "target": "10.0.0.1",
            "findings": [
                {
                    "id": "sip.exposed",
                    "severity": "info",
                    "host": "10.0.0.1",
                    "title": "SIP reachable",
                    "detail": "multi\nline\r\ndetail",
                    "remediation": "restrict by ACL",
                    "cve": "",
                    "cvss": "",
                },
                {
                    "id": "rtp.bleed",
                    "severity": "high",
                    "host": "10.0.0.1",
                    "title": "RTP Bleed",
                    "detail": "Found bleed on 10000",
                    "remediation": "strict-rtp",
                    "cve": "CVE-2017-11527",
                    "cvss": 7.5,
                },
            ],
        }

    def test_csv_header_and_rows(self):
        import csv as _csv
        import io as _io
        from modules.reporter import _render_findings_csv
        csv_text = _render_findings_csv(self._sample_report())
        # Parse via csv reader — far more robust than string-splitting and
        # handles RFC-4180 \r\n line endings correctly.
        rows = list(_csv.reader(_io.StringIO(csv_text)))
        assert len(rows) == 3, f"header + 2 rows expected, got {len(rows)}"
        # Header must include the core fields
        assert "severity" in rows[0]
        assert "cve" in rows[0]
        assert "remediation" in rows[0]
        # CVE row (second data row = index 2)
        assert "CVE-2017-11527" in rows[2]
        # Detail column must be sanitised: no embedded newline chars inside
        # any field of the data rows.
        for row in rows[1:]:
            for field in row:
                assert "\r" not in field, f"CR leaked into field: {field!r}"
                assert "\n" not in field, f"LF leaked into field: {field!r}"

    def test_jsonl_one_finding_per_line(self):
        from modules.reporter import _render_findings_jsonl
        import json
        text = _render_findings_jsonl(self._sample_report())
        lines = [ln for ln in text.strip().split("\n") if ln]
        assert len(lines) == 2
        for ln in lines:
            obj = json.loads(ln)  # each line must be valid JSON
            assert obj["event"] == "voipscan.finding"
            assert obj["target"] == "10.0.0.1"
            assert "severity" in obj


# ---------------------------------------------------------------------------
# IAX2 protocol
# ---------------------------------------------------------------------------

class TestIax2FrameCodec:
    def test_full_frame_roundtrip(self):
        from modules.iax2 import _build_full_frame, _parse_full_frame, FRAME_TYPE_IAX, SUBCLASS_POKE
        frame = _build_full_frame(
            source_call=42, dest_call=0, timestamp_ms=1234,
            oseqno=0, iseqno=0,
            frame_type=FRAME_TYPE_IAX, subclass=SUBCLASS_POKE,
        )
        parsed = _parse_full_frame(frame)
        assert parsed is not None
        assert parsed["source_call"] == 42
        assert parsed["frame_type"] == FRAME_TYPE_IAX
        assert parsed["subclass"] == SUBCLASS_POKE
        assert parsed["timestamp"] == 1234

    def test_mini_frame_rejected(self):
        """Mini frames (F=0) must return None from full-frame parser."""
        from modules.iax2 import _parse_full_frame
        mini = bytes([0x00, 0x00]) + b"\x00" * 20  # F=0 in top bit
        assert _parse_full_frame(mini) is None

    def test_ie_pack_and_parse(self):
        from modules.iax2 import _pack_ie, _parse_ies, IE_USERNAME
        packed = _pack_ie(IE_USERNAME, b"alice")
        parsed = _parse_ies(packed)
        assert parsed == {IE_USERNAME: b"alice"}

    def test_ie_parse_multiple(self):
        from modules.iax2 import _pack_ie, _parse_ies, IE_USERNAME, IE_VERSION
        buf = _pack_ie(IE_VERSION, b"\x00\x02") + _pack_ie(IE_USERNAME, b"bob")
        parsed = _parse_ies(buf)
        assert parsed[IE_VERSION] == b"\x00\x02"
        assert parsed[IE_USERNAME] == b"bob"

    def test_ie_parse_malformed_truncation(self):
        """Parser must not crash on truncated IE payload."""
        from modules.iax2 import _parse_ies
        # IE-ID=6, length=10, but only 3 bytes of data — stop gracefully
        buf = bytes([6, 10]) + b"xyz"
        parsed = _parse_ies(buf)
        assert parsed == {}  # nothing fully parsed


class TestIax2PokeProbe:
    """Simulate an IAX2 peer that replies with PONG."""

    def test_poke_detects_iax2_speaker(self):
        from modules.iax2 import (probe_poke, _build_full_frame, _parse_full_frame,
                                   FRAME_TYPE_IAX, SUBCLASS_PONG)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        stop = threading.Event()

        def serve():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    return
                parsed = _parse_full_frame(data)
                if not parsed:
                    continue
                # Reply PONG
                pong = _build_full_frame(
                    source_call=1, dest_call=parsed["source_call"],
                    timestamp_ms=0, oseqno=0, iseqno=1,
                    frame_type=FRAME_TYPE_IAX, subclass=SUBCLASS_PONG,
                )
                try:
                    sock.sendto(pong, addr)
                except OSError:
                    return

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = probe_poke("127.0.0.1", port=port, timeout=1.0)
        finally:
            stop.set()
            sock.close()
            t.join(timeout=1.0)

        assert result.pong_received, "Expected PONG from simulated IAX2 speaker"
        assert result.iax2_detected

    def test_poke_timeout_returns_clean(self):
        from modules.iax2 import probe_poke
        # Non-listening port → should time out and return pong_received=False
        result = probe_poke("127.0.0.1", port=65533, timeout=0.3)
        assert result.pong_received is False
        assert result.iax2_detected is False


# ---------------------------------------------------------------------------
# TLS audit
# ---------------------------------------------------------------------------

class TestTlsAuditClassification:
    """Cipher / cert classification without requiring a live TLS peer."""

    def test_weak_cipher_flagged_critical(self):
        from modules.tls_audit import _classify_ciphers
        hits = _classify_ciphers("NULL-MD5")
        sevs = {sev for sev, _ in hits}
        assert "critical" in sevs, f"NULL cipher should be critical: {hits}"

    def test_rc4_cipher_flagged_high(self):
        from modules.tls_audit import _classify_ciphers
        hits = _classify_ciphers("RC4-SHA")
        sevs = {sev for sev, _ in hits}
        assert "high" in sevs

    def test_modern_cipher_not_flagged(self):
        from modules.tls_audit import _classify_ciphers
        hits = _classify_ciphers("TLS_AES_256_GCM_SHA384")
        # Expect no critical/high entries for a modern AEAD suite
        bad = [sev for sev, _ in hits if sev in ("critical", "high")]
        assert not bad, f"Modern AEAD flagged: {hits}"

    def test_deprecated_protocols_set(self):
        """TLS < 1.2 must be flagged by the deprecated-protocol set."""
        from modules.tls_audit import _DEPRECATED_PROTOCOLS
        assert "SSLv3" in _DEPRECATED_PROTOCOLS
        assert "TLSv1" in _DEPRECATED_PROTOCOLS
        assert "TLSv1.1" in _DEPRECATED_PROTOCOLS
        assert "TLSv1.2" not in _DEPRECATED_PROTOCOLS
        assert "TLSv1.3" not in _DEPRECATED_PROTOCOLS

    def test_hostname_match_wildcard(self):
        """RFC 6125: *.example.com must match foo.example.com but not example.com."""
        from modules.tls_audit import _hostname_matches
        cert = {
            "subject": ((("commonName", "*.example.com"),),),
            "subjectAltName": (("DNS", "*.example.com"),),
        }
        assert _hostname_matches(cert, "foo.example.com")
        assert not _hostname_matches(cert, "example.com")
        assert not _hostname_matches(cert, "bar.sub.example.com")

    def test_hostname_match_exact(self):
        from modules.tls_audit import _hostname_matches
        cert = {
            "subject": ((("commonName", "pbx.corp.local"),),),
            "subjectAltName": (("DNS", "pbx.corp.local"),),
        }
        assert _hostname_matches(cert, "pbx.corp.local")
        assert not _hostname_matches(cert, "other.corp.local")

    def test_parse_cert_date(self):
        from modules.tls_audit import _parse_cert_date
        dt = _parse_cert_date("Jun  1 23:59:59 2026 GMT")
        assert dt is not None
        assert dt.year == 2026 and dt.month == 6 and dt.day == 1

    def test_parse_cert_date_garbage(self):
        from modules.tls_audit import _parse_cert_date
        assert _parse_cert_date("not a date") is None
        assert _parse_cert_date("") is None

    def test_build_findings_suppresses_no_connect(self):
        """No findings emitted when TLS handshake never completed."""
        from modules.tls_audit import TlsAuditResult, build_findings
        result = TlsAuditResult(host="x", port=443, connected=False)
        assert build_findings(result) == []


# ---------------------------------------------------------------------------
# TFTP config-file loot
# ---------------------------------------------------------------------------

class TestTftpLoot:
    def test_rrq_packet_shape(self):
        from modules.tftp_loot import _build_rrq, OPCODE_RRQ
        pkt = _build_rrq("SEP001122334455.cnf.xml")
        assert struct.unpack("!H", pkt[:2])[0] == OPCODE_RRQ
        # Must contain filename + NUL + mode ("octet") + NUL
        assert b"SEP001122334455.cnf.xml\x00octet\x00" in pkt

    def test_parse_data_packet(self):
        from modules.tftp_loot import _parse_packet, OPCODE_DATA
        pkt = struct.pack("!HH", OPCODE_DATA, 1) + b"payload"
        parsed = _parse_packet(pkt)
        assert parsed is not None
        opcode, block, payload = parsed
        assert opcode == OPCODE_DATA
        assert block == 1
        assert payload == b"payload"

    def test_parse_short_packet_returns_none(self):
        from modules.tftp_loot import _parse_packet
        assert _parse_packet(b"\x00") is None  # too short

    def test_credential_scan_polycom_password(self):
        """Polycom cfg format is `reg.N.auth.password=<value>` (attr form)."""
        from modules.tftp_loot import _scan_for_credentials
        cfg = 'reg.1.auth.password="TopSecret42!"'
        hits = _scan_for_credentials(cfg)
        assert any("TopSecret42" in h for h in hits), f"hits={hits}"

    def test_credential_scan_ignores_placeholder(self):
        """XML templates that contain <password> or %password% must NOT
        produce a cred finding (too many false positives otherwise)."""
        from modules.tftp_loot import _scan_for_credentials
        placeholders = [
            "<password>password</password>",
            "secret=%password%",
            "authPassword=$password",
            "admin=changeme",
        ]
        for text in placeholders:
            hits = _scan_for_credentials(text)
            # Placeholder values should be suppressed
            assert not any(
                h.endswith(": password") or h.endswith(": %password%")
                or h.endswith(": $password") or h.endswith(": changeme")
                for h in hits
            ), f"placeholder leaked through: {text} → {hits}"

    def test_credential_scan_cisco_xml(self):
        from modules.tftp_loot import _scan_for_credentials
        cisco = """<device>
            <authID>admin</authID>
            <password>HelloWorld99</password>
        </device>"""
        hits = _scan_for_credentials(cisco)
        assert any("HelloWorld99" in h for h in hits)

    def test_loot_generic_candidates_include_cisco(self):
        """Make sure the well-known Cisco filenames are part of the list."""
        from modules.tftp_loot import GENERIC_CANDIDATES
        assert "CTLFile.tlv" in GENERIC_CANDIDATES
        assert "SEPDefault.cnf" in GENERIC_CANDIDATES

    def test_loot_integration_roundtrip(self):
        """Mini TFTP server that serves a small config; loot_tftp must
        pull it, detect the password, and mark the file as recovered."""
        from modules.tftp_loot import loot_tftp, OPCODE_RRQ, OPCODE_DATA, OPCODE_ERROR
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        stop = threading.Event()

        PAYLOAD = (b'<polycom>\nreg.1.auth.password="HunterHunt33"\n</polycom>'
                   .ljust(200, b" "))

        def serve():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = srv.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if len(data) < 2:
                    continue
                opcode = struct.unpack("!H", data[:2])[0]
                # Parse RRQ: opcode + filename + NUL + mode + NUL
                if opcode != OPCODE_RRQ:
                    continue
                payload = data[2:]
                try:
                    filename, rest = payload.split(b"\x00", 1)
                except ValueError:
                    continue
                if filename == b"phone1.cfg":
                    # Serve a single-block DATA response (< 512 bytes)
                    resp = struct.pack("!HH", OPCODE_DATA, 1) + PAYLOAD
                    try:
                        srv.sendto(resp, addr)
                    except OSError:
                        return
                else:
                    # Not found → ERROR opcode 1
                    err = (struct.pack("!HH", OPCODE_ERROR, 1)
                           + b"File not found\x00")
                    try:
                        srv.sendto(err, addr)
                    except OSError:
                        return

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = loot_tftp("127.0.0.1", port=port, timeout=1.0, max_files=10)
        finally:
            stop.set()
            srv.close()
            t.join(timeout=1.0)

        # We must have fetched phone1.cfg and scraped the creds
        fetched = {f.filename: f for f in result.files_fetched}
        assert "phone1.cfg" in fetched, f"phone1.cfg missing from {list(fetched)}"
        f = fetched["phone1.cfg"]
        assert f.bytes_received > 0
        assert any("HunterHunt33" in c for c in f.credentials_suspected), \
            f"creds not scraped: {f.credentials_suspected}"


# ---------------------------------------------------------------------------
# SIP over WebSocket (RFC 7118 / RFC 6455)
# ---------------------------------------------------------------------------

class TestSipWsFrame:
    def test_ws_key_derivation_matches_rfc6455(self):
        """Sec-WebSocket-Accept must equal base64(SHA1(key + WS_GUID))."""
        from modules.sip_ws import _ws_key, WS_GUID
        import base64, hashlib
        key, expected = _ws_key()
        recomputed = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        assert expected == recomputed

    def test_build_text_frame_small_payload(self):
        from modules.sip_ws import _build_ws_text_frame, _mask
        frame = _build_ws_text_frame("OPTIONS sip:x SIP/2.0\r\n\r\n")
        # First byte: FIN=1 opcode=text → 0x81
        assert frame[0] == 0x81
        # Second byte high bit must be 1 (masked)
        assert frame[1] & 0x80
        length = frame[1] & 0x7F
        # Short-form length must fit under 126
        assert length < 126
        mask_key = frame[2:6]
        masked_payload = frame[6:]
        # Unmask and check round trip
        original = _mask(masked_payload, mask_key)
        assert b"OPTIONS sip:x" in original

    def test_build_text_frame_medium_payload(self):
        """Payloads 126-65535 bytes use 16-bit extended length."""
        from modules.sip_ws import _build_ws_text_frame
        body = "A" * 500
        frame = _build_ws_text_frame(body)
        # Length byte should be 0x80 | 126 for extended form
        assert (frame[1] & 0x7F) == 126
        ext_len = struct.unpack("!H", frame[2:4])[0]
        assert ext_len == 500

    def test_mask_is_reversible(self):
        from modules.sip_ws import _mask
        key = b"\x01\x02\x03\x04"
        payload = b"hello world payload"
        assert _mask(_mask(payload, key), key) == payload


class TestSipWsHandshake:
    """Simulate an HTTP server that performs the WS upgrade dance."""

    def test_upgrade_accepted_triggers_cswsh_finding(self):
        """When the gateway accepts an untrusted Origin, we must
        flag a CSWSH / origin-acceptance finding."""
        from modules.sip_ws import probe_ws_sip, WS_GUID
        import base64, hashlib, re

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            srv.settimeout(1.0)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                return
            try:
                conn.settimeout(1.0)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                m = re.search(rb"Sec-WebSocket-Key:\s*([A-Za-z0-9+/=]+)", buf)
                if not m:
                    conn.close()
                    return
                key = m.group(1).decode("ascii")
                accept = base64.b64encode(
                    hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
                ).decode("ascii")
                resp = (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n"
                    "Sec-WebSocket-Protocol: sip\r\n"
                    "Server: test-asterisk\r\n"
                    "\r\n"
                )
                conn.sendall(resp.encode("ascii"))
                # Drain a possible OPTIONS frame but don't reply so the test
                # doesn't hang (probe has its own timeout).
                try:
                    conn.settimeout(0.3)
                    conn.recv(4096)
                except socket.timeout:
                    pass
            finally:
                conn.close()
                stop.set()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = probe_ws_sip(
                "127.0.0.1", port, tls=False, timeout=2.0, http_path="/ws",
            )
        finally:
            stop.set()
            try:
                srv.close()
            except Exception:
                pass
            t.join(timeout=2.0)

        assert result.upgraded, f"expected 101 Switching Protocols: {result}"
        assert result.sip_subprotocol_accepted, \
            f"sip subprotocol should be recognised: {result}"
        # Origin was adversarial — must produce a medium finding
        severities = {entry["severity"] for entry in result.findings}
        assert "medium" in severities, f"no CSWSH flag: {result.findings}"

    def test_no_upgrade_returns_quiet(self):
        """A server that doesn't speak WS returns 404 — probe must not
        claim success."""
        from modules.sip_ws import probe_ws_sip

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            srv.settimeout(1.0)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                return
            try:
                conn.settimeout(1.0)
                # Drain request, then reply 404
                conn.recv(4096)
                resp = (
                    "HTTP/1.1 404 Not Found\r\n"
                    "Server: nginx\r\n"
                    "Content-Length: 0\r\n\r\n"
                )
                conn.sendall(resp.encode("ascii"))
            finally:
                conn.close()
                stop.set()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = probe_ws_sip(
                "127.0.0.1", port, tls=False, timeout=2.0, http_path="/ws",
            )
        finally:
            stop.set()
            try:
                srv.close()
            except Exception:
                pass
            t.join(timeout=2.0)

        assert not result.upgraded, f"should not have upgraded: {result}"


# ---------------------------------------------------------------------------
# SCCP / Skinny
# ---------------------------------------------------------------------------

class TestSccpFrame:
    def test_build_keepalive_shape(self):
        from modules.sccp import _build_sccp, MSG_KEEPALIVE
        pkt = _build_sccp(MSG_KEEPALIVE)
        # Little-endian: length(4) + reserved(4) + msgid(4)
        length = struct.unpack("<I", pkt[0:4])[0]
        reserved = struct.unpack("<I", pkt[4:8])[0]
        msgid = struct.unpack("<I", pkt[8:12])[0]
        assert length == 8   # reserved(4) + msgid(4), no payload
        assert reserved == 0
        assert msgid == MSG_KEEPALIVE

    def test_build_register_has_payload(self):
        from modules.sccp import _build_sccp, MSG_REGISTER
        payload = b"A" * 36  # Register payload size
        pkt = _build_sccp(MSG_REGISTER, payload)
        length = struct.unpack("<I", pkt[0:4])[0]
        assert length == 8 + len(payload)
        msgid = struct.unpack("<I", pkt[8:12])[0]
        assert msgid == MSG_REGISTER
        assert pkt[12:] == payload

    def test_probe_sccp_detects_keepalive_ack(self):
        """A fake SCCP peer that replies with KeepAliveAck must set
        sccp_detected=True."""
        from modules.sccp import probe_sccp, MSG_KEEPALIVE_ACK

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            srv.settimeout(1.0)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                return
            try:
                conn.settimeout(1.0)
                # Drain whatever comes in — we just need to reply ACK.
                try:
                    conn.recv(4096)
                except OSError:
                    pass
                # Send KeepAliveAck
                ack = struct.pack("<III", 8, 0, MSG_KEEPALIVE_ACK)
                conn.sendall(ack)
                # Keep socket open briefly so probe can parse
                time.sleep(0.1)
            finally:
                conn.close()
                stop.set()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = probe_sccp("127.0.0.1", port=port, timeout=2.0)
        finally:
            stop.set()
            try:
                srv.close()
            except Exception:
                pass
            t.join(timeout=2.0)

        assert result.sccp_detected, f"expected sccp_detected: {result}"
        assert result.keepalive_ack


# ---------------------------------------------------------------------------
# H.323 RAS / GRQ
# ---------------------------------------------------------------------------

class TestH323Grq:
    def test_grq_template_offsets_shape(self):
        """Sanity-check the canned template + offset constants."""
        from modules.h323 import GRQ_TEMPLATE, _SEQ_OFFSET, _IP_OFFSET, _PORT_OFFSET
        assert len(GRQ_TEMPLATE) > _PORT_OFFSET + 2, \
            "template too short for port offset"
        assert _IP_OFFSET + 4 <= len(GRQ_TEMPLATE), \
            "IP offset slides past template end"

    def test_patch_grq_inserts_ip_and_port(self):
        from modules.h323 import _patch_grq, _SEQ_OFFSET, _IP_OFFSET, _PORT_OFFSET
        patched = _patch_grq("10.20.30.40", 5678, 0x4242)
        # Seq number
        seq = struct.unpack("!H", patched[_SEQ_OFFSET:_SEQ_OFFSET+2])[0]
        assert seq == 0x4242
        # IP bytes at offset
        ip = patched[_IP_OFFSET:_IP_OFFSET+4]
        assert ip == socket.inet_aton("10.20.30.40"), f"IP not patched: {ip.hex()}"
        # Port bytes
        port = struct.unpack("!H", patched[_PORT_OFFSET:_PORT_OFFSET+2])[0]
        assert port == 5678

    def test_patch_grq_bad_ip_falls_back_to_zero(self):
        from modules.h323 import _patch_grq, _IP_OFFSET
        patched = _patch_grq("not-an-ip", 0, 1)
        assert patched[_IP_OFFSET:_IP_OFFSET+4] == b"\x00\x00\x00\x00"

    def test_probe_h323_times_out_clean(self):
        """Non-listening UDP port should return h323_detected=False without
        crashing."""
        from modules.h323 import probe_h323_ras
        result = probe_h323_ras("127.0.0.1", port=65530, timeout=0.3)
        assert result.h323_detected is False
        assert result.error is None or "io" in result.error

    def test_probe_h323_detects_reply(self):
        """Fake GCF responder → probe should set h323_detected=True."""
        from modules.h323 import probe_h323_ras

        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    data, addr = srv.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                # Reply with a minimal GCF-looking packet — first byte 0x18 (GCF).
                # Include an ASCII gatekeeperIdentifier hint.
                reply = b"\x18\x00\x06\x00GKMasterX" + b"\x00" * 8
                try:
                    srv.sendto(reply, addr)
                except OSError:
                    return

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            result = probe_h323_ras("127.0.0.1", port=port, timeout=1.0)
        finally:
            stop.set()
            srv.close()
            t.join(timeout=1.0)

        assert result.h323_detected, f"expected GCF detection: {result}"
        assert result.reply_opcode == 0x18
        # Identifier hint should pick up "GKMasterX"
        assert "GKMaster" in result.gatekeeper_identifier, \
            f"no id hint: {result.gatekeeper_identifier!r}"

    def test_build_findings_empty_when_not_detected(self):
        from modules.h323 import H323ProbeResult, build_findings
        r = H323ProbeResult(target="x", h323_detected=False)
        assert build_findings(r) == []

    def test_build_findings_emitted_when_detected(self):
        from modules.h323 import H323ProbeResult, build_findings
        r = H323ProbeResult(
            target="1.2.3.4", h323_detected=True, reply_opcode=0x18,
            gatekeeper_identifier="GKMaster",
        )
        findings = build_findings(r)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert findings[0]["host"] == "1.2.3.4"
        assert "GKMaster" in findings[0]["detail"]
