"""Tests for scanner/http_probes.py — all network calls are mocked."""
from __future__ import annotations

import os
import socket
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import MagicMock, patch, call

import pytest

from scanner.http_probes import (
    HttpFinding,
    probe_freepbx_admin,
    probe_asterisk_rawman,
    probe_grandstream_ui,
    probe_3cx_admin,
    probe_version_extract,
    run_all,
    _http_get,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_http_response(status: int, server: str, body: bytes) -> tuple[int, str, bytes]:
    """Build the (status, server, body) tuple returned by _http_get/_http_post."""
    return (status, server, body)


def _body(text: str) -> bytes:
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# FreePBX admin probe
# ---------------------------------------------------------------------------

class TestProbeFreepbxAdmin:

    def test_probe_freepbx_admin_reachable(self):
        """HTTP 200 with 'freepbx' in body → HttpFinding returned."""
        response = _make_http_response(200, "Apache", _body("<html>FreePBX</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is not None
        assert isinstance(result, HttpFinding)
        assert result.name == "freepbx-admin-ui"
        assert result.severity == "high"

    def test_probe_freepbx_admin_version_extracted(self):
        """Server header containing 'freepbx' is captured in the evidence string."""
        response = _make_http_response(
            200, "FreePBX/16.0.19", _body("<html>admin panel</html>")
        )
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is not None
        # Evidence must include the server header value
        assert "FreePBX/16.0.19" in result.evidence

    def test_probe_freepbx_admin_unreachable(self):
        """Connection failure (status 0) → None returned, no exception raised."""
        response = _make_http_response(0, "", b"")
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is None

    def test_probe_freepbx_admin_wrong_port_skipped(self):
        """Port not in the allowed set → None without calling _http_get."""
        with patch("scanner.http_probes._http_get") as mock_get:
            result = probe_freepbx_admin("192.0.2.1", 9999, False)

        assert result is None
        mock_get.assert_not_called()

    def test_probe_freepbx_admin_200_no_signature_returns_none(self):
        """HTTP 200 but no FreePBX signature in body or server header → None."""
        response = _make_http_response(200, "nginx", _body("<html>Welcome</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is None


# ---------------------------------------------------------------------------
# Asterisk rawman probe
# ---------------------------------------------------------------------------

class TestProbeAsteriskRawman:

    def test_probe_asterisk_rawman_reachable(self):
        """Response body containing 'Response:' on port 8088 → HttpFinding."""
        response = _make_http_response(
            200, "Asterisk", _body("Response: Follows\r\nOutput: version 18\r\n")
        )
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_asterisk_rawman("192.0.2.1", 8088, False)

        assert result is not None
        assert result.name == "asterisk-rawman-exposed"
        assert result.severity == "high"

    def test_probe_asterisk_rawman_auth_required(self):
        """HTTP 401 with Asterisk Server header — endpoint is reachable, still a finding."""
        # status != 0 AND "Asterisk" in server → finding
        response = _make_http_response(401, "Asterisk/18.1", b"Unauthorized")
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_asterisk_rawman("192.0.2.1", 8088, False)

        assert result is not None
        assert result.name == "asterisk-rawman-exposed"

    def test_probe_asterisk_rawman_wrong_port_skipped(self):
        """Port not in (8088, 8089) → None without network call."""
        with patch("scanner.http_probes._http_get") as mock_get:
            result = probe_asterisk_rawman("192.0.2.1", 80, False)

        assert result is None
        mock_get.assert_not_called()

    def test_probe_asterisk_rawman_no_signature_returns_none(self):
        """HTTP 200 with generic body and no Asterisk server header → None."""
        response = _make_http_response(200, "nginx", _body("<html>nothing here</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_asterisk_rawman("192.0.2.1", 8088, False)

        assert result is None


# ---------------------------------------------------------------------------
# Grandstream web probe
# ---------------------------------------------------------------------------

class TestProbeGrandstreamWeb:

    def test_probe_grandstream_web_unreachable(self):
        """Status 0 on / → None (no finding for unreachable host)."""
        response = _make_http_response(0, "", b"")
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_grandstream_ui("192.0.2.5", 80, False)

        assert result is None

    def test_probe_grandstream_web_reachable_with_signature(self):
        """HTTP 200 with 'grandstream' keyword → HttpFinding."""
        response = _make_http_response(
            200, "mini_httpd", _body("<html>Grandstream UCM6300</html>")
        )
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_grandstream_ui("192.0.2.5", 80, False)

        assert result is not None
        assert result.name == "grandstream-admin-ui"
        assert result.severity == "high"

    def test_probe_grandstream_web_wrong_port_skipped(self):
        """Port not in allowed set → None without any network call."""
        with patch("scanner.http_probes._http_get") as mock_get:
            result = probe_grandstream_ui("192.0.2.5", 9090, False)

        assert result is None
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 3CX management probe
# ---------------------------------------------------------------------------

class TestProbe3cxManagement:

    def test_probe_3cx_management_reachable(self):
        """HTTP 200 with '3cx' keyword on /webclient/ → HttpFinding."""
        def _side_effect(host, port, path, timeout, use_tls):
            if path == "/webclient/":
                return _make_http_response(200, "3CXPhoneSystem", _body("<html>3CX</html>"))
            return _make_http_response(0, "", b"")

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_3cx_admin("192.0.2.10", 443, True)

        assert result is not None
        assert result.name == "3cx-admin-exposed"
        assert result.severity in ("high", "critical")

    def test_probe_3cx_unauthenticated_api_is_critical(self):
        """/api/v1/ path responding HTTP 200 → critical severity."""
        def _side_effect(host, port, path, timeout, use_tls):
            if path == "/webclient/":
                return _make_http_response(0, "", b"")
            if path == "/api/v1/Parameters/List":
                return _make_http_response(200, "", _body('{"params": []}'))
            return _make_http_response(0, "", b"")

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_3cx_admin("192.0.2.10", 443, True)

        assert result is not None
        assert result.severity == "critical"

    def test_probe_3cx_no_match_returns_none(self):
        """All paths unreachable (status 0) or no 3CX signature → None.

        The probe fires on any HTTP 200 from an /api/v1/ path (even without
        a 3CX keyword) because an open unauthenticated API is itself a signal.
        To get a genuine None we must make every path either status 0 or 404.
        """
        def _side_effect(host, port, path, timeout, use_tls):
            # Return HTTP 404 for everything — no 3CX keyword, no 200 on API
            return _make_http_response(404, "nginx", _body("<html>Not Found</html>"))

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_3cx_admin("192.0.2.10", 443, True)

        assert result is None

    def test_probe_3cx_wrong_port_skipped(self):
        """Port not in the 3CX allowed set → None without any network call."""
        with patch("scanner.http_probes._http_get") as mock_get:
            result = probe_3cx_admin("192.0.2.10", 9999, False)

        assert result is None
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Version disclosure in headers
# ---------------------------------------------------------------------------

class TestVersionDisclosureDetected:

    def test_version_disclosure_detected_in_headers(self):
        """Server header containing version string produces an info-level finding."""
        def _side_effect(host, port, path, timeout, use_tls):
            if path == "/":
                return _make_http_response(
                    200, "FreePBX/16.0.19.3",
                    _body("<html><title>PBX Login</title></html>")
                )
            return _make_http_response(0, "", b"")

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_version_extract("192.0.2.1", 80, False)

        assert result is not None
        assert result.name == "http-version-disclosure"
        assert result.severity == "info"
        assert "FreePBX/16.0.19.3" in result.evidence

    def test_version_disclosure_from_meta_generator(self):
        """meta[name=generator] version tag in HTML body → info finding."""
        html = '<html><meta name="generator" content="FreePBX 16.0.19.3"/></html>'
        def _side_effect(host, port, path, timeout, use_tls):
            if path == "/":
                return _make_http_response(200, "", _body(html))
            return _make_http_response(0, "", b"")

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_version_extract("192.0.2.1", 80, False)

        assert result is not None
        assert "FreePBX 16.0.19.3" in result.evidence

    def test_no_version_info_returns_none(self):
        """Completely generic response with no version indicators → None."""
        def _side_effect(host, port, path, timeout, use_tls):
            return _make_http_response(200, "", _body("<html><body>Hello</body></html>"))

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_version_extract("192.0.2.1", 80, False)

        assert result is None


# ---------------------------------------------------------------------------
# Error handling: timeout and SSL
# ---------------------------------------------------------------------------

class TestErrorHandling:

    def test_timeout_handled_gracefully(self):
        """socket.timeout raised during connect → (0, '', b'') returned by _http_get."""
        with patch("scanner.http_probes.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("timed out")
            mock_sock_cls.return_value = mock_sock

            status, server, body = _http_get("192.0.2.1", 80, "/", 1.0)

        assert status == 0
        assert server == ""
        assert body == b""

    def test_ssl_error_handled_gracefully(self):
        """ssl.SSLError raised during TLS wrap → (0, '', b'') returned, no exception."""
        with patch("scanner.http_probes.socket.socket") as mock_sock_cls, \
             patch("scanner.http_probes.ssl.create_default_context") as mock_ctx_fn:
            mock_sock = MagicMock()
            mock_sock.connect.return_value = None

            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.side_effect = ssl.SSLError("certificate verify failed")
            mock_ctx_fn.return_value = mock_ctx

            mock_sock_cls.return_value = mock_sock

            status, server, body = _http_get("192.0.2.1", 443, "/", 1.0, use_tls=True)

        assert status == 0
        assert server == ""
        assert body == b""

    def test_os_error_handled_gracefully(self):
        """OSError (e.g. connection refused) → (0, '', b'') without propagation."""
        with patch("scanner.http_probes.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("Connection refused")
            mock_sock_cls.return_value = mock_sock

            status, server, body = _http_get("192.0.2.1", 80, "/", 1.0)

        assert status == 0
        assert body == b""


# ---------------------------------------------------------------------------
# Redirect following
# ---------------------------------------------------------------------------

class TestRedirectFollowed:

    def test_redirect_followed_correctly(self):
        """HTTP 302 response is treated as a non-zero status — probe can act on it."""
        # probe_freepbx_admin looks for freepbx in body/server regardless of redirect
        response = _make_http_response(
            302, "FreePBX", _body("Redirecting to /admin/config.php")
        )
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        # A 302 with FreePBX in the Server header still triggers the finding
        assert result is not None
        assert result.name == "freepbx-admin-ui"

    def test_non_freepbx_redirect_returns_none(self):
        """HTTP 302 with no FreePBX signature → None."""
        response = _make_http_response(302, "nginx", _body("Moved Permanently"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is None


# ---------------------------------------------------------------------------
# Required fields on all HttpFinding results
# ---------------------------------------------------------------------------

class TestResultRequiredFields:

    _REQUIRED = ("name", "severity", "target", "title", "evidence", "remediation")

    def _assert_finding_fields(self, finding: HttpFinding) -> None:
        for field in self._REQUIRED:
            value = getattr(finding, field, None)
            assert value is not None and value != "", (
                f"HttpFinding.{field} is empty or missing"
            )

    def test_results_contain_required_fields_freepbx(self):
        """probe_freepbx_admin result has all required fields populated."""
        response = _make_http_response(200, "Apache", _body("<html>FreePBX</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is not None
        self._assert_finding_fields(result)

    def test_results_contain_required_fields_rawman(self):
        """probe_asterisk_rawman result has host, port (in target), severity, title, evidence."""
        response = _make_http_response(200, "Asterisk", _body("Response: Follows\r\n"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_asterisk_rawman("192.0.2.1", 8088, False)

        assert result is not None
        self._assert_finding_fields(result)
        # target encodes both host and port
        assert "192.0.2.1" in result.target
        assert "8088" in result.target

    def test_results_contain_required_fields_3cx(self):
        """probe_3cx_admin result has all required fields populated."""
        def _side_effect(host, port, path, timeout, use_tls):
            if path == "/webclient/":
                return _make_http_response(200, "", _body("<html>3CX</html>"))
            return _make_http_response(0, "", b"")

        with patch("scanner.http_probes._http_get", side_effect=_side_effect):
            result = probe_3cx_admin("192.0.2.10", 443, True)

        assert result is not None
        self._assert_finding_fields(result)

    def test_results_contain_required_fields_grandstream(self):
        """probe_grandstream_ui result carries all required fields."""
        response = _make_http_response(200, "", _body("<html>Grandstream GXP</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_grandstream_ui("192.0.2.5", 80, False)

        assert result is not None
        self._assert_finding_fields(result)

    def test_results_target_contains_host_and_port(self):
        """target field must be formatted as 'host:port'."""
        response = _make_http_response(200, "Apache", _body("<html>FreePBX</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("10.0.0.1", 443, True)

        assert result is not None
        assert result.target == "10.0.0.1:443"

    def test_results_severity_is_valid_value(self):
        """severity must be one of the defined values."""
        valid = {"critical", "high", "medium", "low", "info"}
        response = _make_http_response(200, "Apache", _body("<html>FreePBX</html>"))
        with patch("scanner.http_probes._http_get", return_value=response):
            result = probe_freepbx_admin("192.0.2.1", 80, False)

        assert result is not None
        assert result.severity in valid


# ---------------------------------------------------------------------------
# run_all integration (all sockets mocked)
# ---------------------------------------------------------------------------

class TestRunAll:

    def test_run_all_empty_ports_returns_empty(self):
        """run_all() with no ports returns an empty list immediately."""
        result = run_all("192.0.2.1", [])
        assert result == []

    def test_run_all_returns_list(self):
        """run_all() always returns a list even when all probes return None."""
        with patch("scanner.http_probes._http_get", return_value=(0, "", b"")), \
             patch("scanner.http_probes._http_post", return_value=(0, "", b"")):
            result = run_all("192.0.2.1", [80], timeout=0.1)

        assert isinstance(result, list)

    def test_run_all_deduplicates_findings(self):
        """run_all() returns at most one finding per (name, target) pair."""
        # Serve a FreePBX page on port 80 — multiple probes may match
        response = _make_http_response(200, "FreePBX/16", _body("<html>FreePBX</html>"))
        with patch("scanner.http_probes._http_get", return_value=response), \
             patch("scanner.http_probes._http_post", return_value=(0, "", b"")):
            result = run_all("192.0.2.1", [80], timeout=0.1)

        keys = [(f.name, f.target) for f in result]
        assert len(keys) == len(set(keys)), "Duplicate (name, target) pairs found"
