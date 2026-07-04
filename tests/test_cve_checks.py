"""Tests for check_all() and individual check_*() functions in scanner/cve.py."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock

import pytest

from scanner.cve import (
    CveResult,
    check_all,
    check_sip_version_disclosure,
    check_ami_no_tls,
    check_grandstream_cve_2021_37748,
    check_freepbx_cve_2019_19006,
    check_freepbx_cve_2021_45461,
    check_freepbx_path_traversal,
    check_freepbx_module_exposure,
    check_sip_tls_missing,
    check_3cx_admin_exposure,
    _version_lt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_socket_that_refuses():
    """Return a patch context that makes socket.connect raise OSError."""
    import socket as _socket
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = OSError("Connection refused")
    return mock_sock


# ---------------------------------------------------------------------------
# check_all() — routing and structure tests
# ---------------------------------------------------------------------------

class TestCheckAll:

    def test_check_all_empty_sip_returns_list(self):
        """check_all() with no SIP server and no open ports returns an empty list."""
        with patch("scanner.cve._http_get", return_value=(0, {}, "")), \
             patch("scanner.cve._http_post", return_value=(0, {}, "")), \
             patch("scanner.cve.socket.socket") as mock_sock_cls:
            # All socket connections fail
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("refused")
            mock_sock_cls.return_value = mock_sock

            results = check_all(
                host="192.0.2.1",
                tcp_ports=[],
                fingerprint="unknown",
                sip_server="",
                sip_port=5060,
                timeout=0.1,
            )

        assert isinstance(results, list)

    def test_check_all_freepbx_runs_asterisk_checks_only(self):
        """When fingerprint='FreePBX', Grandstream and 3CX checks are not run."""
        calls: list[str] = []

        def mock_get(host, port, path, *args, **kwargs):
            calls.append(path)
            return (0, {}, "")

        def mock_post(host, port, path, body, *args, **kwargs):
            calls.append(path)
            return (0, {}, "")

        with patch("scanner.cve._http_get", side_effect=mock_get), \
             patch("scanner.cve._http_post", side_effect=mock_post), \
             patch("scanner.cve.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("refused")
            mock_sock_cls.return_value = mock_sock

            check_all(
                host="192.0.2.1",
                tcp_ports=[80],
                fingerprint="FreePBX",
                sip_server="",
                sip_port=5060,
                timeout=0.1,
            )

        # FreePBX/Asterisk paths should have been probed
        freepbx_paths = [c for c in calls if "admin" in c or "recordings" in c or "epm" in c]
        assert len(freepbx_paths) > 0, "Expected FreePBX probes"

        # Grandstream-only paths should NOT have been probed
        grandstream_paths = [c for c in calls if "cgi-bin" in c]
        assert len(grandstream_paths) == 0, f"Unexpected Grandstream probes: {grandstream_paths}"

    def test_check_all_unknown_platform_runs_all_checks(self):
        """When fingerprint='unknown', checks for FreePBX, Grandstream, and 3CX all run."""
        calls: list[str] = []

        def mock_get(host, port, path, *args, **kwargs):
            calls.append(path)
            return (0, {}, "")

        def mock_post(host, port, path, body, *args, **kwargs):
            calls.append(path)
            return (0, {}, "")

        with patch("scanner.cve._http_get", side_effect=mock_get), \
             patch("scanner.cve._http_post", side_effect=mock_post), \
             patch("scanner.cve.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("refused")
            mock_sock_cls.return_value = mock_sock

            check_all(
                host="192.0.2.1",
                tcp_ports=[80],
                fingerprint="unknown",
                sip_server="",
                sip_port=5060,
                timeout=0.1,
            )

        # Both FreePBX and Grandstream paths probed
        has_fpbx = any("admin" in c for c in calls)
        has_gs = any("cgi-bin" in c for c in calls)
        has_3cx = any("webclient" in c or "api/v1" in c for c in calls)

        assert has_fpbx, f"Expected FreePBX probes; got: {calls}"
        assert has_gs, f"Expected Grandstream probes; got: {calls}"
        assert has_3cx, f"Expected 3CX probes; got: {calls}"

    def test_no_duplicate_findings_from_check_all(self):
        """check_all() deduplicates findings with the same (cve_id, host, port) key."""
        # Use a SIP server that produces a version finding
        with patch("scanner.cve._http_get", return_value=(0, {}, "")), \
             patch("scanner.cve._http_post", return_value=(0, {}, "")), \
             patch("scanner.cve.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("refused")
            mock_sock_cls.return_value = mock_sock

            results = check_all(
                host="192.0.2.1",
                tcp_ports=[5060],
                fingerprint="FreePBX",
                sip_server="FreePBX/15.0.17.0",
                sip_port=5060,
                timeout=0.1,
            )

        keys = [(r.cve_id, r.host, r.port) for r in results]
        assert len(keys) == len(set(keys)), "Duplicate (cve_id, host, port) found"


# ---------------------------------------------------------------------------
# check_sip_version_disclosure — CVE-2022-2347 version tests
# ---------------------------------------------------------------------------

class TestCheckCVE20222347:

    def test_check_cve_2022_2347_vulnerable_version(self):
        """FreePBX 16.0.18.0 is below 16.0.19.9 — should produce CVE-2022-2347 finding."""
        results = check_sip_version_disclosure(
            host="192.0.2.10",
            sip_port=5060,
            sip_server="FreePBX/16.0.18.0",
        )
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2022-2347" in cve_ids

    def test_check_cve_2022_2347_not_16x(self):
        """FreePBX 15.0.17.0 is not 16.x — CVE-2022-2347 is 16.x-specific, should NOT trigger."""
        results = check_sip_version_disclosure(
            host="192.0.2.10",
            sip_port=5060,
            sip_server="FreePBX/15.0.17.0",
        )
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2022-2347" not in cve_ids

    def test_check_cve_2022_2347_patched_version(self):
        """FreePBX 16.0.20.0 is above 16.0.19.9 — should NOT produce CVE-2022-2347 finding."""
        results = check_sip_version_disclosure(
            host="192.0.2.10",
            sip_port=5060,
            sip_server="FreePBX/16.0.20.0",
        )
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2022-2347" not in cve_ids

    def test_check_cve_2022_2347_no_version_returns_empty(self):
        """No SIP server string → empty results from check_sip_version_disclosure."""
        results = check_sip_version_disclosure(
            host="192.0.2.10",
            sip_port=5060,
            sip_server="",
        )
        assert results == []

    def test_version_below_boundary_detected(self):
        """Version just below patch boundary (16.0.19.8) is still flagged."""
        results = check_sip_version_disclosure(
            host="192.0.2.10",
            sip_port=5060,
            sip_server="FreePBX/16.0.19.8",
        )
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2022-2347" in cve_ids

    def test_version_above_boundary_not_detected(self):
        """Version exactly at patch boundary (16.0.19.9) is NOT flagged."""
        results = check_sip_version_disclosure(
            host="192.0.2.10",
            sip_port=5060,
            sip_server="FreePBX/16.0.19.9",
        )
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2022-2347" not in cve_ids


# ---------------------------------------------------------------------------
# check_sip_tls_missing — CONFIG-SIP-TLS
# ---------------------------------------------------------------------------

class TestCheckSipCleartextUDP:

    def test_check_sip_cleartext_udp_returns_finding(self):
        """SIP on UDP/5060 with no TLS on 5061 → CONFIG-SIP-TLS finding."""
        with patch("scanner.cve.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("refused")
            mock_sock_cls.return_value = mock_sock

            result = check_sip_tls_missing(
                host="192.0.2.10",
                sip_port=5060,
                tcp_ports=[],  # 5061 not in list, socket probe will also fail
                timeout=0.1,
            )

        assert result is not None
        assert result.cve_id == "CONFIG-SIP-TLS"
        assert result.severity == "high"

    def test_check_sip_cleartext_tls_returns_empty(self):
        """When 5061 is in tcp_ports, TLS is available — no finding."""
        result = check_sip_tls_missing(
            host="192.0.2.10",
            sip_port=5060,
            tcp_ports=[5060, 5061],  # 5061 is open → TLS available
            timeout=0.1,
        )
        assert result is None


# ---------------------------------------------------------------------------
# check_ami_no_tls — CONFIG-AMI-NO-TLS with mocked socket
# ---------------------------------------------------------------------------

class TestCheckAMIExposed:

    def test_check_ami_exposed_patches_via_mock_socket(self):
        """Mocked socket returning AMI banner → high-severity CONFIG-AMI-NO-TLS finding."""
        ami_banner = b"Asterisk Call Manager/2.10.4\r\n"

        with patch("scanner.cve.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = ami_banner
            mock_sock_cls.return_value = mock_sock

            result = check_ami_no_tls(
                host="192.0.2.10",
                tcp_ports=[5038],
                timeout=1.0,
            )

        assert result is not None
        assert result.cve_id == "CONFIG-AMI-NO-TLS"
        assert result.severity == "high"
        assert result.port == 5038

    def test_ami_not_in_tcp_ports_returns_none(self):
        """If 5038 is not in tcp_ports, the check is skipped entirely."""
        with patch("scanner.cve.socket.socket") as mock_sock_cls:
            result = check_ami_no_tls(
                host="192.0.2.10",
                tcp_ports=[80, 443],
                timeout=1.0,
            )
        # socket should never have been touched
        mock_sock_cls.assert_not_called()
        assert result is None

    def test_ami_non_asterisk_banner_returns_none(self):
        """Banner not containing 'asterisk' must not produce a finding."""
        with patch("scanner.cve.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.4\r\n"
            mock_sock_cls.return_value = mock_sock

            result = check_ami_no_tls(
                host="192.0.2.10",
                tcp_ports=[5038],
                timeout=1.0,
            )

        assert result is None


# ---------------------------------------------------------------------------
# check_grandstream_cve_2021_37748 — version-based Grandstream check
# ---------------------------------------------------------------------------

class TestCheckGrandstreamVersion:

    def test_check_grandstream_version_vulnerable(self):
        """HTTP 200 with SIP config keywords → CVE-2021-37748 critical finding."""
        body = 'sippassword=secret123\nextension=1001\ncodec=PCMU\n'
        with patch("scanner.cve._http_get", return_value=(200, {}, body)):
            result = check_grandstream_cve_2021_37748("192.0.2.20", 80)

        assert result is not None
        assert result.cve_id == "CVE-2021-37748"
        assert result.severity == "critical"

    def test_grandstream_no_sip_keywords_returns_none(self):
        """HTTP 200 but no SIP config keywords → no finding."""
        body = "<html><body>403 Forbidden</body></html>"
        with patch("scanner.cve._http_get", return_value=(200, {}, body)):
            result = check_grandstream_cve_2021_37748("192.0.2.20", 80)

        assert result is None

    def test_grandstream_non_200_returns_none(self):
        """Non-200 response → no finding."""
        with patch("scanner.cve._http_get", return_value=(403, {}, "Forbidden")):
            result = check_grandstream_cve_2021_37748("192.0.2.20", 80)

        assert result is None

    def test_grandstream_connection_failure_returns_none(self):
        """Connection failure (status 0) → no finding."""
        with patch("scanner.cve._http_get", return_value=(0, {}, "")):
            result = check_grandstream_cve_2021_37748("192.0.2.20", 80)

        assert result is None


# ---------------------------------------------------------------------------
# CveResult field validation
# ---------------------------------------------------------------------------

class TestCveResultFields:

    def test_cve_result_has_required_fields(self):
        """Every CveResult produced by a check must carry cve_id, severity,
        host, port, title, evidence, and remediation."""
        body = 'sippassword=secret123\nextension=1001\n'
        with patch("scanner.cve._http_get", return_value=(200, {}, body)):
            result = check_grandstream_cve_2021_37748("192.0.2.20", 80)

        assert result is not None
        required_fields = ("cve_id", "severity", "host", "port", "title", "evidence", "remediation")
        for field in required_fields:
            value = getattr(result, field, None)
            assert value is not None and value != "", (
                f"CveResult.{field} is empty or missing"
            )

    def test_cve_result_host_and_port_match_call(self):
        """host and port on the result must equal the arguments passed."""
        body = 'sippassword=topsecret\n'
        with patch("scanner.cve._http_get", return_value=(200, {}, body)):
            result = check_grandstream_cve_2021_37748("10.1.2.3", 8080)

        assert result is not None
        assert result.host == "10.1.2.3"
        assert result.port == 8080

    def test_freepbx_result_has_required_fields(self):
        """FreePBX CVE-2019-19006 result also carries all required fields."""
        body = '{"id": 1, "username": "admin", "email": "admin@example.com"}'
        with patch("scanner.cve._http_get", return_value=(200, {}, body)):
            result = check_freepbx_cve_2019_19006("10.0.0.1", 80)

        assert result is not None
        for field in ("cve_id", "severity", "host", "port", "title", "evidence", "remediation"):
            assert getattr(result, field, None) not in (None, ""), f"Missing field: {field}"


# ---------------------------------------------------------------------------
# _version_lt helper — boundary tests
# ---------------------------------------------------------------------------

class TestVersionLt:

    def test_version_lt_older_is_lt(self):
        assert _version_lt("15.0.17.0", "16.0.19.9") is True

    def test_version_lt_newer_is_not_lt(self):
        assert _version_lt("16.0.20.0", "16.0.19.9") is False

    def test_version_lt_equal_is_not_lt(self):
        assert _version_lt("16.0.19.9", "16.0.19.9") is False

    def test_version_lt_just_below_patch(self):
        assert _version_lt("16.0.19.8", "16.0.19.9") is True

    def test_version_lt_invalid_returns_false(self):
        assert _version_lt("not-a-version", "16.0.19.9") is False

    def test_version_lt_shorter_tuple_padded(self):
        # "16.0" should be treated as "16.0.0.0" < "16.0.19.9"
        assert _version_lt("16.0", "16.0.19.9") is True
