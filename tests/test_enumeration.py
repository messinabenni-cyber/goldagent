"""Tests for scanner.enumeration — all probe calls mocked, no real network."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock

import pytest

from scanner import enumeration
from scanner.enumeration import (
    ExtensionResult,
    _classify,
    probe,
    sweep,
)
from tests.mock_pbx import MockPbx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sip_response(status_code: int, reason: str, extra_headers: str = "") -> bytes:
    """Construct a minimal valid SIP response byte string."""
    headers = (
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n"
        "From: <sip:1000@127.0.0.1>;tag=abc123\r\n"
        "To: <sip:1000@127.0.0.1>\r\n"
        "Call-ID: test-call-id@127.0.0.1\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"{extra_headers}"
        "Content-Length: 0\r\n"
    )
    return f"SIP/2.0 {status_code} {reason}\r\n{headers}\r\n".encode()


# ---------------------------------------------------------------------------
# test_enumerate_extension_found_200
# ---------------------------------------------------------------------------

class TestEnumerateExtensionFound200:
    """A 200 OK to REGISTER means open registration — extension exists."""

    def test_enumerate_extension_found_200(self):
        pbx = MockPbx(responses={
            "REGISTER": ("200 OK", ""),
        })
        pbx.start()
        try:
            r = probe(pbx.host, "1001", port=pbx.port,
                      local_ip="127.0.0.1", timeout=1.0, retries=0)
            assert r.exists
            assert r.open_register
            assert not r.auth_required
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# test_enumerate_extension_not_found_404
# ---------------------------------------------------------------------------

class TestEnumerateExtensionNotFound404:
    """A 404 Not Found response means the extension does not exist."""

    def test_enumerate_extension_not_found_404(self):
        pbx = MockPbx(responses={
            "REGISTER": ("404 Not Found", ""),
        })
        pbx.start()
        try:
            r = probe(pbx.host, "9999", port=pbx.port,
                      local_ip="127.0.0.1", timeout=1.0, retries=0)
            assert not r.exists
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# test_enumerate_extension_forbidden_403 (lockout detection)
# ---------------------------------------------------------------------------

class TestEnumerateExtensionForbidden403:
    """403 Forbidden is treated as exists + auth_required (lockout indicator)."""

    def test_enumerate_extension_forbidden_403(self):
        pbx = MockPbx(responses={
            "REGISTER": ("403 Forbidden", ""),
        })
        pbx.start()
        try:
            r = probe(pbx.host, "1001", port=pbx.port,
                      local_ip="127.0.0.1", timeout=1.0, retries=0)
            assert r.exists
            assert r.auth_required
            assert "forbidden" in r.evidence.lower()
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# test_enumerate_range_returns_found_only
# ---------------------------------------------------------------------------

class TestEnumerateRangeReturnsFoundOnly:
    """sweep() must return only extensions where exists=True."""

    def test_enumerate_range_returns_found_only(self):
        # 1000 -> 401 (exists), 1001 -> 404 (not found), 1002 -> 401 (exists)
        call_map = {
            "1000": ExtensionResult("1000", exists=True, auth_required=True,
                                    evidence="REGISTER -> 401 Unauthorized"),
            "1001": ExtensionResult("1001", exists=False,
                                    evidence="REGISTER -> 404 Not Found"),
            "1002": ExtensionResult("1002", exists=True, auth_required=True,
                                    evidence="REGISTER -> 401 Unauthorized"),
        }

        def fake_probe(host, ext, **kwargs):
            return call_map[ext]

        with patch.object(enumeration, "probe", side_effect=fake_probe):
            results = sweep("127.0.0.1", ["1000", "1001", "1002"],
                            max_workers=1)

        found_exts = {r.extension for r in results}
        assert found_exts == {"1000", "1002"}
        assert all(r.exists for r in results)
        assert not any(r.extension == "1001" for r in results)


# ---------------------------------------------------------------------------
# test_enumerate_range_respects_max_extensions
# ---------------------------------------------------------------------------

class TestEnumerateRangeRespectsMaxExtensions:
    """The _MAX_RANGE cap in expand_ext_range prevents runaway sweeps."""

    def test_enumerate_range_respects_max_extensions(self):
        from scanner.enumeration import expand_ext_range, _MAX_RANGE

        # Exactly at the limit — must succeed
        at_limit = expand_ext_range(f"0-{_MAX_RANGE - 1}")
        assert len(at_limit) == _MAX_RANGE

        # One beyond the limit — must raise
        with pytest.raises(ValueError, match="entries"):
            expand_ext_range(f"0-{_MAX_RANGE}")


# ---------------------------------------------------------------------------
# test_enumerate_timeout_continues_gracefully
# ---------------------------------------------------------------------------

class TestEnumerateTimeoutContinuesGracefully:
    """A timeout (no response) must not crash — extension marked as not found."""

    def test_enumerate_timeout_continues_gracefully(self):
        # Simulate send_and_recv returning None (timeout / no data)
        with patch("scanner.sip.send_and_recv", return_value=None), \
             patch("scanner.sip.send_and_recv_tcp", return_value=None):
            r = probe("127.0.0.1", "1000", port=5060,
                      local_ip="127.0.0.1", timeout=0.01, retries=0)

        assert not r.exists
        assert "no response" in r.evidence


# ---------------------------------------------------------------------------
# test_enumerate_extracts_display_name_from_200
# ---------------------------------------------------------------------------

class TestEnumerateExtractsDisplayNameFrom200:
    """200 OK response evidence string captures the status line."""

    def test_enumerate_extracts_display_name_from_200(self):
        pbx = MockPbx(responses={
            "REGISTER": ("200 OK", ""),
        })
        pbx.start()
        try:
            r = probe(pbx.host, "1001", port=pbx.port,
                      local_ip="127.0.0.1", timeout=1.0, retries=0)
            assert r.exists
            # The _classify helper stores "METHOD -> CODE REASON" in evidence
            assert "200" in r.evidence
            assert "OK" in r.evidence
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# test_enumerate_anonymous_register_detection
# ---------------------------------------------------------------------------

class TestEnumerateAnonymousRegisterDetection:
    """200 OK to REGISTER without prior auth means open_register=True."""

    def test_enumerate_anonymous_register_detection(self):
        from scanner.sip import SipResponse

        fake_resp = SipResponse(
            status_code=200,
            reason="OK",
            headers={},
            body="",
            raw=b"",
        )

        with patch("scanner.sip.send_and_recv",
                   return_value=_make_sip_response(200, "OK")):
            r = probe("127.0.0.1", "1001", port=5060,
                      local_ip="127.0.0.1", timeout=1.0, retries=0,
                      method="REGISTER")

        assert r.exists
        assert r.open_register
        assert not r.anonymous_invite


# ---------------------------------------------------------------------------
# test_enumerate_open_register_detection (no auth = open registration)
# ---------------------------------------------------------------------------

class TestEnumerateOpenRegisterDetection:
    """A 200 to REGISTER with no prior 401 challenge flags open_register."""

    def test_enumerate_open_register_detection(self):
        pbx = MockPbx(responses={
            "REGISTER": ("200 OK", ""),
        })
        pbx.start()
        try:
            r = probe(pbx.host, "1000", port=pbx.port,
                      local_ip="127.0.0.1", timeout=1.0, retries=0,
                      method="REGISTER")
            assert r.exists
            assert r.open_register
            assert not r.auth_required
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# test_malformed_response_does_not_crash
# ---------------------------------------------------------------------------

class TestMalformedResponseDoesNotCrash:
    """Garbage bytes returned by the network must not crash probe()."""

    def test_malformed_response_does_not_crash(self):
        garbage = b"\x00\x01\x02\x03 not a SIP response at all \xff\xfe"

        with patch("scanner.sip.send_and_recv", return_value=garbage):
            r = probe("127.0.0.1", "1000", port=5060,
                      local_ip="127.0.0.1", timeout=1.0, retries=0)

        # parse_response returns None for garbage — probe marks as not found
        assert not r.exists
        assert "unparseable" in r.evidence


# ---------------------------------------------------------------------------
# test_empty_extension_range_returns_empty
# ---------------------------------------------------------------------------

class TestEmptyExtensionRangeReturnsEmpty:
    """sweep() over an empty list must return an empty list without error."""

    def test_empty_extension_range_returns_empty(self):
        results = sweep("127.0.0.1", [], max_workers=4, timeout=1.0)
        assert results == []
