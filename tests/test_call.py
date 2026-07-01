"""Tests for scanner.call (toll-fraud PoC)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


class TestCallResultStructure:
    def test_404_response(self):
        from scanner.call import place_call, CallResult
        from tests.mock_pbx import MockPbx
        pbx = MockPbx(responses={"INVITE": ("404 Not Found", "")})
        pbx.start()
        try:
            result = place_call(
                pbx.host, "99999", "1000",
                port=pbx.port, timeout=1.0, max_wait=2.0,
            )
            assert isinstance(result, CallResult)
            assert result.status_code == 404
            assert result.success is False
            assert result.reached_dialplan is False
            assert result.srtp_state == "off"
            assert result.dtmf_digits_sent == []
        finally:
            pbx.stop()

    def test_dry_run_on_180_succeeds(self):
        from scanner.call import place_call
        from tests.mock_pbx import MockPbx
        pbx = MockPbx(responses={"INVITE": ("180 Ringing", "")})
        pbx.start()
        try:
            result = place_call(
                pbx.host, "9000", "1000",
                port=pbx.port, timeout=1.0, max_wait=2.0,
                dry_run=True,
            )
            assert result.reached_dialplan is True
            assert result.success is True
            assert result.status_code == 180
        finally:
            pbx.stop()


class TestSdp:
    def test_sdp_has_pcmu(self):
        from scanner.call import _build_sdp
        sdp = _build_sdp("10.0.0.1")
        assert "m=audio" in sdp
        assert "RTP/AVP" in sdp
        assert "PCMU/8000" in sdp

    def test_sdp_with_srtp_uses_savp(self):
        from scanner.call import _build_sdp
        sdp = _build_sdp("10.0.0.1", srtp_offer="a=crypto:1 SUITE inline:KEY")
        assert "RTP/SAVP" in sdp
        assert "a=crypto:" in sdp


class TestDtmf:
    def test_duration_clamped_high(self):
        from scanner.dtmf import build_info_dtmf_body
        body = build_info_dtmf_body("5", duration_ms=999999)
        assert "Duration=10000" in body

    def test_duration_replaced_low(self):
        from scanner.dtmf import build_info_dtmf_body
        body = build_info_dtmf_body("5", duration_ms=1)
        assert "Duration=160" in body

    def test_valid_duration_passes(self):
        from scanner.dtmf import build_info_dtmf_body
        body = build_info_dtmf_body("5", duration_ms=200)
        assert "Duration=200" in body

    def test_unsupported_digit_raises(self):
        from scanner.dtmf import build_info_dtmf_body
        with pytest.raises(ValueError):
            build_info_dtmf_body("Z")


class TestReferBlindTransfer:
    def _make_response_bytes(self, status: str) -> bytes:
        return (
            f"SIP/2.0 {status}\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()

    def test_202_accepted_is_vulnerable(self, monkeypatch):
        from scanner.call import test_refer_blind_transfer
        from tests.mock_pbx import MockPbx

        pbx = MockPbx(responses={
            "INVITE": ("100 Trying", ""),
            "REFER": ("202 Accepted", ""),
        })
        pbx.start()
        try:
            result = test_refer_blind_transfer(
                pbx.host, "1000", "+442071234567",
                port=pbx.port, timeout=1.5,
            )
            assert result["is_vulnerable"] is True
            assert result["status_code"] == 202
            assert "202" in result["evidence"]
            assert "IRSF" in result["evidence"] or "toll-fraud" in result["evidence"]
        finally:
            pbx.stop()

    def test_403_forbidden_not_vulnerable(self, monkeypatch):
        from scanner.call import test_refer_blind_transfer
        from tests.mock_pbx import MockPbx

        pbx = MockPbx(responses={
            "INVITE": ("100 Trying", ""),
            "REFER": ("403 Forbidden", ""),
        })
        pbx.start()
        try:
            result = test_refer_blind_transfer(
                pbx.host, "1000", "+442071234567",
                port=pbx.port, timeout=1.5,
            )
            assert result["is_vulnerable"] is False
            assert result["status_code"] == 403
            assert "403" in result["evidence"]
        finally:
            pbx.stop()

    def test_timeout_returns_not_vulnerable(self):
        from scanner.call import test_refer_blind_transfer
        result = test_refer_blind_transfer(
            "127.0.0.1", "1000", "+442071234567",
            port=19999, timeout=0.2,
        )
        assert result["is_vulnerable"] is False
        assert result["status_code"] is None
