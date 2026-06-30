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
