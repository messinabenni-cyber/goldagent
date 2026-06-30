"""Tests for scanner.rtp (SDP parsing)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSdpAnswer:
    def test_ipv4_basic(self):
        from scanner.rtp import parse_sdp_answer
        sdp = (
            "v=0\r\n"
            "c=IN IP4 10.0.0.1\r\n"
            "m=audio 20000 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        result = parse_sdp_answer(sdp)
        assert result is not None
        assert result.ip == "10.0.0.1"
        assert result.port == 20000
        assert result.codec == "PCMU"

    def test_ipv6_parses(self):
        from scanner.rtp import parse_sdp_answer
        sdp = (
            "v=0\r\n"
            "c=IN IP6 2001:db8::1\r\n"
            "m=audio 10000 RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        result = parse_sdp_answer(sdp)
        assert result is not None
        assert result.ip == "2001:db8::1"
        assert result.port == 10000

    def test_mixed_line_endings(self):
        from scanner.rtp import parse_sdp_answer
        sdp = (
            "v=0\n"
            "c=IN IP4 10.0.0.1\n"
            "m=audio 20000 RTP/AVP 0\n"
            "a=rtpmap:0 PCMU/8000\n"
        )
        result = parse_sdp_answer(sdp)
        assert result is not None
        assert result.port == 20000

    def test_empty_returns_none(self):
        from scanner.rtp import parse_sdp_answer
        assert parse_sdp_answer("") is None

    def test_no_media_returns_none(self):
        from scanner.rtp import parse_sdp_answer
        assert parse_sdp_answer("v=0\r\nc=IN IP4 10.0.0.1\r\n") is None
