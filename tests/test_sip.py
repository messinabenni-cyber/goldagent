"""Unit tests for scanner.sip."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from scanner import sip


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------

class TestBuildMessage:
    def _common_kwargs(self):
        return dict(
            from_user="alice", to_user="bob",
            host="pbx.example.com", port=5060,
            local_ip="1.2.3.4", local_port=5062,
            call_id="abc@scanner", cseq=1, from_tag="abcd",
        )

    def test_options_basic(self):
        msg = sip.build_message(
            "OPTIONS", "sip:pbx.example.com", **self._common_kwargs()
        )
        text = msg.decode()
        assert text.startswith("OPTIONS sip:pbx.example.com SIP/2.0\r\n")
        assert "Via: SIP/2.0/UDP 1.2.3.4:5062" in text
        assert "From: <sip:alice@pbx.example.com>;tag=abcd" in text
        assert "Content-Length: 0" in text

    def test_invalid_port_raises(self):
        kwargs = self._common_kwargs()
        kwargs["port"] = 99999
        with pytest.raises(ValueError):
            sip.build_message("OPTIONS", "sip:x", **kwargs)

    def test_transport_token_selection(self):
        for transport, expected in [("udp", "SIP/2.0/UDP"),
                                     ("tcp", "SIP/2.0/TCP"),
                                     ("tls", "SIP/2.0/TLS")]:
            msg = sip.build_message(
                "OPTIONS", "sip:x", **self._common_kwargs(),
                transport=transport,
            ).decode()
            assert expected in msg


class TestIdentityHeaders:
    def _kwargs(self):
        return dict(
            from_user="u", to_user="x",
            host="p", port=5060, local_ip="1.2.3.4", local_port=0,
            call_id="c", cseq=1, from_tag="t",
        )

    def test_all_identity_headers_emitted(self):
        msg = sip.build_message(
            "INVITE", "sip:x@p", **self._kwargs(),
            pai="sip:+14155550100@example.com",
            diversion="sip:18005551234@pbx;reason=unconditional",
            privacy="id",
            remote_party_id="sip:alice@example.com",
            from_display="Alice Smith",
        ).decode()
        assert "P-Asserted-Identity:" in msg
        assert "+14155550100" in msg
        assert "Diversion:" in msg
        assert "unconditional" in msg
        assert "Privacy: id" in msg
        assert "Remote-Party-ID:" in msg
        assert '"Alice Smith"' in msg

    def test_from_display_escapes_quotes(self):
        msg = sip.build_message(
            "INVITE", "sip:x@p", **self._kwargs(),
            from_display='O"Brien',
        ).decode()
        from_line = [l for l in msg.split("\r\n") if l.startswith("From:")][0]
        # The embedded quote must be escaped → at most one logical display name
        assert r'\"' in from_line or from_line.count('"') == 2

    def test_from_display_escapes_backslash(self):
        msg = sip.build_message(
            "INVITE", "sip:x@p", **self._kwargs(),
            from_display=r"C:\Users",
        ).decode()
        from_line = [l for l in msg.split("\r\n") if l.startswith("From:")][0]
        assert r"\\" in from_line

    def test_crlf_injection_blocked_on_all_headers(self):
        for kw in ("pai", "diversion", "privacy", "remote_party_id",
                   "from_display"):
            with pytest.raises(ValueError):
                sip.build_message(
                    "INVITE", "sip:x@p", **self._kwargs(),
                    **{kw: "good\r\nX-Inject: evil"},
                )

    def test_privacy_token_validation(self):
        # Valid tokens pass
        sip.build_message("INVITE", "sip:x@p", **self._kwargs(),
                          privacy="id;header")
        # Invalid token raises
        with pytest.raises(ValueError, match="Invalid Privacy"):
            sip.build_message("INVITE", "sip:x@p", **self._kwargs(),
                              privacy="garbage")


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

class TestParseResponse:
    def test_401_with_auth_params(self):
        data = (
            b"SIP/2.0 401 Unauthorized\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4\r\n"
            b'WWW-Authenticate: Digest realm="pbx", nonce="abc123", algorithm=MD5\r\n'
            b"Content-Length: 0\r\n\r\n"
        )
        resp = sip.parse_response(data)
        assert resp is not None
        assert resp.status_code == 401
        assert resp.is_auth_required
        params = resp.auth_params
        assert params["realm"] == "pbx"
        assert params["nonce"] == "abc123"
        assert params["algorithm"] == "MD5"

    def test_garbage_returns_none(self):
        assert sip.parse_response(b"not a sip response") is None
        assert sip.parse_response(b"") is None


# ---------------------------------------------------------------------------
# Digest auth
# ---------------------------------------------------------------------------

class TestDigestAuth:
    def test_md5_basic(self):
        h = sip.build_auth_header(
            "user", "pass", "REGISTER", "sip:pbx",
            {"realm": "pbx", "nonce": "abc", "algorithm": "MD5"},
        )
        assert h.startswith("Authorization: Digest")
        assert 'username="user"' in h
        assert "algorithm=MD5" in h

    def test_sha256_supported(self):
        h = sip.build_auth_header(
            "user", "pass", "REGISTER", "sip:pbx",
            {"realm": "pbx", "nonce": "abc", "algorithm": "SHA-256"},
        )
        assert "SHA-256" in h
        # SHA-256 response should be 64 hex chars
        import re
        m = re.search(r'response="([0-9a-f]+)"', h)
        assert m and len(m.group(1)) == 64

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            sip.build_auth_header(
                "u", "p", "REGISTER", "sip:x",
                {"realm": "r", "nonce": "n", "algorithm": "GOST"},
            )

    def test_qop_auth_includes_nc_cnonce(self):
        h = sip.build_auth_header(
            "u", "p", "REGISTER", "sip:x",
            {"realm": "r", "nonce": "n", "qop": "auth", "algorithm": "MD5"},
        )
        assert "qop=auth" in h
        assert "nc=00000001" in h
        assert "cnonce=" in h
