"""Unit tests for scanner.sip — parse_request, build_response_to_request, parse_contact_uri."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from scanner.sip import (
    SipRequest,
    build_response_to_request,
    parse_contact_uri,
    parse_request,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(method: str, uri: str = "sip:pbx.example.com",
                  extra_headers: str = "") -> bytes:
    base = (
        f"{method} {uri} SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-abc\r\n"
        "From: <sip:alice@pbx.example.com>;tag=fromtag\r\n"
        "To: <sip:bob@pbx.example.com>\r\n"
        "Call-ID: test-call-id@scanner\r\n"
        f"CSeq: 1 {method}\r\n"
        "Content-Length: 0\r\n"
    )
    if extra_headers:
        base += extra_headers + "\r\n"
    base += "\r\n"
    return base.encode()


# ---------------------------------------------------------------------------
# parse_request
# ---------------------------------------------------------------------------

class TestParseRequest:
    def test_parse_request_options(self):
        data = _make_request("OPTIONS")
        req = parse_request(data)
        assert req is not None
        assert req.method == "OPTIONS"
        assert req.request_uri == "sip:pbx.example.com"

    def test_parse_request_bye(self):
        data = _make_request("BYE", uri="sip:alice@pbx.example.com")
        req = parse_request(data)
        assert req is not None
        assert req.method == "BYE"

    def test_parse_request_invite(self):
        data = _make_request("INVITE", uri="sip:1000@pbx.example.com")
        req = parse_request(data)
        assert req is not None
        assert req.method == "INVITE"
        assert req.request_uri == "sip:1000@pbx.example.com"

    def test_parse_request_reinvite(self):
        # A re-INVITE has the same method but carries a to-tag
        data = (
            b"INVITE sip:1000@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-reinvite\r\n"
            b"From: <sip:alice@pbx.example.com>;tag=fromtag\r\n"
            b"To: <sip:bob@pbx.example.com>;tag=totag\r\n"
            b"Call-ID: reinvite-call-id@scanner\r\n"
            b"CSeq: 2 INVITE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        assert req is not None
        assert req.method == "INVITE"
        assert "totag" in req.to_header

    def test_parse_request_malformed_returns_none(self):
        data = b"THIS IS NOT SIP\r\n\r\n"
        assert parse_request(data) is None

    def test_parse_request_sip_response_returns_none(self):
        # A SIP response line (SIP/2.0 200 OK) must NOT be parsed as a request
        data = (
            b"SIP/2.0 200 OK\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        assert parse_request(data) is None


# ---------------------------------------------------------------------------
# build_response_to_request
# ---------------------------------------------------------------------------

class TestBuildResponseToRequest:
    def _make_req(self, method: str = "OPTIONS") -> SipRequest:
        data = _make_request(method)
        req = parse_request(data)
        assert req is not None
        return req

    def test_build_response_reflects_via(self):
        req = self._make_req()
        resp_bytes = build_response_to_request(200, "OK", req)
        resp_text = resp_bytes.decode()
        assert "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-abc" in resp_text

    def test_build_response_reflects_callid(self):
        req = self._make_req()
        resp_bytes = build_response_to_request(200, "OK", req)
        resp_text = resp_bytes.decode()
        assert "Call-ID: test-call-id@scanner" in resp_text

    def test_build_response_reflects_cseq(self):
        req = self._make_req()
        resp_bytes = build_response_to_request(200, "OK", req)
        resp_text = resp_bytes.decode()
        assert "CSeq: 1 OPTIONS" in resp_text

    def test_build_response_adds_to_tag(self):
        req = self._make_req()
        resp_bytes = build_response_to_request(200, "OK", req, to_tag="server-tag-xyz")
        resp_text = resp_bytes.decode()
        to_line = next(l for l in resp_text.split("\r\n") if l.startswith("To:"))
        assert "tag=server-tag-xyz" in to_line


# ---------------------------------------------------------------------------
# parse_contact_uri
# ---------------------------------------------------------------------------

class TestParseContactUri:
    def test_parse_contact_uri_with_port(self):
        headers = {"contact": "<sip:192.168.1.50:5080>"}
        result = parse_contact_uri(headers)
        assert result == ("192.168.1.50", 5080)

    def test_parse_contact_uri_without_port_defaults_5060(self):
        # The function only defaults to 5060 when there is a user@host pattern
        headers = {"contact": "<sip:pbx@192.168.1.50>"}
        result = parse_contact_uri(headers)
        assert result == ("192.168.1.50", 5060)

    def test_parse_contact_uri_with_user_at_host(self):
        headers = {"contact": "<sip:alice@pbx.example.com:5090>"}
        result = parse_contact_uri(headers)
        assert result == ("pbx.example.com", 5090)

    def test_parse_contact_uri_empty_returns_none(self):
        headers = {"contact": ""}
        assert parse_contact_uri(headers) is None
