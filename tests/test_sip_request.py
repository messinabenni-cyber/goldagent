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


def _parse_headers(raw: bytes) -> dict[str, str]:
    """Parse header section of a raw SIP message into a dict."""
    head = raw.split(b"\r\n\r\n")[0].decode()
    headers: dict[str, str] = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


# ---------------------------------------------------------------------------
# parse_request — per-method correctness
# ---------------------------------------------------------------------------

class TestParseRequestOptions:
    def test_method_is_options(self):
        req = parse_request(_make_request("OPTIONS"))
        assert req is not None
        assert req.method == "OPTIONS"

    def test_request_uri(self):
        req = parse_request(_make_request("OPTIONS", uri="sip:pbx.example.com"))
        assert req.request_uri == "sip:pbx.example.com"

    def test_call_id_property(self):
        req = parse_request(_make_request("OPTIONS"))
        assert req.call_id == "test-call-id@scanner"

    def test_from_header_property(self):
        req = parse_request(_make_request("OPTIONS"))
        assert "alice" in req.from_header

    def test_to_header_property(self):
        req = parse_request(_make_request("OPTIONS"))
        assert "bob" in req.to_header

    def test_cseq_property(self):
        req = parse_request(_make_request("OPTIONS"))
        assert "OPTIONS" in req.cseq

    def test_via_property(self):
        req = parse_request(_make_request("OPTIONS"))
        assert "z9hG4bK-abc" in req.via

    def test_body_empty(self):
        req = parse_request(_make_request("OPTIONS"))
        assert req.body == ""

    def test_raw_preserved(self):
        data = _make_request("OPTIONS")
        req = parse_request(data)
        assert req.raw == data


class TestParseRequestBye:
    def test_method_is_bye(self):
        req = parse_request(_make_request("BYE", uri="sip:alice@pbx.example.com"))
        assert req is not None
        assert req.method == "BYE"

    def test_uri_parsed(self):
        req = parse_request(_make_request("BYE", uri="sip:alice@pbx.example.com"))
        assert req.request_uri == "sip:alice@pbx.example.com"

    def test_bye_with_to_tag(self):
        data = (
            b"BYE sip:alice@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-bye\r\n"
            b"From: <sip:bob@pbx.example.com>;tag=btag\r\n"
            b"To: <sip:alice@pbx.example.com>;tag=atag\r\n"
            b"Call-ID: bye-test@scanner\r\n"
            b"CSeq: 2 BYE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        assert req is not None
        assert req.method == "BYE"
        assert "atag" in req.to_header


class TestParseRequestInvite:
    def test_method_is_invite(self):
        req = parse_request(_make_request("INVITE", uri="sip:1000@pbx.example.com"))
        assert req is not None
        assert req.method == "INVITE"

    def test_uri_with_user(self):
        req = parse_request(_make_request("INVITE", uri="sip:1000@pbx.example.com"))
        assert req.request_uri == "sip:1000@pbx.example.com"

    def test_invite_with_sdp_body(self):
        sdp = "v=0\r\no=alice 123 456 IN IP4 1.2.3.4\r\ns=Session\r\n"
        data = (
            f"INVITE sip:1000@pbx.example.com SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-inv\r\n"
            f"From: <sip:alice@pbx.example.com>;tag=ftag\r\n"
            f"To: <sip:1000@pbx.example.com>\r\n"
            f"Call-ID: invite-test@scanner\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n"
            f"\r\n"
            f"{sdp}"
        ).encode()
        req = parse_request(data)
        assert req is not None
        assert req.method == "INVITE"
        assert "v=0" in req.body


class TestParseRequestReInvite:
    def test_reinvite_has_to_tag(self):
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

    def test_reinvite_cseq_incremented(self):
        data = (
            b"INVITE sip:1000@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-reinvite2\r\n"
            b"From: <sip:alice@pbx.example.com>;tag=fromtag\r\n"
            b"To: <sip:bob@pbx.example.com>;tag=totag\r\n"
            b"Call-ID: reinvite-call-id@scanner\r\n"
            b"CSeq: 2 INVITE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        assert "2" in req.cseq


class TestParseRequestMalformed:
    def test_garbage_bytes_returns_none(self):
        assert parse_request(b"THIS IS NOT SIP\r\n\r\n") is None

    def test_empty_bytes_returns_none(self):
        assert parse_request(b"") is None

    def test_sip_response_line_returns_none(self):
        data = (
            b"SIP/2.0 200 OK\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        assert parse_request(data) is None

    def test_lowercase_method_returns_none(self):
        # SIP methods are uppercase; lowercase should not parse
        data = b"options sip:host SIP/2.0\r\nContent-Length: 0\r\n\r\n"
        assert parse_request(data) is None

    def test_missing_request_line_returns_none(self):
        data = b"Via: SIP/2.0/UDP 1.2.3.4\r\nContent-Length: 0\r\n\r\n"
        assert parse_request(data) is None

    def test_truncated_message_no_crash(self):
        data = b"INVITE sip:foo SIP/2.0\r\nVia: SIP/2.0/UDP"
        # May or may not parse, but must not raise
        result = parse_request(data)
        # If it parses, method must be INVITE
        if result is not None:
            assert result.method == "INVITE"

    def test_oversized_message_truncated_to_limit(self):
        # 131073 bytes — must not raise; function clips to 131072
        big = b"OPTIONS sip:pbx SIP/2.0\r\nContent-Length: 0\r\n\r\n" + b"X" * 131060
        result = parse_request(big)
        assert result is not None
        assert result.method == "OPTIONS"


class TestParseRequestMultipleVia:
    def test_multiple_via_headers_accumulated(self):
        data = (
            b"BYE sip:alice@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-first\r\n"
            b"Via: SIP/2.0/UDP 5.6.7.8:5060;branch=z9hG4bK-second\r\n"
            b"From: <sip:bob@pbx.example.com>;tag=btag\r\n"
            b"To: <sip:alice@pbx.example.com>\r\n"
            b"Call-ID: via-test@scanner\r\n"
            b"CSeq: 1 BYE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        assert req is not None
        # Both Via values should be present (comma-separated)
        assert "z9hG4bK-first" in req.via
        assert "z9hG4bK-second" in req.via


class TestParseRequestOtherMethods:
    @pytest.mark.parametrize("method", ["REGISTER", "CANCEL", "ACK",
                                          "INFO", "SUBSCRIBE", "MESSAGE",
                                          "NOTIFY", "REFER", "UPDATE"])
    def test_known_method_parsed(self, method):
        data = _make_request(method)
        req = parse_request(data)
        assert req is not None
        assert req.method == method


# ---------------------------------------------------------------------------
# build_response_to_request — 200 OK and 100 Trying
# ---------------------------------------------------------------------------

class TestBuildResponseToRequest:
    def _make_req(self, method: str = "OPTIONS",
                  uri: str = "sip:pbx.example.com") -> SipRequest:
        data = _make_request(method, uri=uri)
        req = parse_request(data)
        assert req is not None
        return req

    # ── 200 OK ──────────────────────────────────────────────────────────────

    def test_200_ok_status_line(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert resp.startswith(b"SIP/2.0 200 OK\r\n")

    def test_200_ok_reflects_via(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-abc" in resp

    def test_200_ok_reflects_from(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert b"From: <sip:alice@pbx.example.com>;tag=fromtag" in resp

    def test_200_ok_reflects_to(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert b"To: <sip:bob@pbx.example.com>" in resp

    def test_200_ok_reflects_call_id(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert b"Call-ID: test-call-id@scanner" in resp

    def test_200_ok_reflects_cseq(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert b"CSeq: 1 OPTIONS" in resp

    def test_200_ok_adds_to_tag(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req, to_tag="server-tag-xyz")
        to_line = next(
            line for line in resp.decode().split("\r\n")
            if line.startswith("To:")
        )
        assert "tag=server-tag-xyz" in to_line

    def test_200_ok_no_duplicate_to_tag_when_already_present(self):
        data = (
            b"BYE sip:alice@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-bye\r\n"
            b"From: <sip:bob@pbx.example.com>;tag=btag\r\n"
            b"To: <sip:alice@pbx.example.com>;tag=existing-tag\r\n"
            b"Call-ID: bye-test@scanner\r\n"
            b"CSeq: 2 BYE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        resp = build_response_to_request(200, "OK", req, to_tag="new-tag")
        to_line = next(
            line for line in resp.decode().split("\r\n")
            if line.startswith("To:")
        )
        # existing-tag preserved; new-tag NOT added again
        assert "existing-tag" in to_line
        assert "new-tag" not in to_line

    def test_200_ok_content_length_zero_when_no_body(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert b"Content-Length: 0" in resp

    def test_200_ok_with_body_adds_content_type(self):
        req = self._make_req("INVITE")
        sdp = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\n"
        resp = build_response_to_request(200, "OK", req, body=sdp)
        assert b"Content-Type: application/sdp" in resp
        assert sdp.encode() in resp

    def test_200_ok_with_body_content_length_matches(self):
        req = self._make_req("INVITE")
        sdp = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\n"
        resp = build_response_to_request(200, "OK", req, body=sdp)
        cl_line = next(
            line for line in resp.decode().split("\r\n")
            if line.startswith("Content-Length:")
        )
        assert str(len(sdp.encode("utf-8"))) in cl_line

    def test_200_ok_extra_headers_included(self):
        req = self._make_req()
        resp = build_response_to_request(
            200, "OK", req,
            extra_headers=["Allow: INVITE, ACK, BYE, OPTIONS"]
        )
        assert b"Allow: INVITE, ACK, BYE, OPTIONS" in resp

    def test_200_ok_is_bytes(self):
        req = self._make_req()
        resp = build_response_to_request(200, "OK", req)
        assert isinstance(resp, bytes)

    # ── 100 Trying ─────────────────────────────────────────────────────────

    def test_100_trying_status_line(self):
        req = self._make_req("INVITE")
        resp = build_response_to_request(100, "Trying", req)
        assert resp.startswith(b"SIP/2.0 100 Trying\r\n")

    def test_100_trying_reflects_via(self):
        req = self._make_req("INVITE")
        resp = build_response_to_request(100, "Trying", req)
        assert b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-abc" in resp

    def test_100_trying_reflects_from(self):
        req = self._make_req("INVITE")
        resp = build_response_to_request(100, "Trying", req)
        assert b"From:" in resp

    def test_100_trying_reflects_call_id(self):
        req = self._make_req("INVITE")
        resp = build_response_to_request(100, "Trying", req)
        assert b"Call-ID: test-call-id@scanner" in resp

    def test_100_trying_no_to_tag(self):
        req = self._make_req("INVITE")
        resp = build_response_to_request(100, "Trying", req)
        to_line = next(
            line for line in resp.decode().split("\r\n")
            if line.startswith("To:")
        )
        # Provisional 100 Trying should not add a to-tag
        assert "tag=" not in to_line

    def test_100_trying_cseq_invite(self):
        req = self._make_req("INVITE")
        resp = build_response_to_request(100, "Trying", req)
        assert b"CSeq: 1 INVITE" in resp

    # ── Other status codes ──────────────────────────────────────────────────

    def test_404_not_found_status_line(self):
        req = self._make_req("OPTIONS")
        resp = build_response_to_request(404, "Not Found", req)
        assert resp.startswith(b"SIP/2.0 404 Not Found\r\n")

    def test_bye_response_200_cseq(self):
        req = self._make_req("BYE", uri="sip:alice@pbx.example.com")
        resp = build_response_to_request(200, "OK", req)
        assert b"CSeq: 1 BYE" in resp

    # ── Multiple Via headers ────────────────────────────────────────────────

    def test_multiple_via_headers_all_reflected(self):
        data = (
            b"BYE sip:alice@pbx.example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-first\r\n"
            b"Via: SIP/2.0/UDP 5.6.7.8:5060;branch=z9hG4bK-second\r\n"
            b"From: <sip:bob@pbx.example.com>;tag=btag\r\n"
            b"To: <sip:alice@pbx.example.com>\r\n"
            b"Call-ID: multi-via@scanner\r\n"
            b"CSeq: 1 BYE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        assert req is not None
        resp = build_response_to_request(200, "OK", req)
        resp_text = resp.decode()
        assert "z9hG4bK-first" in resp_text
        assert "z9hG4bK-second" in resp_text


# ---------------------------------------------------------------------------
# parse_contact_uri — all formats
# ---------------------------------------------------------------------------

class TestParseContactUri:
    # ── Explicit port ────────────────────────────────────────────────────────

    def test_angle_bracket_ip_with_port(self):
        result = parse_contact_uri({"contact": "<sip:192.168.1.50:5080>"})
        assert result == ("192.168.1.50", 5080)

    def test_angle_bracket_user_at_ip_with_port(self):
        result = parse_contact_uri({"contact": "<sip:alice@192.168.1.50:5090>"})
        assert result == ("192.168.1.50", 5090)

    def test_angle_bracket_user_at_hostname_with_port(self):
        result = parse_contact_uri({"contact": "<sip:alice@pbx.example.com:5090>"})
        assert result == ("pbx.example.com", 5090)

    def test_no_angle_brackets_ip_with_port(self):
        result = parse_contact_uri({"contact": "sip:192.168.1.50:5080"})
        assert result == ("192.168.1.50", 5080)

    def test_display_name_with_angle_bracket_port(self):
        result = parse_contact_uri({"contact": '"Alice" <sip:alice@1.2.3.4:5070>'})
        assert result == ("1.2.3.4", 5070)

    def test_port_5060(self):
        result = parse_contact_uri({"contact": "<sip:bob@10.0.0.1:5060>"})
        assert result == ("10.0.0.1", 5060)

    def test_high_port_number(self):
        result = parse_contact_uri({"contact": "<sip:pbx@192.168.1.1:65000>"})
        assert result == ("192.168.1.1", 65000)

    # ── Default port (5060) ─────────────────────────────────────────────────

    def test_user_at_host_no_port_defaults_5060(self):
        result = parse_contact_uri({"contact": "<sip:pbx@192.168.1.50>"})
        assert result == ("192.168.1.50", 5060)

    def test_user_at_hostname_no_port_defaults_5060(self):
        result = parse_contact_uri({"contact": "<sip:alice@pbx.example.com>"})
        assert result == ("pbx.example.com", 5060)

    # ── No match ────────────────────────────────────────────────────────────

    def test_empty_contact_returns_none(self):
        assert parse_contact_uri({"contact": ""}) is None

    def test_missing_contact_key_returns_none(self):
        assert parse_contact_uri({}) is None

    def test_tel_uri_returns_none(self):
        # tel: URIs should not match the sip: patterns
        result = parse_contact_uri({"contact": "tel:+15005551234"})
        assert result is None

    def test_malformed_sip_uri_no_host(self):
        # sip: with no host should return None (no match)
        result = parse_contact_uri({"contact": "sip:"})
        assert result is None

    # ── URI with parameters ─────────────────────────────────────────────────

    def test_contact_with_transport_param(self):
        result = parse_contact_uri(
            {"contact": "<sip:alice@192.168.1.50:5060;transport=tcp>"}
        )
        # host and port extracted before the semicolon
        assert result is not None
        assert result[0] == "192.168.1.50"
        assert result[1] == 5060

    def test_contact_with_lr_param(self):
        result = parse_contact_uri(
            {"contact": "<sip:proxy.example.com:5060;lr>"}
        )
        assert result is not None
        assert result[0] == "proxy.example.com"
        assert result[1] == 5060

    # ── Return type ─────────────────────────────────────────────────────────

    def test_port_is_int(self):
        result = parse_contact_uri({"contact": "<sip:192.168.1.50:5080>"})
        assert isinstance(result[1], int)

    def test_host_is_str(self):
        result = parse_contact_uri({"contact": "<sip:192.168.1.50:5080>"})
        assert isinstance(result[0], str)


# ---------------------------------------------------------------------------
# SipRequest dataclass properties
# ---------------------------------------------------------------------------

class TestSipRequestProperties:
    def _make(self, method: str = "OPTIONS") -> SipRequest:
        req = parse_request(_make_request(method))
        assert req is not None
        return req

    def test_call_id_property(self):
        assert self._make().call_id == "test-call-id@scanner"

    def test_from_header_property(self):
        assert "alice" in self._make().from_header

    def test_to_header_property(self):
        assert "bob" in self._make().to_header

    def test_cseq_property(self):
        req = self._make("BYE")
        assert "BYE" in req.cseq

    def test_via_property(self):
        req = self._make()
        assert "z9hG4bK-abc" in req.via

    def test_missing_header_property_empty_string(self):
        # Construct a request missing the Call-ID header entirely
        data = (
            b"OPTIONS sip:pbx SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-x\r\n"
            b"From: <sip:alice@pbx>;tag=t\r\n"
            b"To: <sip:bob@pbx>\r\n"
            b"CSeq: 1 OPTIONS\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        req = parse_request(data)
        assert req is not None
        assert req.call_id == ""
