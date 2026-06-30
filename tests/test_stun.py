"""Tests for scanner.stun — offline / unit-level only (no real network)."""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

STUN_MAGIC = 0x2112A442
STUN_RESP  = 0x0101
STUN_XOR   = 0x0020


def _build_response(tid: bytes, ip_str: str) -> bytes:
    """Build a minimal STUN Binding Success response with XOR-Mapped-Address."""
    import socket
    ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    xor_ip = ip_int ^ STUN_MAGIC
    xor_port = 12345 ^ (STUN_MAGIC >> 16)

    # XOR-Mapped-Address attr: family(1) pad(1) port(2) ip(4) = 8 bytes
    attr_val = struct.pack("!BBH", 0, 1, xor_port) + struct.pack("!I", xor_ip)
    attr = struct.pack("!HH", STUN_XOR, len(attr_val)) + attr_val

    # Header: type(2) length(2) magic(4) tid(12)
    header = struct.pack("!HHI", STUN_RESP, len(attr), STUN_MAGIC) + tid
    return header + attr


class TestBuildBindingRequest:
    def test_structure(self):
        from scanner.stun import _build_binding_request
        pkt, tid = _build_binding_request()
        assert len(pkt) == 20
        assert len(tid) == 12
        msg_type, msg_len, magic = struct.unpack_from("!HHI", pkt, 0)
        assert msg_type == 0x0001
        assert msg_len == 0
        assert magic == STUN_MAGIC
        assert pkt[8:20] == tid

    def test_unique_tids(self):
        from scanner.stun import _build_binding_request
        tids = {_build_binding_request()[1] for _ in range(100)}
        assert len(tids) == 100


class TestParseBindingResponse:
    def test_xor_mapped_address(self):
        from scanner.stun import _build_binding_request, _parse_binding_response
        _, tid = _build_binding_request()
        resp = _build_response(tid, "93.184.216.34")
        ip = _parse_binding_response(resp, tid)
        assert ip == "93.184.216.34"

    def test_wrong_tid_returns_none(self):
        from scanner.stun import _build_binding_request, _parse_binding_response
        _, tid = _build_binding_request()
        resp = _build_response(tid, "1.2.3.4")
        bad_tid = bytes(b ^ 0xFF for b in tid)
        assert _parse_binding_response(resp, bad_tid) is None

    def test_truncated_returns_none(self):
        from scanner.stun import _parse_binding_response
        assert _parse_binding_response(b"\x01\x01", b"\x00" * 12) is None

    def test_wrong_magic_returns_none(self):
        from scanner.stun import _parse_binding_response
        tid = os.urandom(12)
        # Corrupt magic in a valid-length header
        bad_pkt = struct.pack("!HHI", STUN_RESP, 0, 0xDEADBEEF) + tid
        assert _parse_binding_response(bad_pkt, tid) is None


class TestResolvePublicIp:
    def test_network_failure_returns_none(self, monkeypatch):
        """When every STUN server is unreachable, resolve_public_ip returns None."""
        import socket
        from scanner import stun

        def mock_sendto(*a, **kw):
            raise socket.timeout("simulated")

        monkeypatch.setattr("socket.socket.sendto", mock_sendto, raising=False)
        # Point at a guaranteed-to-fail server so we don't hit real network
        result = stun.resolve_public_ip(
            stun_server="0.0.0.0", stun_port=9,
            timeout=0.01, retries=1,
        )
        assert result is None
