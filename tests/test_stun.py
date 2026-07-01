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


# ---------------------------------------------------------------------------
# TURN open-relay probe tests
# ---------------------------------------------------------------------------

def _build_turn_error_401(tid: bytes) -> bytes:
    """Build a TURN Allocate Error Response (0x0013) with a 401 error code attr."""
    # Error-Code attr: 4 bytes header + class(1) + number(1) = val[2]=4, val[3]=1 → 401
    error_val = struct.pack("!HBB", 0, 4, 1)   # reserved(2), class=4, number=1
    attr = struct.pack("!HH", 0x0009, len(error_val)) + error_val
    pad = (4 - len(error_val) % 4) % 4
    attr += b"\x00" * pad
    header = struct.pack("!HHI", 0x0013, len(attr), STUN_MAGIC) + tid
    return header + attr


def _build_turn_alloc_success(tid: bytes) -> bytes:
    """Build a minimal TURN Allocate Success Response (0x0103)."""
    header = struct.pack("!HHI", 0x0103, 0, STUN_MAGIC) + tid
    return header


def _build_stun_binding_success(tid: bytes) -> bytes:
    """Build a STUN Binding Success (0x0101) response."""
    header = struct.pack("!HHI", 0x0101, 0, STUN_MAGIC) + tid
    return header


class TestProbeTurnOpenRelay:
    def test_open_relay_critical(self, monkeypatch):
        """Allocate Success (0x0103) without credentials → critical open-relay finding."""
        import socket
        from scanner import stun

        sent_packets = []

        class FakeSocket:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                tid = data[8:20]
                sent_packets.append((data, addr))
                self._resp = _build_turn_alloc_success(tid)

            def recvfrom(self, size):
                return self._resp, ("1.2.3.4", 3478)

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
        result = stun.probe_turn_open_relay("1.2.3.4", port=3478, timeout=1.0)

        assert result["found"] is True
        assert result["open_relay"] is True
        assert result["severity"] == "critical"
        assert "open relay" in result["evidence"].lower()

    def test_turn_auth_required_no_finding(self, monkeypatch):
        """Allocate Error (0x0013) with 401 → TURN exists but auth required, no open-relay."""
        import socket
        from scanner import stun

        class FakeSocket:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                tid = data[8:20]
                self._resp = _build_turn_error_401(tid)

            def recvfrom(self, size):
                return self._resp, ("1.2.3.4", 3478)

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
        result = stun.probe_turn_open_relay("1.2.3.4", port=3478, timeout=1.0)

        assert result["found"] is True
        assert result["open_relay"] is False
        assert result["severity"] == "info"
        assert "401" in result["evidence"] or "authentication required" in result["evidence"].lower()

    def test_stun_amplification_medium(self, monkeypatch):
        """Binding Success (0x0101) in response to Allocate → STUN amplification finding."""
        import socket
        from scanner import stun

        class FakeSocket:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                tid = data[8:20]
                self._resp = _build_stun_binding_success(tid)

            def recvfrom(self, size):
                return self._resp, ("1.2.3.4", 3478)

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
        result = stun.probe_turn_open_relay("1.2.3.4", port=3478, timeout=1.0)

        assert result["found"] is True
        assert result["stun_amp"] is True
        assert result["open_relay"] is False
        assert result["severity"] == "medium"
        assert "amplification" in result["evidence"].lower() or "ddos" in result["evidence"].lower()

    def test_no_response_returns_not_found(self, monkeypatch):
        """Timeout → found=False, no severity."""
        import socket
        from scanner import stun

        class FakeSocket:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                raise socket.timeout("simulated")

            def recvfrom(self, size):
                raise socket.timeout("simulated")

            def close(self):
                pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())
        result = stun.probe_turn_open_relay("1.2.3.4", port=3478, timeout=0.01)

        assert result["found"] is False
        assert result["open_relay"] is False
        assert result["severity"] == ""


class TestProbeTurnIpv4MappedSsrf:
    def test_no_credentials_returns_not_attempted(self):
        """Without credentials, probe returns attempted=False immediately."""
        from scanner import stun
        result = stun.probe_turn_ipv4mapped_ssrf("1.2.3.4", credentials=None)
        assert result["attempted"] is False
        assert result["ssrf_confirmed"] is False
