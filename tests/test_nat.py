"""Unit tests for scanner.nat — offline / unit-level only (no real network)."""
from __future__ import annotations

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from scanner.nat import (
    NatContext,
    _default_local_ip,
    _parse_mapped,
    _stun_binding,
    detect_nat_type,
    get_reflexive_address,
    setup,
    teardown,
)

# ---------------------------------------------------------------------------
# STUN packet builders (offline helpers, no network)
# ---------------------------------------------------------------------------

_STUN_MAGIC   = 0x2112A442
_STUN_RESP    = 0x0101
_ATTR_XOR_MAP = 0x0020
_ATTR_MAP     = 0x0001


def _build_stun_response(tid: bytes, ip_str: str, port: int = 12345,
                          use_xor: bool = True) -> bytes:
    """Build a minimal STUN Binding Success response."""
    ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    if use_xor:
        xor_port = port ^ (_STUN_MAGIC >> 16)
        xor_ip   = ip_int ^ _STUN_MAGIC
        attr_val = struct.pack("!BBH", 0, 1, xor_port) + struct.pack("!I", xor_ip)
        attr_type = _ATTR_XOR_MAP
    else:
        attr_val = struct.pack("!BBH", 0, 1, port) + struct.pack("!I", ip_int)
        attr_type = _ATTR_MAP
    attr = struct.pack("!HH", attr_type, len(attr_val)) + attr_val
    header = struct.pack("!HHI", _STUN_RESP, len(attr), _STUN_MAGIC) + tid
    return header + attr


# ---------------------------------------------------------------------------
# NatContext dataclass
# ---------------------------------------------------------------------------

class TestNatContextIsBehindNat:
    def test_different_ips_is_behind_nat(self):
        ctx = NatContext(local_ip="192.168.1.10", public_ip="203.0.113.5")
        assert ctx.is_behind_nat is True

    def test_same_ips_not_behind_nat(self):
        ctx = NatContext(local_ip="203.0.113.5", public_ip="203.0.113.5")
        assert ctx.is_behind_nat is False

    def test_empty_local_ip_not_behind_nat(self):
        ctx = NatContext(local_ip="", public_ip="203.0.113.5")
        assert ctx.is_behind_nat is False

    def test_empty_public_ip_not_behind_nat(self):
        ctx = NatContext(local_ip="192.168.1.10", public_ip="")
        assert ctx.is_behind_nat is False

    def test_both_empty_not_behind_nat(self):
        ctx = NatContext()
        assert ctx.is_behind_nat is False


class TestNatContextPrefersTcp:
    def test_symmetric_prefers_tcp(self):
        ctx = NatContext(nat_type="symmetric")
        assert ctx.prefers_tcp is True

    def test_port_restricted_prefers_tcp(self):
        ctx = NatContext(nat_type="port_restricted")
        assert ctx.prefers_tcp is True

    def test_full_cone_does_not_prefer_tcp(self):
        ctx = NatContext(nat_type="full_cone")
        assert ctx.prefers_tcp is False

    def test_restricted_does_not_prefer_tcp(self):
        ctx = NatContext(nat_type="restricted")
        assert ctx.prefers_tcp is False

    def test_direct_does_not_prefer_tcp(self):
        ctx = NatContext(nat_type="direct")
        assert ctx.prefers_tcp is False

    def test_unknown_does_not_prefer_tcp(self):
        ctx = NatContext(nat_type="unknown")
        assert ctx.prefers_tcp is False


class TestNatContextSummary:
    def test_summary_contains_nat_type(self):
        ctx = NatContext(nat_type="symmetric")
        assert "symmetric" in ctx.summary()

    def test_summary_contains_local_ip_when_set(self):
        ctx = NatContext(nat_type="restricted", local_ip="10.0.0.1")
        assert "local=10.0.0.1" in ctx.summary()

    def test_summary_contains_public_ip_when_differs(self):
        ctx = NatContext(nat_type="restricted",
                         local_ip="10.0.0.1", public_ip="203.0.113.5")
        assert "public=203.0.113.5" in ctx.summary()

    def test_summary_no_public_when_same_as_local(self):
        ctx = NatContext(nat_type="direct",
                         local_ip="203.0.113.5", public_ip="203.0.113.5")
        assert "public=" not in ctx.summary()

    def test_summary_upnp_ok_with_count(self):
        ctx = NatContext(nat_type="full_cone",
                         upnp_available=True,
                         mapped_ports={5060: 5060, 5061: 5061})
        s = ctx.summary()
        assert "UPnP=OK" in s
        assert "2 mapped" in s

    def test_summary_upnp_ok_no_ports(self):
        ctx = NatContext(nat_type="full_cone", upnp_available=True)
        s = ctx.summary()
        assert "UPnP=OK" in s
        assert "mapped" not in s

    def test_summary_upnp_unavail_when_nat_not_direct(self):
        ctx = NatContext(nat_type="restricted", upnp_available=False)
        assert "UPnP=unavail" in ctx.summary()

    def test_summary_no_upnp_label_when_direct(self):
        ctx = NatContext(nat_type="direct", upnp_available=False)
        assert "UPnP" not in ctx.summary()

    def test_summary_unknown_no_upnp_label(self):
        ctx = NatContext(nat_type="unknown", upnp_available=False)
        assert "UPnP" not in ctx.summary()


class TestNatContextDefaults:
    def test_default_fields(self):
        ctx = NatContext()
        assert ctx.local_ip == ""
        assert ctx.public_ip == ""
        assert ctx.nat_type == "unknown"
        assert ctx.upnp_available is False
        assert ctx.upnp_control_url == ""
        assert ctx.upnp_service_type == ""
        assert ctx.mapped_ports == {}
        assert ctx.reflexive_ports == {}
        assert ctx.setup_log == []

    def test_mapped_ports_independent(self):
        a = NatContext()
        b = NatContext()
        a.mapped_ports[5060] = 5060
        assert b.mapped_ports == {}

    def test_setup_log_independent(self):
        a = NatContext()
        b = NatContext()
        a.setup_log.append("x")
        assert b.setup_log == []


# ---------------------------------------------------------------------------
# _stun_binding (mock socket)
# ---------------------------------------------------------------------------

class TestStunBinding:
    def _fake_socket_factory(self, response: bytes | None):
        """Return a fake socket class whose recvfrom gives *response*."""
        class FakeSock:
            def __init__(self):
                self._response = response
                self._bound_port = 54321

            def settimeout(self, t):
                pass

            def bind(self, addr):
                if addr[1]:
                    self._bound_port = addr[1]

            def sendto(self, data, addr):
                # capture transaction ID so response TID matches
                self._sent_tid = data[8:20]
                if self._response is not None:
                    # Patch TID in the pre-built response
                    magic_bytes = struct.pack("!I", _STUN_MAGIC)
                    header = struct.pack("!HH", _STUN_RESP,
                                        len(self._response) - 20)
                    self._response = (
                        header[:4]
                        + magic_bytes
                        + self._sent_tid
                        + self._response[20:]
                    )

            def recvfrom(self, size):
                if self._response is None:
                    raise socket.timeout("simulated")
                return self._response, ("1.2.3.4", 3478)

            def close(self):
                pass

        return FakeSock

    def test_returns_ip_port_on_xor_response(self, monkeypatch):
        tid = b"\x00" * 12
        resp = _build_stun_response(tid, "93.184.216.34", 44444, use_xor=True)
        FakeSock = self._fake_socket_factory(resp)
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())
        result = _stun_binding("stun.example.com", 3478, timeout=0.1)
        assert result is not None
        ip, port = result
        assert isinstance(ip, str)
        assert isinstance(port, int)
        assert 1 <= port <= 65535

    def test_returns_none_on_timeout(self, monkeypatch):
        FakeSock = self._fake_socket_factory(None)
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())
        result = _stun_binding("stun.example.com", 3478, timeout=0.01)
        assert result is None

    def test_returns_none_on_short_response(self, monkeypatch):
        class TinyRespSock:
            def settimeout(self, t): pass
            def bind(self, a): pass
            def sendto(self, d, a): pass
            def recvfrom(self, s): return b"\x01\x01", ("1.2.3.4", 3478)
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: TinyRespSock())
        result = _stun_binding("stun.example.com", 3478, timeout=0.01)
        assert result is None

    def test_local_port_binding(self, monkeypatch):
        bound_ports = []

        class TrackingSock:
            def settimeout(self, t): pass
            def bind(self, addr): bound_ports.append(addr[1])
            def sendto(self, d, a): raise socket.timeout("simulated")
            def recvfrom(self, s): raise socket.timeout("simulated")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: TrackingSock())
        _stun_binding("stun.example.com", 3478, local_port=15060, timeout=0.01)
        assert 15060 in bound_ports

    def test_wrong_magic_returns_none(self, monkeypatch):
        tid = b"\xaa" * 12
        # Craft a response with wrong magic
        bad_resp = struct.pack("!HHI", _STUN_RESP, 0, 0xDEADBEEF) + tid
        FakeSock = self._fake_socket_factory(bad_resp)
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSock())
        result = _stun_binding("stun.example.com", 3478, timeout=0.01)
        assert result is None

    def test_os_error_returns_none(self, monkeypatch):
        class ErrorSock:
            def settimeout(self, t): pass
            def bind(self, a): pass
            def sendto(self, d, a): raise OSError("network down")
            def recvfrom(self, s): raise OSError("network down")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: ErrorSock())
        result = _stun_binding("stun.example.com", 3478, timeout=0.01)
        assert result is None


# ---------------------------------------------------------------------------
# _parse_mapped
# ---------------------------------------------------------------------------

class TestParseMapped:
    def test_xor_mapped_address(self):
        tid = os.urandom(12)
        resp = _build_stun_response(tid, "93.184.216.34", 12345, use_xor=True)
        result = _parse_mapped(resp, tid)
        assert result is not None
        ip, port = result
        assert ip == "93.184.216.34"
        assert port == 12345

    def test_plain_mapped_address_fallback(self):
        tid = os.urandom(12)
        resp = _build_stun_response(tid, "1.2.3.4", 9876, use_xor=False)
        result = _parse_mapped(resp, tid)
        assert result is not None
        ip, port = result
        assert ip == "1.2.3.4"
        assert port == 9876

    def test_wrong_tid_returns_none(self):
        tid = os.urandom(12)
        resp = _build_stun_response(tid, "1.2.3.4", 5060)
        bad_tid = bytes(b ^ 0xFF for b in tid)
        assert _parse_mapped(resp, bad_tid) is None

    def test_truncated_data_returns_none(self):
        tid = b"\x00" * 12
        assert _parse_mapped(b"\x01\x01\x00\x00", tid) is None

    def test_wrong_magic_returns_none(self):
        tid = os.urandom(12)
        bad_resp = struct.pack("!HHI", _STUN_RESP, 0, 0xDEADBEEF) + tid
        assert _parse_mapped(bad_resp, tid) is None

    def test_wrong_msg_type_returns_none(self):
        tid = os.urandom(12)
        # 0x0001 is a request, not a response
        bad_resp = struct.pack("!HHI", 0x0001, 0, _STUN_MAGIC) + tid
        assert _parse_mapped(bad_resp, tid) is None

    def test_empty_returns_none(self):
        assert _parse_mapped(b"", b"\x00" * 12) is None


# ---------------------------------------------------------------------------
# get_reflexive_address (mock _stun_binding)
# ---------------------------------------------------------------------------

class TestGetReflexiveAddress:
    def test_returns_result_from_stun_binding(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "_stun_binding",
                            lambda host, port, local_port=0, timeout=2.5:
                                ("203.0.113.99", 15060))
        result = get_reflexive_address(local_port=5060)
        assert result == ("203.0.113.99", 15060)

    def test_tries_second_server_when_first_fails(self, monkeypatch):
        from scanner import nat
        calls = []

        def fake_binding(host, port, local_port=0, timeout=2.5):
            calls.append(host)
            if len(calls) == 1:
                return None
            return ("1.2.3.4", 9999)

        monkeypatch.setattr(nat, "_stun_binding", fake_binding)
        result = get_reflexive_address()
        assert result == ("1.2.3.4", 9999)
        assert len(calls) == 2

    def test_all_servers_fail_returns_none(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "_stun_binding",
                            lambda *a, **kw: None)
        result = get_reflexive_address()
        assert result is None

    def test_custom_stun_server_with_port(self, monkeypatch):
        from scanner import nat
        contacted = []

        def fake_binding(host, port, local_port=0, timeout=2.5):
            contacted.append((host, port))
            return ("5.5.5.5", 10000)

        monkeypatch.setattr(nat, "_stun_binding", fake_binding)
        result = get_reflexive_address(stun_server="mystun.example.com:3479")
        assert result == ("5.5.5.5", 10000)
        assert contacted[0] == ("mystun.example.com", 3479)

    def test_custom_stun_server_no_port_defaults_3478(self, monkeypatch):
        from scanner import nat
        contacted = []

        def fake_binding(host, port, local_port=0, timeout=2.5):
            contacted.append((host, port))
            return ("5.5.5.5", 10000)

        monkeypatch.setattr(nat, "_stun_binding", fake_binding)
        get_reflexive_address(stun_server="mystun.example.com")
        assert contacted[0][1] == 3478

    def test_exception_in_stun_binding_continues(self, monkeypatch):
        from scanner import nat
        calls = []

        def exploding_binding(host, port, local_port=0, timeout=2.5):
            calls.append(host)
            if len(calls) == 1:
                raise RuntimeError("bang")
            return ("9.9.9.9", 7777)

        monkeypatch.setattr(nat, "_stun_binding", exploding_binding)
        result = get_reflexive_address()
        assert result == ("9.9.9.9", 7777)


# ---------------------------------------------------------------------------
# detect_nat_type (mock socket)
# ---------------------------------------------------------------------------

class TestDetectNatType:
    """Use monkeypatching of socket.socket to drive detect_nat_type offline."""

    def _make_socket_factory(self, responses: list[tuple[bytes, tuple]]):
        """Return a fake socket class that pops from *responses* on recvfrom."""
        resp_iter = iter(responses)

        class FakeSock:
            def __init__(self):
                self._port = 54321

            def settimeout(self, t):
                pass

            def bind(self, addr):
                self._port = addr[1] or 54321

            def getsockname(self):
                return ("0.0.0.0", self._port)

            def sendto(self, data, addr):
                self._last_tid = data[8:20]
                self._last_addr = addr

            def recvfrom(self, size):
                try:
                    resp_bytes, addr = next(resp_iter)
                    if resp_bytes is None:
                        raise socket.timeout("simulated")
                    return resp_bytes, addr
                except StopIteration:
                    raise socket.timeout("exhausted")

            def close(self):
                pass

            def connect(self, addr):
                pass

        return FakeSock

    def _patch_sockets(self, monkeypatch, udp_responses, probe_ip="192.168.1.10"):
        """Patch socket.socket so the UDP sock and the probe sock behave correctly."""
        from scanner import nat
        resp_iter = iter(udp_responses)

        class MainSock:
            def __init__(self):
                self._port = 54321

            def settimeout(self, t): pass

            def bind(self, addr):
                self._port = addr[1] or 54321

            def getsockname(self):
                return ("0.0.0.0", self._port)

            def sendto(self, data, addr):
                self._last_tid = data[8:20]

            def recvfrom(self, size):
                try:
                    item = next(resp_iter)
                    if item is None:
                        raise socket.timeout("simulated")
                    resp_bytes, addr = item
                    if resp_bytes is None:
                        raise socket.timeout("simulated")
                    return resp_bytes, addr
                except StopIteration:
                    raise socket.timeout("exhausted")

            def close(self): pass

        class ProbeSock:
            def connect(self, addr): pass
            def getsockname(self): return (probe_ip, 0)
            def close(self): pass

        call_count = [0]

        def fake_socket_constructor(family, kind, *args, **kwargs):
            call_count[0] += 1
            if kind == socket.SOCK_DGRAM:
                if call_count[0] == 1:
                    return MainSock()
                return ProbeSock()
            return ProbeSock()

        monkeypatch.setattr(socket, "socket", fake_socket_constructor)

    def _make_response_for_nat(self, tid: bytes, ip: str, port: int) -> tuple:
        return (_build_stun_response(tid, ip, port), ("stun.server.com", 19302))

    def test_symmetric_nat_different_ports(self, monkeypatch):
        """When two STUN servers return different external ports → symmetric."""
        from scanner import nat

        tids_seen = []

        class MainSock:
            def __init__(self): self._port = 54321; self._call = 0
            def settimeout(self, t): pass
            def bind(self, addr): self._port = addr[1] or 54321
            def getsockname(self): return ("0.0.0.0", self._port)
            def sendto(self, data, addr):
                self._call += 1
                self._last_tid = data[8:20]
                tids_seen.append(data[8:20])
            def recvfrom(self, size):
                tid = tids_seen[-1] if tids_seen else b"\x00" * 12
                if self._call == 1:
                    # Different IP from local → behind NAT, port 10000
                    resp = _build_stun_response(tid, "203.0.113.5", 10000)
                else:
                    # Same socket, different destination → port 10001 (symmetric)
                    resp = _build_stun_response(tid, "203.0.113.5", 10001)
                return resp, ("stun.server.com", 19302)
            def close(self): pass

        class ProbeSock:
            def connect(self, addr): pass
            def getsockname(self): return ("192.168.1.10", 0)
            def close(self): pass

        call_count = [0]
        def fake_socket(family, kind, *args, **kwargs):
            call_count[0] += 1
            if kind == socket.SOCK_DGRAM:
                if call_count[0] == 1:
                    return MainSock()
                return ProbeSock()
            return ProbeSock()

        monkeypatch.setattr(socket, "socket", fake_socket)
        result = detect_nat_type(timeout=0.1)
        assert result == "symmetric"

    def test_direct_when_external_equals_local(self, monkeypatch):
        """When reflexive IP == local egress IP → direct (no NAT)."""
        from scanner import nat
        local_ip = "203.0.113.5"

        class MainSock:
            def __init__(self): self._call = 0
            def settimeout(self, t): pass
            def bind(self, addr): pass
            def getsockname(self): return ("0.0.0.0", 54321)
            def sendto(self, data, addr):
                self._call += 1
                self._last_tid = data[8:20]
            def recvfrom(self, size):
                resp = _build_stun_response(self._last_tid, local_ip, 54321)
                return resp, ("stun.server.com", 19302)
            def close(self): pass

        class ProbeSock:
            def connect(self, addr): pass
            def getsockname(self): return (local_ip, 0)
            def close(self): pass

        call_count = [0]
        def fake_socket(family, kind, *args, **kwargs):
            call_count[0] += 1
            if kind == socket.SOCK_DGRAM:
                if call_count[0] == 1:
                    return MainSock()
                return ProbeSock()
            return ProbeSock()

        monkeypatch.setattr(socket, "socket", fake_socket)
        result = detect_nat_type(timeout=0.1)
        assert result == "direct"

    def test_restricted_when_same_port_two_servers(self, monkeypatch):
        """Same external port on two servers → restricted."""
        from scanner import nat

        class MainSock:
            def __init__(self): self._call = 0
            def settimeout(self, t): pass
            def bind(self, addr): pass
            def getsockname(self): return ("0.0.0.0", 54321)
            def sendto(self, data, addr):
                self._call += 1
                self._last_tid = data[8:20]
            def recvfrom(self, size):
                # Same port (10000) on both servers → restricted/full_cone
                resp = _build_stun_response(self._last_tid, "203.0.113.5", 10000)
                return resp, ("stun.server.com", 19302)
            def close(self): pass

        class ProbeSock:
            def connect(self, addr): pass
            def getsockname(self): return ("192.168.1.10", 0)
            def close(self): pass

        call_count = [0]
        def fake_socket(family, kind, *args, **kwargs):
            call_count[0] += 1
            if kind == socket.SOCK_DGRAM:
                if call_count[0] == 1:
                    return MainSock()
                return ProbeSock()
            return ProbeSock()

        monkeypatch.setattr(socket, "socket", fake_socket)
        result = detect_nat_type(timeout=0.1)
        assert result == "restricted"

    def test_unknown_when_test_i_times_out(self, monkeypatch):
        """When Test I times out → unknown."""
        from scanner import nat

        class TimeoutSock:
            def settimeout(self, t): pass
            def bind(self, addr): pass
            def getsockname(self): return ("0.0.0.0", 54321)
            def sendto(self, data, addr): pass
            def recvfrom(self, size): raise socket.timeout("simulated")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: TimeoutSock())
        result = detect_nat_type(timeout=0.01)
        assert result == "unknown"

    def test_restricted_when_test_ii_times_out(self, monkeypatch):
        """When Test II times out (Test I OK, behind NAT) → restricted."""
        from scanner import nat

        call_count = [0]

        class PartialSock:
            def __init__(self): self._call = 0
            def settimeout(self, t): pass
            def bind(self, addr): pass
            def getsockname(self): return ("0.0.0.0", 54321)
            def sendto(self, data, addr):
                self._call += 1
                self._last_tid = data[8:20]
            def recvfrom(self, size):
                if self._call == 1:
                    return _build_stun_response(self._last_tid, "203.0.113.5", 10000), ("s", 19302)
                raise socket.timeout("test II timeout")
            def close(self): pass

        class ProbeSock:
            def connect(self, addr): pass
            def getsockname(self): return ("192.168.1.10", 0)
            def close(self): pass

        call_num = [0]
        def fake_socket(family, kind, *args, **kwargs):
            call_num[0] += 1
            if kind == socket.SOCK_DGRAM:
                if call_num[0] == 1:
                    return PartialSock()
                return ProbeSock()
            return ProbeSock()

        monkeypatch.setattr(socket, "socket", fake_socket)
        result = detect_nat_type(timeout=0.1)
        assert result == "restricted"


# ---------------------------------------------------------------------------
# setup() — comprehensive
# ---------------------------------------------------------------------------

class TestSetup:
    def test_setup_no_upnp_returns_context(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "unknown")
        monkeypatch.setattr(nat, "get_reflexive_address",
                            lambda **kw: ("203.0.113.99", 15060))
        ctx = setup(ports_to_map=[5060], local_ip="192.168.1.10", enable_upnp=False)
        assert isinstance(ctx, NatContext)
        assert ctx.local_ip == "192.168.1.10"
        assert 5060 in ctx.reflexive_ports
        assert ctx.reflexive_ports[5060] == 15060
        assert ctx.public_ip == "203.0.113.99"

    def test_setup_detects_nat_type(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type",
                            lambda timeout=3.0: "symmetric")
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: None)
        ctx = setup(ports_to_map=[], enable_upnp=False)
        assert ctx.nat_type == "symmetric"

    def test_setup_nat_type_detection_failure_logged(self, monkeypatch):
        from scanner import nat

        def boom(**kw):
            raise RuntimeError("stun exploded")

        monkeypatch.setattr(nat, "detect_nat_type", boom)
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: None)
        ctx = setup(ports_to_map=[], enable_upnp=False)
        assert any("NAT type detection failed" in entry for entry in ctx.setup_log)

    def test_setup_multiple_ports_reflexive(self, monkeypatch):
        from scanner import nat

        def fake_reflexive(local_port=0, stun_server=None, timeout=3.0):
            return ("1.2.3.4", local_port + 10000)

        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "restricted")
        monkeypatch.setattr(nat, "get_reflexive_address", fake_reflexive)
        ctx = setup(ports_to_map=[5060, 5061], enable_upnp=False)
        assert ctx.reflexive_ports[5060] == 15060
        assert ctx.reflexive_ports[5061] == 15061

    def test_setup_public_ip_not_overwritten_if_preset(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "restricted")
        monkeypatch.setattr(nat, "get_reflexive_address",
                            lambda **kw: ("9.9.9.9", 15060))
        ctx = setup(ports_to_map=[5060], public_ip="4.4.4.4", enable_upnp=False)
        # Preset public_ip should NOT be replaced by STUN result
        assert ctx.public_ip == "4.4.4.4"

    def test_setup_public_ip_from_first_stun(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "unknown")

        def fake_reflexive(local_port=0, stun_server=None, timeout=3.0):
            return ("5.5.5.5", local_port + 1000)

        monkeypatch.setattr(nat, "get_reflexive_address", fake_reflexive)
        ctx = setup(ports_to_map=[5060, 5061], enable_upnp=False)
        # public_ip set from first successful STUN and not overwritten
        assert ctx.public_ip == "5.5.5.5"

    def test_setup_upnp_disabled_no_upnp_calls(self, monkeypatch):
        from scanner import nat
        called = []
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "unknown")
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: None)
        monkeypatch.setattr(nat, "discover_upnp_gateway",
                            lambda **kw: called.append(1) or ("http://gw", "svc"))
        ctx = setup(ports_to_map=[5060], enable_upnp=False)
        assert called == []
        assert not ctx.upnp_available

    def test_setup_upnp_gateway_found_maps_ports(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "full_cone")
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: None)
        monkeypatch.setattr(nat, "discover_upnp_gateway",
                            lambda timeout=3.0: ("http://gw/ctl",
                                                  "urn:schemas-upnp-org:service:WANIPConnection:1"))
        monkeypatch.setattr(nat, "get_external_ip",
                            lambda ctrl, svc: "203.0.113.10")
        mapped = {}
        monkeypatch.setattr(nat, "add_port_mapping",
                            lambda ctrl, svc, internal_ip, internal_port,
                                   external_port, protocol="UDP",
                                   description="VoIPScan", duration=7200:
                                mapped.__setitem__(internal_port, external_port) or True)
        ctx = setup(ports_to_map=[5060], local_ip="192.168.1.10", enable_upnp=True)
        assert ctx.upnp_available is True
        assert ctx.upnp_control_url == "http://gw/ctl"
        assert ctx.public_ip == "203.0.113.10"
        assert 5060 in ctx.mapped_ports

    def test_setup_upnp_no_gateway_logged(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "unknown")
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: None)
        monkeypatch.setattr(nat, "discover_upnp_gateway", lambda timeout=3.0: None)
        ctx = setup(ports_to_map=[], enable_upnp=True)
        assert any("no igd" in e.lower() for e in ctx.setup_log)

    def test_setup_reflexive_failure_logged(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "unknown")

        def explode(**kw):
            raise OSError("network error")

        monkeypatch.setattr(nat, "get_reflexive_address", explode)
        ctx = setup(ports_to_map=[5060], enable_upnp=False)
        assert any("Reflexive port probe" in e and "failed" in e
                   for e in ctx.setup_log)

    def test_setup_always_returns_nat_context(self, monkeypatch):
        from scanner import nat
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: (_ for _ in ()).throw(RuntimeError()))
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: None)
        ctx = setup(ports_to_map=[], enable_upnp=False)
        assert isinstance(ctx, NatContext)


# ---------------------------------------------------------------------------
# teardown()
# ---------------------------------------------------------------------------

class TestTeardown:
    def test_teardown_removes_mapped_ports(self, monkeypatch):
        from scanner import nat
        deleted: list[int] = []

        def fake_delete(control_url, service_type, external_port, protocol="UDP"):
            deleted.append(external_port)
            return True

        monkeypatch.setattr(nat, "delete_port_mapping", fake_delete)
        ctx = NatContext(
            upnp_available=True,
            upnp_control_url="http://192.168.1.1:1234/ctl",
            upnp_service_type="urn:schemas-upnp-org:service:WANIPConnection:1",
            mapped_ports={5060: 5060, 5061: 5061},
        )
        teardown(ctx)
        assert set(deleted) == {5060, 5061}
        assert ctx.mapped_ports == {}

    def test_teardown_no_upnp_is_noop(self, monkeypatch):
        from scanner import nat
        called = []
        monkeypatch.setattr(nat, "delete_port_mapping",
                            lambda *a, **kw: called.append(1))
        ctx = NatContext(upnp_available=False, mapped_ports={5060: 5060})
        teardown(ctx)
        assert called == []

    def test_teardown_no_control_url_is_noop(self, monkeypatch):
        from scanner import nat
        called = []
        monkeypatch.setattr(nat, "delete_port_mapping",
                            lambda *a, **kw: called.append(1))
        ctx = NatContext(upnp_available=True, upnp_control_url="",
                         mapped_ports={5060: 5060})
        teardown(ctx)
        assert called == []

    def test_teardown_exception_suppressed(self, monkeypatch):
        from scanner import nat

        def exploding_delete(*a, **kw):
            raise RuntimeError("soap error")

        monkeypatch.setattr(nat, "delete_port_mapping", exploding_delete)
        ctx = NatContext(
            upnp_available=True,
            upnp_control_url="http://192.168.1.1/ctl",
            upnp_service_type="urn:schemas-upnp-org:service:WANIPConnection:1",
            mapped_ports={5060: 5060},
        )
        # Must not raise
        teardown(ctx)
        assert ctx.mapped_ports == {}

    def test_teardown_empty_mapped_ports_no_calls(self, monkeypatch):
        from scanner import nat
        called = []
        monkeypatch.setattr(nat, "delete_port_mapping",
                            lambda *a, **kw: called.append(1))
        ctx = NatContext(
            upnp_available=True,
            upnp_control_url="http://192.168.1.1/ctl",
            upnp_service_type="urn:schemas-upnp-org:service:WANIPConnection:1",
            mapped_ports={},
        )
        teardown(ctx)
        assert called == []

    def test_teardown_multiple_protocols_all_deleted(self, monkeypatch):
        from scanner import nat
        deleted = []

        def fake_delete(control_url, service_type, external_port, protocol="UDP"):
            deleted.append(external_port)
            return True

        monkeypatch.setattr(nat, "delete_port_mapping", fake_delete)
        ctx = NatContext(
            upnp_available=True,
            upnp_control_url="http://gw/ctl",
            upnp_service_type="urn:schemas-upnp-org:service:WANIPConnection:1",
            mapped_ports={5060: 5070, 5061: 5071, 5062: 5072},
        )
        teardown(ctx)
        assert set(deleted) == {5070, 5071, 5072}
        assert ctx.mapped_ports == {}


# ---------------------------------------------------------------------------
# _default_local_ip
# ---------------------------------------------------------------------------

class TestDefaultLocalIp:
    def test_returns_string(self):
        ip = _default_local_ip()
        assert isinstance(ip, str)
        assert len(ip) > 0

    def test_dotted_decimal_format(self):
        ip = _default_local_ip()
        parts = ip.split(".")
        assert len(parts) == 4

    def test_fallback_on_socket_error(self, monkeypatch):
        class BrokenSock:
            def connect(self, addr): raise OSError("network down")
            def close(self): pass

        monkeypatch.setattr(socket, "socket", lambda *a, **kw: BrokenSock())
        ip = _default_local_ip()
        assert ip == "127.0.0.1"
