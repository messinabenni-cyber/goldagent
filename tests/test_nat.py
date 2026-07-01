"""Unit tests for scanner.nat — offline / unit-level only (no real network)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from scanner.nat import NatContext, _default_local_ip, setup, teardown


# ---------------------------------------------------------------------------
# NatContext properties
# ---------------------------------------------------------------------------

class TestNatContextIsBehindNat:
    def test_nat_context_is_behind_nat_true(self):
        ctx = NatContext(local_ip="192.168.1.10", public_ip="203.0.113.5")
        assert ctx.is_behind_nat is True

    def test_nat_context_is_behind_nat_false(self):
        ctx = NatContext(local_ip="203.0.113.5", public_ip="203.0.113.5")
        assert ctx.is_behind_nat is False


class TestNatContextPrefersTcp:
    def test_nat_context_prefers_tcp_symmetric(self):
        ctx = NatContext(nat_type="symmetric")
        assert ctx.prefers_tcp is True

    def test_nat_context_prefers_tcp_port_restricted(self):
        ctx = NatContext(nat_type="port_restricted")
        assert ctx.prefers_tcp is True

    def test_nat_context_does_not_prefer_tcp_full_cone(self):
        ctx = NatContext(nat_type="full_cone")
        assert ctx.prefers_tcp is False


class TestNatContextSummary:
    def test_nat_context_summary_contains_type(self):
        ctx = NatContext(nat_type="symmetric")
        summary = ctx.summary()
        assert "symmetric" in summary


# ---------------------------------------------------------------------------
# setup() — no UPnP, STUN mocked
# ---------------------------------------------------------------------------

class TestSetup:
    def test_setup_no_upnp_returns_context(self, monkeypatch):
        """setup() with UPnP disabled returns a NatContext without hitting network."""
        from scanner import nat

        # Suppress real STUN calls
        monkeypatch.setattr(nat, "detect_nat_type", lambda **kw: "unknown")
        monkeypatch.setattr(nat, "get_reflexive_address", lambda **kw: ("203.0.113.99", 15060))

        ctx = setup(
            ports_to_map=[5060],
            local_ip="192.168.1.10",
            enable_upnp=False,
        )

        assert isinstance(ctx, NatContext)
        assert ctx.local_ip == "192.168.1.10"
        # reflexive port recorded from mock STUN
        assert 5060 in ctx.reflexive_ports
        assert ctx.reflexive_ports[5060] == 15060
        # public IP picked up from STUN
        assert ctx.public_ip == "203.0.113.99"


# ---------------------------------------------------------------------------
# teardown()
# ---------------------------------------------------------------------------

class TestTeardown:
    def test_teardown_removes_mapped_ports(self, monkeypatch):
        """teardown() calls DeletePortMapping for each mapped port and clears the dict."""
        from scanner import nat

        deleted: list[int] = []

        def _fake_delete(control_url, service_type, external_port, protocol="UDP"):
            deleted.append(external_port)
            return True

        monkeypatch.setattr(nat, "delete_port_mapping", _fake_delete)

        ctx = NatContext(
            upnp_available=True,
            upnp_control_url="http://192.168.1.1:1234/ctl",
            upnp_service_type="urn:schemas-upnp-org:service:WANIPConnection:1",
            mapped_ports={5060: 5060, 5061: 5061},
        )

        teardown(ctx)

        assert set(deleted) == {5060, 5061}
        assert ctx.mapped_ports == {}


# ---------------------------------------------------------------------------
# _default_local_ip
# ---------------------------------------------------------------------------

class TestDefaultLocalIp:
    def test_default_local_ip_returns_string(self):
        ip = _default_local_ip()
        assert isinstance(ip, str)
        assert len(ip) > 0
        # Should be a dotted-decimal IPv4 address or fallback "127.0.0.1"
        parts = ip.split(".")
        assert len(parts) == 4
