"""Unit tests for scanner.discovery — all mocked, no real network."""
from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from scanner import discovery
from scanner.discovery import (
    expand_target,
    fingerprint_banner,
    version_extract,
    HostResult,
)


# ---------------------------------------------------------------------------
# expand_target
# ---------------------------------------------------------------------------

class TestExpandTarget:
    def test_expand_target_single_ip(self):
        result = expand_target("10.0.0.1")
        assert result == ["10.0.0.1"]

    def test_expand_target_cidr_slash_24(self):
        result = expand_target("192.168.1.0/24")
        # /24 has 254 host addresses (192.168.1.1 – 192.168.1.254)
        assert len(result) == 254
        assert "192.168.1.1" in result
        assert "192.168.1.254" in result
        assert "192.168.1.0" not in result   # network address excluded
        assert "192.168.1.255" not in result  # broadcast excluded

    def test_expand_target_hostname(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname",
                            lambda host: "203.0.113.42")
        result = expand_target("pbx.example.com")
        assert result == ["203.0.113.42"]

    def test_expand_target_invalid_returns_empty(self, monkeypatch):
        # Make DNS resolution fail so it falls through to IP validation
        monkeypatch.setattr(socket, "gethostbyname",
                            lambda h: (_ for _ in ()).throw(
                                socket.gaierror("no such host")
                            ))
        result = expand_target("not-a-valid-host-or-ip!!!")
        assert result == []


# ---------------------------------------------------------------------------
# fingerprint_banner
# ---------------------------------------------------------------------------

class TestFingerprintBanner:
    def test_fingerprint_freepbx_from_server_header(self):
        banner = "FPBX-15.0.38(16.30.0)"
        assert fingerprint_banner(banner) == "FreePBX"

    def test_fingerprint_grandstream_from_banner(self):
        banner = "Grandstream UCM6302 1.0.21.7"
        assert fingerprint_banner(banner) == "Grandstream"

    def test_fingerprint_3cx_from_header(self):
        banner = "3CXPhoneSystem 20.0 build 1234"
        assert fingerprint_banner(banner) == "3CX"

    def test_fingerprint_asterisk_from_server(self):
        banner = "Asterisk PBX 18.12.1"
        assert fingerprint_banner(banner) == "Asterisk"

    def test_fingerprint_unknown_from_unknown_banner(self):
        banner = "nginx/1.24.0"
        assert fingerprint_banner(banner) == "unknown"


# ---------------------------------------------------------------------------
# version_extract
# ---------------------------------------------------------------------------

class TestVersionExtraction:
    def test_version_extraction_from_fpbx_header(self):
        banner = "FPBX-15.0.38(16.30.0)"
        result = version_extract(banner)
        assert result == "FreePBX 15.0.38 / Asterisk 16.30.0"

    def test_version_extract_freepbx_plain(self):
        result = version_extract("FreePBX 16.0.19")
        assert result == "FreePBX 16.0.19"

    def test_version_extract_asterisk(self):
        result = version_extract("Asterisk PBX 18.12.1")
        assert result == "Asterisk 18.12.1"

    def test_version_extract_3cx(self):
        result = version_extract("3CXPhoneSystem 20.0")
        assert result == "3CX 20.0"

    def test_version_extract_no_match_returns_none(self):
        result = version_extract("Apache/2.4.51")
        assert result is None

    def test_version_extract_empty_returns_none(self):
        result = version_extract("")
        assert result is None


# ---------------------------------------------------------------------------
# sweep — mocked at probe_host level
# ---------------------------------------------------------------------------

class _FakeSipResp:
    """Minimal stand-in for sip.SipResponse as returned by sip.options_probe."""
    def __init__(self, status_code=200, server="Asterisk PBX 18.12.1", reason="OK"):
        self.status_code = status_code
        self.server = server
        self.reason = reason
        self.auth_params = {}


class TestSweep:
    def test_sweep_returns_host_objects(self, monkeypatch):
        """sweep() collects HostResult objects for live hosts."""
        def mock_probe_host(host, **kwargs):
            return HostResult(
                ip=host,
                open_ports=[{"port": 5060, "proto": "udp", "service": "SIP"}],
                fingerprint="Asterisk",
            )

        monkeypatch.setattr(discovery, "probe_host", mock_probe_host)
        results = discovery.sweep(["10.0.0.1", "10.0.0.2"], timeout=0.1,
                                   rate_per_second=1000, workers=2)
        assert len(results) == 2
        ips = {r.ip for r in results}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips
        for r in results:
            assert isinstance(r, HostResult)

    def test_sweep_empty_network_returns_empty(self, monkeypatch):
        """sweep() with empty target list returns empty list."""
        called = []

        def mock_probe_host(host, **kwargs):
            called.append(host)
            return None

        monkeypatch.setattr(discovery, "probe_host", mock_probe_host)
        results = discovery.sweep([], timeout=0.1, rate_per_second=1000, workers=2)
        assert results == []
        assert called == []

    def test_sweep_respects_timeout(self, monkeypatch):
        """sweep() passes the timeout kwarg through to probe_host."""
        received_timeouts = []

        def mock_probe_host(host, timeout=2.0, **kwargs):
            received_timeouts.append(timeout)
            return HostResult(
                ip=host,
                open_ports=[{"port": 5060, "proto": "udp", "service": "SIP"}],
            )

        monkeypatch.setattr(discovery, "probe_host", mock_probe_host)
        discovery.sweep(["10.0.0.1"], timeout=0.5, rate_per_second=1000, workers=1)
        assert received_timeouts == [0.5]

    def test_sweep_none_results_excluded(self, monkeypatch):
        """sweep() silently drops hosts where probe_host returns None."""
        def mock_probe_host(host, **kwargs):
            if host == "10.0.0.1":
                return HostResult(
                    ip=host,
                    open_ports=[{"port": 5060, "proto": "udp", "service": "SIP"}],
                )
            return None  # unreachable host

        monkeypatch.setattr(discovery, "probe_host", mock_probe_host)
        results = discovery.sweep(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            timeout=0.1, rate_per_second=1000, workers=2,
        )
        assert len(results) == 1
        assert results[0].ip == "10.0.0.1"
