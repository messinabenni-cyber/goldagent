"""Tests for scanner.report."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBuildFindings:
    def _sample(self):
        return {
            "target": "10.0.0.1",
            "operator": "tester",
            "timestamp": "2026-06-02T10:00:00",
            "hosts": [{
                "ip": "10.0.0.1",
                "open_ports": [
                    {"port": 5060, "proto": "udp", "service": "SIP",
                     "banner": "Asterisk PBX 18"},
                    {"port": 5038, "proto": "tcp", "service": "Asterisk-AMI"},
                ],
                "sip": {"status": 200, "reason": "OK",
                        "server": "Asterisk PBX 18"},
                "fingerprint": "Asterisk",
                "extensions": [
                    {"extension": "1000", "exists": True,
                     "anonymous_invite": True, "evidence": "x"},
                ],
                "credentials_found": [
                    {"extension": "1001", "username": "1001",
                     "password": "1001", "evidence": "200 OK"},
                ],
                "http_findings": [],
                "ami": None,
                "call_test": {
                    "call_to": "+447900900900", "call_from": "1000",
                    "success": True, "reached_dialplan": True,
                    "status_code": 200, "reason": "OK",
                    "evidence": "200 OK (toll-fraud demonstrated)",
                    "srtp_state": "off", "dtmf_digits_sent": [],
                },
            }],
        }

    def test_finds_toll_fraud(self):
        from scanner.report import build_findings
        findings = build_findings(self._sample())
        titles = [f["title"] for f in findings]
        assert any("toll-fraud" in t.lower() for t in titles)

    def test_finds_anonymous_invite(self):
        from scanner.report import build_findings
        findings = build_findings(self._sample())
        titles = [f["title"] for f in findings]
        assert any("anonymous invite" in t.lower() for t in titles)

    def test_finds_ami_exposed(self):
        from scanner.report import build_findings
        findings = build_findings(self._sample())
        titles = [f["title"] for f in findings]
        assert any("ami" in t.lower() for t in titles)

    def test_severity_ordering(self):
        from scanner.report import build_findings
        from scanner.utils import severity_rank
        findings = build_findings(self._sample())
        ranks = [severity_rank(f["severity"]) for f in findings]
        assert ranks == sorted(ranks)


class TestWriteAll:
    def test_emits_html_and_json(self, tmp_path):
        from scanner.report import write_all
        report = {
            "target": "10.0.0.1", "operator": "t",
            "timestamp": "2026-06-02",
            "hosts": [{"ip": "10.0.0.1", "open_ports": [], "sip": None,
                        "fingerprint": "unknown", "extensions": [],
                        "credentials_found": [], "http_findings": [],
                        "ami": None, "call_test": None}],
        }
        paths = write_all(str(tmp_path), report)
        assert "html" in paths
        assert "json" in paths
        assert os.path.exists(paths["html"])
        assert os.path.exists(paths["json"])
        html = open(paths["html"]).read()
        assert "<!doctype html>" in html
        assert "10.0.0.1" in html

    def test_html_escapes_evil_input(self, tmp_path):
        """Malicious data in findings must not produce executable script tags."""
        from scanner.report import write_all
        report = {
            "target": "<script>alert(1)</script>",
            "operator": "t", "timestamp": "2026-06-02",
            "hosts": [],
        }
        paths = write_all(str(tmp_path), report)
        html = open(paths["html"]).read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
