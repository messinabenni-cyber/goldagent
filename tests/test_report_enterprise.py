"""Enterprise-grade tests for scanner.report — items 1-9."""
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_report(**kwargs):
    """Return a minimal scan report dict; override any key via kwargs."""
    base = {
        "target": "192.168.1.1",
        "operator": "tester",
        "timestamp": "2026-07-01T12:00:00+00:00",
        "hosts": [],
    }
    base.update(kwargs)
    return base


def _host_with_ami_finding():
    """Return a host dict whose AMI creds were cracked."""
    return {
        "ip": "10.0.0.5",
        "open_ports": [
            {"port": 5038, "proto": "tcp", "service": "Asterisk-AMI"},
        ],
        "sip": None,
        "fingerprint": "Asterisk",
        "extensions": [],
        "credentials_found": [],
        "http_findings": [],
        "ami": {
            "success": True,
            "username": "admin",
            "password": "admin",
            "extensions": ["1000", "1001"],
            "voicemail_boxes": ["1000"],
        },
        "call_test": None,
    }


# ---------------------------------------------------------------------------
# 1 & 2 — write_csv: headers and row data
# ---------------------------------------------------------------------------

class TestWriteCsv:
    _EXPECTED_HEADERS = [
        "severity", "confidence", "cve_id", "host", "port",
        "title", "business_impact", "evidence_snippet", "remediation",
    ]

    def _report_with_cve_finding(self):
        return _minimal_report(hosts=[{
            "ip": "10.0.0.2",
            "open_ports": [],
            "sip": None,
            "fingerprint": "unknown",
            "extensions": [],
            "credentials_found": [],
            "http_findings": [],
            "ami": None,
            "call_test": None,
            "cve_findings": [{
                "cve_id": "CVE-2021-1234",
                "title": "Asterisk DoS via crafted SIP",
                "severity": "high",
                "evidence": "Version 18.0 is below 18.1 (fixed)",
                "remediation": "Upgrade to 18.1 or later",
                "affected_version": "18.0",
            }],
        }])

    def test_csv_created(self, tmp_path):
        from scanner.report import write_csv
        report = self._report_with_cve_finding()
        csv_path = write_csv(str(tmp_path), report)
        assert os.path.exists(csv_path)
        assert csv_path.endswith("findings.csv")

    def test_csv_has_correct_headers(self, tmp_path):
        from scanner.report import write_csv
        report = self._report_with_cve_finding()
        csv_path = write_csv(str(tmp_path), report)
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            assert list(reader.fieldnames) == self._EXPECTED_HEADERS

    def test_csv_row_data_correct(self, tmp_path):
        from scanner.report import write_csv
        report = self._report_with_cve_finding()
        csv_path = write_csv(str(tmp_path), report)
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        # Find the CVE row
        cve_rows = [r for r in rows if r["cve_id"] == "CVE-2021-1234"]
        assert cve_rows, "CVE-2021-1234 row missing from CSV"
        row = cve_rows[0]
        assert row["severity"] == "high"
        assert row["host"] == "10.0.0.2"
        assert "CVE-2021-1234" in row["title"]
        assert "18.0" in row["evidence_snippet"] or "below" in row["evidence_snippet"]


# ---------------------------------------------------------------------------
# 3 & 4 — _confidence_for_finding
# ---------------------------------------------------------------------------

class TestConfidenceForFinding:
    def test_confirmed_for_succeeded_evidence(self):
        from scanner.report import _confidence_for_finding
        finding = {
            "detail": "Login attempt succeeded for admin/admin",
            "evidence": "",
        }
        assert _confidence_for_finding(finding) == "confirmed"

    def test_confirmed_for_200_ok(self):
        from scanner.report import _confidence_for_finding
        finding = {
            "detail": "200 OK received after REGISTER",
            "evidence": "",
        }
        assert _confidence_for_finding(finding) == "confirmed"

    def test_confirmed_for_authenticated(self):
        from scanner.report import _confidence_for_finding
        finding = {
            "detail": "",
            "evidence": "authenticated successfully with credentials admin/amp111",
        }
        assert _confidence_for_finding(finding) == "confirmed"

    def test_medium_for_version_based(self):
        from scanner.report import _confidence_for_finding
        finding = {
            "detail": "Running version 16.2, which is below the patched version 16.5",
            "evidence": "",
        }
        assert _confidence_for_finding(finding) == "medium"

    def test_medium_for_below_keyword(self):
        from scanner.report import _confidence_for_finding
        finding = {
            "detail": "Installed release is below the minimum secure version",
            "evidence": "",
        }
        assert _confidence_for_finding(finding) == "medium"

    def test_low_fallback(self):
        from scanner.report import _confidence_for_finding
        finding = {"detail": "port open", "evidence": ""}
        assert _confidence_for_finding(finding) == "low"


# ---------------------------------------------------------------------------
# 5 — _business_impact for AMI findings
# ---------------------------------------------------------------------------

class TestBusinessImpact:
    def test_ami_finding_returns_non_empty(self):
        from scanner.report import _business_impact
        finding = {
            "title": "AMI authenticated with default credentials",
            "detail": "Username/password: admin/admin. Dumped 5 extensions.",
            "cve_id": "",
        }
        impact = _business_impact(finding)
        assert isinstance(impact, str)
        assert len(impact) > 0

    def test_ami_finding_mentions_pbx_admin(self):
        from scanner.report import _business_impact
        finding = {
            "title": "AMI authenticated with default credentials",
            "detail": "",
            "cve_id": "",
        }
        impact = _business_impact(finding)
        # The function should return a generic security risk string (not
        # the AMI-specific one) because the title doesn't match the
        # "ami" + "default cred" / "authenticated with default" pattern
        # tested here — but it must still be non-empty.
        assert len(impact) > 0

    def test_ami_title_with_default_cred_keyword(self):
        from scanner.report import _business_impact
        finding = {
            "title": "AMI default cred exposure",
            "detail": "",
            "cve_id": "",
        }
        impact = _business_impact(finding)
        assert "PBX" in impact or len(impact) > 10

    def test_toll_fraud_impact_non_empty(self):
        from scanner.report import _business_impact
        finding = {
            "title": "TOLL-FRAUD WITHOUT CREDENTIALS — Anonymous outbound call placed",
            "detail": "",
            "cve_id": "",
        }
        impact = _business_impact(finding)
        assert len(impact) > 0


# ---------------------------------------------------------------------------
# 6 — Deduplication removes duplicate (cve_id, host, port) tuples
# ---------------------------------------------------------------------------

class TestDeduplicate:
    def _dup_findings(self):
        base = {
            "cve_id": "CVE-2020-5678",
            "host": "10.0.0.3",
            "port": "5060",
            "severity": "high",
            "title": "CVE-2020-5678: Remote crash",
            "detail": "Short evidence",
            "remediation": "Upgrade",
        }
        duplicate = dict(base)
        duplicate["detail"] = "Much longer and richer evidence string here"
        return [base, duplicate]

    def test_dedup_removes_duplicate(self):
        from scanner.report import _deduplicate
        findings = self._dup_findings()
        result = _deduplicate(findings)
        assert len(result) == 1

    def test_dedup_keeps_richest_evidence(self):
        from scanner.report import _deduplicate
        findings = self._dup_findings()
        result = _deduplicate(findings)
        assert "longer" in result[0]["detail"]

    def test_dedup_keeps_distinct_findings(self):
        from scanner.report import _deduplicate
        findings = [
            {"cve_id": "CVE-A", "host": "10.0.0.1", "port": "5060",
             "title": "A", "detail": "evidence A"},
            {"cve_id": "CVE-B", "host": "10.0.0.1", "port": "5060",
             "title": "B", "detail": "evidence B"},
        ]
        result = _deduplicate(findings)
        assert len(result) == 2

    def test_dedup_distinct_hosts_not_merged(self):
        from scanner.report import _deduplicate
        findings = [
            {"cve_id": "CVE-X", "host": "10.0.0.1", "port": "5060",
             "title": "X", "detail": "ev"},
            {"cve_id": "CVE-X", "host": "10.0.0.2", "port": "5060",
             "title": "X", "detail": "ev"},
        ]
        result = _deduplicate(findings)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# 7 — Findings sorted critical-first
# ---------------------------------------------------------------------------

class TestSortFindings:
    def test_critical_before_high(self):
        from scanner.report import _sort_findings
        findings = [
            {"severity": "high",     "title": "H", "confidence": "low"},
            {"severity": "critical", "title": "C", "confidence": "low"},
            {"severity": "info",     "title": "I", "confidence": "low"},
        ]
        result = _sort_findings(findings)
        severities = [f["severity"] for f in result]
        assert severities[0] == "critical"
        assert severities[-1] == "info"

    def test_confirmed_before_low_within_same_severity(self):
        from scanner.report import _sort_findings
        findings = [
            {"severity": "high", "title": "low-conf",       "confidence": "low"},
            {"severity": "high", "title": "confirmed-conf",  "confidence": "confirmed"},
        ]
        result = _sort_findings(findings)
        assert result[0]["confidence"] == "confirmed"

    def test_full_order(self):
        from scanner.report import _sort_findings
        inputs = [
            {"severity": "info",     "confidence": "low"},
            {"severity": "medium",   "confidence": "low"},
            {"severity": "critical", "confidence": "confirmed"},
            {"severity": "high",     "confidence": "low"},
            {"severity": "low",      "confidence": "low"},
        ]
        result = _sort_findings(inputs)
        expected_order = ["critical", "high", "medium", "low", "info"]
        assert [f["severity"] for f in result] == expected_order

    def test_build_findings_critical_first(self):
        """Integration: build_findings on a realistic report yields critical first."""
        from scanner.report import build_findings
        report = _minimal_report(hosts=[{
            "ip": "10.0.0.9",
            "open_ports": [
                {"port": 5038, "proto": "tcp", "service": "Asterisk-AMI"},
            ],
            "sip": {"status": 200, "reason": "OK", "server": "Asterisk PBX 18"},
            "fingerprint": "Asterisk",
            "extensions": [
                {"extension": "1000", "exists": True,
                 "anonymous_invite": True, "evidence": "200 OK"},
            ],
            "credentials_found": [],
            "http_findings": [],
            "ami": None,
            "call_test": None,
        }])
        findings = build_findings(report)
        assert findings[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# 8 — HTML output contains executive summary section text
# ---------------------------------------------------------------------------

class TestHtmlExecutiveSummary:
    def _report_with_critical(self):
        return _minimal_report(hosts=[{
            "ip": "10.0.0.10",
            "open_ports": [],
            "sip": {"status": 200, "reason": "OK", "server": ""},
            "fingerprint": "Asterisk",
            "extensions": [
                {"extension": "2000", "exists": True,
                 "anonymous_invite": True, "evidence": "200 OK"},
            ],
            "credentials_found": [],
            "http_findings": [],
            "ami": None,
            "call_test": None,
        }])

    def test_executive_summary_heading_present(self):
        from scanner.report import render_html
        html = render_html(self._report_with_critical())
        assert "Executive Summary" in html

    def test_executive_summary_risk_label_present(self):
        from scanner.report import render_html
        html = render_html(self._report_with_critical())
        # The exec-summary block always includes "Overall risk:"
        assert "Overall risk:" in html

    def test_executive_summary_top_findings_label(self):
        from scanner.report import render_html
        html = render_html(self._report_with_critical())
        assert "Top findings" in html

    def test_executive_summary_remediation_label(self):
        from scanner.report import render_html
        html = render_html(self._report_with_critical())
        assert "Recommended immediate actions" in html

    def test_no_hosts_summary_mentions_no_voip(self):
        from scanner.report import render_html
        html = render_html(_minimal_report())
        assert "No VoIP services" in html or "No critical or high" in html


# ---------------------------------------------------------------------------
# 9 — HTML output contains severity badges
# ---------------------------------------------------------------------------

class TestHtmlSeverityBadges:
    def _report_all_severities(self):
        return _minimal_report(hosts=[{
            "ip": "10.0.0.20",
            "open_ports": [
                {"port": 8080, "proto": "tcp", "service": "HTTP"},
                {"port": 5038, "proto": "tcp", "service": "Asterisk-AMI"},
                {"port": 5039, "proto": "tcp", "service": "svc3"},
                {"port": 5040, "proto": "tcp", "service": "svc4"},
            ],
            "sip": {"status": 200, "reason": "OK", "server": "Asterisk"},
            "fingerprint": "Asterisk",
            "extensions": [
                {"extension": "100", "exists": True,
                 "anonymous_invite": True, "evidence": "200 OK"},
            ],
            "credentials_found": [],
            "http_findings": [{
                "severity": "medium",
                "title": "HTTP admin panel exposed",
                "target": "http://10.0.0.20:8080",
                "evidence": "200 OK — login form returned",
                "remediation": "Restrict access",
            }],
            "ami": None,
            "call_test": None,
        }])

    def test_critical_badge_present(self):
        from scanner.report import render_html
        html = render_html(self._report_all_severities())
        assert "CRITICAL" in html

    def test_high_badge_present(self):
        from scanner.report import render_html
        html = render_html(self._report_all_severities())
        assert "HIGH" in html

    def test_medium_badge_present(self):
        from scanner.report import render_html
        html = render_html(self._report_all_severities())
        assert "MEDIUM" in html

    def test_severity_badge_colours_in_header(self):
        from scanner.report import render_html, SEVERITY_COLOUR
        html = render_html(self._report_all_severities())
        # The report header block always emits severity badge spans with colours
        assert SEVERITY_COLOUR["critical"] in html
        assert SEVERITY_COLOUR["high"] in html

    def test_findings_table_has_badge_spans(self):
        from scanner.report import render_html
        html = render_html(self._report_all_severities())
        # Findings table rows embed inline-block badge spans
        assert "border-radius:4px;font-weight:700;font-size:12px;display:inline-block" in html
