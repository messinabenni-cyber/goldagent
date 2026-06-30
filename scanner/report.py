"""HTML report — single file output.

Deliberately minimal: one self-contained HTML document with executive
summary, host findings table, and per-host detail sections. No external
CSS, no JavaScript, no embedded fonts. Opens cleanly in any browser and
prints to a PDF that an auditor can attach to their workpaper.
"""
from __future__ import annotations

import html as _html
import json
import time
from pathlib import Path

from .utils import severity_counts, severity_rank


SEVERITY_COLOUR = {
    "critical": "#8b0000",
    "high":     "#c0392b",
    "medium":   "#d68910",
    "low":      "#1e8449",
    "info":     "#2874a6",
}


def build_findings(report: dict) -> list[dict]:
    """Walk the report dict and produce a flat list of findings."""
    findings: list[dict] = []

    for host in report.get("hosts", []):
        ip = host["ip"]
        sip_info = host.get("sip") or {}
        server = sip_info.get("server", "")
        fp = host.get("fingerprint", "unknown")

        # SIP reachable — info
        if sip_info:
            findings.append({
                "severity": "info", "host": ip,
                "title": f"SIP service reachable on {ip}",
                "detail": (f"PBX fingerprint: {fp}. Server: {server or '(none)'}. "
                           f"OPTIONS returned {sip_info.get('status')} "
                           f"{sip_info.get('reason', '')}."),
                "remediation": (
                    "Confirm this SIP endpoint should be exposed to the "
                    "internet. Restrict by ACL/firewall to known peers."
                ),
            })

        # Server banner leak
        if server and server.lower() != "(hidden)":
            findings.append({
                "severity": "low", "host": ip,
                "title": "SIP server reveals software/version",
                "detail": f"Server header: {server!r}",
                "remediation": (
                    "Strip or generalise the Server/User-Agent headers to "
                    "slow reconnaissance and version-targeted exploits."
                ),
            })

        # AMI exposed
        for port in host.get("open_ports", []):
            if port.get("service") == "Asterisk-AMI":
                findings.append({
                    "severity": "high", "host": ip,
                    "title": "Asterisk Manager Interface (AMI) exposed",
                    "detail": (
                        f"TCP/{port['port']} responded. AMI grants full "
                        f"call-plane control if credentials (or defaults) "
                        f"are accepted."
                    ),
                    "remediation": (
                        "Bind AMI to 127.0.0.1 or a management VLAN. "
                        "Require strong credentials and TLS."
                    ),
                })

        # Extensions
        for ext in host.get("extensions", []):
            if ext.get("open_register"):
                findings.append({
                    "severity": "critical", "host": ip,
                    "title": (f"Extension {ext['extension']} accepts REGISTER "
                              "without authentication"),
                    "detail": ext.get("evidence", ""),
                    "remediation": (
                        "Require digest authentication on all REGISTER "
                        "requests. In Asterisk: insecure=no; auth=digest."
                    ),
                })
            if ext.get("anonymous_invite"):
                findings.append({
                    "severity": "critical", "host": ip,
                    "title": (f"Anonymous INVITE accepted for extension "
                              f"{ext['extension']}"),
                    "detail": ext.get("evidence", ""),
                    "remediation": (
                        "Set allowguest=no in sip.conf. Require digest "
                        "authentication on all INVITE requests."
                    ),
                })

        # Credentials cracked
        for cred in host.get("credentials_found", []):
            findings.append({
                "severity": "critical", "host": ip,
                "title": f"Valid credentials for extension {cred['extension']}",
                "detail": (f"{cred['username']}/{cred['password']} accepted "
                           f"on registration. {cred.get('evidence', '')}"),
                "remediation": (
                    "Enforce password complexity (min 14 chars, mixed case, "
                    "no dictionary words, not equal to username/extension)."
                ),
            })

        # AMI exploit
        ami = host.get("ami")
        if ami and ami.get("success"):
            findings.append({
                "severity": "critical", "host": ip,
                "title": "AMI authenticated with default credentials",
                "detail": (
                    f"Username/password: {ami['username']}/{ami['password']}. "
                    f"Dumped {len(ami.get('extensions', []))} extensions, "
                    f"{len(ami.get('voicemail_boxes', []))} voicemail boxes."
                ),
                "remediation": (
                    "Change AMI credentials immediately. Bind AMI to "
                    "localhost or management network only. Use TLS."
                ),
            })

        # Toll-fraud PoC result
        ct = host.get("call_test")
        if ct and ct.get("success"):
            findings.append({
                "severity": "critical", "host": ip,
                "title": "Outbound call placed via PBX (toll-fraud PoC)",
                "detail": (
                    f"Called {ct['call_to']} from {ct['call_from']}. "
                    f"{ct.get('evidence', '')}"
                ),
                "remediation": (
                    "Configure egress dial-plan restrictions: deny "
                    "international and premium-rate destinations by default. "
                    "Require allow-list per extension."
                ),
            })
        elif ct and ct.get("reached_dialplan"):
            findings.append({
                "severity": "high", "host": ip,
                "title": "PBX engaged dial plan for unauthenticated INVITE",
                "detail": (
                    f"Called {ct['call_to']} from {ct['call_from']}. "
                    f"Final: {ct.get('reason', '')}. Provisional response "
                    "indicates the PBX accepted the call and started routing "
                    "before rejecting — anonymous INVITE is reaching the "
                    "dialplan."
                ),
                "remediation": (
                    "Set allowguest=no. Verify anonymous SIP context is "
                    "empty or contains only Hangup()."
                ),
            })

        # HTTP probes
        for f in host.get("http_findings", []):
            findings.append({
                "severity": f["severity"], "host": ip,
                "title": f["title"],
                "detail": f"{f['target']}: {f['evidence']}",
                "remediation": f["remediation"],
            })

    findings.sort(key=lambda x: severity_rank(x.get("severity", "info")))
    return findings


def _esc(value) -> str:
    return _html.escape(str(value))


def render_html(report: dict) -> str:
    """Render the full HTML report. Self-contained — no external assets."""
    findings = build_findings(report)
    counts = severity_counts(findings)
    report["findings"] = findings
    report["severity_counts"] = counts

    target = _esc(report.get("target", "?"))
    operator = _esc(report.get("operator", "?"))
    timestamp = _esc(report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S")))
    scope_file = _esc(report.get("scope_file", ""))
    scope_sha = _esc(report.get("scope_sha256", ""))

    # KPI cards
    kpi_html = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        col = SEVERITY_COLOUR[sev]
        kpi_html += (
            f'<div class="kpi" style="border-top:4px solid {col}">'
            f'<div class="n">{c}</div>'
            f'<div class="l">{sev.upper()}</div></div>'
        )

    # Findings table
    rows_html = ""
    for f in findings:
        sev = f.get("severity", "info")
        col = SEVERITY_COLOUR.get(sev, "#666")
        rows_html += (
            f'<tr>'
            f'<td style="background:{col};color:#fff;font-weight:700">'
            f'{sev.upper()}</td>'
            f'<td>{_esc(f.get("host", ""))}</td>'
            f'<td><b>{_esc(f.get("title", ""))}</b>'
            f'<br><span class="detail">{_esc(f.get("detail", ""))}</span>'
            f'<br><span class="rem"><b>Remediation:</b> '
            f'{_esc(f.get("remediation", ""))}</span></td>'
            f'</tr>'
        )

    # Per-host appendices
    host_sections = ""
    for h in report.get("hosts", []):
        ports_text = ", ".join(
            f"{p['port']}/{p['proto']} ({p['service']})"
            for p in h.get("open_ports", [])
        ) or "—"
        exts_count = len(h.get("extensions", []))
        creds_count = len(h.get("credentials_found", []))
        host_sections += f"""
<h3>{_esc(h['ip'])} <span class="muted">{_esc(h.get('fingerprint','unknown'))}</span></h3>
<table class="kv">
<tr><th>Open ports</th><td>{_esc(ports_text)}</td></tr>
<tr><th>Extensions found</th><td>{exts_count}</td></tr>
<tr><th>Credentials cracked</th><td>{creds_count}</td></tr>
</table>
"""

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>VoIP Pentest Report — {target}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,Arial,sans-serif;margin:40px;max-width:1100px;color:#222;line-height:1.5}}
h1{{color:#0b1a33;border-bottom:3px solid #0b1a33;padding-bottom:8px;margin-bottom:4px}}
h2{{color:#16213e;margin-top:36px;border-left:4px solid #16213e;padding-left:12px}}
h3{{color:#16213e;margin-top:24px}}
.meta{{color:#666;font-size:14px;margin-bottom:24px}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{padding:10px 12px;border:1px solid #ddd;text-align:left;vertical-align:top;font-size:14px}}
th{{background:#0b1a33;color:#fff;font-weight:600;font-size:13px}}
.kpi-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}}
.kpi{{background:#fafafa;padding:20px;text-align:center;border-radius:6px}}
.kpi .n{{font-size:32px;font-weight:700;color:#0b1a33;line-height:1}}
.kpi .l{{font-size:11px;text-transform:uppercase;color:#666;margin-top:8px;letter-spacing:1.5px}}
.detail{{font-size:13px;color:#444}}
.rem{{font-size:13px;color:#0b1a33;display:block;margin-top:6px;padding-top:6px;border-top:1px dashed #ccc}}
.muted{{color:#888;font-weight:400;font-size:14px}}
.kv th{{width:200px;background:#f4f4f4;color:#222;font-weight:600}}
.banner{{background:#fff3cd;border-left:4px solid #d68910;padding:14px;margin:16px 0;font-size:13px}}
</style>
</head><body>

<h1>VoIP Penetration Test Report</h1>
<div class="meta">
  <b>Target:</b> <code>{target}</code> &nbsp;·&nbsp;
  <b>Operator:</b> {operator} &nbsp;·&nbsp;
  <b>Generated:</b> {timestamp}
</div>

{f'<div class="banner"><b>Scope of work:</b> {scope_file}<br><b>SHA-256:</b> <code>{scope_sha}</code></div>' if scope_file else ''}

<h2>Executive Summary</h2>
<div class="kpi-grid">{kpi_html}</div>

<p>This report documents the findings of an authorised VoIP penetration
test against <code>{target}</code>. The assessment targeted SIP/PBX
infrastructure for weaknesses that enable unauthorised call routing,
toll fraud, and management-plane compromise.
{counts.get('critical', 0)} critical and {counts.get('high', 0)} high
severity findings were identified.</p>

<h2>Findings</h2>
<table>
<tr><th style="width:90px">Severity</th><th style="width:140px">Host</th>
<th>Finding</th></tr>
{rows_html or '<tr><td colspan="3"><i>No findings.</i></td></tr>'}
</table>

<h2>Host Detail</h2>
{host_sections or '<p><i>No hosts responded.</i></p>'}

<div style="margin-top:60px;padding-top:20px;border-top:1px solid #ddd;color:#888;font-size:11px">
Generated by VoIPScan v3.0 · {timestamp}
</div>

</body></html>"""


def write_all(report_dir: str, report: dict) -> dict[str, str]:
    """Write report.html + report.json into report_dir.

    Returns a dict of {"html": path, "json": path}.
    """
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)

    html_path = out / "report.html"
    html_path.write_text(render_html(report), encoding="utf-8")

    # Also drop a JSON snapshot for machine-readable downstream tooling.
    # Cheap to include — keeps the option open.
    json_path = out / "report.json"
    json_path.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )

    return {"html": str(html_path), "json": str(json_path)}
