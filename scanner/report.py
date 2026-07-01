"""HTML report — single file output.

Deliberately minimal: one self-contained HTML document with executive
summary, host findings table, and per-host detail sections. No external
CSS, no JavaScript, no embedded fonts. Opens cleanly in any browser and
prints to a PDF that an auditor can attach to their workpaper.
"""
from __future__ import annotations

import csv
import html as _html
import json
import time
from pathlib import Path

from .utils import severity_counts, severity_rank


def _iso_now() -> str:
    """Return current UTC time as a proper ISO 8601 string with colon in offset.

    time.strftime("%z") produces "+0000"; ISO 8601 requires "+00:00".
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    # Insert colon in timezone offset: +0000 → +00:00
    if len(ts) > 5 and ts[-5] in ('+', '-') and ':' not in ts[-5:]:
        ts = ts[:-2] + ':' + ts[-2:]
    return ts


SEVERITY_COLOUR = {
    "critical": "#8b0000",
    "high":     "#c0392b",
    "medium":   "#d68910",
    "low":      "#1e8449",
    "info":     "#2874a6",
}

# Severity order used for sorting (lower = higher priority).
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_ORDER = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# Confidence scoring (item 2)
# ---------------------------------------------------------------------------

def _confidence_for_finding(finding: dict) -> str:
    """Return a confidence label based on the evidence text of a finding."""
    evidence = (
        finding.get("detail", "") + " " + finding.get("evidence", "")
    ).lower()

    if any(kw in evidence for kw in ("succeeded", "200 ok", "authenticated", "cracked")):
        return "confirmed"
    if any(kw in evidence for kw in ("reachable", "banner", "verified")):
        return "high"
    if any(kw in evidence for kw in ("below", "version")):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Business impact (item 3)
# ---------------------------------------------------------------------------

def _business_impact(finding: dict) -> str:
    """Return a concise business risk string specific to VoIP/PBX findings."""
    cve_id = finding.get("cve_id", "").upper()
    title  = finding.get("title", "").lower()
    detail = finding.get("detail", "").lower()

    # AMI default credentials
    if "ami" in title and any(
        kw in title for kw in ("default cred", "authenticated with default")
    ):
        return (
            "Attacker gains full PBX admin access; can originate toll-fraud "
            "calls, dump all extensions and voicemail, and persist a backdoor"
        )

    # Anonymous dial-out / toll-fraud
    if "anonymous" in title and any(
        kw in title for kw in ("outbound", "dial", "invite", "toll-fraud")
    ):
        return (
            "Attacker can place unlimited international calls at the "
            "organisation's expense with no authentication required"
        )
    if "toll-fraud" in title or "outbound call placed" in title:
        return (
            "Attacker can place unlimited international calls at the "
            "organisation's expense with no authentication required"
        )

    # SIP enumeration
    if any(kw in title for kw in ("sip service reachable", "extension", "enumerat")):
        return (
            "Extension list exposed — enables targeted brute-force and "
            "social engineering attacks"
        )

    # Cleartext SIP / media downgrade
    if any(kw in title for kw in ("cleartext", "srtp", "unencrypted", "downgrad")):
        return (
            "All SIP credentials, call metadata, and SRTP keys are visible "
            "to any passive network observer"
        )

    # CVE version-based — derive from CVE description where possible
    if cve_id and ("below" in detail or "version" in detail or "affected" in detail):
        return (
            f"{cve_id} affects a specific software version installed on this "
            "host; a remote attacker may exploit this vulnerability without "
            "authentication to achieve code execution or denial of service"
        )

    return (
        "Security misconfiguration increases attack surface and risk of "
        "service disruption"
    )


# ---------------------------------------------------------------------------
# Deduplication (item 5)
# ---------------------------------------------------------------------------

def _deduplicate(findings: list[dict]) -> list[dict]:
    """Deduplicate by (cve_id, host, port), keeping richest evidence."""
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (
            f.get("cve_id", ""),
            f.get("host", ""),
            str(f.get("port", "")),
        )
        if key == ("", f.get("host", ""), ""):
            # No cve_id / port — use title as discriminator to avoid over-merging
            key = (f.get("title", ""), f.get("host", ""), "")
        if key not in seen:
            seen[key] = f
        else:
            # Keep the one with longer evidence (richer detail)
            existing = seen[key]
            if len(str(f.get("detail", ""))) > len(str(existing.get("detail", ""))):
                seen[key] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# Sorting (item 6)
# ---------------------------------------------------------------------------

def _sort_findings(findings: list[dict]) -> list[dict]:
    """Sort critical → high → medium → low → info; confirmed confidence first."""
    return sorted(
        findings,
        key=lambda f: (
            _SEV_ORDER.get(f.get("severity", "info"), 99),
            _CONF_ORDER.get(f.get("confidence", "low"), 99),
        ),
    )


# ---------------------------------------------------------------------------
# Build findings (combines all enrichment)
# ---------------------------------------------------------------------------

def build_findings(report: dict) -> list[dict]:
    """Walk the report dict and produce a flat, enriched, deduplicated list of findings."""
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
                    "port": port["port"],
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

        # Host exposed services — aggregate all open ports as a single finding
        open_ports = host.get("open_ports", [])
        if open_ports:
            port_list = ", ".join(
                f"{p['port']}/{p.get('proto', 'tcp')} ({p.get('service', 'unknown')})"
                for p in open_ports
            )
            sev = "medium" if len(open_ports) > 3 else "info"
            findings.append({
                "severity": sev, "host": ip,
                "title": f"Host exposed services on {ip}",
                "detail": (
                    f"{len(open_ports)} open port(s) detected: {port_list}. "
                    "Each exposed service increases the attack surface available "
                    "to a remote adversary."
                ),
                "remediation": (
                    "Apply firewall rules to restrict access to each service "
                    "to authorised source IPs only. Disable or remove any "
                    "service that is not required."
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
            _anon_dialout = ct.get("anonymous_dialout", False)
            _confirmed = ct.get("call_confirmed", False)
            _conf_suffix = " (DIALOG CONFIRMED)" if _confirmed else " (SIP 200 OK)"
            _tf_title = (
                "TOLL-FRAUD WITHOUT CREDENTIALS — Anonymous outbound call placed" + _conf_suffix
                if _anon_dialout
                else "TOLL-FRAUD (CREDENTIALED) — Outbound call placed via PBX" + _conf_suffix
            )
            findings.append({
                "severity": "critical", "host": ip,
                "title": _tf_title,
                "detail": (
                    f"Called {ct['call_to']} from {ct['call_from']}. "
                    + ("No authentication required — call placed without any credentials. " if _anon_dialout else "")
                    + f"{ct.get('evidence', '')}"
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

        # SRTP downgrade
        if ct and ct.get("srtp_state") == "downgraded":
            findings.append({
                "severity": "medium", "host": ip,
                "title": "PBX silently accepted unencrypted media when SRTP was offered",
                "detail": (
                    f"An INVITE with a=crypto (AES_CM_128_HMAC_SHA1_80) was sent. "
                    f"The 200 OK answer omitted a=crypto, indicating the PBX "
                    f"downgraded the call to cleartext RTP without notifying either party."
                ),
                "remediation": (
                    "Set rtp_encryption=yes (or media_encryption=sdes) on all "
                    "trunks. Configure force_avp=no and set a deny rule for "
                    "RTP/AVP when SAVP is offered."
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

        # CVE / configuration checks
        for f in host.get("cve_findings", []):
            title = f.get("title", "")
            cve_id = f.get("cve_id", "")
            if cve_id and not title.startswith(cve_id):
                title = f"{cve_id}: {title}"
            ver = f.get("affected_version", "")
            detail = f['evidence']
            if ver:
                detail = f"[{ver}] {detail}"
            findings.append({
                "severity": f["severity"], "host": ip,
                "cve_id": cve_id,
                "title": title,
                "detail": detail,
                "remediation": f["remediation"],
            })

    # Enrich each finding with confidence and business_impact before dedup/sort
    for f in findings:
        f.setdefault("confidence", _confidence_for_finding(f))
        f.setdefault("business_impact", _business_impact(f))

    findings = _deduplicate(findings)
    findings = _sort_findings(findings)
    return findings


def _esc(value) -> str:
    return _html.escape(str(value))


def _auto_executive_summary(report: dict, findings: list[dict]) -> str:
    """Build a one-paragraph plain-English summary from the scan data."""
    hosts = report.get("hosts", [])
    target = report.get("target", "the target")
    counts = severity_counts(findings)

    if not hosts:
        return (
            f"No VoIP services were discovered on <code>{_esc(target)}</code> "
            "during the assessment window. This may indicate the target was "
            "offline, protected by an upstream firewall, or the port range "
            "was restricted. No findings to report."
        )

    # Gather first interesting host data
    pbx_names: list[str] = []
    pbx_ips: list[str] = []
    toll_fraud_ip: str | None = None
    anon_invite_count = 0
    cred_count = 0
    ami_pwned = False

    for h in hosts:
        fp = h.get("fingerprint", "unknown")
        ip = h.get("ip", "")
        if fp != "unknown":
            label = fp
            sip_server = (h.get("sip") or {}).get("server", "")
            if sip_server and fp.lower() in sip_server.lower():
                label = sip_server.split("/")[0].strip()
            pbx_names.append(label)
        pbx_ips.append(ip)

        ct = h.get("call_test")
        if ct and ct.get("success") and not toll_fraud_ip:
            toll_fraud_ip = ip

        anon_invite_count += sum(
            1 for e in h.get("extensions", []) if e.get("anonymous_invite")
        )
        cred_count += len(h.get("credentials_found", []))
        if (h.get("ami") or {}).get("success"):
            ami_pwned = True

    total = counts.get("critical", 0) + counts.get("high", 0)
    host_desc = (
        f"{pbx_names[0]} on {pbx_ips[0]}"
        if (pbx_names and pbx_ips)
        else f"{len(hosts)} PBX host(s)"
    )

    parts: list[str] = [
        f"{counts.get('critical', 0)} critical and "
        f"{counts.get('high', 0)} high severity finding(s) were identified "
        f"against {_esc(host_desc)}."
    ]

    if toll_fraud_ip:
        parts.append(
            "Toll fraud is <strong>immediately exploitable</strong>: "
            "the tool successfully placed an outbound call to the operator-"
            "controlled destination via the PBX without authentication, "
            "confirming that any caller on the internet can route calls at "
            "the account-holder's expense."
        )

    if anon_invite_count:
        parts.append(
            f"{anon_invite_count} extension(s) accepted INVITE requests "
            "without requiring authentication, enabling call routing, "
            "eavesdropping setup, and service abuse without credentials."
        )

    if cred_count:
        parts.append(
            f"{cred_count} valid extension credential(s) were recovered via "
            "default-password spraying — confirmed working on REGISTER."
        )

    if ami_pwned:
        parts.append(
            "The Asterisk Manager Interface authenticated with default "
            "credentials, granting full call-plane control and access to "
            "extension/voicemail enumeration via AMI commands."
        )

    if total == 0:
        parts = [
            f"No critical or high severity findings were identified against "
            f"{_esc(host_desc)}. "
            "Lower-severity findings (informational / medium) are detailed in "
            "the findings table below."
        ]

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Executive summary block (item 4)
# ---------------------------------------------------------------------------

def _render_exec_summary_block(findings: list[dict], counts: dict) -> str:
    """Render a professional executive summary HTML block for the top of the report."""
    # Determine overall risk level from highest severity present
    if counts.get("critical", 0) > 0:
        risk_label = "CRITICAL"
        risk_colour = SEVERITY_COLOUR["critical"]
        risk_sentence = (
            "This assessment has identified <strong>critical severity vulnerabilities</strong> "
            "that represent an immediate risk to the organisation — exploitation is possible "
            "without authentication and could result in direct financial loss through toll fraud, "
            "full PBX compromise, or service disruption."
        )
    elif counts.get("high", 0) > 0:
        risk_label = "HIGH"
        risk_colour = SEVERITY_COLOUR["high"]
        risk_sentence = (
            "This assessment has identified <strong>high severity vulnerabilities</strong> "
            "that significantly increase the probability of a successful attack on the "
            "VoIP infrastructure and require prompt remediation."
        )
    elif counts.get("medium", 0) > 0:
        risk_label = "MEDIUM"
        risk_colour = SEVERITY_COLOUR["medium"]
        risk_sentence = (
            "The overall risk posture is <strong>medium</strong>. No immediately exploitable "
            "vulnerabilities were confirmed, but configuration weaknesses were identified "
            "that could be leveraged in a chained attack."
        )
    else:
        risk_label = "LOW / INFORMATIONAL"
        risk_colour = SEVERITY_COLOUR["info"]
        risk_sentence = (
            "No critical or high severity findings were confirmed during this assessment. "
            "The overall risk posture is <strong>low</strong>; only informational observations "
            "are recorded."
        )

    # Top 3 critical/high findings
    top_findings = [
        f for f in findings
        if f.get("severity") in ("critical", "high")
    ][:3]

    top_bullets = ""
    for f in top_findings:
        sev = f.get("severity", "info")
        col = SEVERITY_COLOUR.get(sev, "#666")
        top_bullets += (
            f'<li>'
            f'<span style="background:{col};color:#fff;padding:2px 7px;'
            f'border-radius:3px;font-size:11px;font-weight:700;margin-right:6px">'
            f'{sev.upper()}</span>'
            f'<b>{_esc(f.get("title", ""))}</b> '
            f'<span style="color:#666;font-size:13px">({_esc(f.get("host",""))})</span>'
            f'</li>'
        )
    if not top_bullets:
        top_bullets = "<li>No critical or high severity findings identified.</li>"

    # Top 3 remediations
    rem_bullets = ""
    seen_rems: set[str] = set()
    for f in findings:
        rem = f.get("remediation", "").strip()
        if rem and rem not in seen_rems and f.get("severity") in ("critical", "high"):
            seen_rems.add(rem)
            rem_bullets += f"<li>{_esc(rem)}</li>"
        if len(seen_rems) >= 3:
            break
    if not rem_bullets:
        rem_bullets = "<li>Review and harden VoIP configuration per vendor guidelines.</li>"

    return f"""
<div style="border-left:6px solid {risk_colour};background:#fafafa;padding:20px 24px;
            border-radius:0 8px 8px 0;margin:20px 0">
  <h2 style="margin-top:0;color:{risk_colour}">&#9632; Executive Summary
    <span style="font-size:14px;font-weight:400;color:#555;margin-left:10px">
      Overall risk: <strong style="color:{risk_colour}">{_esc(risk_label)}</strong>
    </span>
  </h2>
  <p style="margin:8px 0 16px">{risk_sentence}</p>
  <p style="font-weight:600;margin:0 0 6px">Top findings:</p>
  <ul style="margin:0 0 16px;padding-left:20px;line-height:2">{top_bullets}</ul>
  <p style="font-weight:600;margin:0 0 6px">Recommended immediate actions:</p>
  <ol style="margin:0;padding-left:20px;line-height:1.8">{rem_bullets}</ol>
</div>"""


# ---------------------------------------------------------------------------
# HTML render
# ---------------------------------------------------------------------------

def render_html(report: dict) -> str:
    """Render the full HTML report. Self-contained — no external assets."""
    findings = build_findings(report)
    counts = severity_counts(findings)
    report["findings"] = findings
    report["severity_counts"] = counts

    target = _esc(report.get("target", "?"))
    operator = _esc(report.get("operator", "?"))
    timestamp = _esc(report.get("timestamp", _iso_now()))
    scope_file = _esc(report.get("scope_file", ""))
    scope_sha = _esc(report.get("scope_sha256", ""))

    # --- Professional report header (item 7) ---
    finding_badges = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        col = SEVERITY_COLOUR[sev]
        finding_badges += (
            f'<span style="background:{col};color:#fff;padding:4px 10px;'
            f'border-radius:12px;font-size:12px;font-weight:700;margin-right:6px">'
            f'{c} {sev.upper()}</span>'
        )

    report_header_html = f"""
<div class="report-header" style="background:#1a1a2e;color:white;padding:20px;border-radius:8px;margin-bottom:20px">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:22px;font-weight:700;letter-spacing:1px">VoIPScan Enterprise</div>
      <div style="font-size:13px;opacity:0.65;margin-top:2px">VoIP Penetration Test Report</div>
    </div>
    <div style="text-align:right;font-size:13px;opacity:0.8">
      <div><b>Target:</b> <code style="background:rgba(255,255,255,0.1);padding:2px 6px;border-radius:4px">{target}</code></div>
      <div style="margin-top:4px"><b>Operator:</b> {operator}</div>
      <div style="margin-top:4px"><b>Scan date:</b> {timestamp}</div>
    </div>
  </div>
  <div style="margin-top:16px;border-top:1px solid rgba(255,255,255,0.15);padding-top:14px">
    {finding_badges}
  </div>
</div>"""

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

    # Findings table — severity badge spans (item 8)
    rows_html = ""
    for f in findings:
        sev = f.get("severity", "info")
        conf = f.get("confidence", "low")
        col = SEVERITY_COLOUR.get(sev, "#666")
        conf_col = {
            "confirmed": "#155724", "high": "#004085",
            "medium": "#856404", "low": "#6c757d",
        }.get(conf, "#6c757d")
        rows_html += (
            f'<tr>'
            f'<td style="vertical-align:middle">'
            f'<span style="background:{col};color:#fff;padding:4px 8px;'
            f'border-radius:4px;font-weight:700;font-size:12px;display:inline-block;'
            f'min-width:64px;text-align:center">{sev.upper()}</span>'
            f'<br><span style="font-size:11px;color:{conf_col};margin-top:4px;'
            f'display:inline-block">{conf}</span>'
            f'</td>'
            f'<td>{_esc(f.get("host", ""))}</td>'
            f'<td><b>{_esc(f.get("title", ""))}</b>'
            f'<br><span class="detail">{_esc(f.get("detail", ""))}</span>'
            f'<br><span class="rem"><b>Business impact:</b> '
            f'{_esc(f.get("business_impact", ""))}</span>'
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

        # SIP trace from call_test
        _ct = h.get("call_test")
        _sip_trace_html = ""
        if _ct and _ct.get("trace"):
            _trace_html = _html.escape("\n".join(str(line) for line in _ct["trace"]))
            _sip_trace_html = (
                '<details><summary>SIP Trace</summary>'
                f'<pre>{_trace_html}</pre></details>'
            )

        host_sections += f"""
<h3>{_esc(h['ip'])} <span class="muted">{_esc(h.get('fingerprint','unknown'))}</span></h3>
<table class="kv">
<tr><th>Open ports</th><td>{_esc(ports_text)}</td></tr>
<tr><th>Extensions found</th><td>{exts_count}</td></tr>
<tr><th>Credentials cracked</th><td>{creds_count}</td></tr>
</table>
{_sip_trace_html}
"""

    exec_summary = _auto_executive_summary(report, findings)

    # Executive summary block (item 4)
    exec_summary_block = _render_exec_summary_block(findings, counts)

    # Attack chain section
    attack_chain: list[str] = []
    if any(
        f.get('title', '').upper().startswith('ANONYMOUS')
        or 'DIAL-OUT' in f.get('title', '').upper()
        or 'WITHOUT CREDENTIALS' in f.get('title', '').upper()
        for f in findings
    ):
        attack_chain = [
            "1. PBX accepts unauthenticated SIP INVITE from any source IP",
            "2. Attacker discovers working dial-plan prefix (9, 0, 00, etc.)",
            "3. Attacker places outbound PSTN call — PBX bills the victim",
            "4. Any device on the network (or internet if port 5060 exposed) is a launch point",
        ]
    attack_chain_html = ""
    if attack_chain:
        _chain_items = "".join(
            f"<li>{_esc(step)}</li>" for step in attack_chain
        )
        attack_chain_html = (
            "<h2>Attack Chain</h2>"
            "<ol>" + _chain_items + "</ol>"
        )

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

{report_header_html}

{f'<div class="banner"><b>Scope of work:</b> {scope_file}<br><b>SHA-256:</b> <code>{scope_sha}</code></div>' if scope_file else ''}

{exec_summary_block}

<p>{exec_summary}</p>

<div class="kpi-grid">{kpi_html}</div>

<h2>Findings</h2>
<table>
<tr><th style="width:90px">Severity</th><th style="width:140px">Host</th>
<th>Finding</th></tr>
{rows_html or '<tr><td colspan="3"><i>No findings.</i></td></tr>'}
</table>

{attack_chain_html}

<h2>Host Detail</h2>
{host_sections or '<p><i>No hosts responded.</i></p>'}

<div style="margin-top:60px;padding-top:20px;border-top:1px solid #ddd;color:#888;font-size:11px">
Generated by VoIPScan v3.0 · {timestamp}
</div>

</body></html>"""


# ---------------------------------------------------------------------------
# CSV export (item 1)
# ---------------------------------------------------------------------------

def write_csv(report_dir: str, report_data: dict) -> str:
    """Write findings.csv with key columns for spreadsheet analysis.

    Columns: severity, confidence, cve_id, host, port, title,
             business_impact, evidence_snippet, remediation
    """
    findings = report_data.get("findings") or build_findings(report_data)
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)

    csv_path = out / "findings.csv"
    fieldnames = [
        "severity", "confidence", "cve_id", "host", "port",
        "title", "business_impact", "evidence_snippet", "remediation",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            detail = str(f.get("detail", ""))
            writer.writerow({
                "severity":        f.get("severity", ""),
                "confidence":      f.get("confidence", ""),
                "cve_id":          f.get("cve_id", ""),
                "host":            f.get("host", ""),
                "port":            f.get("port", ""),
                "title":           f.get("title", ""),
                "business_impact": f.get("business_impact", ""),
                "evidence_snippet": detail[:200],
                "remediation":     f.get("remediation", ""),
            })

    return str(csv_path)


# ---------------------------------------------------------------------------
# Risk score + toll-fraud estimate
# ---------------------------------------------------------------------------

def risk_score(findings: list[dict]) -> int:
    """Compute a 0-100 risk score from findings.

    Scoring model (additive, capped at 100):
      - critical finding: +35 each (max contribution 35)
      - high finding: +15 each (max contribution 30)
      - medium finding: +5 each (max contribution 15)
      - exposed SIP service: +5
      - AMI exposed: +10
      - toll fraud confirmed: auto 100

    Returns a single integer in the range 0-100.
    """
    # Auto-100 for confirmed toll fraud
    for f in findings:
        title = f.get("title", "").lower()
        if "toll-fraud poc" in title or "outbound call placed" in title:
            return 100

    counts = severity_counts(findings)

    critical_pts = min(counts.get("critical", 0) * 35, 35)
    high_pts = min(counts.get("high", 0) * 15, 30)
    medium_pts = min(counts.get("medium", 0) * 5, 15)

    score = critical_pts + high_pts + medium_pts

    # Bonus: exposed SIP
    for f in findings:
        title = f.get("title", "").lower()
        if "sip service reachable" in title:
            score += 5
            break

    # Bonus: AMI exposed
    for f in findings:
        title = f.get("title", "").lower()
        if "asterisk manager interface" in title and "exposed" in title:
            score += 10
            break

    return max(0, min(score, 100))


def toll_fraud_cost_estimate(findings: list[dict]) -> dict:
    """Estimate toll-fraud financial exposure based on findings.

    Returns:
        {
            "monthly_estimate_usd": float,
            "annual_estimate_usd": float,
            "calculation_basis": str,
            "risk_level": str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        }
    """
    _BASIS = (
        "Based on average toll fraud case studies: attackers typically run "
        "international premium-rate calls at $0.05-0.50/min for 24-72 hours before "
        "detection. Average industry loss: $1,200-$5,000/incident."
    )

    has_toll_fraud = False
    has_anon_invite = False
    has_open_register = False
    has_cracked_creds = False
    has_ami_pwned = False
    has_enumerated = False

    for f in findings:
        title = f.get("title", "").lower()
        sev = f.get("severity", "")

        if "outbound call placed" in title or "toll-fraud poc" in title:
            has_toll_fraud = True
        if "anonymous invite accepted" in title:
            has_anon_invite = True
        if "accepts register without authentication" in title:
            has_open_register = True
        if "valid credentials" in title:
            has_cracked_creds = True
        if "ami authenticated with default" in title:
            has_ami_pwned = True
        if "sip service reachable" in title or sev == "info":
            has_enumerated = True

    if has_toll_fraud:
        monthly = 2500.0
        risk_level = "CRITICAL"
    elif has_ami_pwned:
        monthly = 3000.0
        risk_level = "CRITICAL"
    elif has_anon_invite or has_open_register:
        monthly = 1500.0
        risk_level = "HIGH"
    elif has_cracked_creds:
        monthly = 800.0
        risk_level = "HIGH"
    elif has_enumerated:
        monthly = 200.0
        risk_level = "MEDIUM"
    else:
        monthly = 0.0
        risk_level = "LOW"

    return {
        "monthly_estimate_usd": monthly,
        "annual_estimate_usd": monthly * 12,
        "calculation_basis": _BASIS,
        "risk_level": risk_level,
    }


def render_sales_brief(report):
    findings = report.get("findings") or build_findings(report)
    _rs_raw = risk_score(findings)
    # risk_score returns an int; normalise to the dict shape the template expects
    if isinstance(_rs_raw, int):
        _score_val = _rs_raw
        _band_val = (
            "CRITICAL" if _score_val >= 75 else
            "HIGH" if _score_val >= 50 else
            "MEDIUM" if _score_val > 0 else
            "LOW"
        )
        rs = {"score": _score_val, "band": _band_val}
    else:
        rs = _rs_raw
    # toll_fraud_cost_estimate takes a findings list; map its output to the keys
    # the template expects (high_usd, low_usd, proven)
    _tf_raw = toll_fraud_cost_estimate(findings)
    _monthly = _tf_raw.get("monthly_estimate_usd", 0)
    tf = {
        "high_usd": int(_monthly * 1.5),
        "low_usd": int(_monthly * 0.5),
        "proven": _tf_raw.get("risk_level", "LOW") == "CRITICAL",
    }
    target = _esc(report.get("target", "?"))
    ts = _esc(report.get("timestamp", _iso_now()))
    score = rs.get("score", 0)
    band = rs.get("band", "")
    band_col = SEVERITY_COLOUR.get(
        "critical" if score >= 75 else "high" if score >= 50 else "medium" if score > 0 else "info",
        "#666"
    )
    top5 = [f for f in findings if f.get("severity") in ("critical", "high")][:5]
    rows = "".join(
        '<tr><td style="background:' + SEVERITY_COLOUR.get(f.get("severity","info"),"#666") + ';color:#fff;font-weight:700;width:90px">' +
        f.get("severity","").upper() + '</td><td><b>' + _esc(f.get("title","")) + '</b></td><td>' +
        _esc(f.get("host","")) + '</td></tr>'
        for f in top5
    ) or '<tr><td colspan="3"><i>No critical/high findings.</i></td></tr>'
    hi_usd = tf.get("high_usd", 0)
    lo_usd = tf.get("low_usd", 0)
    cost_str = ("$" + str(lo_usd // 1000) + "k–$" + str(hi_usd // 1000) + "k/month") if hi_usd else "None identified"
    proven_label = "CONFIRMED" if tf.get("proven") else "ESTIMATED"
    remediation_items = "".join(
        "<li><b>" + _esc(f.get("title","")) + "</b> — " + _esc(f.get("remediation","")[:120]) + "...</li>"
        for f in top5
    ) or "<li>No immediate actions required.</li>"
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>VoIP Security Brief — " + target + "</title>"
        "<style>"
        "body{font-family:-apple-system,Arial,sans-serif;margin:0;color:#222}"
        ".hdr{background:#0b1a33;color:#fff;padding:28px 40px}"
        ".hdr h1{margin:0;font-size:22px;font-weight:700}"
        ".hdr p{margin:6px 0 0;opacity:.7;font-size:13px}"
        ".body{padding:32px 40px;max-width:900px}"
        ".score-box{display:inline-block;background:" + band_col + ";color:#fff;padding:20px 36px;border-radius:8px;margin:16px 16px 16px 0}"
        ".score-box .n{font-size:52px;font-weight:900;line-height:1}"
        ".score-box .l{font-size:14px;font-weight:600;margin-top:4px;letter-spacing:2px}"
        ".cost-box{display:inline-block;background:#0b1a33;color:#fff;padding:20px 36px;border-radius:8px;margin:16px 0}"
        ".cost-box .n{font-size:28px;font-weight:700;line-height:1}"
        ".cost-box .l{font-size:12px;margin-top:4px;opacity:.8}"
        "h2{color:#0b1a33;border-left:4px solid #0b1a33;padding-left:12px;margin-top:32px}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}"
        "th,td{padding:10px 12px;border:1px solid #ddd;font-size:13px;text-align:left;vertical-align:top}"
        "th{background:#0b1a33;color:#fff;font-weight:600}"
        ".footer{margin-top:48px;padding-top:16px;border-top:1px solid #ddd;color:#888;font-size:11px}"
        "</style></head><body>"
        "<div class=hdr><h1>VoIP Security Assessment — Findings Summary</h1>"
        "<p>Target: " + target + " &nbsp;·&nbsp; Generated: " + ts + "</p></div>"
        "<div class=body>"
        "<div class=score-box><div class=n>" + str(score) + "</div><div class=l>" + band + "</div></div>"
        "<div class=cost-box><div class=n>" + cost_str + "</div><div class=l>TOLL-FRAUD EXPOSURE (" + proven_label + ")</div></div>"
        "<h2>Top Findings</h2>"
        "<table><tr><th>Severity</th><th>Finding</th><th>Host</th></tr>" + rows + "</table>"
        "<h2>Remediation Actions</h2>"
        "<ol>" + remediation_items + "</ol>"
        "<p class=footer>Executive summary only. Full technical report with evidence, traffic logs, and detailed steps available on request.<br>Generated by VoIPScan v4.1</p>"
        "</div></body></html>"
    )


_ACTIONABLE_SEVERITIES = {"critical", "high", "medium"}


def write_findings(report_dir: str, findings: list[dict]) -> str:
    """Write a clean findings.json with only actionable (critical/high/medium) findings.

    Each entry carries: severity, host, title, detail, remediation, timestamp.
    This file is the primary machine-readable artefact — ready for import into
    a SIEM, ticketing system, or further automation.
    """
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)

    actionable = [
        f for f in findings
        if f.get("severity") in _ACTIONABLE_SEVERITIES
    ]
    # Attach a per-finding timestamp for traceability
    ts = _iso_now()
    for f in actionable:
        f.setdefault("timestamp", ts)

    path = out / "findings.json"
    path.write_text(json.dumps(actionable, indent=2, default=str), encoding="utf-8")
    return str(path)


def write_all(report_dir: str, report: dict) -> dict[str, str]:
    """Write report.html, report.json, findings.json, findings.csv, and sales_brief.html.

    findings.json contains only actionable (critical/high/medium) findings —
    the default machine-readable export. report.json is the full raw snapshot.
    findings.csv is a spreadsheet-friendly export of all findings.
    sales_brief.html is a one-page client-facing summary.

    Returns a dict of:
        {"html": path, "json": path, "findings": path,
         "csv": path, "sales_brief": path}

    Also attaches risk_score and toll_fraud_estimate to the report dict.
    """
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)

    html_path = out / "report.html"
    html_text = render_html(report)   # also populates report["findings"]
    html_path.write_text(html_text, encoding="utf-8")

    # Attach risk score and toll fraud estimate (after render_html populates findings)
    findings = report.get("findings", [])
    report["risk_score"] = risk_score(findings)
    report["toll_fraud_estimate"] = toll_fraud_cost_estimate(findings)

    json_path = out / "report.json"
    json_path.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )

    findings_path = write_findings(report_dir, findings)

    # CSV export (item 1)
    csv_path = write_csv(report_dir, report)

    # Sales brief — rendered after risk_score and toll_fraud_estimate are attached
    sales_brief_path = out / "sales_brief.html"
    sales_brief_text = render_sales_brief(report)
    sales_brief_path.write_text(sales_brief_text, encoding="utf-8")

    return {
        "html": str(html_path),
        "json": str(json_path),
        "findings": findings_path,
        "csv": csv_path,
        "sales_brief": str(sales_brief_path),
    }
