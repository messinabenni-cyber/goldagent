"""Report generation: JSON, plain text, HTML, CSV, and JSON Lines."""
from __future__ import annotations

import base64
import csv
import html
import io
import json
import os
import re
import tempfile
import time
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#8b0000",
    "high":     "#c0392b",
    "medium":   "#d68910",
    "low":      "#1e8449",
    "info":     "#2874a6",
}


def build_findings(report: dict[str, Any]) -> list[dict]:
    findings: list[dict] = []

    for host in report.get("hosts", []):
        ip = host["ip"]
        sip = host.get("sip") or {}
        server = sip.get("server", "")
        pbx = host.get("pbx_fingerprint", "unknown")

        if sip:
            findings.append({
                "severity": "info",
                "host": ip,
                "title": f"SIP service reachable on {ip}",
                "detail": f"PBX fingerprint: {pbx}. Server banner: {server or '(none)'}. "
                          f"OPTIONS returned {sip.get('status')} {sip.get('reason','')}.",
                "remediation": "Confirm this SIP service is intentionally exposed. "
                               "Restrict by ACL/firewall to known signaling peers.",
            })
            if server and server != "(hidden)":
                findings.append({
                    "severity": "low",
                    "host": ip,
                    "title": "SIP server reveals software/version",
                    "detail": f"Server header: {server!r}",
                    "remediation": "Strip or generalize the Server/User-Agent header to slow "
                                   "reconnaissance and version-targeted exploits.",
                })

        # Exposed management surfaces
        for p in host.get("open_ports", []):
            if p["service"] == "Asterisk-AMI":
                findings.append({
                    "severity": "high",
                    "host": ip,
                    "title": "Asterisk Manager Interface (AMI) exposed",
                    "detail": f"TCP/{p['port']} responded. AMI allows full call-plane control "
                              f"if credentials (or defaults) are accepted.",
                    "remediation": "Bind AMI to 127.0.0.1 or an ACL'd management VLAN only; "
                                   "require strong credentials and TLS.",
                })
            if p["service"] in ("FreePBX-HTTP", "FreePBX-HTTPS", "FreePBX-alt"):
                banner = p.get("banner", "")
                if "FreePBX" in banner or "Asterisk" in banner:
                    findings.append({
                        "severity": "medium",
                        "host": ip,
                        "title": "FreePBX/Asterisk web UI exposed",
                        "detail": f"TCP/{p['port']} banner: {banner[:200]}",
                        "remediation": "FreePBX admin UI should not be reachable from "
                                       "untrusted networks. Put it behind VPN or IP ACL.",
                    })

        for ext in host.get("extensions", []):
            if ext.get("open_register"):
                findings.append({
                    "severity": "critical",
                    "host": ip,
                    "title": f"Extension {ext['extension']} accepts REGISTER without authentication",
                    "detail": f"Evidence: {ext['evidence']}. Anyone on the network can register "
                              f"as this extension and place calls.",
                    "remediation": "Require authentication on all extensions. In Asterisk set "
                                   "'allowguest=no' and enforce type=friend with a secret.",
                })
            if ext.get("anonymous_invite"):
                findings.append({
                    "severity": "critical",
                    "host": ip,
                    "title": f"Anonymous INVITE accepted for extension {ext['extension']}",
                    "detail": f"Evidence: {ext['evidence']}. PBX engages the dial plan for "
                              f"unauthenticated callers — direct toll-fraud exposure.",
                    "remediation": "Disable anonymous SIP. On Asterisk: allowguest=no, "
                                   "alwaysauthreject=yes. Restrict the default context to "
                                   "'from-trunk' routes only; do NOT mix inbound trunks with "
                                   "the user context.",
                })

        for cred in host.get("credentials_found", []):
            findings.append({
                "severity": "critical",
                "host": ip,
                "title": f"Valid credentials for extension {cred['extension']}",
                "detail": f"Username {cred['username']!r}, password {cred['password']!r}. "
                          f"Evidence: {cred['evidence']}",
                "remediation": "Reset the password to a long random secret. Roll out a "
                               "password policy for extensions. If other extensions share "
                               "this password, rotate them all.",
            })

        call = host.get("call_test")
        if call:
            if call.get("success"):
                findings.append({
                    "severity": "critical",
                    "host": ip,
                    "title": "Outbound call successfully placed via PBX (toll-fraud PoC)",
                    "detail": f"Destination {call.get('call_to')} from {call.get('call_from')}. "
                              f"Result: {call.get('evidence')}. Call was torn down immediately "
                              f"with BYE — no audio was streamed.",
                    "remediation": "This proves the PBX will carry unauthorized outbound calls. "
                                   "Fix the underlying auth/ACL weakness, then audit CDRs for "
                                   "historical abuse. Cap per-extension concurrent/outbound "
                                   "minutes and set a per-day spend ceiling at the SIP trunk.",
                })
            elif call.get("reached_dialplan"):
                findings.append({
                    "severity": "high",
                    "host": ip,
                    "title": "PBX engaged dial plan for unauthenticated INVITE",
                    "detail": f"Provisional response received ({call.get('status_code')}); "
                              f"call did not complete but the PBX did attempt to route it.",
                    "remediation": "Reject unauthenticated INVITEs at signaling before the dial "
                                   "plan is consulted.",
                })

        # Live call (voip_demo.py flow) — full RTP toll-fraud demonstration
        live_calls = host.get("live_call") or []
        for live in live_calls:
            if live.get("success"):
                detail_parts = [
                    f"Destination {live.get('call_to')} from ext "
                    f"{live.get('extension')} via {live.get('label','')}.",
                    f"Codec: {live.get('codec')}, duration {live.get('duration_s')}s,"
                    f" RTP packets: {live.get('rtp_packets_sent')}.",
                    f"Hang-up side: {live.get('hangup_side')}.",
                ]
                if live.get("dtmf_sent"):
                    detail_parts.append(
                        f"DTMF sent during call: {''.join(live['dtmf_sent'])!r}"
                        f" — proves the tool could navigate the PBX's IVR.")
                rec = live.get("recording")
                if rec and rec.get("wav_path"):
                    detail_parts.append(
                        f"Far-end audio recorded to "
                        f"{os.path.basename(rec['wav_path'])} "
                        f"({rec.get('audio_seconds', 0)}s, "
                        f"{rec.get('audio_packets', 0)} RTP pkts).")
                findings.append({
                    "severity": "critical",
                    "host": ip,
                    "title": "Live call placed and answered via compromised PBX",
                    "detail": " ".join(detail_parts),
                    "remediation": ("Client should see this in their CDR as a "
                                    "real billed call. Reset the auth gap "
                                    "identified above. Audit CDRs for prior "
                                    "abuse matching the same attack path. "
                                    "Cap per-extension outbound concurrent "
                                    "calls and set a daily spend ceiling at "
                                    "the SIP trunk."),
                })

        # CVE-targeted HTTP probes (voip_demo.py vuln_probes output)
        for v in host.get("vuln_findings", []):
            findings.append({
                "severity": v["severity"],
                "host": ip,
                "title": v["title"],
                "detail": f"{v['name']} — {v['evidence']} (target: {v['target']})",
                "remediation": v["remediation"],
            })

        # AMI post-exploitation findings
        post = host.get("ami_post_exploit")
        if post:
            if post.get("voicemail"):
                findings.append({
                    "severity": "high",
                    "host": ip,
                    "title": f"{len(post['voicemail'])} voicemail boxes "
                             f"disclosed via AMI",
                    "detail": ("Attacker with AMI access can list every "
                               "voicemail user (mailbox number, fullname, "
                               "email, message counts). Combined with weak "
                               "mailbox PINs this leads to voicemail "
                               "extraction and caller-ID-based social "
                               "engineering."),
                    "remediation": ("Remove AMI exposure to untrusted "
                                    "networks. Enforce strong mailbox PINs. "
                                    "Consider disabling VoicemailUsersList "
                                    "in manager.conf's allowed actions."),
                })
            if post.get("channels"):
                findings.append({
                    "severity": "medium",
                    "host": ip,
                    "title": f"Real-time call activity disclosed "
                             f"({len(post['channels'])} active channels)",
                    "detail": ("AMI exposed current live call state "
                               "including channel names, caller IDs, "
                               "dialed extensions, and call duration. "
                               "Enables traffic analysis and active-call "
                               "interception planning."),
                    "remediation": ("Restrict AMI read permissions; audit "
                                    "which manager users need 'call' class."),
                })
            if post.get("registrations"):
                findings.append({
                    "severity": "medium",
                    "host": ip,
                    "title": f"Outbound SIP trunk registrations exposed "
                             f"({len(post['registrations'])} trunks)",
                    "detail": ("AMI revealed the PBX's upstream SIP "
                               "trunk(s). This identifies the carrier an "
                               "attacker would route toll-fraud through, "
                               "and the exact username/hostname used for "
                               "trunk registration."),
                    "remediation": ("Do not expose AMI. Rotate SIP trunk "
                                    "credentials if this test is not a "
                                    "sanctioned review."),
                })
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def _atomic_write(path: str, content: str) -> None:
    """Write file atomically: write to .tmp in the same directory, then
    rename. Avoids leaving half-written reports if we're interrupted."""
    dir_ = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".report-", dir=dir_)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_all(report_dir: str, report: dict[str, Any]) -> dict[str, str]:
    os.makedirs(report_dir, exist_ok=True)
    findings = build_findings(report)
    report["findings"] = findings

    json_path = os.path.join(report_dir, "report.json")
    _atomic_write(json_path, json.dumps(report, indent=2, default=str))

    txt_path = os.path.join(report_dir, "report.txt")
    _atomic_write(txt_path, _render_text(report))

    html_path = os.path.join(report_dir, "report.html")
    _atomic_write(html_path, _render_html(report))

    # CSV — findings only, flattened.  Consumed by spreadsheet tools and
    # most ticketing systems (Jira CSV import, ServiceNow bulk upload).
    csv_path = os.path.join(report_dir, "findings.csv")
    _atomic_write(csv_path, _render_findings_csv(report))

    # JSON Lines — one finding per line, suitable for SIEM / Elastic / Splunk
    # ingestion without custom parsers.  Each line is self-describing with
    # target and timestamp context.
    jsonl_path = os.path.join(report_dir, "findings.jsonl")
    _atomic_write(jsonl_path, _render_findings_jsonl(report))

    return {
        "json": json_path,
        "txt": txt_path,
        "html": html_path,
        "csv": csv_path,
        "jsonl": jsonl_path,
    }


def _render_findings_csv(r: dict) -> str:
    """Flatten findings into a CSV that matches common ticket-import formats.

    Columns chosen to line up with Jira Service Management + ServiceNow
    vulnerability record fields so operators can bulk-upload without
    column remapping.  String values are quoted by csv.writer so embedded
    commas/newlines in 'detail' survive round-trips.
    """
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow([
        "timestamp",
        "target",
        "host",
        "severity",
        "id",
        "cve",
        "cvss",
        "title",
        "detail",
        "remediation",
    ])
    ts = r.get("timestamp", "")
    target = r.get("target", "")
    for f in r.get("findings", []) or []:
        w.writerow([
            ts,
            target,
            f.get("host", ""),
            f.get("severity", ""),
            f.get("id", ""),
            f.get("cve", ""),
            f.get("cvss", ""),
            f.get("title", ""),
            (f.get("detail", "") or "").replace("\r\n", " ").replace("\n", " "),
            (f.get("remediation", "") or "").replace("\r\n", " ").replace("\n", " "),
        ])
    return buf.getvalue()


def _render_findings_jsonl(r: dict) -> str:
    """One JSON object per line.  Each line carries enough context to stand
    alone in a SIEM pipeline without requiring joins against a master report.
    """
    ts = r.get("timestamp", "")
    target = r.get("target", "")
    operator = r.get("operator", "")
    scope_sha = r.get("scope_sha256", "")
    lines: list[str] = []
    for f in r.get("findings", []) or []:
        line = {
            "@timestamp": ts,
            "event": "voipscan.finding",
            "target": target,
            "operator": operator,
            "scope_sha256": scope_sha,
            **f,
        }
        lines.append(json.dumps(line, default=str))
    return "\n".join(lines) + ("\n" if lines else "")


def _render_text(r: dict) -> str:
    lines: list[str] = []
    lines.append("VOIP PENETRATION TEST — SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Timestamp   : {r.get('timestamp')}")
    lines.append(f"Operator    : {r.get('operator')}")
    lines.append(f"Target(s)   : {r.get('target')}")
    lines.append(f"Scope file  : {r.get('scope_file','(none)')}"
                 + (f"  sha256={r['scope_sha256']}" if r.get("scope_sha256") else ""))
    lines.append("")
    lines.append("SUMMARY")
    lines.append("-" * 60)
    counts = r.get("severity_counts", {})
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"  {sev:<8} : {counts.get(sev, 0)}")
    lines.append("")
    lines.append("HOSTS")
    lines.append("-" * 60)
    for h in r.get("hosts", []):
        lines.append(f"[{h['ip']}]  PBX={h.get('pbx_fingerprint','?')}")
        for p in h.get("open_ports", []):
            lines.append(f"    {p['proto']:<3}/{p['port']:<5} {p['service']:<15} {p.get('banner','')[:120]}")
        for e in h.get("extensions", []):
            flags = []
            if e.get("auth_required"): flags.append("auth")
            if e.get("open_register"): flags.append("OPEN-REGISTER")
            if e.get("anonymous_invite"): flags.append("ANON-INVITE")
            lines.append(f"    ext {e['extension']}  [{', '.join(flags) or 'exists'}]  {e['evidence']}")
        for c in h.get("credentials_found", []):
            lines.append(f"    CRED  {c['extension']}  {c['username']}:{c['password']}  ({c['evidence']})")
        if h.get("call_test"):
            ct = h["call_test"]
            lines.append(f"    CALL  {ct.get('call_from')} -> {ct.get('call_to')}  "
                         f"success={ct.get('success')}  evidence={ct.get('evidence')}")
        lines.append("")
    lines.append("FINDINGS")
    lines.append("-" * 60)
    for f in r.get("findings", []):
        lines.append(f"[{f['severity'].upper()}] {f['title']}  ({f['host']})")
        lines.append(f"    {f['detail']}")
        lines.append(f"    Remediation: {f['remediation']}")
        lines.append("")
    return "\n".join(lines)


def _render_html(r: dict) -> str:
    esc = html.escape
    rows: list[str] = []
    for h in r.get("hosts", []):
        ports = "<br>".join(
            f"{esc(p['proto'])}/{p['port']} {esc(p['service'])} "
            f"<span style='color:#888'>{esc(p.get('banner','')[:120])}</span>"
            for p in h.get("open_ports", [])
        )
        exts = "<br>".join(
            f"<b>{esc(e['extension'])}</b> — "
            + ("<span style='color:#c0392b'>OPEN-REGISTER</span>" if e.get("open_register")
               else "<span style='color:#c0392b'>ANON-INVITE</span>" if e.get("anonymous_invite")
               else "<span style='color:#888'>auth-required</span>" if e.get("auth_required")
               else "exists")
            + f" <span style='color:#888'>({esc(e['evidence'])})</span>"
            for e in h.get("extensions", [])
        )
        creds = "<br>".join(
            f"<b>{esc(c['extension'])}</b> — <code>{esc(c['username'])}:{esc(c['password'])}</code>"
            f" <span style='color:#888'>({esc(c['evidence'])})</span>"
            for c in h.get("credentials_found", [])
        )
        call = ""
        if h.get("call_test"):
            ct = h["call_test"]
            color = "#8b0000" if ct.get("success") else "#2874a6"
            call = (f"<div style='color:{color}'>"
                    f"<b>Call test:</b> {esc(ct.get('call_from',''))} &rarr; "
                    f"{esc(ct.get('call_to',''))} — success={ct.get('success')} "
                    f"({esc(ct.get('evidence',''))})</div>")
        rows.append(f"""
          <section class="host">
            <h3>{esc(h['ip'])} <small>{esc(h.get('pbx_fingerprint','unknown PBX'))}</small></h3>
            <div><b>Open ports</b><br>{ports or '<i>none</i>'}</div>
            {'<div><b>Extensions</b><br>'+exts+'</div>' if exts else ''}
            {'<div><b>Credentials found</b><br>'+creds+'</div>' if creds else ''}
            {call}
          </section>""")
    finding_rows: list[str] = []
    for f in r.get("findings", []):
        finding_rows.append(f"""
          <tr class="sev-{f['severity']}">
            <td class="sev">{f['severity'].upper()}</td>
            <td>{esc(f['host'])}</td>
            <td><b>{esc(f['title'])}</b><br>
                <span class="detail">{esc(f['detail'])}</span><br>
                <span class="rem"><i>Remediation:</i> {esc(f['remediation'])}</span>
            </td>
          </tr>""")
    counts = r.get("severity_counts", {})
    badges = " ".join(
        f"<span style='background:{SEVERITY_COLOR[s]};color:white;padding:2px 8px;"
        f"border-radius:4px;margin-right:4px'>{s}: {counts.get(s,0)}</span>"
        for s in ("critical","high","medium","low","info")
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>VoIP Pentest Report — {esc(r.get('target','?'))}</title>
<style>
  body {{ font-family: -apple-system, Helvetica, Arial; margin: 2em; max-width: 1100px; color:#222 }}
  h1 {{ margin-bottom: 0 }}
  .meta {{ color:#666; margin-bottom: 1.5em }}
  section.host {{ border:1px solid #ddd; padding:1em; margin:1em 0; border-radius:6px }}
  section.host h3 small {{ color:#888; font-weight:normal; margin-left:.5em }}
  table {{ border-collapse: collapse; width: 100% }}
  td {{ border:1px solid #eee; padding:8px; vertical-align:top }}
  td.sev {{ font-weight:bold; white-space:nowrap }}
  tr.sev-critical td.sev {{ color:{SEVERITY_COLOR['critical']} }}
  tr.sev-high td.sev     {{ color:{SEVERITY_COLOR['high']} }}
  tr.sev-medium td.sev   {{ color:{SEVERITY_COLOR['medium']} }}
  tr.sev-low td.sev      {{ color:{SEVERITY_COLOR['low']} }}
  tr.sev-info td.sev     {{ color:{SEVERITY_COLOR['info']} }}
  .rem {{ color:#444 }}
  .detail {{ color:#555 }}
  code {{ background:#f4f4f4; padding:1px 4px; border-radius:3px }}
</style></head><body>
<h1>VoIP Pentest Report</h1>
<div class="meta">
  Target: <b>{esc(r.get('target','?'))}</b><br>
  Timestamp: {esc(str(r.get('timestamp','')))} &nbsp; Operator: {esc(str(r.get('operator','')))}<br>
  Scope file: <code>{esc(str(r.get('scope_file','(none)')))}</code>
  {("<br>Scope sha256: <code>"+esc(r['scope_sha256'])+"</code>") if r.get('scope_sha256') else ''}
</div>
<h2>Summary</h2>
<p>{badges}</p>
<h2>Findings</h2>
<table>{''.join(finding_rows) or '<tr><td colspan=3><i>No findings.</i></td></tr>'}</table>
<h2>Hosts</h2>
{''.join(rows) or '<i>No hosts returned VoIP responses.</i>'}
<hr><small>Generated by voip-scan. Authorized penetration testing only.</small>
</body></html>"""


# ---------------------------------------------------------------------------
# Addition 1: Executive Summary Generator
# ---------------------------------------------------------------------------

def generate_executive_summary(report: dict) -> str:
    """Produce a 3-5 paragraph non-technical executive summary of the scan."""
    esc_text = lambda s: str(s) if s else ""

    target    = esc_text(report.get("target", "the target environment"))
    timestamp = esc_text(report.get("timestamp", ""))
    operator  = esc_text(report.get("operator", "the assessment team"))
    scope     = esc_text(report.get("scope_file", ""))

    # Collect data across all hosts
    anon_invite_exts: list[str] = []
    cracked_creds: list[dict]   = []
    live_call_data: list[dict]  = []
    vuln_findings: list[dict]   = []

    for host in report.get("hosts", []):
        for ext in host.get("extensions", []):
            if ext.get("anonymous_invite"):
                anon_invite_exts.append(ext.get("extension", "?"))
        for c in host.get("credentials_found", []):
            cracked_creds.append(c)
        for live in host.get("live_call") or []:
            if live.get("success"):
                live_call_data.append(live)
        for v in host.get("vuln_findings", []):
            vuln_findings.append(v)

    paragraphs: list[str] = []

    # --- Paragraph 1: What was tested ---
    scope_clause = f" against the scope defined in {scope}" if scope else ""
    date_clause  = f" on {timestamp}" if timestamp else ""
    p1 = (
        f"This report documents the findings of an authorized Voice over IP (VoIP) "
        f"penetration test conducted by {operator}{date_clause}{scope_clause}. "
        f"The assessment targeted {target} and was designed to identify security "
        f"weaknesses in the SIP infrastructure, including unauthenticated call routing, "
        f"weak extension credentials, exposed management interfaces, and the potential "
        f"for toll fraud. All testing was performed under written authorization and in "
        f"accordance with an agreed scope of work."
    )
    paragraphs.append(p1)

    # --- Paragraph 2: Critical findings ---
    crit_parts: list[str] = []
    if anon_invite_exts:
        ext_list = ", ".join(anon_invite_exts[:5])
        more     = f" (and {len(anon_invite_exts)-5} more)" if len(anon_invite_exts) > 5 else ""
        crit_parts.append(
            f"The most severe issue discovered is that extension(s) {ext_list}{more} "
            f"accept unauthenticated SIP INVITE messages — meaning anyone on the internet "
            f"can make calls through your PBX without any authentication. This is the "
            f"primary enabler of toll fraud."
        )
    if cracked_creds:
        ext_list = ", ".join(c.get("extension", "?") for c in cracked_creds[:5])
        crit_parts.append(
            f"Valid credentials were recovered for extension(s) {ext_list}, "
            f"demonstrating that weak or default passwords are in use. An attacker with "
            f"these credentials can register as a legitimate user and place calls "
            f"billed to the organization."
        )
    critical_vulns = [v for v in vuln_findings if v.get("severity") == "critical"]
    if critical_vulns:
        crit_parts.append(
            f"{len(critical_vulns)} critical vulnerability finding(s) were identified "
            f"in the PBX software or its management interfaces, including: "
            + "; ".join(v.get("title", "") for v in critical_vulns[:3]) + "."
        )
    if not crit_parts:
        crit_parts.append(
            "No directly exploitable anonymous-call or credential weaknesses were confirmed "
            "during this assessment; however, lesser findings still represent meaningful risk."
        )
    p2 = "Critical Findings: " + " ".join(crit_parts)
    paragraphs.append(p2)

    # --- Paragraph 3: Business impact (toll fraud estimate) ---
    # Use live call data if available for a realistic rate estimate
    rate_per_min = 0.05   # conservative USD/min for international calls
    calls_per_h  = 10     # plausible concurrent fraud calls
    hours_per_day = 24
    daily_exposure = rate_per_min * calls_per_h * 60 * hours_per_day
    monthly_exposure = daily_exposure * 30

    if live_call_data:
        # Surface the actual call duration in the estimate context
        sample = live_call_data[0]
        duration_s = sample.get("duration_s", 0)
        rtp_pkts   = sample.get("rtp_packets_sent", 0)
        call_to    = sample.get("call_to", "a destination number")
        proof_clause = (
            f" The assessment proved this by placing a live, fully-routed call to "
            f"{call_to} lasting {duration_s} seconds with {rtp_pkts} RTP packets "
            f"exchanged — indistinguishable from a legitimate outbound call."
        )
    else:
        proof_clause = ""

    p3 = (
        f"Business Impact: Toll fraud is an immediate and quantifiable financial risk. "
        f"Using conservative estimates of ${rate_per_min:.2f}/minute for international "
        f"call rates and {calls_per_h} simultaneous fraudulent calls, the organization "
        f"faces an exposure of approximately ${daily_exposure:,.0f}/day "
        f"(${monthly_exposure:,.0f}/month) before the attack is detected. "
        f"Real-world toll-fraud incidents routinely reach tens of thousands of dollars "
        f"within 24-48 hours.{proof_clause}"
    )
    paragraphs.append(p3)

    # --- Paragraph 4: What was proven (live call evidence) ---
    if live_call_data:
        proof_parts: list[str] = []
        for live in live_call_data[:3]:
            number    = live.get("call_to", "a destination number")
            duration  = live.get("duration_s", 0)
            rtp       = live.get("rtp_packets_sent", 0)
            codec     = live.get("codec", "unknown")
            dtmf      = live.get("dtmf_sent")
            rec       = live.get("recording") or {}
            audio_s   = rec.get("audio_seconds", 0)
            wav       = rec.get("wav_path", "")
            parts = [
                f"A live call was successfully placed to {number}, lasting {duration}s "
                f"({rtp} RTP packets, codec {codec})."
            ]
            if dtmf:
                parts.append(
                    f"DTMF tones {''.join(dtmf)!r} were sent mid-call, proving the tool "
                    f"can navigate IVR menus — as an attacker would to reach premium-rate services."
                )
            if wav:
                parts.append(
                    f"Far-end audio was captured ({audio_s}s) and saved as evidence; "
                    f"the recording is embedded in the HTML report."
                )
            proof_parts.append(" ".join(parts))
        p4 = (
            "Live Call Evidence: " + " ".join(proof_parts) + " "
            "These results constitute real, reproducible proof-of-exploitation and "
            "will appear in the PBX call-detail records (CDRs) as billable calls."
        )
        paragraphs.append(p4)

    # --- Paragraph 5: Top 3 remediation steps ---
    remed_steps: list[str] = []
    if anon_invite_exts:
        remed_steps.append(
            "Immediately disable anonymous SIP calling: set allowguest=no and "
            "alwaysauthreject=yes in sip.conf (Asterisk) or the equivalent in your PBX "
            "configuration. Restrict the default dial-plan context so unauthenticated "
            "callers cannot reach outbound routes."
        )
    if cracked_creds:
        remed_steps.append(
            "Rotate all extension passwords to randomly generated secrets of at least "
            "16 characters. Enforce a password policy that prevents reuse of the "
            "extension number as the password or secret."
        )
    remed_steps.append(
        "Audit all SIP trunk call-detail records immediately for unauthorized call "
        "activity matching the patterns identified in this report, and set a daily "
        "spend ceiling at the carrier level to limit future fraud exposure."
    )
    remed_steps.append(
        "Restrict management interfaces (AMI, FreePBX web UI) to trusted IP addresses "
        "only, require strong credentials, and place them behind a VPN or dedicated "
        "management VLAN."
    )
    remed_steps.append(
        "Deploy SIP-aware rate-limiting and anomaly detection to alert on unusual call "
        "volumes, off-hours activity, or calls to premium-rate or international "
        "destinations that fall outside normal business patterns."
    )

    top3 = remed_steps[:3]
    numbered = " ".join(f"({i+1}) {s}" for i, s in enumerate(top3))
    p5 = (
        "Recommended Remediation — Top 3 Priority Actions: " + numbered
    )
    paragraphs.append(p5)

    return "\n\n".join(paragraphs)


# ---------------------------------------------------------------------------
# Addition 2: Enhanced HTML report with embedded audio
# ---------------------------------------------------------------------------

_RATING_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH":     "#e3694e",
    "MEDIUM":   "#d29922",
    "LOW":      "#3fb950",
}

_SIP_METHOD_COLORS = {
    "INVITE":     "#58a6ff",
    "BYE":        "#8b949e",
    "CANCEL":     "#8b949e",
    "OPTIONS":    "#8b949e",
    "REGISTER":   "#79c0ff",
    "ACK":        "#8b949e",
    "200":        "#3fb950",
    "180":        "#3fb950",
    "183":        "#3fb950",
    "401":        "#e3694e",
    "403":        "#f85149",
    "404":        "#f85149",
    "407":        "#e3694e",
    "486":        "#e3694e",
    "487":        "#8b949e",
    "100":        "#8b949e",
}


def _colorize_sip_trace(trace: str) -> str:
    """Wrap SIP methods and response codes in colored spans for HTML display."""
    esc = html.escape
    lines: list[str] = []
    for raw_line in trace.splitlines():
        escaped = esc(raw_line)
        colored = escaped
        for token, color in _SIP_METHOD_COLORS.items():
            # Match token at start of line or after whitespace, or as standalone status code
            pattern = re.compile(
                rf'(?<![&\w])({re.escape(esc(token))})(?=\s|$|&)',
            )
            colored = pattern.sub(
                rf'<span style="color:{color};font-weight:bold">\1</span>',
                colored,
                count=1,
            )
        lines.append(colored)
    return "\n".join(lines)


def generate_html_report(report: dict, report_dir: str) -> str:
    """Generate a self-contained dark-theme HTML pentest report.

    If a .wav file exists in *report_dir* it is embedded as base64 audio.
    Returns the rendered HTML string (does not write to disk).
    """
    esc = html.escape

    # --- Risk score ---
    risk = calculate_risk_score(report)
    rating       = risk["rating"]
    score        = risk["score"]
    badge_color  = _RATING_COLORS.get(rating, "#8b949e")
    factors_html = "".join(f"<li>{esc(f)}</li>" for f in risk["factors"])

    # --- Embedded audio ---
    audio_html = ""
    wav_path   = None
    if os.path.isdir(report_dir):
        for fname in sorted(os.listdir(report_dir)):
            if fname.lower().endswith(".wav"):
                wav_path = os.path.join(report_dir, fname)
                break
    if wav_path and os.path.isfile(wav_path):
        with open(wav_path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
        audio_html = f"""
        <div class="section" id="audio-evidence">
          <h2>Live Call Evidence</h2>
          <div class="banner-red">&#9888;&#65039; UNAUTHORIZED CALL PLACED &mdash; THIS IS REAL EVIDENCE</div>
          <p>Click to hear the unauthorized call placed through your PBX:</p>
          <audio controls style="width:100%;margin:1em 0">
            <source src="data:audio/wav;base64,{b64}" type="audio/wav">
            Your browser does not support the audio element.
          </audio>
          <p style="color:#8b949e;font-size:0.85em">File: {esc(os.path.basename(wav_path))}</p>
        </div>"""

    # --- Extensions table ---
    ext_rows: list[str] = []
    for host in report.get("hosts", []):
        ip = host["ip"]
        for ext in host.get("extensions", []):
            if ext.get("anonymous_invite"):
                row_color, label = "#3d1a1a", '<span style="color:#f85149;font-weight:bold">ANON-INVITE</span>'
            elif ext.get("open_register"):
                row_color, label = "#3d1a1a", '<span style="color:#f85149;font-weight:bold">OPEN-REGISTER</span>'
            elif ext.get("auth_required"):
                row_color, label = "#2d2a1a", '<span style="color:#d29922">AUTH-ONLY</span>'
            else:
                row_color, label = "#1a2d1a", '<span style="color:#3fb950">EXISTS</span>'
            ext_rows.append(
                f'<tr style="background:{row_color}">'
                f'<td>{esc(ip)}</td>'
                f'<td>{esc(str(ext.get("extension","?")))}</td>'
                f'<td>{label}</td>'
                f'<td style="color:#8b949e;font-size:0.85em">{esc(str(ext.get("evidence","")))}</td>'
                f'</tr>'
            )

    # --- Credentials table ---
    cred_rows: list[str] = []
    for host in report.get("hosts", []):
        ip = host["ip"]
        for c in host.get("credentials_found", []):
            cred_rows.append(
                f'<tr>'
                f'<td>{esc(ip)}</td>'
                f'<td>{esc(str(c.get("extension","?")))}</td>'
                f'<td><code>{esc(str(c.get("username","?")))}</code></td>'
                f'<td><code>{esc(str(c.get("password","?")))}</code></td>'
                f'<td><span style="color:#f85149;font-weight:bold">EXPOSED</span></td>'
                f'</tr>'
            )

    # --- Findings table ---
    finding_rows: list[str] = []
    for f in report.get("findings", []):
        sev = f.get("severity", "info")
        sev_color = {
            "critical": "#f85149",
            "high":     "#e3694e",
            "medium":   "#d29922",
            "low":      "#3fb950",
            "info":     "#58a6ff",
        }.get(sev, "#8b949e")
        finding_rows.append(
            f'<tr>'
            f'<td><span style="color:{sev_color};font-weight:bold">{esc(sev.upper())}</span></td>'
            f'<td>{esc(f.get("host",""))}</td>'
            f'<td><b>{esc(f.get("title",""))}</b>'
            f'<br><span style="color:#8b949e;font-size:0.9em">{esc(f.get("detail",""))}</span>'
            f'<br><span style="color:#58a6ff;font-size:0.85em"><i>Remediation:</i> {esc(f.get("remediation",""))}</span>'
            f'</td>'
            f'</tr>'
        )

    # --- SIP trace (first available across all hosts) ---
    sip_trace_html = ""
    for host in report.get("hosts", []):
        trace_raw = host.get("sip_trace") or ""
        if not trace_raw:
            # Also check live_call for a trace field
            for live in host.get("live_call") or []:
                trace_raw = live.get("sip_trace") or ""
                if trace_raw:
                    break
        if trace_raw:
            sip_trace_html = (
                f'<pre class="sip-trace">{_colorize_sip_trace(str(trace_raw))}</pre>'
            )
            break
    if not sip_trace_html:
        sip_trace_html = '<p style="color:#8b949e"><i>No SIP trace captured.</i></p>'

    # --- Executive summary ---
    exec_summary = generate_executive_summary(report)
    exec_summary_html = "".join(
        f"<p>{esc(para)}</p>" for para in exec_summary.split("\n\n")
    )

    # --- Metadata ---
    target    = esc(str(report.get("target", "?")))
    timestamp = esc(str(report.get("timestamp", "")))
    operator  = esc(str(report.get("operator", "")))
    tool_ver  = esc(str(report.get("tool_version", "voip-scan")))

    ext_table = (
        f'<table><thead><tr><th>Host</th><th>Extension</th><th>Status</th><th>Evidence</th></tr></thead>'
        f'<tbody>{"".join(ext_rows) or "<tr><td colspan=4><i>None discovered.</i></td></tr>"}</tbody></table>'
    )
    cred_table = (
        f'<table><thead><tr><th>Host</th><th>Extension</th><th>Username</th><th>Password</th><th>Status</th></tr></thead>'
        f'<tbody>{"".join(cred_rows) or "<tr><td colspan=5><i>None cracked.</i></td></tr>"}</tbody></table>'
    )
    findings_table = (
        f'<table><thead><tr><th>Severity</th><th>Host</th><th>Finding</th></tr></thead>'
        f'<tbody>{"".join(finding_rows) or "<tr><td colspan=3><i>No findings.</i></td></tr>"}</tbody></table>'
    )

    # --- Hashcat hashes section ---
    all_hashcat_hashes: list[str] = []
    for host in report.get("hosts", []):
        all_hashcat_hashes.extend(host.get("hashcat_hashes", []))
    hashcat_html = ""
    if all_hashcat_hashes:
        hashes_pre = "\n".join(esc(h) for h in all_hashcat_hashes)
        hashcat_html = f"""
        <div class="section" id="hashcat-export">
          <h2>SIP Digest Hash Export (Hashcat Mode 11400)</h2>
          <div class="banner-red">
            &#9888; These hashes can be cracked offline with hashcat to recover SIP passwords.
          </div>
          <pre style="background:#0d1117;padding:1em;border-radius:4px;font-size:0.82em;overflow-x:auto;border:1px solid #30363d">{hashes_pre}</pre>
          <p style="margin-top:0.75em;color:#8b949e;font-size:0.9em">
            Crack command: <code>hashcat -m 11400 sip_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt</code><br>
            4-digit PIN brute: <code>hashcat -m 11400 sip_hashes_hashcat.txt -a 3 ?d?d?d?d</code><br>
            John the Ripper: <code>john --format=sip sip_hashes_john.txt --wordlist=rockyou.txt</code>
          </p>
        </div>"""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoIP Pentest Report &mdash; {target}</title>
<style>
  :root {{
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #30363d;
    --text:    #e6edf3;
    --muted:   #8b949e;
    --accent:  #f85149;
    --link:    #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}
  a {{ color: var(--link); }}
  h1 {{ font-size: 1.8em; margin-bottom: .25em; }}
  h2 {{ font-size: 1.3em; color: var(--link); border-bottom: 1px solid var(--border);
        padding-bottom: .3em; margin: 1.5em 0 .75em; }}
  .wrapper {{ max-width: 1200px; margin: 0 auto; padding: 2em; }}
  .banner-red {{
    background: #3d0000;
    border: 2px solid var(--accent);
    color: var(--accent);
    font-size: 1.1em;
    font-weight: bold;
    padding: .75em 1em;
    border-radius: 6px;
    margin-bottom: 1em;
    text-align: center;
  }}
  .section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25em 1.5em;
    margin-bottom: 1.5em;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: .5em 2em;
    color: var(--muted);
    font-size: 0.9em;
  }}
  .meta-grid span {{ color: var(--text); }}
  .badge {{
    display: inline-block;
    padding: .3em .9em;
    border-radius: 20px;
    font-weight: bold;
    font-size: 1em;
    color: #0d1117;
    margin-bottom: .5em;
  }}
  .score-number {{
    font-size: 2.5em;
    font-weight: bold;
    line-height: 1;
  }}
  .risk-box {{
    display: flex;
    align-items: center;
    gap: 1.5em;
  }}
  .factors {{ color: var(--muted); font-size: 0.88em; }}
  .factors ul {{ padding-left: 1.2em; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: .5em;
  }}
  th, td {{
    border: 1px solid var(--border);
    padding: 7px 10px;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background: #21262d;
    color: var(--muted);
    font-weight: 600;
    font-size: 0.85em;
    text-transform: uppercase;
    letter-spacing: .04em;
  }}
  tr:nth-child(even) td {{ background: #0d1117; }}
  code {{
    background: #21262d;
    color: #79c0ff;
    padding: 1px 5px;
    border-radius: 4px;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 0.9em;
  }}
  .sip-trace {{
    background: #010409;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1em;
    overflow-x: auto;
    max-height: 420px;
    overflow-y: scroll;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 0.82em;
    line-height: 1.5;
    white-space: pre;
    color: #cdd9e5;
  }}
  nav {{
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: .5em 2em;
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    gap: 1.5em;
    font-size: 0.88em;
  }}
  nav a {{ text-decoration: none; color: var(--muted); }}
  nav a:hover {{ color: var(--text); }}
  footer {{
    border-top: 1px solid var(--border);
    padding: 1.5em 2em;
    color: var(--muted);
    font-size: 0.82em;
    text-align: center;
  }}
</style>
</head><body>

<nav>
  <a href="#exec-summary">Executive Summary</a>
  <a href="#risk-score">Risk Score</a>
  <a href="#findings">Findings</a>
  <a href="#extensions">Extensions</a>
  <a href="#credentials">Credentials</a>
  {'<a href="#audio-evidence">Live Call Evidence</a>' if audio_html else ''}
  {'<a href="#hashcat-export">Hash Export</a>' if hashcat_html else ''}
  <a href="#sip-trace">Technical Trace</a>
</nav>

<div class="wrapper">

  <div class="banner-red">&#9888;&#65039; UNAUTHORIZED CALL PLACED &mdash; THIS IS REAL EVIDENCE</div>

  <h1>VoIP Penetration Test Report</h1>
  <div class="meta-grid" style="margin-bottom:1.5em">
    <div>Target: <span>{target}</span></div>
    <div>Date: <span>{timestamp}</span></div>
    <div>Operator: <span>{operator}</span></div>
    <div>Tool: <span>{tool_ver}</span></div>
  </div>

  <div class="section" id="exec-summary">
    <h2>Executive Summary</h2>
    {exec_summary_html}
  </div>

  <div class="section" id="risk-score">
    <h2>Risk Score</h2>
    <div class="risk-box">
      <div>
        <div class="score-number" style="color:{badge_color}">{score}</div>
        <div style="color:var(--muted);font-size:0.85em">/100</div>
      </div>
      <div>
        <span class="badge" style="background:{badge_color}">{rating}</span>
        <div class="factors">
          <ul>{factors_html}</ul>
        </div>
      </div>
    </div>
  </div>

  <div class="section" id="findings">
    <h2>Findings</h2>
    {findings_table}
  </div>

  <div class="section" id="extensions">
    <h2>Extensions</h2>
    {ext_table}
  </div>

  <div class="section" id="credentials">
    <h2>Credentials</h2>
    {cred_table}
  </div>

  {audio_html}

  {hashcat_html}

  <div class="section" id="sip-trace">
    <h2>Technical Trace</h2>
    {sip_trace_html}
  </div>

</div>

<footer>
  Generated: {timestamp} &nbsp;|&nbsp;
  Operator: {operator} &nbsp;|&nbsp;
  Tool: {tool_ver} &nbsp;|&nbsp;
  Authorized penetration testing only.
</footer>

</body></html>"""


# ---------------------------------------------------------------------------
# Addition 3: Risk score calculator
# ---------------------------------------------------------------------------

def calculate_risk_score(report: dict) -> dict:
    """Calculate a 0-100 risk score with rating and contributing factors.

    Returns:
        dict with keys:
          score   (int 0-100)
          rating  ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW")
          factors (list[str])
    """
    score: int       = 0
    factors: list[str] = []

    # Collect per-host data
    anon_invite_count: int = 0
    cred_count: int        = 0
    ext_count: int         = 0
    critical_vuln_count: int = 0
    high_vuln_count: int     = 0

    for host in report.get("hosts", []):
        for ext in host.get("extensions", []):
            ext_count += 1
            if ext.get("anonymous_invite") or ext.get("open_register"):
                anon_invite_count += 1
        cred_count += len(host.get("credentials_found", []))
        for v in host.get("vuln_findings", []):
            if v.get("severity") == "critical":
                critical_vuln_count += 1
            elif v.get("severity") == "high":
                high_vuln_count += 1

    # Also check pre-built findings list if already populated
    for f in report.get("findings", []):
        if f.get("severity") == "critical":
            if "anonymous invite" in f.get("title", "").lower() or "open register" in f.get("title", "").lower():
                pass  # already counted via extensions above
        if f.get("severity") == "critical" and "credentials" in f.get("title", "").lower():
            pass  # already counted via credentials above

    # +40 if any anonymous_invite extension
    if anon_invite_count > 0:
        score += 40
        factors.append(
            f"+40: {anon_invite_count} extension(s) accept unauthenticated INVITE/REGISTER "
            f"— direct toll-fraud exposure."
        )

    # +30 if any credentials cracked
    if cred_count > 0:
        score += 30
        factors.append(
            f"+30: {cred_count} extension credential(s) cracked — attacker can "
            f"authenticate as a legitimate user."
        )

    # +20 if any CRITICAL vuln findings
    if critical_vuln_count > 0:
        score += 20
        factors.append(
            f"+20: {critical_vuln_count} critical vulnerability finding(s) in PBX "
            f"software or management interfaces."
        )

    # +10 if any HIGH vuln findings
    if high_vuln_count > 0:
        score += 10
        factors.append(
            f"+10: {high_vuln_count} high-severity vulnerability finding(s) identified."
        )

    # +5 per extension (max +20)
    ext_contribution = min(ext_count * 5, 20)
    if ext_contribution > 0:
        score += ext_contribution
        factors.append(
            f"+{ext_contribution}: {ext_count} extension(s) discovered "
            f"(+5 each, capped at +20) — larger attack surface."
        )

    if not factors:
        factors.append("No significant risk contributors identified.")

    # Cap at 100
    score = min(score, 100)

    # Determine rating
    if score >= 70:
        rating = "CRITICAL"
    elif score >= 50:
        rating = "HIGH"
    elif score >= 30:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return {"score": score, "rating": rating, "factors": factors}
