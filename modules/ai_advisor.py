"""AI-powered exploit advisor — analyses scan results and produces
prioritised attack recommendations using the Anthropic Claude API.

All HTTP I/O uses the stdlib ``urllib.request`` so there is no dependency
on the ``anthropic`` SDK package.  When no API key is provided the module
falls back to a deterministic rule-based analysis that mirrors the heuristics
embedded in the main reporter but frames them as actionable attack guidance.
"""
from __future__ import annotations

import json
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class AdvisorResult:
    """Structured output from the AI (or rule-based) advisor."""

    recommendations: list[str]
    """Ordered list of short, actionable recommendations."""

    priority_attack: str
    """Single-sentence description of the highest-value attack path."""

    risk_summary: str
    """One-paragraph executive risk assessment."""

    client_narrative: str
    """Plain-English business-impact statement suitable for a non-technical reader."""

    exploits_ranked: list[dict]
    """Ranked exploit items.  Each dict has keys:
        title       str   — short exploit title
        reason      str   — why this exploit is ranked here
        confidence  int   — 0-100 confidence score
        action      str   — concrete next step for the tester
    """

    toll_fraud_cost_estimate: str = ""
    """1-2 sentence estimate of potential financial impact (toll fraud cost in USD)."""

    raw_response: str = ""
    """Raw text returned by the LLM (empty for rule-based results)."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


def _build_prompt(report: dict) -> str:
    """Convert the scan report dict into a structured analyst prompt."""

    hosts_summary: list[str] = []
    ami_blocks: list[str] = []
    hashcat_total = 0

    for h in report.get("hosts", []):
        ip = h.get("ip", "?")
        pbx = h.get("pbx_fingerprint", "unknown")
        extensions = h.get("extensions", [])
        ext_flags: list[str] = []
        for ext in extensions:
            flags = []
            if ext.get("anonymous_invite"):
                flags.append("anonymous-INVITE")
            if ext.get("open_register"):
                flags.append("open-REGISTER")
            if ext.get("auth_required"):
                flags.append("auth-required")
            ext_str = ext.get("extension", "?")
            if flags:
                ext_flags.append(f"  {ext_str}: {', '.join(flags)}")
            else:
                ext_flags.append(f"  {ext_str}: exists")

        creds = h.get("credentials_found", [])
        cred_lines = [
            f"  {c.get('extension','?')}: {c.get('username','?')}:{c.get('password','?')}"
            for c in creds
        ]

        vuln_findings = h.get("vuln_findings", [])
        vuln_lines = [
            f"  [{v.get('severity','?').upper()}] {v.get('title','?')} — {v.get('evidence','')[:200]}"
            for v in vuln_findings
        ]

        fingerprints = h.get("fingerprints", {})
        fp_lines = [f"  {k}: {v}" for k, v in fingerprints.items()] if fingerprints else []

        block = f"Host: {ip}  PBX: {pbx}\n"
        if ext_flags:
            block += "Extensions:\n" + "\n".join(ext_flags) + "\n"
        if cred_lines:
            block += "Credentials found:\n" + "\n".join(cred_lines) + "\n"
        if vuln_lines:
            block += "Vulnerability findings:\n" + "\n".join(vuln_lines) + "\n"
        if fp_lines:
            block += "Fingerprints:\n" + "\n".join(fp_lines) + "\n"

        hosts_summary.append(block)

        # AMI post-exploit context
        ami = h.get("ami_post_exploit")
        if ami:
            dialplan_raw = str(ami.get("dialplan", ""))[:1000]
            vm_count = ami.get("voicemail_count", 0)
            chan_count = ami.get("active_channel_count", 0)
            sip_registry = ami.get("sip_registry_entries", [])
            reg_lines = "\n".join(f"    {r}" for r in sip_registry) if sip_registry else "    (none)"
            ami_blocks.append(
                f"Host {ip}:\n"
                f"  Dialplan (truncated): {dialplan_raw}\n"
                f"  Voicemail count: {vm_count}\n"
                f"  Active channels: {chan_count}\n"
                f"  SIP registry entries:\n{reg_lines}"
            )

        # Hashcat hashes
        hashes = h.get("hashcat_hashes", [])
        if hashes:
            hashcat_total += len(hashes)

    hosts_text = "\n---\n".join(hosts_summary) if hosts_summary else "(no hosts)"

    # OSINT context
    osint_lines: list[str] = []
    osint = report.get("osint")
    if osint:
        osint_lines.append(f"  Risk score: {osint.get('risk_score', 'N/A')}")
        osint_lines.append(f"  Org: {osint.get('org', 'N/A')}")
        osint_lines.append(f"  Country: {osint.get('country', 'N/A')}")
        cves = osint.get("CVEs", [])
        if cves:
            osint_lines.append(f"  CVEs: {', '.join(str(c) for c in cves)}")
        known_ports = osint.get("known_ports", [])
        if known_ports:
            osint_lines.append(f"  Known ports: {', '.join(str(p) for p in known_ports)}")

    # Build extra context sections
    extra_context = ""
    if ami_blocks:
        extra_context += "\n=== AMI INTELLIGENCE ===\n"
        extra_context += "\n".join(ami_blocks)
        extra_context += "\n========================\n"
    if osint_lines:
        extra_context += "\n=== OSINT INTELLIGENCE ===\n"
        extra_context += "\n".join(osint_lines)
        extra_context += "\n==========================\n"
    if hashcat_total > 0:
        extra_context += "\n=== HASHCAT HASHES ===\n"
        extra_context += f"  {hashcat_total} crackable SIP digest hash(es) captured and available for offline cracking.\n"
        extra_context += "======================\n"

    prompt = textwrap.dedent(f"""
        You are an expert VoIP penetration tester reviewing a live scan report.
        Analyse the findings below and respond ONLY with a single JSON object
        matching the schema at the end of this message.  Do not add markdown
        fences, prose, or any text outside the JSON object.

        === SCAN REPORT ===
        {hosts_text}
        ====================={extra_context}

        Required JSON schema:
        {{
          "recommendations": ["<string>", ...],
          "priority_attack": "<string>",
          "risk_summary": "<string>",
          "client_narrative": "<string>",
          "toll_fraud_cost_estimate": "<string>",
          "exploits_ranked": [
            {{
              "title": "<string>",
              "reason": "<string>",
              "confidence": <integer 0-100>,
              "action": "<string>"
            }}
          ]
        }}

        Guidelines:
        - recommendations: 3-8 concise, ordered, actionable steps.
        - priority_attack: one sentence naming the single highest-value attack.
        - risk_summary: 2-4 sentences, suitable for inclusion in a pentest report.
        - client_narrative: non-technical, business-impact oriented, 2-3 sentences.
        - toll_fraud_cost_estimate: 1-2 sentence estimate of potential financial impact (toll fraud cost in USD) if the worst-case finding is exploited.
        - exploits_ranked: ordered highest-confidence first; include ALL distinct
          attack classes observed (anonymous-INVITE toll fraud, credential reuse,
          open-REGISTER, CVE exploits, etc.).
        - confidence values should reflect how directly the scan evidence supports
          exploit success (cracked creds = 95+, anonymous-INVITE = 90+,
          CVE without confirmed version = 50, inference only = 30).
        - For CVE findings, reference CVSS v3 score if available; CRITICAL (9.0-10.0) findings should rank above all credential findings unless credentials give direct PSTN access.
    """).strip()

    return prompt


def _post_anthropic(prompt: str, api_key: str, model: str,
                    timeout: float) -> str:
    """POST to the Anthropic Messages API via urllib.  Returns the raw text
    content of the first content block."""
    body = json.dumps({
        "model": model,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        _ANTHROPIC_API_URL,
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        method="POST",
    )

    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429 or exc.code >= 500:
                last_exc = exc
                time.sleep(2 ** attempt)
                continue
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Anthropic API error {exc.code}: {error_body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error calling Anthropic API: {exc.reason}") from exc
    else:
        exc = last_exc
        error_body = exc.read().decode("utf-8", errors="replace") if last_exc else ""
        raise RuntimeError(
            f"Anthropic API error {exc.code} after 3 attempts: {error_body}"
        ) from last_exc

    data = json.loads(raw)
    try:
        return data["content"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(
            f"Unexpected Anthropic API response structure: {raw[:400]}"
        ) from exc


def _parse_llm_output(text: str, raw: str) -> AdvisorResult:
    """Parse the LLM JSON output into an AdvisorResult.  Falls back to a
    partial result if the JSON is malformed rather than crashing."""
    try:
        # Strip any stray fences the model might emit despite instructions
        stripped = text.strip()
        if stripped.startswith("```"):
            lines = stripped.splitlines()
            stripped = "\n".join(
                l for l in lines
                if not l.startswith("```")
            )
        obj: dict[str, Any] = json.loads(stripped)
    except json.JSONDecodeError:
        # Last-ditch: try to extract JSON object with a bracket scan
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            obj = json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            return AdvisorResult(
                recommendations=["Unable to parse LLM output — review raw_response."],
                priority_attack="(parse error)",
                risk_summary=text[:500],
                client_narrative="",
                exploits_ranked=[],
                raw_response=raw,
            )

    def _str(key: str, default: str = "") -> str:
        v = obj.get(key, default)
        return v if isinstance(v, str) else str(v)

    def _list_str(key: str) -> list[str]:
        v = obj.get(key, [])
        if isinstance(v, list):
            return [str(i) for i in v]
        return []

    def _ranked(key: str) -> list[dict]:
        items = obj.get(key, [])
        if not isinstance(items, list):
            return []
        result = []
        for item in items:
            if not isinstance(item, dict):
                continue
            confidence = item.get("confidence", 0)
            try:
                confidence = int(confidence)
            except (TypeError, ValueError):
                confidence = 0
            result.append({
                "title":      str(item.get("title", "")),
                "reason":     str(item.get("reason", "")),
                "confidence": max(0, min(100, confidence)),
                "action":     str(item.get("action", "")),
            })
        return result

    return AdvisorResult(
        recommendations=_list_str("recommendations"),
        priority_attack=_str("priority_attack"),
        risk_summary=_str("risk_summary"),
        client_narrative=_str("client_narrative"),
        toll_fraud_cost_estimate=_str("toll_fraud_cost_estimate"),
        exploits_ranked=_ranked("exploits_ranked"),
        raw_response=raw,
    )


# ---------------------------------------------------------------------------
# Rule-based fallback
# ---------------------------------------------------------------------------

def _rule_based_analysis(report: dict) -> AdvisorResult:
    """Deterministic heuristic analysis used when no API key is available.

    Checks for anonymous INVITE extensions, cracked credentials, and
    vulnerability findings, then synthesises a risk narrative.
    """
    recommendations: list[str] = []
    exploits: list[dict] = []
    has_anon_invite = False
    has_open_register = False
    has_creds = False
    has_vulns = False
    crit_vuln_names: list[str] = []
    affected_hosts: list[str] = []

    for h in report.get("hosts", []):
        ip = h.get("ip", "?")
        found_something = False

        for ext in h.get("extensions", []):
            if ext.get("anonymous_invite"):
                has_anon_invite = True
                found_something = True
                exploits.append({
                    "title": f"Anonymous INVITE — {ip} ext {ext.get('extension','?')}",
                    "reason": (
                        "The PBX accepts inbound call requests from unauthenticated "
                        "sources. A remote attacker can place toll calls directly "
                        "without registering or providing credentials."
                    ),
                    "confidence": 92,
                    "action": (
                        f"Send a crafted SIP INVITE to sip:{ext.get('extension','?')}@{ip} "
                        "with an ITSP destination and confirm the PBX routes it. "
                        "Document the CDR entry as billing evidence."
                    ),
                })
            if ext.get("open_register"):
                has_open_register = True
                found_something = True
                exploits.append({
                    "title": f"Open REGISTER — {ip} ext {ext.get('extension','?')}",
                    "reason": (
                        "Extension accepts SIP REGISTER without a secret, allowing "
                        "an attacker to hijack the extension and intercept calls."
                    ),
                    "confidence": 88,
                    "action": (
                        f"Register as extension {ext.get('extension','?')} using any "
                        "SIP softphone pointed at {ip}. Confirm inbound call hijack "
                        "and outbound dialling capability."
                    ),
                })

        for cred in h.get("credentials_found", []):
            has_creds = True
            found_something = True
            exploits.append({
                "title": f"Cracked credential — {ip} ext {cred.get('extension','?')}",
                "reason": (
                    f"Valid SIP credentials ({cred.get('username','?')}:"
                    f"{cred.get('password','?')}) were recovered. Full "
                    "authenticated call-placement capability follows."
                ),
                "confidence": 97,
                "action": (
                    f"Register SIP UA as {cred.get('username','?')} on {ip} "
                    f"with password {cred.get('password','?')}. Place a test "
                    "call to an external number to demonstrate toll-fraud impact."
                ),
            })

        for v in h.get("vuln_findings", []):
            has_vulns = True
            found_something = True
            severity = v.get("severity", "info")
            confidence = {"critical": 80, "high": 65, "medium": 45,
                          "low": 25, "info": 10}.get(severity, 30)
            exploits.append({
                "title": f"{v.get('name','?')} — {ip}",
                "reason": v.get("title", ""),
                "confidence": confidence,
                "action": (
                    f"Verify {v.get('target','?')}: {v.get('evidence','')[:200]}. "
                    f"Remediation: {v.get('remediation','')[:200]}"
                ),
            })
            if severity in ("critical", "high"):
                crit_vuln_names.append(v.get("name", "?"))

        if found_something:
            affected_hosts.append(ip)

    # Sort exploits by confidence descending
    exploits.sort(key=lambda x: x["confidence"], reverse=True)

    # Build recommendations from observed conditions
    if has_creds:
        recommendations.append(
            "Immediately rotate all SIP extension credentials; enforce minimum "
            "16-character random passwords and per-extension unique secrets."
        )
        recommendations.append(
            "Audit Call Detail Records (CDRs) for unauthorized call activity "
            "made under the compromised extension(s) before this assessment."
        )
    if has_anon_invite:
        recommendations.append(
            "Disable anonymous SIP: set allowguest=no and alwaysauthreject=yes "
            "in Asterisk sip.conf / pjsip.conf, or equivalent on your PBX."
        )
        recommendations.append(
            "Place outbound PSTN destinations behind authentication-checked "
            "contexts; never expose toll routes to the 'default' context."
        )
    if has_open_register:
        recommendations.append(
            "Require authentication for all REGISTER operations; remove "
            "any 'type=peer' entries without a 'secret=' directive."
        )
    if has_vulns:
        recommendations.append(
            f"Patch or mitigate identified vulnerabilities: "
            f"{', '.join(crit_vuln_names) if crit_vuln_names else 'see findings'}. "
            "Apply vendor security advisories within the SLA defined by severity."
        )
    if not recommendations:
        recommendations.append(
            "No critical findings detected. Verify scope coverage and consider "
            "deeper credential spraying and authenticated session testing."
        )
    recommendations.append(
        "Enable SIP access control lists (ACLs) restricting registration and "
        "INVITE to known IP ranges; block all other sources at the firewall."
    )
    recommendations.append(
        "Deploy a SIP-aware intrusion detection system (e.g., Fail2Ban with "
        "SIP rules) to alert on and block brute-force and enumeration attempts."
    )

    # Determine priority attack
    if has_creds:
        priority_attack = (
            "Use recovered SIP credentials to authenticate and place toll calls "
            "through the target PBX, demonstrating direct financial fraud impact."
        )
        risk_level = "CRITICAL"
    elif has_anon_invite:
        priority_attack = (
            "Submit unauthenticated SIP INVITE messages to reachable extensions "
            "to route outbound calls via the PBX without any credential material."
        )
        risk_level = "CRITICAL"
    elif has_open_register:
        priority_attack = (
            "Register a SIP UA as an open extension to hijack inbound calls and "
            "gain authenticated outbound calling capability."
        )
        risk_level = "HIGH"
    elif has_vulns and crit_vuln_names:
        priority_attack = (
            f"Exploit {crit_vuln_names[0]} to gain administrative access to the "
            "PBX management plane and escalate to full call-control compromise."
        )
        risk_level = "HIGH"
    else:
        priority_attack = (
            "Conduct deeper credential spraying and dial-plan mapping; no "
            "immediately exploitable path was found in this scan pass."
        )
        risk_level = "MEDIUM"

    # Risk summary
    host_count = len(affected_hosts)
    risk_summary_parts: list[str] = []
    if has_creds:
        risk_summary_parts.append(
            f"Valid SIP credentials were recovered on {host_count} host(s), "
            "enabling immediate authenticated toll-fraud with no further exploitation required."
        )
    if has_anon_invite:
        risk_summary_parts.append(
            "One or more extensions accept anonymous SIP INVITE requests, "
            "exposing the organisation to direct toll-fraud from any network-reachable attacker."
        )
    if has_open_register:
        risk_summary_parts.append(
            "Open SIP REGISTER acceptance was observed, allowing extension hijacking "
            "without credential material."
        )
    if has_vulns:
        risk_summary_parts.append(
            f"Additional vulnerability findings ({', '.join(crit_vuln_names)}) "
            "indicate unpatched management surfaces that extend the attack surface."
        )
    if not risk_summary_parts:
        risk_summary_parts.append(
            "The scan completed without identifying immediately critical findings; "
            "however, the exposed SIP infrastructure surface warrants continued hardening."
        )
    risk_summary = "  ".join(risk_summary_parts)

    # Client narrative
    if risk_level == "CRITICAL":
        client_narrative = (
            "During this authorised assessment our team identified weaknesses in "
            "your phone system that would allow an outside attacker to make "
            "unlimited phone calls — including international and premium-rate "
            "numbers — and charge those calls to your account. "
            "This type of attack, known as toll fraud, can result in telephone "
            "bills of thousands of dollars within hours. "
            "Immediate remediation is strongly recommended before this system "
            "is accessible from any untrusted network."
        )
    elif risk_level == "HIGH":
        client_narrative = (
            "The assessment identified significant weaknesses in your VoIP "
            "infrastructure that could allow a malicious actor to intercept "
            "phone calls, impersonate your extensions, or gain unauthorised "
            "access to your phone system. "
            "While active toll fraud was not demonstrated in this scan pass, "
            "the conditions for it are present and should be resolved promptly."
        )
    else:
        client_narrative = (
            "No immediately critical vulnerabilities were confirmed during "
            "this scan pass. Your phone system's attack surface remains "
            "present and should be monitored; the recommendations in this "
            "report describe hardening steps that reduce exposure to future "
            "enumeration and exploitation attempts."
        )

    if has_creds or has_anon_invite:
        toll_fraud_cost_estimate = (
            "Potential exposure: $1,000–$100,000+ per day in toll fraud charges "
            "based on premium-rate destination routing. Prioritise immediate remediation."
        )
    else:
        toll_fraud_cost_estimate = ""

    return AdvisorResult(
        recommendations=recommendations,
        priority_attack=priority_attack,
        risk_summary=risk_summary,
        client_narrative=client_narrative,
        toll_fraud_cost_estimate=toll_fraud_cost_estimate,
        exploits_ranked=exploits,
        raw_response="",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse_scan(
    report: dict,
    api_key: str,
    model: str = "claude-3-5-haiku-20241022",
    timeout: float = 30.0,
) -> AdvisorResult:
    """Analyse a scan report dict and return prioritised attack recommendations.

    Parameters
    ----------
    report:
        The scan report dictionary (as produced by ``voip_scan.py``).  The
        advisor uses the following keys when present:
        ``hosts``, ``vuln_findings``, ``extensions``, ``credentials_found``,
        ``fingerprints``.
    api_key:
        Anthropic API key.  If ``None`` or empty the rule-based fallback is
        used instead — no network call is made.
    model:
        Claude model identifier.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    AdvisorResult
    """
    if not api_key:
        return _rule_based_analysis(report)

    prompt = _build_prompt(report)
    try:
        raw_text = _post_anthropic(prompt, api_key, model, timeout)
    except RuntimeError:
        # API failure → graceful fallback so the scan pipeline is never blocked
        fallback = _rule_based_analysis(report)
        return fallback

    return _parse_llm_output(raw_text, raw_text)


def format_advisor_report(result: AdvisorResult) -> str:
    """Render an AdvisorResult as a human-readable rich text report."""
    lines: list[str] = []
    sep = "=" * 72
    thin = "-" * 72

    lines.append(sep)
    lines.append("AI EXPLOIT ADVISOR  —  PRIORITISED ATTACK ANALYSIS")
    lines.append(sep)
    lines.append("")

    lines.append("PRIORITY ATTACK PATH")
    lines.append(thin)
    lines.append(f"  {result.priority_attack}")
    lines.append("")

    if result.toll_fraud_cost_estimate:
        lines.append("FINANCIAL IMPACT ESTIMATE")
        lines.append(thin)
        for para in textwrap.wrap(result.toll_fraud_cost_estimate, width=70):
            lines.append(f"  {para}")
        lines.append("")

    lines.append("RISK SUMMARY")
    lines.append(thin)
    for para in textwrap.wrap(result.risk_summary, width=70):
        lines.append(f"  {para}")
    lines.append("")

    lines.append("CLIENT NARRATIVE")
    lines.append(thin)
    for para in textwrap.wrap(result.client_narrative, width=70):
        lines.append(f"  {para}")
    lines.append("")

    lines.append("EXPLOITS — RANKED BY CONFIDENCE")
    lines.append(thin)
    for idx, exploit in enumerate(result.exploits_ranked, start=1):
        confidence = exploit.get("confidence", 0)
        if confidence >= 90:
            conf_label = "VERY HIGH"
        elif confidence >= 70:
            conf_label = "HIGH     "
        elif confidence >= 50:
            conf_label = "MEDIUM   "
        elif confidence >= 30:
            conf_label = "LOW      "
        else:
            conf_label = "VERY LOW "

        lines.append(f"  [{idx}] {exploit.get('title','')}  "
                     f"(confidence: {confidence}% — {conf_label})")
        for line in textwrap.wrap(exploit.get("reason", ""), width=66):
            lines.append(f"       {line}")
        lines.append(f"       ACTION: {exploit.get('action','')}")
        lines.append("")

    lines.append("RECOMMENDATIONS")
    lines.append(thin)
    for idx, rec in enumerate(result.recommendations, start=1):
        for i, line in enumerate(textwrap.wrap(rec, width=68)):
            prefix = f"  {idx}. " if i == 0 else "     "
            lines.append(f"{prefix}{line}")
    lines.append("")

    if result.raw_response:
        lines.append("RAW LLM RESPONSE")
        lines.append(thin)
        for line in result.raw_response.splitlines():
            lines.append(f"  {line}")
        lines.append("")

    lines.append(sep)
    return "\n".join(lines)
