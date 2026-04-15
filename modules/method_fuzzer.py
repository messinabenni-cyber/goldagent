"""SIP method fuzzer — exercise non-standard, private, and malformed methods.

Standard SIP (RFC 3261 + extensions) defines:
  INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, SUBSCRIBE, NOTIFY,
  PUBLISH, MESSAGE, REFER, UPDATE, PRACK, INFO

Real-world PBXs ship with non-RFC methods that are rarely documented:
  * Asterisk chan_sip custom verbs from loaded modules
  * Cisco CUCM proprietary UPDATE variants
  * Vendor debug methods (DO, EXECUTE, SHOW) that occasionally survive
    into production builds
  * Legacy methods from SIMPLE / early RFC drafts (DO, SEARCH, INSERT)

Why fuzz methods?
  1. Unexpected 200 OK to a made-up verb = application-layer bug / possible
     RCE surface — CVE-2020-35508 (MyPBX), CVE-2021-36148 (Cisco) are real.
  2. Information leak via error verbosity — 501 Not Implemented vs.
     500 Internal Server Error vs. silent drop identifies PBX family.
  3. Some DoS vectors (method confusion) stem from proxies accepting verbs
     they can't route.

What we do:
  * Send each method as a bare request-line + canonical headers.
  * Record: status code, reason phrase, Server header, whether response
    echoes the method in CSeq (some proxies echo the original verb even
    when they don't understand it — indicates a bypass surface).
  * Flag any 2xx response as 'high' — accepting an unknown verb is bad.
  * Flag 401/407 on non-standard verbs as 'medium' — means the PBX has
    a handler for this method, even if auth-gated.

No third-party dependencies.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .sip import build_message, parse_response, send_and_recv
from .utils import RateLimiter, local_ip_for, rand_call_id, rand_tag


# Methods we fuzz.  Categorised by risk tier for the report narrative.
#   tier 0 — well-known methods we expect implementations to accept or 405 on
#   tier 1 — historical / draft methods kept for back-compat
#   tier 2 — vendor-specific methods from real pentest reports
#   tier 3 — intentionally weird / malformed case variants
FUZZ_METHODS: list[tuple[str, int, str]] = [
    # (method, tier, note)
    ("OPTIONS",       0, "RFC 3261 — baseline"),
    ("INVITE",        0, "RFC 3261 — baseline, expect 401/100"),
    ("REGISTER",      0, "RFC 3261 — baseline, expect 401"),
    ("PUBLISH",       1, "RFC 3903 — presence"),
    ("REFER",         1, "RFC 3515 — call transfer"),
    ("NOTIFY",        1, "RFC 3265 — event notification"),
    ("INFO",          1, "RFC 6086 — mid-dialog application info"),
    ("UPDATE",        1, "RFC 3311 — session refresh"),
    ("PRACK",         1, "RFC 3262 — reliable 1xx"),
    ("MESSAGE",       1, "RFC 3428 — instant messaging"),
    # Draft / legacy
    ("DO",            2, "SIMPLE draft — should be unimplemented"),
    ("SEARCH",        2, "early draft — should be unimplemented"),
    ("INSERT",        2, "DB-like verb seen in broken gateways"),
    ("QUERY",         2, "DB-like verb"),
    ("SERVICE",       2, "draft-campbell-sip-service"),
    ("STORE",         2, "draft"),
    # Vendor / admin
    ("DEBUG",         2, "seen in PJSIP custom modules"),
    ("ADMIN",         2, "seen in legacy FreePBX builds"),
    ("RELOAD",        2, "Asterisk AMI adjacent"),
    ("SHOW",          2, "debug"),
    ("EXECUTE",       2, "dialplan surface"),
    # Case / whitespace weirdness — proxies are required to be case-insensitive
    # per RFC 3261 §7.1 but many aren't.  Responses that differ by case are a
    # bug-smell for input handling.
    ("invite",        3, "lowercase — RFC 3261 §7.1 says same as INVITE"),
    ("Invite",        3, "titlecase"),
    ("NULL",          3, "garbage verb"),
    ("AAAAAAAAAAAA",  3, "long verb — framing / buffer smell"),
]


@dataclass
class MethodProbeResult:
    method: str
    tier: int
    note: str
    status_code: int | None = None
    reason: str = ""
    server: str = ""
    cseq_echoed: bool = False
    response_excerpt: str = ""


@dataclass
class MethodFuzzReport:
    target: str
    probes: list[MethodProbeResult] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    def summary(self) -> str:
        return (
            f"{len(self.probes)} probes, "
            f"{len(self.anomalies)} anomalies, "
            f"{self.elapsed_s:.1f}s"
        )


def _send_method(
    method: str,
    host: str,
    port: int,
    local_ip: str,
    timeout: float,
    traffic_log=None,
) -> tuple[int | None, str, str, bool, bytes]:
    """Fire a single method probe.  Returns (status, reason, server, cseq_match, raw)."""
    call_id = rand_call_id()
    tag = rand_tag()
    try:
        msg = build_message(
            method,
            f"sip:{host}",
            from_user="fuzzer",
            to_user="fuzzer",
            host=host,
            port=port,
            local_ip=local_ip,
            local_port=0,
            call_id=call_id,
            cseq=1,
            from_tag=tag,
        )
    except ValueError:
        return None, "build-error", "", False, b""
    data = send_and_recv(msg, host, port, 0, timeout, traffic_log=traffic_log)
    if not data:
        return None, "", "", False, b""
    resp = parse_response(data)
    if not resp:
        return None, "", "", False, data
    cseq = resp.headers.get("cseq", "").upper()
    # CSeq MUST echo the original method per RFC 3261 §8.1.1.5
    cseq_echoed = method.upper() in cseq
    return resp.status_code, resp.reason, resp.server, cseq_echoed, data


def fuzz_methods(
    host: str,
    port: int = 5060,
    methods: list[tuple[str, int, str]] | None = None,
    rate: float = 10.0,
    timeout: float = 2.0,
    traffic_log=None,
) -> MethodFuzzReport:
    """Cycle through ``methods`` against ``host:port`` and record responses.

    ``rate`` is packets/sec — 10 pps keeps us polite against unknown gear.
    """
    start = time.monotonic()
    local_ip = local_ip_for(host)
    method_list = methods or FUZZ_METHODS
    rl = RateLimiter(rate)
    report = MethodFuzzReport(target=f"{host}:{port}")

    for method, tier, note in method_list:
        rl.wait()
        code, reason, server, cseq_echoed, raw = _send_method(
            method, host, port, local_ip, timeout, traffic_log
        )
        excerpt = ""
        if raw:
            excerpt = raw[:120].decode("utf-8", errors="replace").replace("\r\n", " | ")
        result = MethodProbeResult(
            method=method,
            tier=tier,
            note=note,
            status_code=code,
            reason=reason,
            server=server,
            cseq_echoed=cseq_echoed,
            response_excerpt=excerpt,
        )
        report.probes.append(result)

        # Classify anomalies.  2xx on anything outside tier 0 standard verbs
        # is very surprising; 401/407 challenges on vendor/admin methods
        # means the PBX has a handler (credential-gated RCE potential).
        if code and 200 <= code < 300 and tier >= 2:
            report.anomalies.append(
                f"{method}: accepted ({code} {reason}) — non-standard verb "
                f"not expected to be implemented"
            )
        elif code in (401, 407) and tier >= 2:
            report.anomalies.append(
                f"{method}: auth-challenged ({code}) — PBX has a handler for "
                f"a non-standard verb; credentialed testing warranted"
            )
        elif code and code >= 500 and tier == 3:
            report.anomalies.append(
                f"{method}: 5xx ({code} {reason}) — malformed / case-variant "
                f"triggered server error (possible input-handling bug)"
            )

    report.elapsed_s = time.monotonic() - start
    return report


def build_findings(report: MethodFuzzReport) -> list[dict]:
    """Convert fuzz-report anomalies into findings entries.

    Emits one 'info' finding per scan summarising what we probed, plus
    medium/high findings for each anomaly.
    """
    findings: list[dict] = []

    # Always-on informational finding so the operator knows the probe ran.
    findings.append({
        "id": "sip.method_fuzz.summary",
        "title": f"SIP method fuzzing — {len(report.probes)} verbs probed",
        "severity": "info",
        "detail": (
            f"Probed {len(report.probes)} SIP methods against {report.target}. "
            f"Observed {len(report.anomalies)} anomalous response(s). "
            f"See the raw probe table in the detailed report for per-method "
            f"status codes."
        ),
    })

    for anom in report.anomalies:
        # 2xx accepted verbs are high severity; everything else medium.
        severity = "high" if "accepted" in anom else "medium"
        findings.append({
            "id": f"sip.method_fuzz.{anom.split(':', 1)[0].lower()}",
            "title": f"SIP method fuzz anomaly: {anom.split(':', 1)[0]}",
            "severity": severity,
            "detail": anom + (
                ". Unexpected handling of unusual SIP methods is a well-known "
                "source of input-validation bugs and occasionally remote code "
                "execution paths (e.g. CVE-2020-35508, CVE-2021-36148). "
                "Follow up with credentialed fuzzing and review the PBX "
                "SIP dispatch code for this verb."
            ),
            "remediation": (
                "Configure the PBX/SBC to reject any SIP method not on the "
                "RFC-sanctioned list used by your deployment. Most "
                "enterprise SBCs (Ribbon, Oracle, AudioCodes) expose a "
                "method-whitelist — enable it. For Asterisk, audit loaded "
                "modules with 'module show' and unload any that register "
                "non-standard verbs."
            ),
        })

    return findings
