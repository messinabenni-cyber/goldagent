"""OSINT pre-scan module — passive intelligence gathering via Shodan and Censys.

Queries Shodan and Censys for existing knowledge about a target IP *before*
any active scanning touches the target.  Results are merged into an
:class:`OsintResult` dataclass that the rest of the tool can use for
prioritisation and risk scoring.

All HTTP is performed with :mod:`urllib.request` from the standard library;
no third-party dependencies are required.

Typical usage::

    from modules.osint import run_osint, format_osint_report

    result = run_osint(
        ip="203.0.113.10",
        shodan_key="YOUR_SHODAN_KEY",
        censys_id="YOUR_CENSYS_ID",
        censys_secret="YOUR_CENSYS_SECRET",
    )
    print(format_osint_report(result))

Thread safety
-------------
No module-level mutable state.  :func:`run_osint` spawns worker threads
internally via :class:`~concurrent.futures.ThreadPoolExecutor` and joins them
before returning — callers do not need to manage threads.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Risk-scoring constants
# ---------------------------------------------------------------------------

# SIP signalling ports — each open port adds to risk score
_SIP_PORTS: frozenset[int] = frozenset({5060, 5061, 5080})

# Asterisk Manager Interface — highly privileged, very dangerous if exposed
_AMI_PORT: int = 5038

# Service names that commonly ship with default credentials
_DEFAULT_CRED_SERVICES: frozenset[str] = frozenset({
    "asterisk",
    "freepbx",
    "elastix",
    "3cx",
    "freeswitch",
    "grandstream",
    "cisco-ccm",
    "avaya",
    "mitel",
})

_RISK_SIP_PORT: int = 10     # per SIP port present
_RISK_CVE: int = 20          # per CVE in vuln data
_RISK_AMI: int = 15          # AMI port exposed
_RISK_DEFAULT_CRED: int = 10 # per service with known default credentials

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class OsintResult:
    """Aggregated OSINT findings for a single IP address.

    Attributes
    ----------
    ip:
        The queried IP address.
    shodan_data:
        Raw JSON response from the Shodan host API, or empty dict if
        unavailable.
    censys_data:
        Raw JSON response from the Censys v2 hosts API, or empty dict if
        unavailable.
    known_ports:
        Deduplicated list of open ports seen by Shodan and/or Censys.
    known_services:
        Service names associated with open ports (e.g. ``"sip"``, ``"http"``).
    cves:
        CVE identifiers extracted from Shodan's ``vulns`` field.
    banners:
        Service banners/version strings collected from both sources.
    country:
        ISO country code of the IP, or empty string if unknown.
    org:
        Organisation or ASN name owning the IP, or empty string if unknown.
    last_seen:
        ISO-8601 timestamp of the most recent scan observation, or empty
        string if unknown.
    risk_score:
        Integer 0–100 computed from exposed VoIP ports, CVEs, and known
        risky services.  Higher is worse.
    summary:
        Human-readable one-paragraph summary of findings.
    """
    ip: str
    shodan_data: dict = field(default_factory=dict)
    censys_data: dict = field(default_factory=dict)
    known_ports: list[int] = field(default_factory=list)
    known_services: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    banners: list[str] = field(default_factory=list)
    country: str = ""
    org: str = ""
    last_seen: str = ""
    risk_score: int = 0
    summary: str = ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> dict:
    """Perform an HTTP GET request and return the parsed JSON body.

    Parameters
    ----------
    url:
        The full URL to request.
    headers:
        Optional mapping of additional HTTP headers (e.g. ``Authorization``).
    timeout:
        Socket timeout in seconds.

    Returns
    -------
    dict
        Parsed JSON response body, or an empty dict on any error.  Errors are
        silently swallowed so that a failed OSINT source does not abort the
        overall scan.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "voip-pentest-scanner/1.0")
    if headers:
        for key, val in headers.items():
            req.add_header(key, val)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        # 404 → target not indexed; 401/403 → bad key; 5xx → server error.
        # All are non-fatal for our purposes.
        _ = exc.code  # referenced to satisfy linters
        return {}
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# Source-specific lookup functions
# ---------------------------------------------------------------------------

def shodan_lookup(
    ip: str,
    api_key: str,
    timeout: float = 5.0,
) -> dict:
    """Query the Shodan Host API for a single IP address.

    Sends ``GET https://api.shodan.io/shodan/host/{ip}?key={api_key}`` and
    returns the raw JSON response as a dict.

    Parameters
    ----------
    ip:
        Target IPv4 address to look up.
    api_key:
        Shodan API key.  Obtain one from https://account.shodan.io.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    dict
        Shodan host object on success (see Shodan API docs for schema), or
        empty dict on network error, invalid key, or unknown IP.

    Notes
    -----
    - The Shodan free tier allows 1 query/second; this function does not
      rate-limit on its own.  Callers responsible for pacing if querying in
      bulk.
    - No Shodan credits are consumed by this lookup (read-only host query).
    """
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    return _http_get_json(url, timeout=timeout)


def censys_lookup(
    ip: str,
    api_id: str,
    api_secret: str,
    timeout: float = 5.0,
) -> dict:
    """Query the Censys v2 Hosts API for a single IP address.

    Sends ``GET https://search.censys.io/api/v2/hosts/{ip}`` with HTTP Basic
    authentication using *api_id* as the username and *api_secret* as the
    password.

    Parameters
    ----------
    ip:
        Target IPv4 address to look up.
    api_id:
        Censys API ID (username).  Obtain one from https://search.censys.io.
    api_secret:
        Censys API secret (password).
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    dict
        Censys ``result`` sub-object on success (see Censys API docs), or
        empty dict on error.

    Notes
    -----
    - Censys uses Basic authentication over HTTPS — credentials are sent
      base64-encoded in the ``Authorization`` header.
    - The ``result`` key is unpacked for convenience; callers receive the
      host object directly rather than the wrapper envelope.
    """
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    credentials = f"{api_id}:{api_secret}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    auth_header = {"Authorization": f"Basic {encoded}"}
    raw = _http_get_json(url, headers=auth_header, timeout=timeout)
    # Censys wraps the result: {"code": 200, "status": "OK", "result": {...}}
    return raw.get("result", raw) if raw else {}


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_shodan(data: dict) -> dict:
    """Normalise Shodan host data into a common intermediate structure.

    Returns a dict with keys: ports, services, cves, banners, country, org,
    last_seen.
    """
    out: dict = {
        "ports": [],
        "services": [],
        "cves": [],
        "banners": [],
        "country": "",
        "org": "",
        "last_seen": "",
    }
    if not data:
        return out

    # Open ports
    out["ports"] = [int(p) for p in data.get("ports", []) if isinstance(p, (int, str))]

    # Per-service records (Shodan calls them "data" entries)
    for svc in data.get("data", []):
        port = svc.get("port")
        if isinstance(port, int) and port not in out["ports"]:
            out["ports"].append(port)

        transport = svc.get("transport", "")
        product = svc.get("product", "")
        svc_name = svc.get("_shodan", {}).get("module", "")
        label = product or svc_name or transport
        if label and label not in out["services"]:
            out["services"].append(label.lower())

        banner = svc.get("banner", "").strip()
        if not banner:
            # Try data field used by some modules
            banner = str(svc.get("data", "")).strip()
        if banner and len(banner) <= 512 and banner not in out["banners"]:
            out["banners"].append(banner)

    # CVEs from Shodan's vulnerability data
    vulns = data.get("vulns", {})
    if isinstance(vulns, dict):
        out["cves"] = list(vulns.keys())
    elif isinstance(vulns, list):
        out["cves"] = [str(v) for v in vulns]

    # Geolocation & org
    out["country"] = data.get("country_code", "")
    out["org"] = data.get("org", data.get("isp", ""))
    out["last_seen"] = data.get("last_update", "")

    return out


def _extract_censys(data: dict) -> dict:
    """Normalise Censys v2 host data into a common intermediate structure.

    Returns a dict with keys: ports, services, cves, banners, country, org,
    last_seen.
    """
    out: dict = {
        "ports": [],
        "services": [],
        "cves": [],
        "banners": [],
        "country": "",
        "org": "",
        "last_seen": "",
    }
    if not data:
        return out

    # Services list (Censys v2 schema)
    for svc in data.get("services", []):
        port = svc.get("port")
        if isinstance(port, int):
            if port not in out["ports"]:
                out["ports"].append(port)

        svc_name = svc.get("service_name", "").lower()
        transport = svc.get("transport_protocol", "").lower()
        label = svc_name or transport
        if label and label not in out["services"]:
            out["services"].append(label)

        # Banners — Censys stores extended data per protocol
        extended = svc.get("extended_service_name", "")
        banner = svc.get("banner", "")
        # Dig into known sub-dicts for version strings
        for proto_key in ("http", "tls", "ssh", "ftp", "smtp"):
            proto_data = svc.get(proto_key, {})
            if isinstance(proto_data, dict):
                # Common banner locations in Censys protocol objects
                for field_key in ("banner", "server_header", "version"):
                    val = proto_data.get(field_key, "")
                    if val and str(val).strip():
                        banner = str(val).strip()
                        break
        final_banner = banner or extended
        if final_banner and len(final_banner) <= 512 and final_banner not in out["banners"]:
            out["banners"].append(final_banner)

    # Geolocation (Censys v2 puts it under "location")
    location = data.get("location", {})
    if isinstance(location, dict):
        out["country"] = location.get("country_code", "")

    # ASN / org info
    asn_info = data.get("autonomous_system", {})
    if isinstance(asn_info, dict):
        out["org"] = asn_info.get("name", asn_info.get("description", ""))

    out["last_seen"] = data.get("last_updated_at", "")

    return out


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_risk_score(
    ports: list[int],
    services: list[str],
    cves: list[str],
) -> int:
    """Compute a risk score in the range 0–100.

    Scoring rules
    -------------
    +10 per open SIP port (5060, 5061, 5080)
    +20 per CVE present in Shodan vuln data
    +15 if AMI port 5038 is exposed
    +10 per service with known default credentials

    The score is clamped to [0, 100].
    """
    score = 0

    port_set = set(ports)

    for p in _SIP_PORTS:
        if p in port_set:
            score += _RISK_SIP_PORT

    score += len(cves) * _RISK_CVE

    if _AMI_PORT in port_set:
        score += _RISK_AMI

    for svc in services:
        svc_lower = svc.lower()
        for known in _DEFAULT_CRED_SERVICES:
            if known in svc_lower:
                score += _RISK_DEFAULT_CRED
                break  # count each service only once

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------

def _build_summary(result: OsintResult) -> str:
    """Produce a one-paragraph human-readable summary of OSINT findings."""
    parts: list[str] = []

    sources: list[str] = []
    if result.shodan_data:
        sources.append("Shodan")
    if result.censys_data:
        sources.append("Censys")

    if sources:
        parts.append(f"OSINT data for {result.ip} retrieved from {' and '.join(sources)}.")
    else:
        parts.append(f"No OSINT data could be retrieved for {result.ip}.")
        return " ".join(parts)

    if result.country or result.org:
        loc_parts: list[str] = []
        if result.org:
            loc_parts.append(f"org: {result.org}")
        if result.country:
            loc_parts.append(f"country: {result.country}")
        parts.append(f"Host is registered to {', '.join(loc_parts)}.")

    if result.known_ports:
        port_str = ", ".join(str(p) for p in sorted(result.known_ports))
        parts.append(f"Open ports observed: {port_str}.")

    sip_exposed = [p for p in result.known_ports if p in _SIP_PORTS]
    if sip_exposed:
        parts.append(
            f"SIP signalling port(s) visible from the internet: "
            f"{', '.join(str(p) for p in sorted(sip_exposed))}."
        )

    if _AMI_PORT in result.known_ports:
        parts.append(
            "WARNING: Asterisk Manager Interface (port 5038) is internet-exposed. "
            "This provides administrative control over the PBX."
        )

    if result.cves:
        cve_list = ", ".join(result.cves[:5])
        extra = f" (and {len(result.cves) - 5} more)" if len(result.cves) > 5 else ""
        parts.append(f"Known vulnerabilities: {cve_list}{extra}.")

    if result.known_services:
        parts.append(f"Identified services: {', '.join(sorted(set(result.known_services)))}.")

    risk_label = "Low"
    if result.risk_score >= 70:
        risk_label = "Critical"
    elif result.risk_score >= 50:
        risk_label = "High"
    elif result.risk_score >= 25:
        risk_label = "Medium"

    parts.append(f"Computed risk score: {result.risk_score}/100 ({risk_label}).")

    if result.last_seen:
        parts.append(f"Most recent scan observation: {result.last_seen}.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_osint(
    ip: str,
    shodan_key: Optional[str] = None,
    censys_id: Optional[str] = None,
    censys_secret: Optional[str] = None,
    timeout: float = 5.0,
) -> OsintResult:
    """Run passive OSINT lookups against *ip* and return aggregated findings.

    Queries Shodan and/or Censys in parallel using a
    :class:`~concurrent.futures.ThreadPoolExecutor`.  Sources with missing API
    credentials are silently skipped, so callers may pass only the keys they
    have without error.

    Parameters
    ----------
    ip:
        Target IPv4 address to investigate.
    shodan_key:
        Shodan API key.  Pass ``None`` to skip Shodan lookup.
    censys_id:
        Censys API ID.  Both *censys_id* and *censys_secret* must be provided
        to enable Censys lookups.
    censys_secret:
        Censys API secret.  See *censys_id*.
    timeout:
        Per-source HTTP request timeout in seconds.

    Returns
    -------
    OsintResult
        Merged and scored result object.  Fields are always populated (possibly
        with empty defaults) even when one or both sources fail.

    Example
    -------
    ::

        result = run_osint("1.2.3.4", shodan_key="abc123")
        if result.risk_score >= 50:
            print("High-risk target — review before active scanning")
    """
    result = OsintResult(ip=ip)

    futures: dict = {}

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="osint") as pool:
        if shodan_key:
            futures["shodan"] = pool.submit(shodan_lookup, ip, shodan_key, timeout)
        if censys_id and censys_secret:
            futures["censys"] = pool.submit(
                censys_lookup, ip, censys_id, censys_secret, timeout
            )

        for key, fut in futures.items():
            try:
                data = fut.result()
            except Exception:
                data = {}

            if key == "shodan":
                result.shodan_data = data
            elif key == "censys":
                result.censys_data = data

    # Extract normalised fields from each source
    shodan_extracted = _extract_shodan(result.shodan_data)
    censys_extracted = _extract_censys(result.censys_data)

    # Merge ports — deduplicated, sorted
    all_ports: set[int] = set(shodan_extracted["ports"]) | set(censys_extracted["ports"])
    result.known_ports = sorted(all_ports)

    # Merge services — deduplicated
    all_services: set[str] = (
        set(shodan_extracted["services"]) | set(censys_extracted["services"])
    )
    result.known_services = sorted(all_services)

    # CVEs come only from Shodan's vuln data (Censys v2 free tier doesn't expose them)
    result.cves = list(dict.fromkeys(shodan_extracted["cves"]))  # dedup, preserve order

    # Banners — merged and deduped
    seen_banners: set[str] = set()
    merged_banners: list[str] = []
    for banner in shodan_extracted["banners"] + censys_extracted["banners"]:
        if banner not in seen_banners:
            seen_banners.add(banner)
            merged_banners.append(banner)
    result.banners = merged_banners

    # Prefer Shodan for geo/org since it's generally richer; fall back to Censys
    result.country = (
        shodan_extracted["country"] or censys_extracted["country"]
    )
    result.org = shodan_extracted["org"] or censys_extracted["org"]

    # Prefer the most recent last_seen timestamp
    result.last_seen = shodan_extracted["last_seen"] or censys_extracted["last_seen"]

    # Compute risk score
    result.risk_score = _compute_risk_score(
        result.known_ports, result.known_services, result.cves
    )

    # Generate human-readable summary
    result.summary = _build_summary(result)

    return result


def format_osint_report(result: OsintResult) -> str:
    """Format an :class:`OsintResult` as a plain-text CLI report.

    Parameters
    ----------
    result:
        The result object returned by :func:`run_osint`.

    Returns
    -------
    str
        Multi-line human-readable report suitable for printing to a terminal.

    Example
    -------
    ::

        result = run_osint("203.0.113.10", shodan_key="...")
        print(format_osint_report(result))
    """
    SEP = "=" * 60
    sep = "-" * 60

    risk_label = "Low"
    if result.risk_score >= 70:
        risk_label = "CRITICAL"
    elif result.risk_score >= 50:
        risk_label = "HIGH"
    elif result.risk_score >= 25:
        risk_label = "MEDIUM"

    lines: list[str] = [
        SEP,
        f"  OSINT Report — {result.ip}",
        SEP,
    ]

    lines += [
        f"  Organisation : {result.org or '(unknown)'}",
        f"  Country      : {result.country or '(unknown)'}",
        f"  Last seen    : {result.last_seen or '(unknown)'}",
        f"  Risk score   : {result.risk_score}/100  [{risk_label}]",
        sep,
    ]

    if result.known_ports:
        lines.append(f"  Open ports   : {', '.join(str(p) for p in sorted(result.known_ports))}")
    else:
        lines.append("  Open ports   : (none observed)")

    if result.known_services:
        lines.append(
            f"  Services     : {', '.join(sorted(set(result.known_services)))}"
        )

    sip_ports = [p for p in result.known_ports if p in _SIP_PORTS]
    if sip_ports:
        lines.append(
            f"  SIP ports    : {', '.join(str(p) for p in sorted(sip_ports))}  [!]"
        )

    if _AMI_PORT in result.known_ports:
        lines.append(
            f"  AMI (5038)   : EXPOSED  [!! HIGH RISK]"
        )

    lines.append(sep)

    if result.cves:
        lines.append(f"  CVEs ({len(result.cves)}):")
        for cve in result.cves:
            lines.append(f"    - {cve}")
    else:
        lines.append("  CVEs         : none indexed")

    lines.append(sep)

    if result.banners:
        lines.append(f"  Banners ({len(result.banners)}):")
        for banner in result.banners[:10]:  # cap output at 10 for readability
            # Truncate very long banners
            display = banner if len(banner) <= 120 else banner[:117] + "..."
            lines.append(f"    {display}")
        if len(result.banners) > 10:
            lines.append(f"    ... and {len(result.banners) - 10} more")
    else:
        lines.append("  Banners      : (none)")

    lines += [sep, "  Summary:", ""]
    # Word-wrap summary to 78 columns
    words = result.summary.split()
    current_line: list[str] = []
    current_len = 0
    for word in words:
        if current_len + len(word) + 1 > 76:
            lines.append("    " + " ".join(current_line))
            current_line = [word]
            current_len = len(word)
        else:
            current_line.append(word)
            current_len += len(word) + 1
    if current_line:
        lines.append("    " + " ".join(current_line))

    lines += ["", SEP]
    return "\n".join(lines)
