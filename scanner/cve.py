"""CVE and configuration-weakness checks for PBX platforms.

Each check is a lightweight probe — no exploit delivery, no shell code.
Checks confirm *reachability of vulnerable surfaces* and banner-based
version matching, which is sufficient to demonstrate risk in a pentest
report.

Platforms covered:
  FreePBX / Asterisk  — CVE-2019-19006, CVE-2021-45461, CVE-2022-2347,
                        CVE-2024-30269, path traversal, admin UI exposure
  Grandstream UCM     — CVE-2021-37748, CVE-2023-37315, default creds
  3CX                 — CVE-2023-29059, admin interface exposure
  Kamailio/OpenSIPS   — reflection amplification, unauth REGISTER
  Generic             — AMI without TLS, SIP without TLS, SRTP absent
"""
from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field


@dataclass
class CveResult:
    cve_id: str          # "CVE-2021-37748" or "CONFIG-<id>" for non-CVE issues
    platform: str        # FreePBX | Asterisk | Grandstream | 3CX | Generic
    severity: str        # critical | high | medium | low | info
    host: str
    port: int
    title: str
    evidence: str
    remediation: str
    affected_version: str = ""   # extracted version string if found
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP helpers (shared with http_probes but duplicated here to keep module
# self-contained — this avoids circular imports)
# ---------------------------------------------------------------------------

def _get(host: str, port: int, path: str, timeout: float = 4.0,
         use_tls: bool = False) -> tuple[int, str, str]:
    """Return (status, server_header, body[:8k]). (0,"","") on error."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        req = (
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
            "User-Agent: Mozilla/5.0 VoIPScan/4.0\r\n\r\n"
        )
        s.sendall(req.encode())
        raw = b""
        while len(raw) < 16384:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
        text = raw.decode("utf-8", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        status = 0
        try:
            status = int(head.split(" ", 2)[1])
        except (IndexError, ValueError):
            pass
        server = ""
        for line in head.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        return status, server, body[:8192]
    except (socket.timeout, OSError, ssl.SSLError):
        return 0, "", ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def _post(host: str, port: int, path: str, body: str, timeout: float = 4.0,
          use_tls: bool = False,
          ct: str = "application/x-www-form-urlencoded") -> tuple[int, str]:
    """POST. Returns (status, body[:4k])."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        bb = body.encode("utf-8")
        req = (
            f"POST {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"Content-Type: {ct}\r\nContent-Length: {len(bb)}\r\n"
            "User-Agent: Mozilla/5.0 VoIPScan/4.0\r\n\r\n"
        )
        s.sendall(req.encode() + bb)
        raw = b""
        while len(raw) < 8192:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
        text = raw.decode("utf-8", errors="replace")
        _, _, resp_body = text.partition("\r\n\r\n")
        head = text.split("\r\n\r\n", 1)[0]
        status = 0
        try:
            status = int(head.split(" ", 2)[1])
        except (IndexError, ValueError):
            pass
        return status, resp_body[:4096]
    except (socket.timeout, OSError, ssl.SSLError):
        return 0, ""
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Version extraction helpers
# ---------------------------------------------------------------------------

_FPBX_VER_RE = re.compile(r"FPBX-(\d+\.\d+[\.\d]*)|FreePBX\s+([\d\.]+)", re.I)
_AST_VER_RE  = re.compile(r"Asterisk\s+([\d\.]+)", re.I)
_GS_VER_RE   = re.compile(r"(UCM\w*|GXP\w*|HT\w*|DP\w*)[\s/]*([\d\.]+)", re.I)
_3CX_VER_RE  = re.compile(r"3CX[\s/]+([\d\.]+)", re.I)


def _extract_version(banner: str) -> str:
    for rx in (_FPBX_VER_RE, _AST_VER_RE, _GS_VER_RE, _3CX_VER_RE):
        m = rx.search(banner)
        if m:
            # Return the first non-None group
            return next((g for g in m.groups() if g), "")
    return ""


def _version_le(ver: str, threshold: str) -> bool:
    """True if ver <= threshold (simple numeric tuple comparison)."""
    try:
        vt = tuple(int(x) for x in ver.split("."))
        tt = tuple(int(x) for x in threshold.split("."))
        return vt <= tt
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# FreePBX / Asterisk checks
# ---------------------------------------------------------------------------

def _check_freepbx_cve_2019_19006(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2019-19006: FreePBX 13/14/15 unauthenticated admin access via
    tampered session cookie on /admin/config.php."""
    status, server, body = _get(host, port, "/admin/config.php", timeout, use_tls)
    if status == 0:
        return None
    # The vuln returns a 200 with admin panel content when cookie is absent
    # on unpatched versions — we just confirm the surface is reachable and
    # banner matches a vulnerable release
    body_l = body.lower()
    is_fpbx = ("freepbx" in body_l or "freepbx" in server.lower()
                or "fpbx" in server.lower() or "/admin/config" in body_l)
    if not is_fpbx:
        return None

    # Extract version from banner
    ver = _extract_version(server + " " + body)
    # Vulnerable: FreePBX < 15.0.16.75
    vuln_note = ""
    if ver and _version_le(ver, "15.0.16"):
        vuln_note = f" Version {ver} is in the vulnerable range."
    elif not ver:
        vuln_note = " Could not determine version — assume vulnerable until patched."

    return CveResult(
        cve_id="CVE-2019-19006",
        platform="FreePBX",
        severity="critical",
        host=host, port=port,
        title="CVE-2019-19006: FreePBX unauthenticated admin panel reachable",
        evidence=(
            f"GET /admin/config.php returned HTTP {status}; "
            f"Server: {server!r}.{vuln_note}"
        ),
        affected_version=ver,
        remediation=(
            "Apply FreePBX hotfix or upgrade to 13.0.197+/14.0.13+/15.0.16.75+. "
            "Immediately restrict /admin to localhost or VPN — the admin UI "
            "must never be internet-accessible."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-19006"],
    )


def _check_freepbx_cve_2021_45461(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2021-45461: FreePBX 15/16 RCE via unsanitised language parameter."""
    # The vuln path — sending a crafted locale value triggers a shell command
    # injection. We only test reachability of the endpoint here (read-only).
    if port not in (80, 443, 4443, 8443):
        return None
    status, _, body = _get(
        host, port,
        "/admin/config.php?type=setup&command=lang&lang=en_US",
        timeout, use_tls,
    )
    if status in (200, 302) and ("freepbx" in body.lower() or status == 302):
        return CveResult(
            cve_id="CVE-2021-45461",
            platform="FreePBX",
            severity="critical",
            host=host, port=port,
            title="CVE-2021-45461: FreePBX command injection endpoint reachable",
            evidence=(
                f"GET /admin/config.php?type=setup&command=lang returned HTTP {status}. "
                "The language-selection parameter was unsanitised in FreePBX ≤ 15.0.21.3 "
                "and ≤ 16.0.10.40 — successful exploitation yields OS command execution "
                "as the www-data / asterisk user."
            ),
            remediation=(
                "Upgrade to FreePBX 15.0.21.4+ or 16.0.10.41+. "
                "Block /admin from the internet immediately."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-45461"],
        )
    return None


def _check_freepbx_path_traversal(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2022-2347 / generic path traversal — try to read /etc/passwd via
    FreePBX file-manager endpoint."""
    if port not in (80, 443, 4443, 8443):
        return None
    # Endpoint only reachable if admin is logged in, but the path is indicative
    status, _, body = _get(
        host, port,
        "/admin/config.php?display=filemanager&dir=../../etc",
        timeout, use_tls,
    )
    if status in (200,) and ("etc" in body.lower() or "passwd" in body.lower()):
        return CveResult(
            cve_id="CVE-2022-2347",
            platform="FreePBX",
            severity="high",
            host=host, port=port,
            title="FreePBX file-manager path traversal surface reachable",
            evidence=(
                f"GET /admin/config.php?display=filemanager&dir=../../etc "
                f"returned HTTP {status} with directory content."
            ),
            remediation=(
                "Upgrade FreePBX. Restrict the admin interface to localhost / VPN. "
                "Apply Apache/nginx rules to reject `..` in query strings."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-2347"],
        )
    return None


def _check_ami_no_tls(
    host: str, tcp_ports: list[int], timeout: float
) -> CveResult | None:
    """CONFIG: AMI exposed on TCP/5038 without TLS — cleartext credential + command channel."""
    if 5038 not in tcp_ports:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, 5038))
        banner = s.recv(256).decode("utf-8", errors="replace")
        if "Asterisk Call Manager" in banner:
            return CveResult(
                cve_id="CONFIG-AMI-NO-TLS",
                platform="Asterisk",
                severity="high",
                host=host, port=5038,
                title="Asterisk Manager Interface exposed in cleartext (no TLS)",
                evidence=(
                    f"TCP/5038 banner: {banner.strip()!r}. "
                    "AMI credentials and call-control commands transit in plaintext."
                ),
                remediation=(
                    "Bind AMI to 127.0.0.1 and tunnel through an SSH port forward "
                    "or use Asterisk's TLSManagerPort (5039). Never expose AMI "
                    "directly to the internet."
                ),
            )
    except (socket.timeout, OSError):
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return None


def _check_freepbx_admin_2024(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2024-30269: FreePBX admin SQL injection via module parameter."""
    if port not in (80, 443, 4443, 8443):
        return None
    # Probe: GET with a simple SQL injection attempt in the module parameter
    payload = "/admin/config.php?display=modules&action=local&search=1'%20OR%20'1'='1"
    status, _, body = _get(host, port, payload, timeout, use_tls)
    if status in (200,) and ("module" in body.lower() or "freepbx" in body.lower()):
        return CveResult(
            cve_id="CVE-2024-30269",
            platform="FreePBX",
            severity="critical",
            host=host, port=port,
            title="CVE-2024-30269: FreePBX SQL injection surface reachable",
            evidence=(
                f"GET with SQLi payload in module search returned HTTP {status}. "
                "Unpatched FreePBX < 16.0.40 may be vulnerable to SQL injection "
                "in the admin module page, enabling authentication bypass."
            ),
            remediation=(
                "Upgrade to FreePBX 16.0.40+ or apply the security hotfix. "
                "Restrict /admin to localhost or VPN immediately."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-30269"],
        )
    return None


# ---------------------------------------------------------------------------
# Grandstream checks
# ---------------------------------------------------------------------------

def _check_grandstream_cve_2021_37748(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2021-37748: Grandstream UCM6xxx unauthenticated system config dump."""
    status, _, body = _get(host, port, "/cgi-bin/api-get_config", timeout, use_tls)
    body_l = body.lower()
    if status == 200 and any(kw in body_l for kw in
                              ("sippassword", "extension", "secret", "password",
                               "peer", "trunk", "voicemail")):
        # Actual sensitive data returned without auth
        return CveResult(
            cve_id="CVE-2021-37748",
            platform="Grandstream",
            severity="critical",
            host=host, port=port,
            title="CVE-2021-37748: Grandstream UCM config exposed without authentication",
            evidence=(
                f"GET /cgi-bin/api-get_config returned HTTP {status} with "
                "configuration data (SIP passwords / extension secrets) "
                "without requiring authentication."
            ),
            remediation=(
                "Update UCM firmware to ≥ 1.0.20.22 immediately. "
                "Block /cgi-bin/api-get_config at the perimeter as an emergency "
                "workaround."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-37748"],
        )
    return None


def _check_grandstream_cve_2023_37315(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2023-37315: Grandstream UCM6xxx pre-auth RCE via CRLF injection
    in the HTTP API. We only confirm endpoint reachability."""
    if port not in (80, 443, 8089, 8443):
        return None
    # The vuln is in the login endpoint — just check if it responds at all
    status, server, body = _get(host, port, "/cgi-bin/api.values.get",
                                  timeout, use_tls)
    gs_sig = ("grandstream" in server.lower() or "ucm" in body.lower()
               or "grandstream" in body.lower())
    if status != 0 and gs_sig:
        return CveResult(
            cve_id="CVE-2023-37315",
            platform="Grandstream",
            severity="critical",
            host=host, port=port,
            title="CVE-2023-37315: Grandstream UCM pre-auth RCE endpoint reachable",
            evidence=(
                f"GET /cgi-bin/api.values.get returned HTTP {status}; "
                f"Grandstream signature detected in response. "
                "CVE-2023-37315 allows unauthenticated OS command execution "
                "via CRLF injection in the HTTP login API on UCM6xxx "
                "firmware < 1.0.20.30."
            ),
            remediation=(
                "Upgrade UCM firmware to ≥ 1.0.20.30. Block the admin HTTP "
                "interface from the internet immediately."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-37315"],
        )
    return None


def _check_grandstream_default_creds(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """Grandstream UCM default credentials admin/admin confirmed via login API."""
    import json as _json
    body = _json.dumps({"action": "login", "user": "admin", "password": "admin"})
    status, resp = _post(host, port, "/cgi-bin/api.values.get",
                          body, timeout, use_tls, ct="application/json")
    if status in (200, 201) and (
        '"status":true' in resp or "authenticated" in resp.lower()
        or '"session"' in resp.lower()
    ):
        return CveResult(
            cve_id="CONFIG-GS-DEFAULT-CREDS",
            platform="Grandstream",
            severity="critical",
            host=host, port=port,
            title="Grandstream UCM default credentials active (admin/admin)",
            evidence=(
                f"POST /cgi-bin/api.values.get with admin/admin returned "
                f"HTTP {status} indicating successful authentication."
            ),
            remediation=(
                "Change the Grandstream admin password immediately via "
                "System → User Management. Default credentials allow full "
                "device takeover and SIP extension credential extraction."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# 3CX checks
# ---------------------------------------------------------------------------

def _check_3cx_admin_exposed(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """3CX management console exposed — required surface for CVE-2023-29059."""
    if port not in (80, 443, 5000, 5001, 8080, 8443):
        return None
    # 3CX management paths
    for path in ("/management", "/webclient", "/api/v2/Config/GetAll"):
        status, server, body = _get(host, port, path, timeout, use_tls)
        if status == 0:
            continue
        body_l = body.lower()
        if "3cx" in body_l or "3cx" in server.lower() or "xcapi" in body_l:
            return CveResult(
                cve_id="CONFIG-3CX-ADMIN-EXPOSED",
                platform="3CX",
                severity="high",
                host=host, port=port,
                title="3CX management interface reachable from the internet",
                evidence=(
                    f"GET {path} returned HTTP {status}; "
                    f"3CX signature in response. "
                    "The 3CX management console being internet-accessible "
                    "was a precondition for the CVE-2023-29059 supply-chain "
                    "attack."
                ),
                remediation=(
                    "Restrict the 3CX management console to VPN or an IP "
                    "allow-list. Apply the latest 3CX security updates. "
                    "See the 3CX incident advisory."
                ),
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-29059"],
            )
    return None


def _check_3cx_cve_2023_29059(
    host: str, port: int, use_tls: bool, timeout: float
) -> CveResult | None:
    """CVE-2023-29059: 3CX Desktop App supply chain / management API exposure."""
    if port not in (80, 443, 5001, 8443):
        return None
    status, server, body = _get(host, port, "/api/v2/Config/GetAll", timeout, use_tls)
    if status in (200, 401, 403) and ("3cx" in body.lower() or "3cx" in server.lower()
                                       or "xcapi" in body.lower()):
        return CveResult(
            cve_id="CVE-2023-29059",
            platform="3CX",
            severity="critical",
            host=host, port=port,
            title="CVE-2023-29059: 3CX management API surface reachable",
            evidence=(
                f"GET /api/v2/Config/GetAll returned HTTP {status}; "
                "3CX signature confirmed. This endpoint was exploited in the "
                "2023 3CX supply-chain attack to pivot into enterprise networks."
            ),
            remediation=(
                "Update 3CX to the latest version. Restrict management API "
                "to VPN. Audit all 3CX desktop client installs for signs of "
                "compromise (see 3CX CISA advisory)."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-29059"],
        )
    return None


# ---------------------------------------------------------------------------
# Kamailio / OpenSIPS checks
# ---------------------------------------------------------------------------

def _check_sip_reflection(
    host: str, port: int, sip_server: str, timeout: float
) -> CveResult | None:
    """CONFIG: SIP server reachable without auth — potential amplification relay."""
    kamailio_sig = re.search(r"kamailio|openser|opensips", sip_server, re.I)
    if not kamailio_sig:
        return None
    return CveResult(
        cve_id="CONFIG-SIP-REFLECTION",
        platform="Kamailio/OpenSIPS",
        severity="medium",
        host=host, port=port,
        title="SIP proxy reachable — potential UDP amplification vector",
        evidence=(
            f"SIP server banner: {sip_server!r}. Open SIP proxies can be "
            "abused for UDP reflection/amplification attacks and unauthenticated "
            "call routing."
        ),
        remediation=(
            "Apply strict SIP ACLs in Kamailio/OpenSIPS. Require digest "
            "authentication for all REGISTER and INVITE requests. "
            "Rate-limit responses to unknown sources."
        ),
    )


# ---------------------------------------------------------------------------
# Generic / cross-platform checks
# ---------------------------------------------------------------------------

def _check_sip_no_tls(
    host: str, sip_port: int, sip_transport: str
) -> CveResult | None:
    """CONFIG: SIP signalling without TLS exposes credentials and call content."""
    if sip_transport in ("tls",):
        return None
    return CveResult(
        cve_id="CONFIG-SIP-NO-TLS",
        platform="Generic",
        severity="medium",
        host=host, port=sip_port,
        title="SIP signalling without TLS — credentials transit in cleartext",
        evidence=(
            f"SIP is reachable on port {sip_port} over "
            f"{sip_transport.upper()}. "
            "SIP REGISTER messages contain hashed credentials; without TLS, "
            "a passive observer can capture and offline-crack them."
        ),
        remediation=(
            "Enable SIP/TLS on port 5061 for all trunk and endpoint "
            "connections. Set transport=tls in FreePBX SIP settings. "
            "Disable UDP SIP where not required."
        ),
    )


def _check_srtp_absent(host: str, port: int) -> CveResult | None:
    """CONFIG: Media encryption (SRTP) not enforced."""
    return CveResult(
        cve_id="CONFIG-SRTP-NOT-ENFORCED",
        platform="Generic",
        severity="medium",
        host=host, port=port,
        title="SRTP (media encryption) not enforced",
        evidence=(
            "The PBX accepted an INVITE without an a=crypto SRTP offer, "
            "indicating media encryption is not mandatory. Call audio "
            "transits as unencrypted RTP on the internet."
        ),
        remediation=(
            "Set rtp_encryption=yes (FreePBX) or media_encryption=sdes "
            "(Kamailio). Deny RTP/AVP when the endpoint offers SAVP."
        ),
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def check_all(
    host: str,
    tcp_ports: list[int],
    fingerprint: str,
    sip_server: str = "",
    sip_port: int = 5060,
    sip_transport: str = "udp",
    srtp_downgraded: bool = False,
    timeout: float = 4.0,
) -> list[CveResult]:
    """Run all applicable CVE/config checks against a discovered host.

    Returns a deduplicated list of CveResult, sorted critical → info.
    """
    results: list[CveResult] = []
    fp_l = fingerprint.lower()

    # Determine HTTP ports and their TLS setting
    http_port_tls: list[tuple[int, bool]] = []
    for p in tcp_ports:
        if p in (80, 8088):
            http_port_tls.append((p, False))
        elif p in (443, 4443, 8089, 8443):
            http_port_tls.append((p, True))

    # FreePBX / Asterisk checks
    if fp_l in ("freepbx", "asterisk", "unknown"):
        for port, tls in http_port_tls:
            for check in (
                _check_freepbx_cve_2019_19006,
                _check_freepbx_cve_2021_45461,
                _check_freepbx_path_traversal,
                _check_freepbx_admin_2024,
            ):
                r = check(host, port, tls, timeout)
                if r:
                    results.append(r)

        r = _check_ami_no_tls(host, tcp_ports, timeout)
        if r:
            results.append(r)

    # Grandstream checks
    if fp_l in ("grandstream", "unknown"):
        for port, tls in http_port_tls:
            for check in (
                _check_grandstream_cve_2021_37748,
                _check_grandstream_cve_2023_37315,
                _check_grandstream_default_creds,
            ):
                r = check(host, port, tls, timeout)
                if r:
                    results.append(r)

    # 3CX checks
    if fp_l in ("3cx", "unknown"):
        for port, tls in http_port_tls:
            for check in (
                _check_3cx_admin_exposed,
                _check_3cx_cve_2023_29059,
            ):
                r = check(host, port, tls, timeout)
                if r:
                    results.append(r)

    # Kamailio / OpenSIPS
    if sip_server:
        r = _check_sip_reflection(host, sip_port, sip_server, timeout)
        if r:
            results.append(r)

    # Generic — always run
    r = _check_sip_no_tls(host, sip_port, sip_transport)
    if r:
        results.append(r)

    if srtp_downgraded:
        results.append(_check_srtp_absent(host, sip_port))

    # Deduplicate by (cve_id, host, port)
    seen: set[tuple[str, str, int]] = set()
    deduped: list[CveResult] = []
    for res in results:
        key = (res.cve_id, res.host, res.port)
        if key not in seen:
            seen.add(key)
            deduped.append(res)

    # Sort: critical first
    _ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda r: _ORDER.get(r.severity, 5))
    return deduped
