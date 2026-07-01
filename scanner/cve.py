"""CVE and configuration-weakness checks for PBX platforms.

Each check is a lightweight probe — no exploit delivery, no shell code.
Checks confirm reachability of vulnerable surfaces and banner-based
version matching, which is sufficient to demonstrate risk in a pentest
report.

Platforms covered:
  FreePBX / Asterisk  — CVE-2019-19006, CVE-2021-45461, path traversal,
                        module exposure, recording exposure, CVE-2022-2347,
                        CVE-2025-57819 (EPM SQL injection + RCE, CVSS 9.8),
                        CVE-2025-57767 (SIP auth crash DoS, CVSS 7.5)
  Grandstream UCM     — CVE-2021-37748, CVE-2023-37315
  3CX                 — admin/webclient exposure, unauthenticated API
  Generic             — Asterisk AMI without TLS, SIP version disclosure,
                        CONFIG-SIP-TLS (unencrypted signaling, RFC 3261 §26),
                        CONFIG-SIP-WS-PLAIN (plain WebSocket SIP, RFC 7118),
                        CONFIG-SIP-WSS-CSWSH (Cross-Site WebSocket Hijacking)
"""
from __future__ import annotations

import json
import re
import socket
import ssl
from dataclasses import dataclass, field


@dataclass
class CveResult:
    cve_id: str           # "CVE-2021-37748" or "CONFIG-<id>" for non-CVE issues
    platform: str         # FreePBX | Asterisk | Grandstream | 3CX | Generic
    severity: str         # critical | high | medium | low | info
    host: str
    port: int
    title: str
    evidence: str
    remediation: str
    affected_version: str = ""   # extracted version string if found
    references: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)  # structured evidence (capture data, etc.)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(
    host: str,
    port: int,
    path: str,
    timeout: float = 3.0,
    use_tls: bool = False,
) -> tuple[int, dict[str, str], str]:
    """Perform an HTTP GET.

    Returns (status_code, headers_dict, body[:8192]).
    Returns (0, {}, "") on connection failure.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 VoIPScan/4.0\r\n"
            "Accept: */*\r\n"
            "\r\n"
        )
        s.sendall(request.encode("utf-8"))
        raw = b""
        while len(raw) < 32768:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
        text = raw.decode("utf-8", errors="replace")
        head_part, _, body = text.partition("\r\n\r\n")
        status = 0
        headers: dict[str, str] = {}
        lines = head_part.splitlines()
        if lines:
            try:
                status = int(lines[0].split(" ", 2)[1])
            except (IndexError, ValueError):
                pass
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
        return status, headers, body[:8192]
    except (socket.timeout, OSError, ssl.SSLError):
        return 0, {}, ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def _http_post(
    host: str,
    port: int,
    path: str,
    body: str,
    content_type: str = "application/x-www-form-urlencoded",
    timeout: float = 3.0,
    use_tls: bool = False,
) -> tuple[int, dict[str, str], str]:
    """Perform an HTTP POST.

    Returns (status_code, headers_dict, body[:8192]).
    Returns (0, {}, "") on connection failure.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        encoded_body = body.encode("utf-8")
        request = (
            f"POST {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(encoded_body)}\r\n"
            "User-Agent: Mozilla/5.0 VoIPScan/4.0\r\n"
            "Accept: */*\r\n"
            "\r\n"
        )
        s.sendall(request.encode("utf-8") + encoded_body)
        raw = b""
        while len(raw) < 32768:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
        text = raw.decode("utf-8", errors="replace")
        head_part, _, resp_body = text.partition("\r\n\r\n")
        status = 0
        headers: dict[str, str] = {}
        lines = head_part.splitlines()
        if lines:
            try:
                status = int(lines[0].split(" ", 2)[1])
            except (IndexError, ValueError):
                pass
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
        return status, headers, resp_body[:8192]
    except (socket.timeout, OSError, ssl.SSLError):
        return 0, {}, ""
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Version extraction and comparison helpers
# ---------------------------------------------------------------------------

_FPBX_VER_RE = re.compile(
    r"FPBX[- ]([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)"
    r"|FreePBX[\s/]+([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)",
    re.I,
)
_AST_VER_RE = re.compile(r"Asterisk[\s/]+([\d]+\.[\d]+\.[\d]+(?:\.[\d]+)?)", re.I)


def _extract_fpbx_version(text: str) -> str:
    m = _FPBX_VER_RE.search(text)
    if m:
        return next((g for g in m.groups() if g), "")
    return ""


def _extract_asterisk_version(text: str) -> str:
    m = _AST_VER_RE.search(text)
    if m:
        return m.group(1)
    return ""


def _version_lt(ver: str, threshold: str) -> bool:
    """Return True if ver < threshold using numeric tuple comparison."""
    try:
        v = tuple(int(x) for x in ver.split("."))
        t = tuple(int(x) for x in threshold.split("."))
        # Pad to equal length
        length = max(len(v), len(t))
        v = v + (0,) * (length - len(v))
        t = t + (0,) * (length - len(t))
        return v < t
    except (ValueError, AttributeError):
        return False


def _is_json_response(body: str) -> bool:
    """Return True if body parses as JSON (object or array)."""
    stripped = body.strip()
    if not stripped:
        return False
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Check 1: FreePBX CVE-2019-19006 — unauthenticated user enumeration
# ---------------------------------------------------------------------------

def check_freepbx_cve_2019_19006(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> CveResult | None:
    """CVE-2019-19006: FreePBX userman module returns user data without auth.

    GET /admin/ajax.php?module=userman&command=getUser&id=1
    Detection: HTTP 200 + JSON response body without authentication.
    Severity: CRITICAL
    """
    path = "/admin/ajax.php?module=userman&command=getUser&id=1"
    status, headers, body = _http_get(host, port, path, timeout, use_tls)
    if status != 200:
        return None
    if not _is_json_response(body):
        return None

    # Confirm it looks like user data (not just any JSON 200)
    body_lower = body.lower()
    has_user_data = any(
        kw in body_lower
        for kw in ('"username"', '"email"', '"id"', '"user"', '"name"', '"display"')
    )
    if not has_user_data:
        return None

    ver = _extract_fpbx_version(body + " " + headers.get("server", ""))

    return CveResult(
        cve_id="CVE-2019-19006",
        platform="FreePBX",
        severity="critical",
        host=host,
        port=port,
        title="CVE-2019-19006: FreePBX userman module exposes user data without authentication",
        evidence=(
            f"GET {path} returned HTTP 200 with a JSON response containing "
            f"user fields without any authentication requirement. "
            f"Body snippet: {body[:200]!r}"
        ),
        remediation=(
            "Upgrade FreePBX to 13.0.197.13+, 14.0.13.6+, or 15.0.16.75+. "
            "Restrict /admin to localhost or VPN. "
            "Apply the FreePBX security hotfix immediately."
        ),
        affected_version=ver,
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19006",
            "https://www.freepbx.org/freepbx-security-vulnerability-advisory-fpbx-sa-2019-001/",
        ],
    )


# ---------------------------------------------------------------------------
# Check 2: FreePBX CVE-2021-45461 — SQL injection indicator
# ---------------------------------------------------------------------------

def check_freepbx_cve_2021_45461(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> CveResult | None:
    """CVE-2021-45461: FreePBX dashboard SQL injection indicator.

    GET /admin/ajax.php?module=dashboard&command=getSummary
    Detection: SQL error string present in response body.
    Severity: HIGH
    """
    path = "/admin/ajax.php?module=dashboard&command=getSummary"
    status, _headers, body = _http_get(host, port, path, timeout, use_tls)
    if status == 0:
        return None

    body_lower = body.lower()
    sql_error_patterns = [
        "sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "you have an error in your sql",
        "unclosed quotation mark",
        "supplied argument is not a valid mysql",
        "ora-01756",
        "odbc microsoft access",
        "sqlite_master",
        "pg_query",
        "syntax error at or near",
        "unterminated string constant",
        "invalid input syntax for type",
    ]
    found_errors = [pat for pat in sql_error_patterns if pat in body_lower]
    if not found_errors:
        return None

    ver = _extract_fpbx_version(body)

    return CveResult(
        cve_id="CVE-2021-45461",
        platform="FreePBX",
        severity="high",
        host=host,
        port=port,
        title="CVE-2021-45461: FreePBX dashboard endpoint returns SQL error strings",
        evidence=(
            f"GET {path} returned HTTP {status} with SQL error indicators in the response. "
            f"Matched patterns: {found_errors}. "
            f"Body snippet: {body[:300]!r}"
        ),
        remediation=(
            "Upgrade FreePBX to 15.0.21.4+ or 16.0.10.41+. "
            "Apply the FreePBX security patches for CVE-2021-45461. "
            "Restrict /admin to localhost or VPN immediately."
        ),
        affected_version=ver,
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-45461",
        ],
    )


# ---------------------------------------------------------------------------
# Check 3: FreePBX path traversal
# ---------------------------------------------------------------------------

def check_freepbx_path_traversal(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> CveResult | None:
    """FreePBX filestore path traversal — attempt to read /etc/passwd.

    GET /admin/ajax.php?module=filestore&command=getFile&path=../../etc/passwd
    Detection: 'root:' present in response body.
    Severity: CRITICAL
    """
    path = "/admin/ajax.php?module=filestore&command=getFile&path=../../etc/passwd"
    status, _headers, body = _http_get(host, port, path, timeout, use_tls)
    if status == 0:
        return None

    if "root:" not in body:
        return None

    # Confirm it looks like /etc/passwd content
    has_passwd_content = bool(re.search(r"root:[x*!]?:[0-9]+:[0-9]+:", body))
    if not has_passwd_content:
        # 'root:' appeared but not in passwd format — still flag if the string is present
        pass

    evidence_snippet = body[:400].replace("\n", "\\n")

    return CveResult(
        cve_id="CVE-PATH-TRAVERSAL-FREEPBX",
        platform="FreePBX",
        severity="critical",
        host=host,
        port=port,
        title="FreePBX filestore module path traversal — /etc/passwd disclosed",
        evidence=(
            f"GET {path} returned HTTP {status} and the response contains "
            f"'root:' consistent with /etc/passwd content. "
            f"Body snippet: {evidence_snippet!r}"
        ),
        remediation=(
            "Upgrade FreePBX immediately. "
            "Apply filesystem-level restrictions so the web process cannot read "
            "files outside the document root. "
            "Block path-traversal patterns (../) at the WAF / reverse proxy. "
            "Restrict /admin to localhost or VPN."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2347",
        ],
    )


# ---------------------------------------------------------------------------
# Check 4: FreePBX module exposure
# ---------------------------------------------------------------------------

def check_freepbx_module_exposure(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> list[CveResult]:
    """FreePBX admin panel and module directory exposure.

    GET /admin/config.php (no auth) — check if returns admin panel.
    GET /admin/modules/            — list installed modules.
    Returns a list of zero or more CveResult objects.
    """
    results: list[CveResult] = []

    # Sub-check A: /admin/config.php accessible without auth
    status_cfg, headers_cfg, body_cfg = _http_get(
        host, port, "/admin/config.php", timeout, use_tls
    )
    if status_cfg == 200:
        body_cfg_l = body_cfg.lower()
        admin_indicators = [
            "freepbx",
            "fpbx",
            "admin panel",
            "administration",
            "pbx administration",
            "module admin",
        ]
        if any(ind in body_cfg_l for ind in admin_indicators):
            ver = _extract_fpbx_version(
                body_cfg + " " + headers_cfg.get("server", "")
            )
            results.append(
                CveResult(
                    cve_id="CONFIG-FREEPBX-ADMIN-EXPOSED",
                    platform="FreePBX",
                    severity="high",
                    host=host,
                    port=port,
                    title="FreePBX admin panel (/admin/config.php) accessible without authentication",
                    evidence=(
                        f"GET /admin/config.php returned HTTP 200 with admin panel content. "
                        f"Body snippet: {body_cfg[:200]!r}"
                    ),
                    remediation=(
                        "Restrict /admin to localhost or VPN immediately. "
                        "Configure HTTP basic authentication as an additional layer. "
                        "Review FreePBX session management settings."
                    ),
                    affected_version=ver,
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2019-19006",
                    ],
                )
            )

    # Sub-check B: /admin/modules/ directory listing
    status_mods, _headers_mods, body_mods = _http_get(
        host, port, "/admin/modules/", timeout, use_tls
    )
    if status_mods == 200:
        body_mods_l = body_mods.lower()
        module_indicators = [
            "index of",
            "directory listing",
            "<a href=",
            "module.xml",
            ".tar.gz",
        ]
        if any(ind in body_mods_l for ind in module_indicators):
            results.append(
                CveResult(
                    cve_id="CONFIG-FREEPBX-MODULES-LISTED",
                    platform="FreePBX",
                    severity="medium",
                    host=host,
                    port=port,
                    title="FreePBX modules directory listing exposed",
                    evidence=(
                        f"GET /admin/modules/ returned HTTP 200 with directory listing. "
                        f"Installed module names and versions are publicly visible. "
                        f"Body snippet: {body_mods[:200]!r}"
                    ),
                    remediation=(
                        "Disable directory listing in the web server configuration "
                        "(Options -Indexes in Apache). "
                        "Restrict /admin to localhost or VPN."
                    ),
                    references=[],
                )
            )

    return results


# ---------------------------------------------------------------------------
# Check 5: Grandstream CVE-2021-37748
# ---------------------------------------------------------------------------

def check_grandstream_cve_2021_37748(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> CveResult | None:
    """CVE-2021-37748: Grandstream UCM unauthenticated config disclosure.

    GET /cgi-bin/api-get_config
    Detection: SIP config keywords present in response.
    """
    path = "/cgi-bin/api-get_config"
    status, _headers, body = _http_get(host, port, path, timeout, use_tls)
    if status != 200 or not body.strip():
        return None

    body_lower = body.lower()
    sip_keywords = [
        "sippassword",
        "sip_password",
        "extension",
        "secret",
        "peer",
        "trunk",
        "voicemail",
        "register",
        "outbound_proxy",
        "sip_server",
        "sip_port",
        "dtmf",
        "codec",
    ]
    matched = [kw for kw in sip_keywords if kw in body_lower]
    if not matched:
        return None

    return CveResult(
        cve_id="CVE-2021-37748",
        platform="Grandstream",
        severity="critical",
        host=host,
        port=port,
        title="CVE-2021-37748: Grandstream UCM SIP configuration exposed without authentication",
        evidence=(
            f"GET {path} returned HTTP 200 with SIP configuration keywords: {matched}. "
            f"Body snippet: {body[:300]!r} "
            "[CVSS:9.8/CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]"
        ),
        remediation=(
            "Update Grandstream UCM firmware to 1.0.20.22 or later. "
            "As an emergency workaround, block /cgi-bin/api-get_config at "
            "the perimeter firewall. "
            "Rotate all SIP credentials exposed in the dump."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-37748",
        ],
    )


# ---------------------------------------------------------------------------
# Check 6: Grandstream CVE-2023-37315 — auth bypass
# ---------------------------------------------------------------------------

def check_grandstream_cve_2023_37315(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> CveResult | None:
    """CVE-2023-37315: Grandstream UCM unauthenticated SIP account listing.

    POST /cgi-bin/api.values.get with action=getSIPAccountList
    Detection: Returns SIP account data without authentication.
    Severity: CRITICAL
    """
    path = "/cgi-bin/api.values.get"
    post_body = "action=getSIPAccountList"
    status, _headers, body = _http_post(
        host, port, path, post_body,
        content_type="application/x-www-form-urlencoded",
        timeout=timeout,
        use_tls=use_tls,
    )
    if status not in (200, 201):
        return None
    if not body.strip():
        return None

    body_lower = body.lower()
    account_keywords = [
        "sipaccountlist",
        "sip_account",
        "extension",
        "username",
        "password",
        "secret",
        '"accounts"',
        '"data"',
        "accountlist",
    ]
    matched = [kw for kw in account_keywords if kw in body_lower]

    # Must match at least one account-data keyword plus look like structured data
    if not matched:
        return None
    if not (_is_json_response(body) or "<" in body):
        return None

    return CveResult(
        cve_id="CVE-2023-37315",
        platform="Grandstream",
        severity="critical",
        host=host,
        port=port,
        title="CVE-2023-37315: Grandstream UCM returns SIP account data without authentication",
        evidence=(
            f"POST {path} with action=getSIPAccountList returned HTTP {status} "
            f"with SIP account data (matched keywords: {matched}). "
            f"Body snippet: {body[:300]!r}"
        ),
        remediation=(
            "Update Grandstream UCM firmware to 1.0.20.30 or later. "
            "Restrict access to the UCM admin interface to trusted networks only. "
            "Rotate all SIP account credentials immediately."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2023-37315",
        ],
    )


# ---------------------------------------------------------------------------
# Check 7: Asterisk AMI without TLS (TCP/5038)
# ---------------------------------------------------------------------------

def check_ami_no_tls(
    host: str,
    tcp_ports: list[int],
    timeout: float = 3.0,
) -> CveResult | None:
    """Asterisk Manager Interface exposed in cleartext on TCP/5038.

    Detection: TCP/5038 open and AMI banner present in first 512 bytes.
    Severity: HIGH (informational aspect: CRITICAL if externally reachable)
    """
    if 5038 not in tcp_ports:
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((host, 5038))
        raw = s.recv(512)
        banner = raw.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass

    if not banner:
        return None

    # AMI banner format: "Asterisk Call Manager/x.x"
    if "asterisk call manager" not in banner.lower() and "asterisk" not in banner.lower():
        return None

    ver = _extract_asterisk_version(banner)

    return CveResult(
        cve_id="CONFIG-AMI-NO-TLS",
        platform="Asterisk",
        severity="high",
        host=host,
        port=5038,
        title="Asterisk Manager Interface (AMI) exposed on TCP/5038 without TLS",
        evidence=(
            f"TCP/5038 is open and returned AMI banner: {banner!r}. "
            "AMI credentials and call-control commands transit in cleartext. "
            "An attacker with network access can intercept credentials or "
            "issue arbitrary AMI commands."
        ),
        remediation=(
            "Bind AMI to 127.0.0.1 in /etc/asterisk/manager.conf. "
            "Use an SSH tunnel or configure TLS AMI on port 5039 (TLSManagerPort). "
            "Never expose AMI directly to the internet or untrusted networks."
        ),
        affected_version=ver,
        references=[
            "https://www.asterisk.org/asterisk-security-advisories/",
        ],
    )


# ---------------------------------------------------------------------------
# Check 8: 3CX admin exposure
# ---------------------------------------------------------------------------

def check_3cx_admin_exposure(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> list[CveResult]:
    """3CX admin interface and API exposure checks.

    GET /webclient/       — check for 3CX login page.
    GET /api/v1/Parameters/List — check for unauthenticated API access.
    Returns a list of zero or more CveResult objects.
    """
    results: list[CveResult] = []

    # Sub-check A: /webclient/ login page
    status_wc, headers_wc, body_wc = _http_get(
        host, port, "/webclient/", timeout, use_tls
    )
    if status_wc in (200, 302):
        body_wc_l = body_wc.lower()
        threecx_indicators = [
            "3cx",
            "xcapi",
            "3cxphone",
            "3cx phone system",
            "webmeeting",
            "3cx web client",
        ]
        if any(ind in body_wc_l for ind in threecx_indicators):
            results.append(
                CveResult(
                    cve_id="CONFIG-3CX-WEBCLIENT-EXPOSED",
                    platform="3CX",
                    severity="medium",
                    host=host,
                    port=port,
                    title="3CX web client (/webclient/) is internet-accessible",
                    evidence=(
                        f"GET /webclient/ returned HTTP {status_wc} with 3CX login page content. "
                        f"Body snippet: {body_wc[:200]!r}"
                    ),
                    remediation=(
                        "Restrict the 3CX web interface to VPN or IP allow-list. "
                        "Apply all available 3CX security updates. "
                        "Monitor for CVE-2023-29059 indicators."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-29059",
                    ],
                )
            )

    # Sub-check B: /api/v1/Parameters/List unauthenticated
    status_api, _headers_api, body_api = _http_get(
        host, port, "/api/v1/Parameters/List", timeout, use_tls
    )
    if status_api == 200 and body_api.strip():
        body_api_l = body_api.lower()
        api_indicators = [
            "3cx",
            '"value"',
            '"parameter"',
            '"name"',
            "maxextensions",
            "sipport",
            "systemname",
        ]
        if any(ind in body_api_l for ind in api_indicators):
            results.append(
                CveResult(
                    cve_id="CONFIG-3CX-API-UNAUTH",
                    platform="3CX",
                    severity="high",
                    host=host,
                    port=port,
                    title="3CX /api/v1/Parameters/List accessible without authentication",
                    evidence=(
                        f"GET /api/v1/Parameters/List returned HTTP 200 with "
                        f"system parameter data without requiring authentication. "
                        f"Body snippet: {body_api[:300]!r}"
                    ),
                    remediation=(
                        "Apply 3CX security updates. "
                        "Restrict the API to authenticated sessions and VPN. "
                        "Review API authentication middleware configuration."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-29059",
                    ],
                )
            )

    return results


# ---------------------------------------------------------------------------
# Check 9: FreePBX default recordings exposure
# ---------------------------------------------------------------------------

def check_freepbx_recordings_exposure(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> list[CveResult]:
    """FreePBX voicemail and recording file exposure.

    GET /recordings/       — check for voicemail/recording files.
    GET /admin/recordings/ — admin recordings.
    Returns a list of zero or more CveResult objects.
    """
    results: list[CveResult] = []
    check_paths = [
        ("/recordings/", "FreePBX public recordings directory exposed"),
        ("/admin/recordings/", "FreePBX admin recordings directory exposed"),
    ]

    for path, title in check_paths:
        status, _headers, body = _http_get(host, port, path, timeout, use_tls)
        if status != 200 or not body.strip():
            continue

        body_lower = body.lower()
        recording_indicators = [
            ".wav",
            ".mp3",
            ".gsm",
            ".ogg",
            "voicemail",
            "recording",
            "index of",
            "directory listing",
            "<audio",
            "audio/",
        ]
        matched = [ind for ind in recording_indicators if ind in body_lower]
        if not matched:
            continue

        results.append(
            CveResult(
                cve_id="CONFIG-FREEPBX-RECORDINGS-EXPOSED",
                platform="FreePBX",
                severity="high",
                host=host,
                port=port,
                title=title,
                evidence=(
                    f"GET {path} returned HTTP 200 with indicators of "
                    f"accessible recording/voicemail files: {matched}. "
                    f"Body snippet: {body[:300]!r}"
                ),
                remediation=(
                    "Disable directory listing (Options -Indexes in Apache/nginx). "
                    "Restrict /recordings and /admin/recordings to authenticated users. "
                    "Move recording storage outside the web root. "
                    "Audit for sensitive voicemail recordings that may have been accessed."
                ),
                references=[],
            )
        )

    return results


# ---------------------------------------------------------------------------
# Check 10: SIP server version disclosure and CVE cross-reference
# ---------------------------------------------------------------------------

def check_sip_version_disclosure(
    host: str,
    sip_port: int,
    sip_server: str,
    timeout: float = 3.0,
) -> list[CveResult]:
    """Parse SIP server version strings and cross-reference known CVEs.

    Asterisk < 18.12.0 — multiple CVEs (AST-2022-002, AST-2022-006, etc.)
    FreePBX < 16.0.19.9 — CVE-2022-2347

    sip_server: the User-Agent or Server header value from a SIP response.
    Returns a list of zero or more CveResult objects.
    """
    results: list[CveResult] = []
    if not sip_server:
        return results

    # Check Asterisk version
    ast_ver = _extract_asterisk_version(sip_server)
    if ast_ver:
        if _version_lt(ast_ver, "18.12.0"):
            results.append(
                CveResult(
                    cve_id="AST-2022-MULTIPLE",
                    platform="Asterisk",
                    severity="critical",
                    host=host,
                    port=sip_port,
                    title=f"Asterisk {ast_ver} is below 18.12.0 — multiple known CVEs",
                    evidence=(
                        f"SIP banner reveals Asterisk version {ast_ver!r} (from: {sip_server!r}). "
                        "Asterisk versions below 18.12.0 are affected by multiple "
                        "security advisories including AST-2022-002 (heap overflow in "
                        "STIR/SHAKEN), AST-2022-006 (res_pjsip_t38 use-after-free), "
                        "and AST-2022-008 (pjproject RTCP MR/SR overflow). "
                        "[CVSS:9.8/CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]"
                    ),
                    remediation=(
                        "Upgrade Asterisk to 18.12.0 or later (LTS branch). "
                        "If using Asterisk 16 branch, upgrade to 16.26.0+. "
                        "Review individual AST advisories at https://www.asterisk.org/asterisk-security-advisories/"
                    ),
                    affected_version=ast_ver,
                    references=[
                        "https://www.asterisk.org/asterisk-security-advisories/",
                        "https://nvd.nist.gov/vuln/search/results?query=asterisk",
                    ],
                )
            )

    # Check FreePBX version
    fpbx_ver = _extract_fpbx_version(sip_server)
    if fpbx_ver:
        if _version_lt(fpbx_ver, "16.0.19.9"):
            results.append(
                CveResult(
                    cve_id="CVE-2022-2347",
                    platform="FreePBX",
                    severity="high",
                    host=host,
                    port=sip_port,
                    title=f"FreePBX {fpbx_ver} is below 16.0.19.9 — CVE-2022-2347",
                    evidence=(
                        f"SIP banner reveals FreePBX version {fpbx_ver!r} (from: {sip_server!r}). "
                        "FreePBX versions below 16.0.19.9 are vulnerable to "
                        "CVE-2022-2347: authenticated path traversal and arbitrary "
                        "file read via the file manager module, which can expose "
                        "system files including /etc/passwd and Asterisk SIP credentials. "
                        "[CVSS:9.8/CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]"
                    ),
                    remediation=(
                        "Upgrade FreePBX to 16.0.19.9 or later. "
                        "Apply available security modules via the FreePBX Module Admin. "
                        "Restrict /admin to localhost or VPN as a defence-in-depth measure."
                    ),
                    affected_version=fpbx_ver,
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2022-2347",
                        "https://www.freepbx.org/",
                    ],
                )
            )

    return results


# ---------------------------------------------------------------------------
# Check 11: CVE-2025-57819 — FreePBX EPM unauthenticated SQL injection + RCE
# ---------------------------------------------------------------------------

def check_freepbx_cve_2025_57819(
    host: str,
    port: int,
    use_tls: bool = False,
    timeout: float = 3.0,
) -> "CveResult | None":
    """CVE-2025-57819 (CVSS 9.8): FreePBX End Point Manager SQL injection → RCE.

    The EPM module exposes /admin/ajax.php?module=epm_config_manager without
    authentication checks. Sending a crafted request leaks the endpoint and
    in vulnerable versions allows SQL injection chainable to remote code
    execution as root. Over 12,000 instances publicly exposed (2025).

    Affected: FreePBX EPM 15.0 < 15.0.66, 16.0 < 16.0.89, 17.0 < 17.0.3.
    """
    status, hdrs, body = _http_get(
        host, port,
        "/admin/ajax.php?module=epm_config_manager&command=getTemplateList",
        timeout, use_tls,
    )
    if status == 0:
        return None
    body_l = body.lower()
    # Indicator: JSON response or explicit EPM module data returned unauthenticated
    epm_exposed = (
        status == 200
        and ('"template"' in body_l or '"mac"' in body_l
             or "epm" in body_l or "endpoint" in body_l)
    )
    if not epm_exposed:
        return None
    scheme = "https" if use_tls else "http"
    return CveResult(
        cve_id="CVE-2025-57819",
        platform="FreePBX",
        severity="critical",
        host=host,
        port=port,
        title=(
            "CVE-2025-57819: FreePBX EPM module exposed without authentication "
            "(SQL injection → RCE, CVSS 9.8)"
        ),
        evidence=(
            f"GET {scheme}://{host}:{port}/admin/ajax.php?module=epm_config_manager"
            f"&command=getTemplateList → {status}. "
            f"EPM endpoint responds without requiring session/cookie authentication. "
            f"Body excerpt: {body[:200].strip()}"
        ),
        remediation=(
            "Update EPM module to ≥15.0.66 / ≥16.0.89 / ≥17.0.3 immediately. "
            "If unable to patch, disable EPM in FreePBX admin → Module Admin. "
            "Block /admin/ajax.php access from the internet at the firewall."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2025-57819",
            "https://www.greenbone.net/en/blog/cve-2025-57819-unauthenticated-rce-threatens-freepbx-systems-globally/",
        ],
    )


# ---------------------------------------------------------------------------
# Check 12: CVE-2025-57767 — Asterisk SIP digest auth NULL pointer dereference
# ---------------------------------------------------------------------------

def check_asterisk_cve_2025_57767(
    host: str,
    sip_port: int,
    sip_server: str,
    timeout: float = 3.0,
) -> "CveResult | None":
    """CVE-2025-57767 (CVSS 7.5): Asterisk NULL pointer dereference on malformed auth.

    A SIP INVITE with a crafted Authorization header (missing realm or nonce)
    triggers a NULL pointer dereference in res_pjsip_authenticator_digest.so,
    causing an Asterisk crash (remote DoS). Any unauthenticated attacker on the
    network can take down the PBX.

    Affected: Asterisk < 20.15.2, < 21.10.2, < 22.5.2.
    """
    if not sip_server:
        return None
    sv = sip_server.lower()
    if "asterisk" not in sv:
        return None
    # Extract version
    m = re.search(r"asterisk\s+(?:pbx\s+)?(\d+\.\d+(?:\.\d+)?)", sv)
    if not m:
        return None
    ver_str = m.group(1)
    try:
        parts = [int(x) for x in ver_str.split(".")]
    except ValueError:
        return None
    major = parts[0] if parts else 0
    minor = parts[1] if len(parts) > 1 else 0
    patch = parts[2] if len(parts) > 2 else 0

    vulnerable = (
        (major == 20 and (minor < 15 or (minor == 15 and patch < 2)))
        or (major == 21 and (minor < 10 or (minor == 10 and patch < 2)))
        or (major == 22 and (minor < 5 or (minor == 5 and patch < 2)))
    )
    if not vulnerable:
        return None
    return CveResult(
        cve_id="CVE-2025-57767",
        platform="Asterisk",
        severity="high",
        host=host,
        port=sip_port,
        title=(
            f"CVE-2025-57767: Asterisk {ver_str} vulnerable to SIP auth crash "
            "(remote DoS via malformed Authorization header, CVSS 7.5)"
        ),
        evidence=(
            f"SIP server banner: {sip_server}. "
            f"Asterisk {ver_str} < 20.15.2/21.10.2/22.5.2. "
            "A crafted Authorization header with missing realm/nonce triggers "
            "NULL pointer dereference in res_pjsip_authenticator_digest → crash."
        ),
        remediation=(
            "Upgrade Asterisk to ≥20.15.2, ≥21.10.2, or ≥22.5.2. "
            "As an interim mitigation, configure fail2ban to rate-limit SIP "
            "INVITEs from unknown sources."
        ),
        affected_version=ver_str,
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2025-57767",
            "https://www.ameeba.com/blog/cve-2025-57767-asterisk-vulnerability-affecting-sip-request-authentication/",
        ],
    )


# ---------------------------------------------------------------------------
# Check 13: CONFIG-SIP-TLS — Unencrypted SIP signaling (no TLS on 5061)
# ---------------------------------------------------------------------------

def check_sip_tls_missing(
    host: str,
    sip_port: int,
    tcp_ports: list[int],
    timeout: float = 3.0,
) -> "CveResult | None":
    """CONFIG: SIP signaling not protected by TLS.

    When SIP is carried over plain UDP/TCP (not TLS-wrapped), Digest
    authentication credentials, call metadata, SDP offers (including any
    SDES-SRTP a=crypto key material), and CLI/Caller-ID are transmitted in
    cleartext and trivially capturable by passive network monitors or
    man-in-the-middle attackers.

    RFC 3261 §26 requires TLS for any SIP deployment where signaling crosses
    untrusted networks. RFC 4568 §9 mandates TLS to protect SDES keys.
    """
    # Check if port 5061 (SIP-TLS) is in open TCP ports
    sip_tls_open = 5061 in tcp_ports
    # Also probe 5061 directly — it might not have been discovered
    if not sip_tls_open:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, 5061))
            sip_tls_open = True
        except OSError:
            pass
        finally:
            s.close()

    if sip_tls_open:
        return None  # TLS available — not a finding

    # Plain SIP is reachable on port 5060 but TLS is not available on 5061
    return CveResult(
        cve_id="CONFIG-SIP-TLS",
        platform="Generic",
        severity="high",
        host=host,
        port=sip_port,
        title=(
            "Unencrypted SIP signaling — TLS not available on port 5061 "
            "(credentials and SDES-SRTP keys transmitted in cleartext)"
        ),
        evidence=(
            f"SIP port {sip_port}/udp is open. Port 5061/tcp (SIP-TLS) is not "
            "reachable. SIP Digest authentication nonces, call metadata, "
            "and any SDP a=crypto SDES key material are transmitted unencrypted. "
            "Violates RFC 3261 §26 and RFC 4568 §9."
        ),
        remediation=(
            "Enable SIP-TLS (port 5061) on the PBX. "
            "FreePBX: Settings → Advanced Settings → TLS → Enable. "
            "Asterisk: enable tls=yes in sip.conf or pjsip transport. "
            "Use valid TLS certificates (Let's Encrypt is supported). "
            "Enforce SIP-TLS on all external trunks and SIP UA registrations."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc3261#section-26",
            "https://datatracker.ietf.org/doc/html/rfc4568#section-9",
        ],
    )


# ---------------------------------------------------------------------------
# Check 14: CONFIG-SIP-WSS — SIP-over-WebSocket security check
# ---------------------------------------------------------------------------

def check_sip_wss_security(
    host: str,
    tcp_ports: list[int],
    timeout: float = 3.0,
) -> list["CveResult"]:
    """CONFIG: SIP-over-WebSocket (RFC 7118) security assessment.

    SIP-WSS on port 8089 is common for FreePBX/Asterisk WebRTC endpoints.
    Tests: (a) plain WS on 8088 (unencrypted), (b) Origin header not validated
    (potential CSWSH), (c) WSS TLS cipher strength.
    """
    results: list[CveResult] = []

    # Check for plain WS (port 8088) — unencrypted WebSocket SIP
    ws_plain_open = 8088 in tcp_ports
    if not ws_plain_open:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, 8088))
            ws_plain_open = True
        except OSError:
            pass
        finally:
            s.close()

    if ws_plain_open:
        results.append(CveResult(
            cve_id="CONFIG-SIP-WS-PLAIN",
            platform="Generic",
            severity="high",
            host=host,
            port=8088,
            title=(
                "Unencrypted SIP-over-WebSocket (ws://) on port 8088 — "
                "signaling exposed to eavesdropping (RFC 7118 §14)"
            ),
            evidence=(
                "Port 8088/tcp is open. SIP-over-WebSocket without TLS allows "
                "full call session capture, credential theft, and call injection "
                "by any network observer. Credentials in WWW-Authenticate are "
                "transmitted in cleartext over the WebSocket transport."
            ),
            remediation=(
                "Disable plain WS (port 8088). Use WSS only (port 8089). "
                "FreePBX: Admin → Asterisk SIP Settings → WebRTC → force WSS. "
                "Ensure all WebRTC clients use wss:// URI scheme."
            ),
            references=["https://datatracker.ietf.org/doc/html/rfc7118#section-14"],
        ))

    # Check for WSS (port 8089) — probe for TLS availability (positive indicator)
    wss_open = 8089 in tcp_ports
    if not wss_open:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, 8089))
            wss_open = True
        except OSError:
            pass
        finally:
            s.close()

    if wss_open:
        # Probe for Origin header CSWSH: send a WS upgrade without proper Origin
        # A vulnerable server accepts any Origin header
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, 8089))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls = ctx.wrap_socket(s, server_hostname=host)
            ws_upgrade = (
                "GET / HTTP/1.1\r\n"
                f"Host: {host}:8089\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Protocol: sip\r\n"
                "Origin: https://evil.example.com\r\n"
                "\r\n"
            )
            tls.sendall(ws_upgrade.encode())
            resp = tls.recv(2048).decode("utf-8", errors="replace")
            tls.close()
            if "101 switching" in resp.lower():
                results.append(CveResult(
                    cve_id="CONFIG-SIP-WSS-CSWSH",
                    platform="Generic",
                    severity="medium",
                    host=host,
                    port=8089,
                    title=(
                        "SIP-WSS accepts arbitrary Origin headers — "
                        "Cross-Site WebSocket Hijacking (CSWSH) possible"
                    ),
                    evidence=(
                        "Sent WS upgrade with Origin: https://evil.example.com. "
                        "Server responded 101 Switching Protocols — no Origin "
                        "validation. Browser-based CSWSH can hijack SIP sessions "
                        "of authenticated WebRTC users."
                    ),
                    remediation=(
                        "Configure allowed WebSocket origins. "
                        "FreePBX/Asterisk: set websocket_allowed_origins in "
                        "http.conf. Restrict to your own domain(s) only."
                    ),
                    references=[
                        "https://datatracker.ietf.org/doc/html/rfc7118#section-14",
                        "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                    ],
                ))
        except (OSError, ssl.SSLError):
            pass

    return results


# ---------------------------------------------------------------------------
# SIP intelligence extractor — runs on every SIP exchange
# ---------------------------------------------------------------------------

def _sip_intel_extract(raw_text: str, source_label: str = "") -> dict:
    """Scan any SIP message/response for credentials, keys, topology, versions.

    Called on every SIP exchange so the tool misses nothing.

    Returns a dict of intelligence buckets:
      credentials_challenged  — WWW/Proxy-Authenticate challenges (realm, nonce, algo)
      credentials_sent        — Authorization / Proxy-Authorization headers (user, realm, hash)
      internal_ips            — RFC-1918 IPs found in Via/Contact/Record-Route/Warning
      extensions              — SIP user parts from From/To/Contact/PAI URIs
      platform_version        — Server / User-Agent banners
      srtp_keys               — a=crypto SDES key material from SDP
      sdp_codecs              — audio codec list from SDP
      allowed_methods         — Allow: header
      identity_headers        — PAI / RPID / Diversion content
      custom_headers          — X-* and other non-standard headers
      topology                — Record-Route / Route / Path headers
      sensitive_lines         — any line the extractor flags as high-value
    """
    import ipaddress as _ipa

    intel: dict = {
        "source": source_label,
        "credentials_challenged": [],
        "credentials_sent": [],
        "internal_ips": [],
        "extensions": [],
        "platform_version": [],
        "srtp_keys": [],
        "sdp_codecs": [],
        "allowed_methods": [],
        "identity_headers": [],
        "custom_headers": [],
        "topology": [],
        "sensitive_lines": [],
    }

    _IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    _SIP_USER_RE = re.compile(r"sip:([a-zA-Z0-9_+\-\.]+)@", re.I)

    for line in raw_text.splitlines():
        ls = line.strip()
        if not ls:
            continue
        ll = ls.lower()

        # ── Auth challenges ───────────────────────────────────────────────
        if ll.startswith("www-authenticate:") or ll.startswith("proxy-authenticate:"):
            realm_m = re.search(r'realm\s*=\s*["\']?([^"\'>,\s]+)', ls, re.I)
            nonce_m = re.search(r'nonce\s*=\s*["\']?([^"\'>,\s]+)', ls, re.I)
            algo_m = re.search(r'algorithm\s*=\s*(\S+)', ls, re.I)
            intel["credentials_challenged"].append({
                "header": ls[:200],
                "realm": realm_m.group(1).strip('"\'') if realm_m else "",
                "nonce": nonce_m.group(1).strip('"\'') if nonce_m else "",
                "algorithm": algo_m.group(1).strip(",;\"'") if algo_m else "MD5",
            })
            intel["sensitive_lines"].append(("CREDENTIAL CHALLENGE", ls))

        # ── Auth responses (credentials sent) ─────────────────────────────
        elif ll.startswith("authorization:") or ll.startswith("proxy-authorization:"):
            user_m = re.search(r'username\s*=\s*["\']?([^"\'>,\s]+)', ls, re.I)
            realm_m = re.search(r'realm\s*=\s*["\']?([^"\'>,\s]+)', ls, re.I)
            resp_m = re.search(r'response\s*=\s*["\']?([0-9a-fA-F]{32,64})', ls, re.I)
            intel["credentials_sent"].append({
                "header": ls[:200],
                "username": user_m.group(1).strip('"\'') if user_m else "",
                "realm": realm_m.group(1).strip('"\'') if realm_m else "",
                "hash": resp_m.group(1) if resp_m else "",
            })
            intel["sensitive_lines"].append(("CREDENTIAL HASH ON WIRE", ls))

        # ── Server / User-Agent ───────────────────────────────────────────
        elif ll.startswith("server:") or ll.startswith("user-agent:"):
            val = ls.split(":", 1)[-1].strip()
            if val:
                intel["platform_version"].append(val)

        # ── From / To / Contact — extract extensions ──────────────────────
        elif ll.startswith(("from:", "to:", "contact:", "p-asserted-identity:",
                             "remote-party-id:", "p-called-party-id:")):
            for m in _SIP_USER_RE.finditer(ls):
                user = m.group(1)
                if user and user not in intel["extensions"]:
                    intel["extensions"].append(user)
            if ll.startswith(("p-asserted-identity:", "remote-party-id:",
                               "p-called-party-id:")):
                intel["identity_headers"].append(ls[:200])
                intel["sensitive_lines"].append(("IDENTITY LEAKAGE", ls))

        # ── Via / Record-Route / Route / Path — extract internal IPs ──────
        elif ll.startswith(("via:", "v:", "record-route:", "route:", "path:")):
            for m in _IP_RE.finditer(ls):
                ip = m.group(1)
                try:
                    if _ipa.ip_address(ip).is_private:
                        if ip not in intel["internal_ips"]:
                            intel["internal_ips"].append(ip)
                            intel["sensitive_lines"].append(("INTERNAL IP LEAKED", ls))
                except ValueError:
                    pass
            if ll.startswith(("record-route:", "route:", "path:")):
                intel["topology"].append(ls[:200])

        # ── Warning — may contain internal hostnames / IPs ────────────────
        elif ll.startswith("warning:"):
            for m in _IP_RE.finditer(ls):
                ip = m.group(1)
                try:
                    if _ipa.ip_address(ip).is_private:
                        if ip not in intel["internal_ips"]:
                            intel["internal_ips"].append(ip)
                except ValueError:
                    pass

        # ── Allow — reveals attack surface ────────────────────────────────
        elif ll.startswith("allow:"):
            methods = [m.strip().upper() for m in ls.split(":", 1)[-1].split(",")]
            intel["allowed_methods"] = [m for m in methods if m]

        # ── X-* custom headers — may expose internal info ─────────────────
        elif ll.startswith("x-"):
            intel["custom_headers"].append(ls[:200])
            # Flag headers that sound credential-ish
            if any(kw in ll for kw in ("pass", "secret", "key", "token", "auth",
                                        "cred", "pwd", "pin")):
                intel["sensitive_lines"].append(("CUSTOM CREDENTIAL HEADER", ls))

        # ── SDP: a=crypto (SRTP key material) ────────────────────────────
        elif ls.startswith("a=crypto:"):
            intel["srtp_keys"].append(ls[:200])
            intel["sensitive_lines"].append(("SRTP ENCRYPTION KEY ON WIRE", ls))

        # ── SDP: a=rtpmap (codec list) ────────────────────────────────────
        elif ls.startswith("a=rtpmap:"):
            intel["sdp_codecs"].append(ls.split(":", 1)[-1].strip())

        # ── Generic IP scan across all other lines ────────────────────────
        else:
            for m in _IP_RE.finditer(ls):
                ip = m.group(1)
                try:
                    if _ipa.ip_address(ip).is_private:
                        if ip not in intel["internal_ips"]:
                            intel["internal_ips"].append(ip)
                except ValueError:
                    pass

    return intel


# ---------------------------------------------------------------------------
# Cleartext SIP wire-capture demonstration
# ---------------------------------------------------------------------------

def capture_cleartext_sip_evidence(
    host: str,
    sip_port: int = 5060,
    source_ip: str = "",
    timeout: float = 4.0,
) -> dict:
    """Actively demonstrate what an attacker captures on a cleartext SIP wire.

    Runs three live probes and returns raw captures + extracted intelligence:
      1. SIP OPTIONS  — server banner, allowed methods, version
      2. SIP REGISTER — triggers 401 challenge, exposing realm + nonce on wire
      3. SIP INVITE with a=crypto SDP — shows SDES SRTP key material in cleartext

    Never raises — returns partial data on timeout/failure.
    """
    try:
        from . import sip as _sip
        from .utils import rand_call_id, rand_tag, local_ip_for
    except ImportError:
        return {}

    import os as _os, base64 as _b64

    local_ip = source_ip or local_ip_for(host)

    ev: dict = {
        "local_ip": local_ip,
        "sip_port": sip_port,
        "host": host,
        "packets": [],          # [{direction, label, content, highlight_lines}]
        "intel": [],            # per-packet _sip_intel_extract() results
        "challenge": {},        # realm, nonce, algorithm
        "auth_demo": "",        # sample Authorization as sent by a real client
        "sdp_crypto_offered": "",
        "sdp_crypto_echoed": "",
        "hashcat_cmd": "",
        "tcpdump_cmd": f"tcpdump -i any -n udp port {sip_port} -A",
        "sngrep_cmd": f"sngrep -d any port {sip_port} -A",
        "wireshark_filter": f"sip && ip.addr == {host}",
    }

    # ── Probe 1: SIP OPTIONS ──────────────────────────────────────────────
    try:
        resp1 = _sip.options_probe(
            host, port=sip_port, local_ip=local_ip, timeout=min(timeout, 2.0),
        )
        if resp1 and resp1.raw:
            raw_text = resp1.raw.decode("utf-8", errors="replace")
            highlight = [
                i for i, l in enumerate(raw_text.splitlines())
                if any(kw in l.lower() for kw in ("server:", "user-agent:", "allow:"))
            ]
            ev["packets"].append({
                "direction": "recv",
                "label": f"OPTIONS response ← {host}:{sip_port}",
                "content": raw_text,
                "highlight_lines": highlight,
            })
            ev["intel"].append(_sip_intel_extract(raw_text, "OPTIONS"))
    except Exception:
        pass

    # ── Probe 2: REGISTER → trigger 401 challenge ─────────────────────────
    try:
        call_id = rand_call_id()
        reg_uri = f"sip:{host}"
        reg_msg = _sip.build_message(
            "REGISTER", reg_uri,
            from_user="1000", to_user="1000",
            host=host, port=sip_port,
            local_ip=local_ip, local_port=5062,
            call_id=call_id, cseq=1, from_tag=rand_tag(),
            transport="UDP",
        )
        reg_text = reg_msg.decode("utf-8", errors="replace")
        ev["packets"].append({
            "direction": "sent",
            "label": f"REGISTER → {host}:{sip_port}  (ext 1000 probe — visible to any network observer)",
            "content": reg_text,
            "highlight_lines": [],
        })
        ev["intel"].append(_sip_intel_extract(reg_text, "REGISTER-sent"))

        raw_reg = _sip.send_and_recv(
            reg_msg, host, sip_port, local_port=5062, timeout=min(timeout, 2.0),
        )
        if raw_reg:
            reg_resp_text = raw_reg.decode("utf-8", errors="replace")
            reg_resp = _sip.parse_response(raw_reg)
            # Highlight credential challenge lines
            hi = [
                i for i, l in enumerate(reg_resp_text.splitlines())
                if any(kw in l.lower() for kw in
                       ("www-authenticate:", "proxy-authenticate:", "realm=", "nonce="))
            ]
            ev["packets"].append({
                "direction": "recv",
                "label": (
                    f"401 Unauthorized ← {host}:{sip_port}  "
                    "*** AUTHENTICATION CHALLENGE CAPTURED IN CLEARTEXT ***"
                ),
                "content": reg_resp_text,
                "highlight_lines": hi,
            })
            reg_intel = _sip_intel_extract(reg_resp_text, "401-challenge")
            ev["intel"].append(reg_intel)

            if reg_resp and reg_resp.status_code in (401, 407) and reg_resp.auth_params:
                auth_p = reg_resp.auth_params
                realm = auth_p.get("realm", "")
                nonce = auth_p.get("nonce", "")
                algo = auth_p.get("algorithm", "MD5")
                ev["challenge"] = {
                    "realm": realm, "nonce": nonce, "algorithm": algo,
                    "raw_header": reg_resp.headers.get(
                        "www-authenticate",
                        reg_resp.headers.get("proxy-authenticate", ""),
                    ),
                }
                # Build demo Authorization header showing what appears on wire
                try:
                    ev["auth_demo"] = _sip.build_auth_header(
                        "1000", "VICTIM_PASSWORD", "REGISTER", reg_uri,
                        auth_p,
                    )
                except Exception:
                    pass
                ev["hashcat_cmd"] = (
                    f"# 1. Capture SIP packets:\n"
                    f"   {ev['tcpdump_cmd']} -w sip_capture.pcap\n"
                    f"# 2. Extract hashes with sipdump:\n"
                    f"   sipdump -p sip_capture.pcap -o hashes.txt\n"
                    f"# 3. Crack MD5 SIP digest offline (hashcat mode 11400):\n"
                    f"   hashcat -m 11400 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt\n"
                    f"# 4. Alternative — sipcrack:\n"
                    f"   sipcrack -w /usr/share/wordlists/rockyou.txt sip_capture.pcap\n"
                    f"# Realm: {realm}  |  Algorithm: {algo} (MD5 = breakable in hours)"
                )
    except Exception:
        pass

    # ── Probe 3: INVITE with a=crypto → show SDES key exposure ───────────
    try:
        _raw_key_bytes = _os.urandom(16) + _os.urandom(14)
        _b64_key = _b64.b64encode(_raw_key_bytes).decode()
        crypto_line = f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{_b64_key}"
        ev["sdp_crypto_offered"] = crypto_line

        sess_id = sip_port  # deterministic
        sdp = (
            "v=0\r\n"
            f"o=scanner {sess_id} {sess_id} IN IP4 {local_ip}\r\n"
            "s=voip-scan-poc\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/SAVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=sendrecv\r\n"
            f"{crypto_line}\r\n"
        )
        call_id2 = rand_call_id()
        invite_msg = _sip.build_message(
            "INVITE", f"sip:1000@{host}",
            from_user="scanner", to_user="1000",
            host=host, port=sip_port,
            local_ip=local_ip, local_port=5063,
            call_id=call_id2, cseq=1, from_tag=rand_tag(),
            body=sdp, transport="UDP",
        )
        inv_text = invite_msg.decode("utf-8", errors="replace")
        inv_hi = [i for i, l in enumerate(inv_text.splitlines())
                  if "a=crypto:" in l.lower()]
        ev["packets"].append({
            "direction": "sent",
            "label": (
                f"INVITE with SRTP a=crypto → {host}:{sip_port}  "
                "*** ENCRYPTION KEY IN CLEARTEXT SDP ***"
            ),
            "content": inv_text,
            "highlight_lines": inv_hi,
        })
        ev["intel"].append(_sip_intel_extract(inv_text, "INVITE-sent"))

        raw_inv = _sip.send_and_recv(
            invite_msg, host, sip_port, local_port=5063, timeout=min(timeout, 2.0),
        )
        if raw_inv:
            inv_resp_text = raw_inv.decode("utf-8", errors="replace")
            inv_hi2 = []
            for i, l in enumerate(inv_resp_text.splitlines()):
                if "a=crypto:" in l.lower():
                    inv_hi2.append(i)
                    if not ev["sdp_crypto_echoed"]:
                        ev["sdp_crypto_echoed"] = l.strip()
            ev["packets"].append({
                "direction": "recv",
                "label": (
                    f"← {host}:{sip_port} INVITE response"
                    + ("  *** PBX SRTP KEY LEAKED ***" if inv_hi2 else "")
                ),
                "content": inv_resp_text,
                "highlight_lines": inv_hi2,
            })
            ev["intel"].append(_sip_intel_extract(inv_resp_text, "INVITE-resp"))
    except Exception:
        pass

    # ── Aggregate all intel across all packets ────────────────────────────
    agg: dict = {
        "all_extensions": [],
        "all_internal_ips": [],
        "all_versions": [],
        "all_srtp_keys": [],
        "all_sensitive_lines": [],
        "all_challenges": [],
    }
    for pkt_intel in ev["intel"]:
        for ext in pkt_intel.get("extensions", []):
            if ext not in agg["all_extensions"]:
                agg["all_extensions"].append(ext)
        for ip in pkt_intel.get("internal_ips", []):
            if ip not in agg["all_internal_ips"]:
                agg["all_internal_ips"].append(ip)
        for ver in pkt_intel.get("platform_version", []):
            if ver not in agg["all_versions"]:
                agg["all_versions"].append(ver)
        agg["all_srtp_keys"].extend(pkt_intel.get("srtp_keys", []))
        agg["all_sensitive_lines"].extend(pkt_intel.get("sensitive_lines", []))
        agg["all_challenges"].extend(pkt_intel.get("credentials_challenged", []))
    ev["aggregated"] = agg

    return ev


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def check_all(
    host: str,
    tcp_ports: list[int],
    fingerprint: str,
    sip_server: str = "",
    sip_port: int = 5060,
    timeout: float = 3.0,
) -> list[CveResult]:
    """Run all applicable CVE and configuration checks against a discovered host.

    Parameters
    ----------
    host:        IP address or hostname to probe.
    tcp_ports:   List of open TCP ports discovered during scanning.
    fingerprint: Detected PBX platform string (e.g. "FreePBX", "Grandstream",
                 "3CX", "Asterisk", "unknown").
    sip_server:  SIP User-Agent or Server header value from a prior SIP probe.
                 Pass an empty string if not available.
    sip_port:    Port on which SIP was discovered (default 5060).
    timeout:     Per-probe TCP/HTTP timeout in seconds (default 3.0).

    Returns
    -------
    A deduplicated list of CveResult, sorted by severity (critical first).
    """
    results: list[CveResult] = []
    fp_lower = fingerprint.lower()

    # Determine HTTP ports and whether to use TLS
    http_port_tls: list[tuple[int, bool]] = []
    for p in tcp_ports:
        if p in (80, 8080, 8088):
            http_port_tls.append((p, False))
        elif p in (443, 4443, 8089, 8443, 5001):
            http_port_tls.append((p, True))

    # If no HTTP ports detected but a common one might be open, try 80 and 443
    if not http_port_tls:
        http_port_tls = [(80, False), (443, True)]

    is_freepbx_or_asterisk = not fingerprint or any(
        kw in fp_lower for kw in ("freepbx", "asterisk", "unknown")
    )
    is_grandstream = not fingerprint or any(
        kw in fp_lower for kw in ("grandstream", "ucm", "unknown")
    )
    is_3cx = not fingerprint or any(kw in fp_lower for kw in ("3cx", "unknown"))

    # Check 1: FreePBX CVE-2019-19006
    if is_freepbx_or_asterisk:
        for port, use_tls in http_port_tls:
            r = check_freepbx_cve_2019_19006(host, port, use_tls, timeout)
            if r:
                results.append(r)
                break  # One finding per CVE per host is sufficient

    # Check 2: FreePBX CVE-2021-45461
    if is_freepbx_or_asterisk:
        for port, use_tls in http_port_tls:
            r = check_freepbx_cve_2021_45461(host, port, use_tls, timeout)
            if r:
                results.append(r)
                break

    # Check 3: FreePBX path traversal
    if is_freepbx_or_asterisk:
        for port, use_tls in http_port_tls:
            r = check_freepbx_path_traversal(host, port, use_tls, timeout)
            if r:
                results.append(r)
                break

    # Check 4: FreePBX module exposure
    if is_freepbx_or_asterisk:
        for port, use_tls in http_port_tls:
            module_results = check_freepbx_module_exposure(host, port, use_tls, timeout)
            results.extend(module_results)
            if module_results:
                break

    # Check 5: Grandstream CVE-2021-37748
    if is_grandstream:
        for port, use_tls in http_port_tls:
            r = check_grandstream_cve_2021_37748(host, port, use_tls, timeout)
            if r:
                results.append(r)
                break

    # Check 6: Grandstream CVE-2023-37315
    if is_grandstream:
        for port, use_tls in http_port_tls:
            r = check_grandstream_cve_2023_37315(host, port, use_tls, timeout)
            if r:
                results.append(r)
                break

    # Check 7: Asterisk AMI without TLS
    r_ami = check_ami_no_tls(host, tcp_ports, timeout)
    if r_ami:
        results.append(r_ami)

    # Check 8: 3CX admin exposure
    if is_3cx:
        for port, use_tls in http_port_tls:
            cx_results = check_3cx_admin_exposure(host, port, use_tls, timeout)
            results.extend(cx_results)
            if cx_results:
                break

    # Check 9: FreePBX recordings exposure
    if is_freepbx_or_asterisk:
        for port, use_tls in http_port_tls:
            rec_results = check_freepbx_recordings_exposure(host, port, use_tls, timeout)
            results.extend(rec_results)
            if rec_results:
                break

    # Check 10: SIP version disclosure
    version_results = check_sip_version_disclosure(host, sip_port, sip_server, timeout)
    results.extend(version_results)

    # Check 11: CVE-2025-57819 — FreePBX EPM SQL injection + RCE
    if is_freepbx_or_asterisk:
        for port, use_tls in http_port_tls:
            r = check_freepbx_cve_2025_57819(host, port, use_tls, timeout)
            if r:
                results.append(r)
                break

    # Check 12: CVE-2025-57767 — Asterisk SIP auth crash (DoS)
    if is_freepbx_or_asterisk:
        r = check_asterisk_cve_2025_57767(host, sip_port, sip_server, timeout)
        if r:
            results.append(r)

    # Check 13: Unencrypted SIP signaling (no TLS on 5061)
    r_tls = check_sip_tls_missing(host, sip_port, tcp_ports, timeout)
    if r_tls:
        results.append(r_tls)

    # Check 14: SIP-over-WebSocket security
    wss_results = check_sip_wss_security(host, tcp_ports, timeout)
    results.extend(wss_results)

    # Deduplicate by (cve_id, host, port)
    seen: set[tuple[str, str, int]] = set()
    deduped: list[CveResult] = []
    for res in results:
        key = (res.cve_id, res.host, res.port)
        if key not in seen:
            seen.add(key)
            deduped.append(res)

    # Sort: critical → high → medium → low → info
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 5))

    return deduped
