"""HTTP probes against PBX management interfaces.

Scoped tightly to the platforms you actually target — FreePBX, vanilla
Asterisk web UIs, Grandstream UCM/GXP/HT/DP, 3CX Phone System, Sangoma
Connect, and Mitel MiVoice. Each probe returns either a finding dict or None.

All probes are read-only — they identify exposed admin surfaces but do not
attempt login. The credential testing pipeline (auth.py) handles that
separately.
"""
from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class HttpFinding:
    name: str           # internal id, e.g. "freepbx-admin-ui"
    severity: str       # critical | high | medium | low | info
    target: str         # "host:port"
    title: str
    evidence: str
    remediation: str


def _http_post(host: str, port: int, path: str, body: str, timeout: float,
               use_tls: bool = False,
               content_type: str = "application/json") -> tuple[int, str, bytes]:
    """POST request. Returns (status, server_header, body_first_4k). (0,"",b"") on error."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        body_bytes = body.encode("utf-8")
        req = (
            f"POST {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "User-Agent: Mozilla/5.0 VoIPScan/3.0\r\n"
            "\r\n"
        )
        s.sendall(req.encode() + body_bytes)
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
        head, _, resp_body = text.partition("\r\n\r\n")
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
        return status, server, resp_body.encode("utf-8", errors="replace")[:4096]
    except (socket.timeout, OSError, ssl.SSLError):
        return 0, "", b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def _http_get(host: str, port: int, path: str, timeout: float,
              use_tls: bool = False) -> tuple[int, str, bytes]:
    """Return (status, server_header, body_first_4k). (0,"",b"") on error."""
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
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 VoIPScan/3.0\r\n"
            "\r\n"
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
        return status, server, body.encode("utf-8", errors="replace")[:4096]
    except (socket.timeout, OSError, ssl.SSLError):
        return 0, "", b""
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Probes — existing
# ---------------------------------------------------------------------------

def probe_freepbx_admin(host: str, port: int, use_tls: bool,
                        timeout: float = 3.0) -> HttpFinding | None:
    """FreePBX admin UI reachable from the internet — common high-impact finding."""
    if port not in (80, 443, 4443, 8088, 8443):
        return None
    status, server, body = _http_get(host, port, "/admin/config.php",
                                      timeout, use_tls)
    if status == 0:
        return None
    body_text = body.decode("utf-8", errors="replace").lower()
    if ("freepbx" in body_text or "freepbx" in server.lower() or
            "/admin/config.php" in body_text):
        return HttpFinding(
            name="freepbx-admin-ui",
            severity="high",
            target=f"{host}:{port}",
            title="FreePBX admin web UI exposed",
            evidence=f"HTTP {status} on /admin/config.php; Server: {server!r}",
            remediation=(
                "Restrict /admin to VPN or an IP allow-list. The FreePBX "
                "admin console must never be reachable from the public "
                "internet — exploit chains in 2021-2024 (CVE-2024-30269, "
                "CVE-2022-2347, etc.) require nothing beyond reachability."
            ),
        )
    return None


def probe_freepbx_recordings(host: str, port: int, use_tls: bool,
                              timeout: float = 3.0) -> HttpFinding | None:
    """FreePBX UCP / call recordings UI publicly accessible."""
    if port not in (80, 443, 4443, 8088, 8443):
        return None
    status, _, body = _http_get(host, port, "/ucp/", timeout, use_tls)
    if status in (200, 302) and b"User Control Panel" in body:
        return HttpFinding(
            name="freepbx-ucp-exposed",
            severity="medium",
            target=f"{host}:{port}",
            title="FreePBX User Control Panel (UCP) exposed",
            evidence=f"HTTP {status} on /ucp/ returned UCP page",
            remediation=(
                "UCP exposes voicemail, call history, and contacts. Restrict "
                "by VPN or IP allow-list. Force SSO/2FA if exposed by design."
            ),
        )
    return None


def probe_asterisk_arf(host: str, port: int, use_tls: bool,
                       timeout: float = 3.0) -> HttpFinding | None:
    """Asterisk HTTP interface (built-in mini-HTTP server, default off — but
    if on, dangerous)."""
    if port not in (8088, 8089):
        return None
    status, server, body = _http_get(host, port, "/static/config/", timeout,
                                      use_tls)
    if status != 0 and "Asterisk" in (server + body.decode(errors="replace")):
        return HttpFinding(
            name="asterisk-builtin-http",
            severity="high",
            target=f"{host}:{port}",
            title="Asterisk built-in HTTP interface enabled",
            evidence=f"HTTP {status} on /static/config/; Server: {server!r}",
            remediation=(
                "Set enabled=no in /etc/asterisk/http.conf unless required. "
                "If required, bindaddr=127.0.0.1 plus a reverse proxy with "
                "auth."
            ),
        )
    return None


def probe_grandstream_ui(host: str, port: int, use_tls: bool,
                          timeout: float = 3.0) -> HttpFinding | None:
    """Grandstream UCM / GXP / HT / DP web admin."""
    if port not in (80, 443, 8089, 8443):
        return None
    status, server, body = _http_get(host, port, "/", timeout, use_tls)
    if status == 0:
        return None
    text = body.decode("utf-8", errors="replace").lower()
    if ("grandstream" in text or "grandstream" in server.lower() or
            "ucm" in text or "gxv" in text or "gxp" in text):
        # Grandstream UIs typically self-identify in the title / login banner
        return HttpFinding(
            name="grandstream-admin-ui",
            severity="high",
            target=f"{host}:{port}",
            title="Grandstream device admin UI exposed",
            evidence=f"HTTP {status} on / matched Grandstream signature",
            remediation=(
                "Grandstream devices ship with default credentials "
                "(admin/admin, admin/123 etc.) and have a long history of "
                "auth-bypass CVEs (CVE-2023-37315, CVE-2022-3324, ...). "
                "Restrict the admin UI to a management VLAN."
            ),
        )
    return None


def probe_grandstream_cve_2021_37748(host: str, port: int, use_tls: bool,
                                      timeout: float = 3.0) -> HttpFinding | None:
    """CVE-2021-37748: Grandstream UCM6xxx unauthenticated config disclosure."""
    if port not in (80, 443, 8089, 8443):
        return None
    status, _, body = _http_get(host, port, "/cgi-bin/api-get_config",
                                 timeout, use_tls)
    text = body.decode("utf-8", errors="replace").lower()
    if status == 200 and any(kw in text for kw in
                              ("extension", "password", "sippassword", "secret",
                               "peer", "trunk", "voicemail")):
        return HttpFinding(
            name="grandstream-cve-2021-37748",
            severity="critical",
            target=f"{host}:{port}",
            title="CVE-2021-37748: Grandstream UCM config exposed without authentication",
            evidence=(
                f"GET /cgi-bin/api-get_config returned HTTP {status} with "
                "config keywords (extension/password/secret) in the response "
                "— no authentication required."
            ),
            remediation=(
                "Update UCM firmware to 1.0.20.22 or later. Block "
                "/cgi-bin/api-get_config at the perimeter firewall as an "
                "immediate mitigation."
            ),
        )
    return None


def probe_grandstream_default_creds(host: str, port: int, use_tls: bool,
                                     timeout: float = 3.0) -> HttpFinding | None:
    """Try Grandstream UCM default admin/admin via the REST login API."""
    if port not in (80, 443, 8089, 8443):
        return None
    import json as _json
    body = _json.dumps({"action": "login", "user": "admin", "password": "admin"})
    status, _, resp = _http_post(host, port, "/cgi-bin/api.values.get",
                                  body, timeout, use_tls)
    text = resp.decode("utf-8", errors="replace")
    text_lower = text.lower()
    # Success indicators: HTTP 200 AND (positive auth token/session in response)
    # AND NOT still on the login form (login form contains "password" input field)
    # OR response contains "logout" link (post-login page)
    login_success = (
        status == 200
        and (
            '"status":true' in text
            or '"authenticated"' in text
            or '"session"' in text_lower
            or "logout" in text_lower
        )
        and "password" not in text_lower[:500]
    )
    # Also accept 201 with explicit auth markers regardless of password field
    if not login_success and status == 201 and (
        '"status":true' in text or '"authenticated"' in text
    ):
        login_success = True
    if login_success:
        return HttpFinding(
            name="grandstream-default-creds",
            severity="critical",
            target=f"{host}:{port}",
            title="Grandstream UCM authenticated with default credentials (admin/admin)",
            evidence=(
                f"POST /cgi-bin/api.values.get with admin/admin returned HTTP {status} "
                "indicating login success (auth token/session present, no login form in response)."
            ),
            remediation=(
                "Change the Grandstream admin password immediately via "
                "System → User Management. Default credentials allow full "
                "device takeover and SIP credential extraction."
            ),
        )
    return None


def probe_freepbx_rest_api(host: str, port: int, use_tls: bool,
                            timeout: float = 3.0) -> HttpFinding | None:
    """FreePBX REST API (/admin/api) reachability check with default cred attempt."""
    if port not in (80, 443, 4443, 8443):
        return None
    status, _, body = _http_get(host, port, "/admin/api/api/version",
                                 timeout, use_tls)
    text = body.decode("utf-8", errors="replace").lower()
    if not (status in (200, 401, 403) and any(kw in text for kw in
                                               ("freepbx", "fpbx", "version",
                                                "api", "unauthorized"))):
        return None

    # Endpoint confirmed reachable — try default credentials via config.php
    _default_cred_pairs = [
        ("admin", "admin"),
        ("admin", "freepbx"),
    ]
    cred_note = ""
    for _u, _p in _default_cred_pairs:
        _body = f"username={_u}&password={_p}"
        _cs, _, _cr = _http_post(
            host, port, "/admin/config.php", _body, timeout, use_tls,
            content_type="application/x-www-form-urlencoded",
        )
        _ct = _cr.decode("utf-8", errors="replace").lower()
        # Successful login: response contains "Logged in" or lacks "login" form
        _logged_in = (
            _cs == 200
            and ("logged in" in _ct or "logout" in _ct)
            and "login" not in _ct[:300]
        )
        if _logged_in:
            cred_note = f" DEFAULT CREDENTIALS WORK: {_u}/{_p} grants admin access."
            break

    return HttpFinding(
        name="freepbx-rest-api-exposed",
        severity="critical" if cred_note else "high",
        target=f"{host}:{port}",
        title=(
            "FreePBX REST API exposed with working default credentials"
            if cred_note
            else "FreePBX REST API exposed to the internet"
        ),
        evidence=(
            f"GET /admin/api/api/version returned HTTP {status}. "
            "The REST API uses the same admin credentials as the web UI "
            f"and allows full PBX control via authenticated requests.{cred_note}"
        ),
        remediation=(
            "Restrict /admin/api to an IP allow-list or VPN. "
            "Enable HTTP basic auth or API key requirements. "
            "Change default admin credentials immediately."
        ),
    )


def probe_asterisk_rawman(host: str, port: int, use_tls: bool,
                           timeout: float = 3.0) -> HttpFinding | None:
    """Asterisk built-in HTTP management API (/rawman) reachability check."""
    if port not in (8088, 8089):
        return None
    status, server, body = _http_get(host, port, "/rawman", timeout, use_tls)
    text = body.decode("utf-8", errors="replace")
    if status != 0 and ("Response:" in text or "Asterisk" in server
                         or "rawman" in text.lower()):
        return HttpFinding(
            name="asterisk-rawman-exposed",
            severity="high",
            target=f"{host}:{port}",
            title="Asterisk HTTP management API (/rawman) reachable",
            evidence=(
                f"GET /rawman returned HTTP {status}; Server: {server!r}. "
                "/rawman provides call-plane control equivalent to AMI over "
                "plain HTTP — Originate, Hangup, SIPpeers, etc."
            ),
            remediation=(
                "Set enabled=no in /etc/asterisk/http.conf unless the "
                "Asterisk built-in HTTP server is required. If needed, bind "
                "to 127.0.0.1 and reverse-proxy with strong authentication."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Probes — new
# ---------------------------------------------------------------------------

def probe_3cx_admin(host: str, port: int, use_tls: bool,
                    timeout: float = 3.0) -> HttpFinding | None:
    """3CX Phone System management interface and REST API exposure."""
    if port not in (80, 443, 4443, 5000, 5001, 8088, 8443):
        return None

    paths = ["/webclient/", "/api/v1/Parameters/List", "/api/v1/UserSettings"]
    unauthenticated_api = False
    matched_path = ""
    matched_status = 0
    matched_server = ""

    for path in paths:
        status, server, body = _http_get(host, port, path, timeout, use_tls)
        if status == 0:
            continue
        text = body.decode("utf-8", errors="replace")
        text_lower = text.lower()
        server_lower = server.lower()
        hit = ("3cx" in text_lower or "phonesystem" in server_lower or
               "3cx" in server_lower or "phonesystem" in text_lower)
        if hit or (path.startswith("/api/v1/") and status == 200):
            matched_path = path
            matched_status = status
            matched_server = server
            if path.startswith("/api/v1/") and status == 200:
                unauthenticated_api = True
            break

    if not matched_path:
        return None

    severity = "critical" if unauthenticated_api else "high"
    title = (
        "3CX REST API responds without authentication"
        if unauthenticated_api
        else "3CX Phone System management interface exposed"
    )
    evidence = (
        f"GET {matched_path} returned HTTP {matched_status}; "
        f"Server: {matched_server!r}"
    )
    if unauthenticated_api:
        evidence += " — API path responded with HTTP 200 without credentials"

    return HttpFinding(
        name="3cx-admin-exposed",
        severity=severity,
        target=f"{host}:{port}",
        title=title,
        evidence=evidence,
        remediation=(
            "Restrict 3CX management ports to VPN or an IP allow-list. "
            "Ensure /api/v1/ endpoints require authentication. "
            "Apply all 3CX security updates — the 2023 supply-chain attack "
            "(CVE-2023-29059) was facilitated by exposed management surfaces."
        ),
    )


def probe_freepbx_ajax(host: str, port: int, use_tls: bool,
                       timeout: float = 3.0) -> HttpFinding | None:
    """FreePBX AJAX endpoint — sensitive system data exposed without authentication."""
    if port not in (80, 443, 4443, 8088, 8443):
        return None

    path = "/admin/ajax.php?module=dashboard&command=getSummary"
    status, server, body = _http_get(host, port, path, timeout, use_tls)
    if status == 0:
        return None

    text = body.decode("utf-8", errors="replace").strip()
    # Detect a JSON response: starts with '{' or '[', and no auth-challenge
    # indicators (login redirect, 401, 403).
    is_json = text.startswith(("{", "["))
    no_auth_challenge = status not in (401, 403) and "login" not in text.lower()[:200]

    if is_json and no_auth_challenge:
        return HttpFinding(
            name="freepbx-ajax-unauthenticated",
            severity="high",
            target=f"{host}:{port}",
            title="FreePBX AJAX endpoint returns data without authentication",
            evidence=(
                f"GET {path} returned HTTP {status} with a JSON response "
                f"(no auth challenge). Server: {server!r}. "
                f"Response preview: {text[:200]!r}"
            ),
            remediation=(
                "Restrict /admin/ajax.php to authenticated sessions only. "
                "Apply available FreePBX security patches and restrict "
                "/admin/ to a management network or VPN."
            ),
        )
    return None


def probe_freepbx_recordings_dir(host: str, port: int, use_tls: bool,
                                  timeout: float = 3.0) -> HttpFinding | None:
    """FreePBX call recordings directory — voicemail and call recordings exposed."""
    if port not in (80, 443, 4443, 8088, 8443):
        return None

    status, server, body = _http_get(host, port, "/recordings/", timeout, use_tls)
    if status == 0:
        return None

    text = body.decode("utf-8", errors="replace").lower()
    # Directory listing indicators or audio file extensions in links
    dir_listing = ("index of" in text or "parent directory" in text)
    recording_files = any(ext in text for ext in (".wav", ".mp3", ".gsm", ".ogg",
                                                    ".opus", ".g722"))

    if status == 200 and (dir_listing or recording_files):
        detail = "directory listing" if dir_listing else "recording file links"
        return HttpFinding(
            name="freepbx-recordings-exposed",
            severity="high",
            target=f"{host}:{port}",
            title="FreePBX call recordings directory exposed",
            evidence=(
                f"GET /recordings/ returned HTTP {status} with {detail}. "
                f"Server: {server!r}"
            ),
            remediation=(
                "Disable directory listing for /recordings/ in the web server "
                "configuration. Require authentication to access recording "
                "files. Consider serving recordings only through the FreePBX "
                "UCP with proper session validation."
            ),
        )
    return None


def probe_sangoma_connect(host: str, port: int, use_tls: bool,
                           timeout: float = 3.0) -> HttpFinding | None:
    """Sangoma Connect portal exposure."""
    if port not in (80, 443, 4443, 8088, 8443):
        return None

    status, server, body = _http_get(host, port, "/sangoma-connect/",
                                      timeout, use_tls)
    if status == 0:
        return None

    text = body.decode("utf-8", errors="replace").lower()
    if status in (200, 302) and "sangoma" in text:
        return HttpFinding(
            name="sangoma-connect-exposed",
            severity="medium",
            target=f"{host}:{port}",
            title="Sangoma Connect portal reachable from the internet",
            evidence=(
                f"GET /sangoma-connect/ returned HTTP {status} with "
                f"'Sangoma' in the response body. Server: {server!r}"
            ),
            remediation=(
                "Restrict the Sangoma Connect portal to known IP ranges or "
                "a VPN. Ensure multi-factor authentication is enabled for "
                "all portal accounts."
            ),
        )
    return None


def probe_mitel_uc(host: str, port: int, use_tls: bool,
                   timeout: float = 3.0) -> HttpFinding | None:
    """Mitel MiVoice / MiCollab UC interface exposure."""
    if port not in (80, 443, 4443, 8080, 8443):
        return None

    paths = ["/bcmslite/", "/mitel/", "/MiCollab/"]
    for path in paths:
        status, server, body = _http_get(host, port, path, timeout, use_tls)
        if status == 0:
            continue
        text = body.decode("utf-8", errors="replace")
        text_lower = text.lower()
        if status in (200, 302) and any(kw in text_lower for kw in
                                         ("mitel", "mivoice", "micollab")):
            return HttpFinding(
                name="mitel-uc-exposed",
                severity="high",
                target=f"{host}:{port}",
                title="Mitel MiVoice/MiCollab UC interface exposed",
                evidence=(
                    f"GET {path} returned HTTP {status} with Mitel signature "
                    f"('mitel'/'mivoice'/'micollab') in the response. "
                    f"Server: {server!r}"
                ),
                remediation=(
                    "Restrict Mitel UC management paths to VPN or an IP "
                    "allow-list. Apply Mitel security advisories — "
                    "CVE-2022-41765, CVE-2023-25597, and related "
                    "vulnerabilities affect exposed MiVoice instances. "
                    "Disable unused web components via the Mitel admin console."
                ),
            )
    return None


def probe_version_extract(host: str, port: int, use_tls: bool,
                           timeout: float = 3.0) -> HttpFinding | None:
    """Extract software version strings from HTTP responses (version disclosure)."""
    if port not in (80, 443, 4443, 5000, 8080, 8088, 8443):
        return None

    paths = ["/", "/admin/", "/admin/config.php"]
    version_found = ""
    source_path = ""
    source_server = ""

    # Patterns to detect version strings
    _ver_patterns = [
        re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                   re.IGNORECASE),
        re.compile(r'<title>([^<]{3,80})</title>', re.IGNORECASE),
        re.compile(r'(?:version|ver|release)[^\d]{0,10}(\d+\.\d[\d.a-zA-Z-]{0,20})',
                   re.IGNORECASE),
        re.compile(r'v(\d+\.\d[\d.]{0,10})', re.IGNORECASE),
    ]

    for path in paths:
        status, server, body = _http_get(host, port, path, timeout, use_tls)
        if status == 0:
            continue

        candidates: list[str] = []

        # Server header
        if server:
            candidates.append(f"Server: {server}")

        text = body.decode("utf-8", errors="replace")
        for pat in _ver_patterns:
            m = pat.search(text)
            if m:
                snippet = m.group(0).strip()
                if len(snippet) <= 120:
                    candidates.append(snippet)

        if candidates:
            version_found = "; ".join(candidates[:4])
            source_path = path
            source_server = server
            break

    if not version_found:
        return None

    return HttpFinding(
        name="http-version-disclosure",
        severity="info",
        target=f"{host}:{port}",
        title="Software version information disclosed via HTTP",
        evidence=(
            f"GET {source_path} revealed version strings: {version_found!r}. "
            f"Server header: {source_server!r}"
        ),
        remediation=(
            "Suppress the Server header (ServerTokens Prod in Apache, "
            "server_tokens off in nginx). Remove or genericise meta generator "
            "tags and version strings from login pages. Version disclosure "
            "assists targeted exploit selection."
        ),
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

PROBES = [
    probe_freepbx_admin,
    probe_freepbx_recordings,
    probe_asterisk_arf,
    probe_grandstream_ui,
    probe_grandstream_cve_2021_37748,
    probe_grandstream_default_creds,
    probe_freepbx_rest_api,
    probe_asterisk_rawman,
    # new probes
    probe_3cx_admin,
    probe_freepbx_ajax,
    probe_freepbx_recordings_dir,
    probe_sangoma_connect,
    probe_mitel_uc,
    probe_version_extract,
]

# Ports that carry HTTPS in some deployments even though the number is not
# the standard TLS port (e.g. some 3CX and Asterisk configs use 8088 for
# HTTPS as well as HTTP).
_DUAL_TLS_PORTS = frozenset({8088})


def run_all(host: str, tcp_ports: list[int],
            timeout: float = 3.0,
            max_workers: int = 16) -> list[HttpFinding]:
    """Run every probe against every relevant port. Returns deduplicated findings."""
    if not tcp_ports:
        return []

    work: list[tuple] = []
    for port in tcp_ports:
        use_tls = port in (443, 4443, 8089, 8443)
        for probe in PROBES:
            work.append((probe, host, port, use_tls))
        # For ports that some deployments serve over HTTPS, also try TLS=True
        # when we have not already scheduled a TLS pass.
        if port in _DUAL_TLS_PORTS and not use_tls:
            for probe in PROBES:
                work.append((probe, host, port, True))

    findings: list[HttpFinding] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(p, h, port, tls, timeout): (p, port)
                for p, h, port, tls in work}
        for fut in as_completed(futs):
            try:
                f = fut.result()
                if f:
                    findings.append(f)
            except (OSError, ConnectionError, TimeoutError):
                continue

    # Deduplicate (name, target)
    seen: set = set()
    deduped: list[HttpFinding] = []
    for f in findings:
        key = (f.name, f.target)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped
