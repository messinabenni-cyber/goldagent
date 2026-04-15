"""CVE-targeted / known-issue probes for VoIP infrastructure.

Non-invasive HTTP(S) GETs against well-known management endpoints. Each
probe identifies a specific known-bad configuration or leaks version info,
and emits a VulnFinding ready to merge into the main report.

Probes are intentionally targeted — we only touch endpoints that are known
to be management surfaces, never generic application paths.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

from .events import bus


@dataclass
class VulnFinding:
    name: str           # CVE ID or short identifier
    severity: str       # 'critical', 'high', 'medium', 'low', 'info'
    target: str         # "host:port"
    title: str
    evidence: str
    remediation: str


def _http_get(host: str, port: int, path: str, timeout: float = 3.0,
              tls: bool = False, headers: dict | None = None) -> tuple:
    """Single HTTP GET. Returns (status, headers_dict, body_snippet_str)
    or (None, {}, '') on error. Reads at most 8 KiB of body."""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path,
                         headers=headers or {"User-Agent": "voip-scan/1.0"})
            resp = conn.getresponse()
            body = resp.read(8192).decode("utf-8", errors="replace")
            return resp.status, dict(resp.getheaders()), body
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, socket.timeout, ssl.SSLError):
        return None, {}, ""


def _any_value_contains(headers: dict, needle: str) -> bool:
    needle_low = needle.lower()
    for v in headers.values():
        if needle_low in str(v).lower():
            return True
    return False


# -------- individual probes --------

def probe_freepbx_admin(host: str, port: int, tls: bool,
                        timeout: float = 3.0) -> VulnFinding | None:
    """FreePBX admin panel disclosure."""
    for path in ("/admin/config.php", "/admin/", "/"):
        status, headers, body = _http_get(host, port, path, timeout, tls)
        if status is None:
            continue
        combined = body + "".join(str(v) for v in headers.values())
        if "FreePBX" in combined or "PBXact" in combined:
            m = re.search(r"FreePBX[^\d]*(\d+(?:\.\d+){1,2})", combined, re.I)
            version = m.group(1) if m else "unknown"
            return VulnFinding(
                name="FreePBX-Admin-Exposed",
                severity="medium",
                target=f"{host}:{port}",
                title=f"FreePBX admin UI reachable (version {version})",
                evidence=f"GET {path} returned HTTP {status}; FreePBX signature "
                         f"found. Known CVEs: CVE-2019-19006 (admin auth bypass "
                         f"in 14/15), CVE-2014-1903 (recordings module disclosure).",
                remediation="Never expose the FreePBX admin panel to untrusted "
                            "networks. Use VPN/ACL, and keep FreePBX patched "
                            "(run `fwconsole update` on a scheduled cadence).",
            )
    return None


def probe_asterisk_ari(host: str, port: int, tls: bool,
                       timeout: float = 3.0) -> VulnFinding | None:
    """Asterisk REST Interface (ARI) default endpoint."""
    status, _, body = _http_get(host, port, "/ari/api-docs/resources.json",
                                timeout, tls)
    if status == 200 and ("ARI" in body.upper() or "asterisk" in body.lower()):
        return VulnFinding(
            name="Asterisk-ARI-Exposed",
            severity="high",
            target=f"{host}:{port}",
            title="Asterisk REST Interface (ARI) publicly accessible",
            evidence=(f"GET /ari/api-docs/resources.json → HTTP 200 with ARI "
                      f"metadata. ARI allows full call-plane control if creds "
                      f"(or defaults) are accepted."),
            remediation="Bind ARI to loopback/management VLAN only; enforce "
                        "strong per-application credentials; place behind TLS "
                        "with client-cert auth.",
        )
    return None


def probe_asterisk_server_header(host: str, port: int, tls: bool,
                                 timeout: float = 3.0) -> VulnFinding | None:
    """Asterisk HTTP listener version disclosure."""
    status, headers, body = _http_get(host, port, "/httpstatus", timeout, tls)
    if status is not None and ("Asterisk" in body or _any_value_contains(headers, "Asterisk")):
        m = re.search(r"Asterisk[^\d]*(\d+(?:\.\d+){1,2})",
                      body + str(headers), re.I)
        version = m.group(1) if m else "unknown"
        return VulnFinding(
            name="Asterisk-HTTP-Version-Disclosure",
            severity="low",
            target=f"{host}:{port}",
            title=f"Asterisk built-in HTTP server version disclosure (v{version})",
            evidence=f"/httpstatus → {status}; version discoverable in response.",
            remediation="Set enabled=no in http.conf or at least strip the "
                        "Server header; outdated Asterisk versions have "
                        "multiple RCE CVEs.",
        )
    return None


def probe_cucm_axl(host: str, port: int, tls: bool,
                   timeout: float = 3.0) -> VulnFinding | None:
    """Cisco CUCM AXL web service exposure."""
    status, _, body = _http_get(host, port, "/axl/", timeout, tls)
    if status in (200, 401, 404):
        # 401 is the "normal" response; the presence of /axl/ itself is the
        # signal. 200 without auth prompt is a misconfig (rare).
        # 404 on '/' is fine; try the WSDL path.
        status2, _, body2 = _http_get(host, port,
                                      "/axl/services/AXLAPIService?wsdl",
                                      timeout, tls)
        blob = body + body2
        if "AXLAPI" in blob or "axlsoap" in blob.lower():
            sev = "high" if status == 200 else "medium"
            return VulnFinding(
                name="CUCM-AXL-Exposed",
                severity=sev,
                target=f"{host}:{port}",
                title="Cisco CUCM AXL web service reachable",
                evidence=(f"/axl/ → {status}; AXL WSDL fingerprint present. "
                          f"AXL allows full UC configuration changes if "
                          f"authenticated."),
                remediation="Restrict AXL to trusted admin subnets only. "
                            "Enforce strong AXL credentials; rotate them.",
            )
    return None


def probe_3cx_webclient(host: str, port: int, tls: bool,
                        timeout: float = 3.0) -> VulnFinding | None:
    """3CX WebClient exposure + version (CVE-2023-29059 family)."""
    for path in ("/webclient/", "/webclient"):
        status, headers, body = _http_get(host, port, path, timeout, tls)
        if status is not None and ("3CX" in body or _any_value_contains(headers, "3CX")):
            m = re.search(r"3CX[^\d]*(\d{1,2}(?:\.\d+){2,3})",
                          body + str(headers))
            version = m.group(1) if m else "unknown"
            return VulnFinding(
                name="3CX-WebClient-Exposed",
                severity="medium",
                target=f"{host}:{port}",
                title=f"3CX WebClient publicly accessible (v{version})",
                evidence=(f"GET {path} → {status}; 3CX signature present. "
                          f"CVE-2023-29059 (supply-chain RCE) affected 18.x; "
                          f"verify update status."),
                remediation="Place 3CX management plane behind VPN. Keep 3CX "
                            "patched. Monitor 3CX security bulletins.",
            )
    return None


def probe_grandstream(host: str, port: int, tls: bool,
                      timeout: float = 3.0) -> VulnFinding | None:
    """Grandstream UCM / phones default admin panel."""
    status, headers, body = _http_get(host, port, "/", timeout, tls)
    if status is None:
        return None
    blob = body + str(headers)
    if re.search(r"grandstream|gxp\d+|ucm\d+", blob, re.I):
        m = re.search(r"(UCM\d+|GXP\d+)", blob, re.I)
        model = m.group(1) if m else "Grandstream"
        return VulnFinding(
            name="Grandstream-Admin-Exposed",
            severity="medium",
            target=f"{host}:{port}",
            title=f"{model} admin/web interface reachable",
            evidence=(f"GET / → {status}; Grandstream signature. Default "
                      f"creds (admin/admin) and CVE-2020-5736 are worth "
                      f"testing."),
            remediation="Change default credentials immediately; restrict "
                        "admin to management VLAN; patch firmware to latest.",
        )
    return None


def probe_polycom(host: str, port: int, tls: bool,
                  timeout: float = 3.0) -> VulnFinding | None:
    """Polycom/Poly phone web UI."""
    status, headers, body = _http_get(host, port, "/", timeout, tls)
    blob = body + str(headers)
    if status is not None and re.search(r"polycom|soundpoint|vvx", blob, re.I):
        return VulnFinding(
            name="Polycom-Web-UI-Exposed",
            severity="low",
            target=f"{host}:{port}",
            title="Polycom/Poly phone web UI reachable",
            evidence=(f"GET / → {status}; Polycom signature. Default "
                      f"admin passcode is 456; change immediately."),
            remediation="Disable web UI entirely (MGMT.SECURE_TLS flag) "
                        "or restrict to management VLAN. Rotate passcodes.",
        )
    return None


def probe_avaya_webLM(host: str, port: int, tls: bool,
                      timeout: float = 3.0) -> VulnFinding | None:
    """Avaya WebLM licensing / admin login page (signals Avaya environment)."""
    status, _, body = _http_get(host, port, "/WebLM/", timeout, tls)
    if status is not None and ("Avaya" in body or "WebLM" in body):
        return VulnFinding(
            name="Avaya-WebLM-Exposed",
            severity="low",
            target=f"{host}:{port}",
            title="Avaya WebLM/SMGR management page reachable",
            evidence=f"GET /WebLM/ → {status}; Avaya signature present.",
            remediation="Restrict Avaya management interfaces to ops network; "
                        "enforce MFA on admin accounts.",
        )
    return None


def probe_asterisk_ari_default_creds(host: str, port: int, tls: bool,
                                     timeout: float = 3.0) -> VulnFinding | None:
    """Asterisk ARI REST: probe with known default credentials.

    Tries the most common defaults: asterisk:asterisk, admin:admin,
    admin:asterisk.  A 200 response means full call-plane control is
    accessible without proper credential hardening.
    """
    import base64
    default_pairs = [("asterisk", "asterisk"), ("admin", "admin"),
                     ("admin", "asterisk"), ("asterisk", "password")]
    for user, pwd in default_pairs:
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        status, _, body = _http_get(
            host, port, "/ari/api-docs/resources.json", timeout, tls,
            headers={"Authorization": f"Basic {token}",
                     "User-Agent": "voip-scan/1.0"},
        )
        if status == 200 and ("ARI" in body.upper() or "asterisk" in body.lower()):
            return VulnFinding(
                name="Asterisk-ARI-Default-Creds",
                severity="critical",
                target=f"{host}:{port}",
                title=f"Asterisk ARI accessible with default creds ({user}:{pwd})",
                evidence=(f"GET /ari/api-docs/resources.json with Basic "
                          f"{user}:{pwd} → HTTP 200 with ARI metadata. "
                          f"Full call-plane control via REST (POST /channels "
                          f"places arbitrary calls)."),
                remediation="Change ARI credentials in ari.conf immediately. "
                            "Bind to loopback only; place behind TLS + client cert.",
            )
    return None


def probe_ami_unauthenticated(host: str, port: int, tls: bool,
                               timeout: float = 3.0) -> VulnFinding | None:
    """Asterisk AMI: attempt TCP login with known default credentials.

    AMI runs on TCP not HTTP, so this probe is only meaningful when port
    is 5038 (standard AMI). We attempt common defaults; a successful
    'Originate' action allows placing arbitrary outbound calls.
    """
    if port not in (5038, 5039):
        return None
    import socket as _socket
    default_pairs = [("admin", "amp111"), ("admin", "admin"),
                     ("admin", "password"), ("asterisk", "asterisk"),
                     ("admin", ""), ("", "")]
    for user, pwd in default_pairs:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
                if "asterisk call manager" not in banner.lower():
                    return None  # not AMI — skip remaining pairs too
                login_cmd = (
                    f"Action: Login\r\nUsername: {user}\r\nSecret: {pwd}\r\n\r\n"
                )
                s.sendall(login_cmd.encode())
                resp = s.recv(512).decode("utf-8", errors="replace")
                if "response: success" in resp.lower():
                    return VulnFinding(
                        name="Asterisk-AMI-Default-Creds",
                        severity="critical",
                        target=f"{host}:{port}",
                        title=f"Asterisk AMI accepts default credentials ({user}:{pwd})",
                        evidence=(f"TCP {host}:{port} — AMI banner: {banner!r}. "
                                  f"Login {user}:{pwd} returned Success. "
                                  f"AMI 'Originate' can place arbitrary calls "
                                  f"(CVE-2019-18610 pattern)."),
                        remediation="Change AMI credentials in manager.conf. "
                                    "Restrict AMI to loopback/management IP only. "
                                    "Disable 'originate' permission for all users.",
                    )
            finally:
                s.close()
        except OSError:
            pass
    return None


def probe_freepbx_rce_recording(host: str, port: int, tls: bool,
                                  timeout: float = 3.0) -> VulnFinding | None:
    """FreePBX recordings module unauthenticated RCE exposure (CVE-2019-19006 family).

    The recordings module at /recordings/ has had multiple unauthenticated
    access issues. A reachable /recordings/ without forced auth is a
    significant finding regardless of exact CVE applicability.
    """
    for path in ("/recordings/", "/admin/ajax.php",
                 "/admin/views/recordings_view.php"):
        status, headers, body = _http_get(host, port, path, timeout, tls)
        if status is None:
            continue
        combined = body + "".join(str(v) for v in headers.values())
        if status in (200, 302) and any(
            kw in combined
            for kw in ("FreePBX", "PBXact", "recordings", "pbxadmin")
        ):
            return VulnFinding(
                name="FreePBX-Recordings-Exposed",
                severity="high",
                target=f"{host}:{port}",
                title="FreePBX recordings module reachable (CVE-2019-19006 family)",
                evidence=(f"GET {path} → HTTP {status}; FreePBX recordings "
                          f"interface signature found. CVE-2019-19006 allows "
                          f"unauthenticated admin access on FreePBX 14/15."),
                remediation="Apply FreePBX security patch SNG7-PBX-2019-19006. "
                            "Restrict admin UI to management VLAN. Run "
                            "`fwconsole update` to ensure latest patches.",
            )
    return None


def probe_freeswitch_default_creds(host: str, port: int, tls: bool,
                                    timeout: float = 3.0) -> VulnFinding | None:
    """FreeSWITCH Event Socket Library (ESL) and HTTP API default creds."""
    # ESL runs on TCP 8021 — probe it directly
    if port not in (8000, 8080, 8021, 8081, 8082):
        return None
    # Try HTTP admin with default creds
    import base64
    for user, pwd in [("freeswitch", "works"), ("admin", "admin"),
                      ("admin", "password"), ("freeswitch", "freeswitch")]:
        token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        for path in ("/", "/api/version", "/api/status"):
            status, _, body = _http_get(
                host, port, path, timeout, tls,
                headers={"Authorization": f"Basic {token}",
                         "User-Agent": "voip-scan/1.0"},
            )
            if status == 200 and any(kw in body.lower()
                                     for kw in ("freeswitch", "freeswitch version",
                                                "uptime", "session")):
                return VulnFinding(
                    name="FreeSWITCH-Default-Creds",
                    severity="critical",
                    target=f"{host}:{port}",
                    title=f"FreeSWITCH HTTP API accessible with default creds ({user}:{pwd})",
                    evidence=(f"GET {path} with Basic {user}:{pwd} → HTTP {status}; "
                              f"FreeSWITCH signature. ESL allows full PBX control "
                              f"including call origination and dialplan injection."),
                    remediation="Change FreeSWITCH HTTP credentials in vars.xml; "
                                "restrict ESL to loopback or management VLAN only.",
                )
    return None


def probe_yealink_rce(host: str, port: int, tls: bool,
                      timeout: float = 3.0) -> VulnFinding | None:
    """Yealink phones CVE-2021-27561 — unauthenticated command injection via
    the HTTP API (/cgi-bin/cgiserver.cgi). Affects T19/T21/T23/T27/T29/T40/T41
    series. Attacker can factory-reset, change SIP config, exfiltrate creds."""
    if port not in (80, 443, 8080, 8443):
        return None
    # CVE-2021-27561: GET /cgi-bin/cgiserver.cgi with crafted URL_action
    path = "/cgi-bin/cgiserver.cgi?URL_action=AutoproSrv_Dir_Write"
    status, headers, body = _http_get(host, port, path, timeout, tls)
    if status is not None:
        blob = body + str(headers)
        if any(kw in blob.lower()
               for kw in ("yealink", "sipphone", "vcs", "auto provision")):
            return VulnFinding(
                name="Yealink-CVE-2021-27561",
                severity="critical",
                target=f"{host}:{port}",
                title="Yealink phone CVE-2021-27561 — unauthenticated RCE endpoint reachable",
                evidence=(f"GET {path} → HTTP {status}; Yealink CGI signature "
                          f"detected. CVE-2021-27561 allows unauthenticated command "
                          f"injection, SIP config theft, and factory reset."),
                remediation="Update Yealink firmware to latest. Disable the web UI "
                            "admin panel if not required. Place phones behind VLAN "
                            "with no external management access.",
            )
    # Also check for generic Yealink web UI
    status2, headers2, body2 = _http_get(host, port, "/", timeout, tls)
    blob2 = body2 + str(headers2)
    if status2 is not None and re.search(r"yealink|T[0-9]{2}[GP]?", blob2, re.I):
        return VulnFinding(
            name="Yealink-WebUI-Exposed",
            severity="medium",
            target=f"{host}:{port}",
            title="Yealink phone web interface publicly reachable",
            evidence=(f"GET / → HTTP {status2}; Yealink signature. "
                      f"Default admin password is 'admin'. CVE-2021-27561 applies "
                      f"if firmware < 58.85.0.5/55.85.0.5."),
            remediation="Change default password (admin/admin). Update firmware. "
                        "Restrict web management to management VLAN.",
        )
    return None


def probe_sangoma_pbxact(host: str, port: int, tls: bool,
                          timeout: float = 3.0) -> VulnFinding | None:
    """Sangoma PBXact / Business Voice+ admin panel (FreePBX derivative)."""
    for path in ("/admin/config.php", "/admin/", "/pbxact/"):
        status, headers, body = _http_get(host, port, path, timeout, tls)
        if status is None:
            continue
        combined = body + "".join(str(v) for v in headers.values())
        if re.search(r"sangoma|pbxact|business voice", combined, re.I):
            m = re.search(r"(PBXact|Business Voice|Sangoma)[^\d]*(\d+(?:\.\d+)?)",
                          combined, re.I)
            version = m.group(2) if m else "unknown"
            return VulnFinding(
                name="Sangoma-PBXact-Exposed",
                severity="medium",
                target=f"{host}:{port}",
                title=f"Sangoma PBXact admin panel reachable (v{version})",
                evidence=(f"GET {path} → HTTP {status}; Sangoma PBXact signature. "
                          f"Inherits FreePBX vulnerabilities (CVE-2019-19006 etc). "
                          f"Default admin portal creds may apply."),
                remediation="Restrict PBXact admin to management VLAN. "
                            "Keep PBXact patched via yum/dnf. Enforce strong password.",
            )
    return None


def probe_opensips_mi(host: str, port: int, tls: bool,
                      timeout: float = 3.0) -> VulnFinding | None:
    """OpenSIPS/Kamailio Management Interface HTTP exposure."""
    for path in ("/mi", "/mi/", "/json_rpc"):
        status, _, body = _http_get(host, port, path, timeout, tls)
        if status in (200, 405) and any(kw in body.lower()
                                         for kw in ("opensips", "kamailio",
                                                    "json-rpc", "management")):
            return VulnFinding(
                name="OpenSIPS-MI-Exposed",
                severity="high",
                target=f"{host}:{port}",
                title="OpenSIPS/Kamailio Management Interface publicly reachable",
                evidence=(f"GET {path} → HTTP {status}; MI/JSON-RPC signature. "
                          f"Allows module reload, user registration dump, "
                          f"and routing manipulation without auth."),
                remediation="Bind MI listener to loopback or management VLAN only. "
                            "Add IP-ACL to mi_datagram.conf / httpd.conf.",
            )
    return None


def probe_siptrunk_scan(host: str, port: int, tls: bool,
                         timeout: float = 3.0) -> VulnFinding | None:
    """Generic SIP trunk management portal signatures (Twilio, Bandwidth,
    VoIP.ms, SIP.us reseller panels that may be self-hosted)."""
    if port not in (80, 443, 8080, 8443):
        return None
    status, headers, body = _http_get(host, port, "/", timeout, tls)
    if status is None:
        return None
    blob = body + str(headers)
    patterns = [
        (r"voip\.ms|voipms", "VoIP.ms portal"),
        (r"sip\.us", "SIP.us portal"),
        (r"twilio", "Twilio management"),
        (r"bandwidth.*pbx|bandwidth.*voice", "Bandwidth.com Voice portal"),
        (r"anveo|broadvoice|onsip", "SIP carrier portal"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, blob, re.I):
            return VulnFinding(
                name="SIP-Carrier-Portal-Exposed",
                severity="info",
                target=f"{host}:{port}",
                title=f"{label} reachable from scan scope",
                evidence=(f"GET / → HTTP {status}; {label} signature. "
                          f"Carrier portals contain trunk credentials, billing "
                          f"info, and call routing that are prime toll-fraud targets."),
                remediation="Ensure carrier portal login uses MFA. Enable IP "
                            "allowlisting for portal access. Monitor call logs.",
            )
    return None


def probe_webrtc_gateway(host: str, port: int, tls: bool,
                          timeout: float = 3.0) -> VulnFinding | None:
    """WebRTC gateway / SIP-WebSocket bridge exposure.

    Janus, Asterisk WebRTC, FreeSWITCH Verto, 3CX WebMeeting all expose
    REST APIs and WebSocket endpoints that can be probed over HTTP.
    """
    if port not in (80, 443, 8080, 8088, 8089, 7443):
        return None
    probes = [
        ("/janus", "Janus WebRTC gateway"),
        ("/verto", "FreeSWITCH Verto WebRTC"),
        ("/asterisk/hep", "Asterisk HEP/WebRTC"),
        ("/api/v1/", "Generic WebRTC API"),
    ]
    for path, label in probes:
        status, _, body = _http_get(host, port, path, timeout, tls)
        if status in (200, 401) and any(
            kw in body.lower()
            for kw in ("janus", "verto", "webrtc", "websocket", "ice", "stun")
        ):
            return VulnFinding(
                name="WebRTC-Gateway-Exposed",
                severity="high",
                target=f"{host}:{port}",
                title=f"{label} API publicly reachable",
                evidence=(f"GET {path} → HTTP {status}; WebRTC gateway signature. "
                          f"WebRTC gateways can bridge SIP calls via browser; "
                          f"unauthenticated access allows eavesdropping or call "
                          f"injection through the WebSocket SIP channel."),
                remediation="Require API key authentication on the WebRTC gateway. "
                            "Bind to internal network only. Implement rate limiting.",
            )
    return None


def probe_snom_admin(host: str, port: int, tls: bool,
                     timeout: float = 3.0) -> VulnFinding | None:
    """Snom IP phone web interface (default creds: admin/admin)."""
    if port not in (80, 443):
        return None
    status, headers, body = _http_get(host, port, "/", timeout, tls)
    if status is None:
        return None
    blob = body + str(headers)
    if re.search(r"snom|phonesystem|settings\.htm", blob, re.I):
        return VulnFinding(
            name="Snom-Phone-UI-Exposed",
            severity="low",
            target=f"{host}:{port}",
            title="Snom IP phone web interface reachable",
            evidence=(f"GET / → HTTP {status}; Snom signature. "
                      f"Default creds admin/admin. SIP credentials visible in "
                      f"phone settings if authenticated."),
            remediation="Change admin password. Restrict web access to admin VLAN. "
                        "Disable HTTP admin if not needed (use HTTPS only).",
        )
    return None


def probe_cisco_phone_admin(host: str, port: int, tls: bool,
                             timeout: float = 3.0) -> VulnFinding | None:
    """Cisco IP Phone web interface — reveals SIP config + XML services."""
    if port not in (80, 443):
        return None
    for path in ("/", "/localmenus.cgi", "/CGI/Execute"):
        status, headers, body = _http_get(host, port, path, timeout, tls)
        if status is None:
            continue
        blob = body + str(headers)
        if re.search(r"cisco|callmanager|skinny|sccp|ip phone", blob, re.I):
            m = re.search(r"Cisco[^\d]*(79\d\d|88\d\d|68\d\d)", blob, re.I)
            model = m.group(1) if m else "Cisco IP Phone"
            return VulnFinding(
                name="Cisco-Phone-Web-UI-Exposed",
                severity="medium",
                target=f"{host}:{port}",
                title=f"Cisco {model} web interface reachable",
                evidence=(f"GET {path} → HTTP {status}; Cisco phone signature. "
                          f"Web UI exposes SIP proxy config, extension, and "
                          f"device XML services. CVE-2020-3111 (7800/8800 series RCE) "
                          f"may apply if firmware not patched."),
                remediation="Disable Cisco phone web access in CUCM/CME policy. "
                            "Apply firmware update. Use 802.1X for phone authentication.",
            )
    return None


ALL_PROBES: list[tuple[Callable, bool]] = [
    # (probe_fn, prefers_tls)
    (probe_freepbx_admin, False),
    (probe_asterisk_ari, False),
    (probe_asterisk_ari_default_creds, False),
    (probe_asterisk_server_header, False),
    (probe_ami_unauthenticated, False),   # only fires on port 5038/5039
    (probe_cucm_axl, True),
    (probe_3cx_webclient, True),
    (probe_grandstream, False),
    (probe_polycom, False),
    (probe_avaya_webLM, True),
    (probe_freepbx_rce_recording, False),
    # PhD-level additions
    (probe_freeswitch_default_creds, False),
    (probe_yealink_rce, False),
    (probe_sangoma_pbxact, False),
    (probe_opensips_mi, False),
    (probe_siptrunk_scan, False),
    (probe_webrtc_gateway, False),
    (probe_snom_admin, False),
    (probe_cisco_phone_admin, False),
]


def run_all(host: str, open_tcp_ports: list[int],
            timeout: float = 3.0) -> list[VulnFinding]:
    """Run every relevant probe against every plausibly-HTTP open TCP port.

    All (port × tls × probe) combinations fire concurrently so a 3s timeout
    per probe does not multiply across the matrix. Max 32 workers keeps the
    socket count sane even against large port lists.
    """
    skip = {5060, 5061, 5038, 4569, 1719, 1720, 2000, 2427, 2727}
    http_ports = sorted({p for p in open_tcp_ports if p not in skip})
    if not http_ports:
        return []

    # Build the full work list: (probe_fn, port, tls)
    work: list[tuple[Callable, int, bool]] = []
    for port in http_ports:
        tls_attempts = [True] if port in (443, 8443) else [False, True]
        for tls in tls_attempts:
            for probe_fn, _prefers_tls in ALL_PROBES:
                work.append((probe_fn, port, tls))

    findings: list[VulnFinding] = []
    seen: set[str] = set()
    lock = __import__("threading").Lock()

    def _run_probe(probe_fn: Callable, port: int, tls: bool) -> VulnFinding | None:
        try:
            return probe_fn(host, port, tls, timeout)
        except Exception:
            return None

    max_workers = min(32, len(work))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_run_probe, fn, port, tls): (fn, port, tls)
                for fn, port, tls in work}
        for fut in as_completed(futs):
            f = fut.result()
            if not f:
                continue
            key = f"{f.name}|{f.target}"
            with lock:
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)
            bus.emit("vuln.found", {
                "name": f.name, "severity": f.severity,
                "target": f.target, "title": f.title,
            })
    return findings
