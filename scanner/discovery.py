"""Host & port discovery + SIP OPTIONS fingerprinting.

Built for internet-facing PBX engagements:
  - Expand target spec (single IP / CIDR / hostname / hostlist file)
  - Scan known FreePBX / Asterisk / Grandstream ports
  - SIP OPTIONS probe to capture banner + Allow methods

Parallel via ThreadPoolExecutor — single-threaded would crawl on /24s.
"""
from __future__ import annotations

import ipaddress
import socket
import re
import ssl as _ssl
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from . import sip
from .utils import RateLimiter, local_ip_for


# Ports commonly running PBX management / SIP on internet-facing hosts.
# (proto, port, service_label)
DEFAULT_PORTS: list[tuple[str, int, str]] = [
    ("udp", 5060,  "SIP"),
    ("tcp", 5060,  "SIP-TCP"),
    ("tcp", 5061,  "SIP-TLS"),
    ("tcp", 5038,  "Asterisk-AMI"),
    ("tcp", 80,    "HTTP"),
    ("tcp", 443,   "HTTPS"),
    ("tcp", 4443,  "FreePBX-HTTPS"),
    ("tcp", 5000,  "3CX-SIP"),
    ("tcp", 5001,  "3CX-SIP-TLS"),
    ("tcp", 5090,  "SIP-alt"),
    ("tcp", 8080,  "HTTP-alt"),
    ("tcp", 8088,  "Asterisk-HTTP"),
    ("tcp", 8089,  "Grandstream-HTTPS"),
    ("tcp", 8443,  "PBX-HTTPS-alt"),
    ("tcp", 10000, "Asterisk-RTP-check"),
]


@dataclass
class HostResult:
    ip: str
    open_ports: list[dict] = field(default_factory=list)
    sip: dict | None = None    # OPTIONS response summary
    fingerprint: str = "unknown"
    version: str = ""
    rdns: str = ""
    ssl_cn: str = ""


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------

def expand_target(spec: str) -> list[str]:
    """Expand a target spec into a list of IPs.

    Accepts:
      - Single IP:          10.0.0.1
      - CIDR:               10.0.0.0/24
      - Dash range:         10.0.0.50-100  or  10.0.0.50-10.0.0.100
      - Hostname:           pbx.example.com  -> DNS resolved
      - file:               file:hosts.txt   -> one host per line
      - Comma-separated:    a, b, c
    """
    if spec.startswith("file:"):
        path = spec[5:]
        with open(path) as f:
            return [line.strip() for line in f
                    if line.strip() and not line.startswith("#")]

    if "," in spec:
        out: list[str] = []
        for part in spec.split(","):
            out.extend(expand_target(part.strip()))
        return out

    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return []

    # Dash range: 10.0.0.50-100  or  10.0.0.50-10.0.0.100
    if "-" in spec:
        parts = spec.split("-", 1)
        start_s, end_s = parts[0].strip(), parts[1].strip()
        try:
            start_ip = ipaddress.IPv4Address(start_s)
            # Short form: end is just the last octet
            if re.fullmatch(r'\d+', end_s):
                prefix = ".".join(str(start_ip).split(".")[:3])
                end_ip = ipaddress.IPv4Address(f"{prefix}.{end_s}")
            else:
                end_ip = ipaddress.IPv4Address(end_s)
            if int(end_ip) < int(start_ip):
                return []
            return [str(ipaddress.IPv4Address(i))
                    for i in range(int(start_ip), int(end_ip) + 1)]
        except (ipaddress.AddressValueError, ValueError):
            pass  # fall through to hostname resolution

    # Try resolving as hostname first; fall back to treating as IP literal
    try:
        return [socket.gethostbyname(spec)]
    except socket.gaierror:
        # Last resort: validate as IP, return as-is
        try:
            ipaddress.ip_address(spec)
            return [spec]
        except ValueError:
            return []


# ---------------------------------------------------------------------------
# Port probing
# ---------------------------------------------------------------------------

def _tcp_probe(host: str, port: int, timeout: float) -> str | None:
    """Return any banner bytes received, or "" for open-no-banner, None for closed."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # Some services chat first (HTTP doesn't, SIP-TCP doesn't, but try)
        s.settimeout(min(timeout, 0.5))
        try:
            data = s.recv(512)
            return data.decode("utf-8", errors="replace")[:300]
        except socket.timeout:
            return ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        s.close()


def _http_banner(host: str, port: int, timeout: float, use_tls: bool = False) -> str:
    """Send a minimal HTTP/1.0 GET and capture Server header for fingerprinting."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: VoIPScan/3.0\r\n\r\n"
            .encode()
        )
        chunks = b""
        while len(chunks) < 4096:
            try:
                d = s.recv(2048)
            except socket.timeout:
                break
            if not d:
                break
            chunks += d
        return chunks.decode("utf-8", errors="replace")
    except (socket.timeout, OSError, _ssl.SSLError):
        return ""
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------

# Pattern order matters: more specific patterns must come before generic ones.
_VERSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # FPBX-15.0.38(16.30.0) -> "FreePBX 15.0.38 / Asterisk 16.30.0"
    (re.compile(r"FPBX-(\d[\d.]+)\((\d[\d.]+)\)", re.I), "FreePBX {1} / Asterisk {2}"),
    # FreePBX 16.0.19
    (re.compile(r"FreePBX\s+(\d[\d.]+)", re.I), "FreePBX {1}"),
    # Asterisk PBX 18.12.1
    (re.compile(r"Asterisk(?:\s+PBX)?\s+(\d[\d.]+)", re.I), "Asterisk {1}"),
    # 3CXPhoneSystem 20.0 or 3CX 20.0
    (re.compile(r"3CXPhoneSystem\s+(\d[\d.]+)", re.I), "3CX {1}"),
    (re.compile(r"3CX\s+(\d[\d.]+)", re.I), "3CX {1}"),
]


def version_extract(banner: str) -> str | None:
    """Extract a human-readable version string from a SIP/HTTP server banner.

    Examples:
      "FPBX-15.0.38(16.30.0)"   -> "FreePBX 15.0.38 / Asterisk 16.30.0"
      "Asterisk PBX 18.12.1"    -> "Asterisk 18.12.1"
      "3CXPhoneSystem 20.0"     -> "3CX 20.0"
      "FreePBX 16.0.19"         -> "FreePBX 16.0.19"

    Returns None if no recognisable version is found.
    """
    if not banner:
        return None
    for pattern, template in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            result = template
            for i, group in enumerate(m.groups(), start=1):
                result = result.replace("{" + str(i) + "}", group)
            return result
    return None


# ---------------------------------------------------------------------------
# Reverse DNS lookup
# ---------------------------------------------------------------------------

def rdns_lookup(ip: str) -> str | None:
    """Perform a PTR record lookup for *ip*.

    Uses socket.gethostbyaddr with a 2-second timeout enforced via SIGALRM
    (Unix only) or a best-effort approach on other platforms.
    Returns the primary hostname string, or None on failure.
    """
    def _lookup() -> str | None:
        try:
            hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
            return hostname if hostname else None
        except (socket.herror, socket.gaierror, OSError):
            return None

    # Use SIGALRM for a hard 2-second timeout where available (Linux/macOS).
    try:
        def _handler(signum, frame):
            raise TimeoutError

        old_handler = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(2)
        try:
            return _lookup()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    except (AttributeError, ValueError):
        # SIGALRM not available (Windows); fall through without timeout.
        return _lookup()


# ---------------------------------------------------------------------------
# TLS certificate CN/SAN extraction
# ---------------------------------------------------------------------------

def ssl_cn_extract(host: str, port: int, timeout: float) -> str | None:
    """Connect TLS to *host*:*port* and return the certificate CN or SANs.

    SANs (dNSName entries) are preferred over the Common Name.
    Returns a comma-separated string of names, or None on any failure.
    """
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE  # Accept self-signed certs common on PBXes

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return None

                # Prefer SANs
                sans: list[str] = []
                for kind, value in cert.get("subjectAltName", []):
                    if kind.lower() == "dns":
                        sans.append(value)
                if sans:
                    return ", ".join(sans)

                # Fall back to CN from subject
                for rdn in cert.get("subject", []):
                    for key, value in rdn:
                        if key == "commonName":
                            return value
    except (socket.timeout, OSError, _ssl.SSLError, ConnectionRefusedError):
        pass
    return None


# ---------------------------------------------------------------------------
# PBX fingerprinting
# ---------------------------------------------------------------------------

PBX_SIGNATURES = [
    ("FreePBX",      re.compile(r"FreePBX|FPBX-", re.I)),
    ("Asterisk",     re.compile(r"Asterisk", re.I)),
    ("Grandstream",  re.compile(r"Grandstream|GXP|GXV|UCM|HT[0-9]|DP[0-9]", re.I)),
    ("Kamailio",     re.compile(r"Kamailio|OpenSER|SER", re.I)),
    ("OpenSIPS",     re.compile(r"OpenSIPS", re.I)),
    ("3CX",          re.compile(r"3CX|PhoneSystem|3CXPhoneSystem", re.I)),
    ("FreeSWITCH",   re.compile(r"FreeSWITCH", re.I)),
    ("Mitel",      re.compile(r"Mitel|MiVoice|MiCollab|5000HCP", re.I)),
    ("Sangoma",    re.compile(r"Sangoma|PBXact", re.I)),
    ("Avaya",      re.compile(r"Avaya|Aura|IPOffice", re.I)),
    ("Yealink",    re.compile(r"Yealink", re.I)),
    ("Cisco",      re.compile(r"Cisco|CUCM|SPA[0-9]", re.I)),
]


def fingerprint_banner(banner: str) -> str:
    if not banner:
        return "unknown"
    for name, rx in PBX_SIGNATURES:
        if rx.search(banner):
            return name
    return "unknown"


def version_from_banner(banner):
    if not banner:
        return ""
    m = re.search(r"FPBX-([\d.]+)\(([\d.]+)\)", banner, re.I)
    if m:
        return "FreePBX " + m.group(1) + " / Asterisk " + m.group(2)
    m = re.search(r"FreePBX[\s/]+([\d.]+)", banner, re.I)
    if m:
        return "FreePBX " + m.group(1)
    m = re.search(r"Asterisk[\s/]+([\d.]+)", banner, re.I)
    if m:
        return "Asterisk " + m.group(1)
    m = re.search(r"3CX[a-zA-Z]*/?( [\d.]+)", banner, re.I)
    if m:
        return "3CX " + m.group(1)
    m = re.search(r"(UCM\w+)\s+([\d.]+)", banner, re.I)
    if m:
        return "Grandstream " + m.group(1) + " " + m.group(2)
    return ""


# ---------------------------------------------------------------------------
# Host probe
# ---------------------------------------------------------------------------

# Ports that carry HTTPS (TLS-wrapped HTTP).
_HTTPS_PORTS: frozenset[int] = frozenset({443, 4443, 8443, 8089})

# Ports where we fetch HTTP(S) banners.
_HTTP_PROBE_PORTS: frozenset[int] = frozenset({80, 443, 4443, 8080, 8088, 8089, 8443})


def probe_host(host: str, timeout: float = 2.0,
               traffic_log=None,
               extra_udp_ports: list[int] | None = None,
               source_ip: str = "") -> HostResult | None:
    """Probe one host across all DEFAULT_PORTS + SIP OPTIONS. Returns None if
    no port/service responded.

    source_ip: if set, used as local_ip in SIP headers (e.g. STUN public IP).
    extra_udp_ports: additional UDP ports to SIP-probe (e.g. non-standard --port).
    """
    result = HostResult(ip=host)
    # local_ip for SIP headers: prefer caller-supplied public/reflexive IP
    local_ip = source_ip if source_ip else local_ip_for(host)

    ports_to_probe = list(DEFAULT_PORTS)
    if extra_udp_ports:
        existing_udp = {(proto, port) for proto, port, _ in ports_to_probe}
        for p in extra_udp_ports:
            if ("udp", p) not in existing_udp:
                ports_to_probe.append(("udp", p, f"SIP-alt-{p}"))

    for proto, port, service in ports_to_probe:
        if proto == "udp":
            # Use SIP OPTIONS as the "is it alive on UDP/5060" probe
            resp = sip.options_probe(host, port=port, local_ip=local_ip,
                                      timeout=timeout, traffic_log=traffic_log)
            if resp:
                result.open_ports.append({
                    "port": port, "proto": "udp", "service": service,
                    "status": resp.status_code,
                    "banner": resp.server[:200],
                })
                result.sip = {
                    "status": resp.status_code,
                    "reason": resp.reason,
                    "server": resp.server,
                    "allow": sip.parse_allowed_methods(resp),
                    "transport": "udp",
                }
                result.fingerprint = fingerprint_banner(resp.server)
                result.version = version_from_banner(resp.server)
                # Version from SIP banner
                if not result.version:
                    ver = version_extract(resp.server)
                    if ver:
                        result.version = ver
            continue

        # TCP
        banner = _tcp_probe(host, port, timeout)
        if banner is None:
            continue
        entry: dict = {"port": port, "proto": "tcp", "service": service,
                        "banner": banner[:200]}

        # Extract HTTP server header where applicable
        if port in _HTTP_PROBE_PORTS:
            use_tls = port in _HTTPS_PORTS
            http_text = _http_banner(host, port, timeout, use_tls=use_tls)
            entry["banner"] = http_text[:300]
            srv_m = re.search(r"(?i)^server\s*:\s*([^\r\n]+)", http_text, re.MULTILINE)
            if srv_m:
                srv_header = srv_m.group(1).strip()
                entry["server"] = srv_header
                # Fingerprint from HTTP Server header if SIP hasn't set one yet
                if result.fingerprint == "unknown":
                    fp = fingerprint_banner(srv_header)
                    if fp != "unknown":
                        result.fingerprint = fp
                # Version from HTTP Server header
                if not result.version:
                    ver = version_extract(srv_header)
                    if ver:
                        result.version = ver

            # TLS certificate CN/SAN
            if use_tls and not result.ssl_cn:
                cn = ssl_cn_extract(host, port, timeout)
                if cn:
                    result.ssl_cn = cn

        result.open_ports.append(entry)

    # --- TCP SIP fallback ---
    # If UDP gave no SIP response but TCP/5060 or TCP/5061 is open, try SIP/TCP
    # and SIP/TLS. Many internet-facing PBXes only accept SIP over TCP/TLS.
    if result.sip is None:
        for sip_port, use_tls in [(5060, False), (5061, True)]:
            if not any(p["port"] == sip_port and p["proto"] == "tcp"
                       for p in result.open_ports):
                continue
            transport = "tls" if use_tls else "tcp"
            resp = sip.options_probe(host, port=sip_port, local_ip=local_ip,
                                      timeout=timeout, traffic_log=traffic_log,
                                      tcp=True, use_tls=use_tls)
            if resp:
                result.sip = {
                    "status": resp.status_code,
                    "reason": resp.reason,
                    "server": resp.server,
                    "allow": sip.parse_allowed_methods(resp),
                    "transport": transport,
                }
                result.fingerprint = fingerprint_banner(resp.server)
                result.version = version_from_banner(resp.server)
                if not result.version:
                    ver = version_extract(resp.server)
                    if ver:
                        result.version = ver
                # Mark the TCP port as SIP
                for p in result.open_ports:
                    if p["port"] == sip_port and p["proto"] == "tcp":
                        p["service"] = f"SIP-{transport.upper()}"
                        p["status"] = resp.status_code
                        p["banner"] = resp.server[:200]
                break

    if not result.open_ports:
        return None

    if result.fingerprint == "unknown":
        # Fall back to HTTP server banner fingerprint
        for op in result.open_ports:
            if "server" in op:
                fp = fingerprint_banner(op["server"])
                if fp != "unknown":
                    result.fingerprint = fp
                    if not result.version:
                        ver = version_extract(op["server"])
                        if ver:
                            result.version = ver
                    break

    # rDNS lookup (always, regardless of whether SIP/HTTP responded)
    rdns = rdns_lookup(host)
    if rdns:
        result.rdns = rdns

    return result


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------

def sweep(
    targets: list[str],
    timeout: float = 2.0,
    rate_per_second: float = 50.0,
    workers: int = 32,
    traffic_log=None,
    extra_udp_ports: list[int] | None = None,
    source_ip: str = "",
) -> list[HostResult]:
    """Run probe_host concurrently over a target list. Returns hosts that
    responded on at least one port."""
    rate = RateLimiter(rate_per_second)
    results: list[HostResult] = []

    def _probe(host: str) -> HostResult | None:
        rate.wait()
        return probe_host(host, timeout=timeout, traffic_log=traffic_log,
                           extra_udp_ports=extra_udp_ports, source_ip=source_ip)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_probe, t): t for t in targets}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception:
                continue
    return sorted(results, key=lambda r: r.ip)
