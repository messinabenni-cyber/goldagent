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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import sip
from .utils import RateLimiter, local_ip_for


# Ports commonly running PBX management / SIP on internet-facing hosts.
# (proto, port, service_label, fingerprint_hint)
DEFAULT_PORTS: list[tuple[str, int, str]] = [
    ("udp", 5060,  "SIP"),
    ("tcp", 5060,  "SIP-TCP"),
    ("tcp", 5061,  "SIP-TLS"),
    ("tcp", 5038,  "Asterisk-AMI"),
    ("tcp", 80,    "HTTP"),
    ("tcp", 443,   "HTTPS"),
    ("tcp", 4443,  "FreePBX-HTTPS"),
    ("tcp", 8088,  "Asterisk-HTTP"),
    ("tcp", 8089,  "Grandstream-HTTPS"),
    ("tcp", 8443,  "PBX-HTTPS-alt"),
]


@dataclass
class HostResult:
    ip: str
    open_ports: list[dict] = field(default_factory=list)
    sip: dict | None = None    # OPTIONS response summary
    fingerprint: str = "unknown"


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------

def expand_target(spec: str) -> list[str]:
    """Expand a target spec into a list of IPs.

    Accepts:
      - Single IP:          10.0.0.1
      - CIDR:               10.0.0.0/24
      - Hostname:           pbx.example.com  → DNS resolved
      - file:               file:hosts.txt   → one host per line
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
    import ssl as _ssl
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


def probe_host(host: str, timeout: float = 2.0,
               traffic_log=None,
               extra_udp_ports: list[int] | None = None) -> HostResult | None:
    """Probe one host across all DEFAULT_PORTS + SIP OPTIONS. Returns None if
    no port/service responded.

    extra_udp_ports: additional UDP ports to SIP-probe (e.g. when the user
    specifies a non-standard --port on the CLI).
    """
    result = HostResult(ip=host)
    local_ip = local_ip_for(host)

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
                }
                result.fingerprint = fingerprint_banner(resp.server)
            continue

        # TCP
        banner = _tcp_probe(host, port, timeout)
        if banner is None:
            continue
        entry = {"port": port, "proto": "tcp", "service": service, "banner": banner[:200]}

        # Extract HTTP server header where applicable
        if port in (80, 443, 4443, 8088, 8089, 8443):
            http_text = _http_banner(host, port, timeout,
                                      use_tls=(port in (443, 4443, 8089, 8443)))
            entry["banner"] = http_text[:300]
            srv = re.search(r"(?i)^server\s*:\s*([^\r\n]+)", http_text, re.MULTILINE)
            if srv:
                entry["server"] = srv.group(1).strip()
        result.open_ports.append(entry)

    if not result.open_ports:
        return None
    if result.fingerprint == "unknown":
        # Fall back to HTTP server banner fingerprint
        for op in result.open_ports:
            if "server" in op:
                fp = fingerprint_banner(op["server"])
                if fp != "unknown":
                    result.fingerprint = fp
                    break
    return result


# ---------------------------------------------------------------------------
# PBX fingerprinting
# ---------------------------------------------------------------------------

PBX_SIGNATURES = [
    ("FreePBX",      re.compile(r"FreePBX", re.I)),
    ("Asterisk",     re.compile(r"Asterisk", re.I)),
    ("Grandstream",  re.compile(r"Grandstream|GXP|GXV|UCM|HT[0-9]|DP[0-9]", re.I)),
    ("Kamailio",     re.compile(r"Kamailio|OpenSER|SER", re.I)),
    ("OpenSIPS",     re.compile(r"OpenSIPS", re.I)),
    ("3CX",          re.compile(r"3CX", re.I)),
    ("FreeSWITCH",   re.compile(r"FreeSWITCH", re.I)),
]


def fingerprint_banner(banner: str) -> str:
    if not banner:
        return "unknown"
    for name, rx in PBX_SIGNATURES:
        if rx.search(banner):
            return name
    return "unknown"


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
) -> list[HostResult]:
    """Run probe_host concurrently over a target list. Returns hosts that
    responded on at least one port."""
    rate = RateLimiter(rate_per_second)
    results: list[HostResult] = []

    def _probe(host: str) -> HostResult | None:
        rate.wait()
        return probe_host(host, timeout=timeout, traffic_log=traffic_log,
                           extra_udp_ports=extra_udp_ports)

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
