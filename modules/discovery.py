"""Host + port discovery for VoIP services."""
from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import sip
from .events import bus
from .utils import RateLimiter, local_ip_for


# (name, port, proto, probe-kind)
VOIP_PORTS: list[tuple[str, int, str, str]] = [
    ("SIP",            5060, "udp", "sip-options"),
    ("SIP",            5060, "tcp", "tcp-connect"),
    ("SIPS",           5061, "tcp", "tcp-connect"),
    ("SIP-alt",        5070, "udp", "sip-options"),
    ("SIP-alt",        5080, "udp", "sip-options"),
    ("IAX2",           4569, "udp", "udp-connect"),
    ("H.323-CS",       1720, "tcp", "tcp-connect"),
    ("H.323-RAS",      1719, "udp", "udp-connect"),
    ("SCCP",           2000, "tcp", "tcp-connect"),
    ("MGCP-GW",        2427, "udp", "udp-connect"),
    ("MGCP-CA",        2727, "udp", "udp-connect"),
    ("Asterisk-AMI",   5038, "tcp", "tcp-connect"),
    ("FreePBX-HTTP",     80, "tcp", "http-banner"),
    ("FreePBX-HTTPS",   443, "tcp", "tcp-connect"),
    ("FreePBX-alt",    8080, "tcp", "tcp-connect"),
    ("TFTP-config",      69, "udp", "udp-connect"),  # phones pull configs
    # RFC 7118 — SIP over WebSocket (Asterisk, 3CX, Kamailio, FreeSWITCH)
    ("SIP-WS",         8088, "tcp", "tcp-connect"),  # Asterisk HTTP WS
    ("SIP-WSS",        8089, "tcp", "tcp-connect"),  # Asterisk HTTPS WS
    ("SIP-WSS-3CX",    5090, "tcp", "tcp-connect"),  # 3CX WebRTC gateway
    # Janus WebRTC / FreeSWITCH Verto / 3CX WebMeeting
    ("Janus-WS",       7188, "tcp", "tcp-connect"),
    ("Janus-WSS",      7189, "tcp", "tcp-connect"),
    ("Verto",          8081, "tcp", "tcp-connect"),  # FreeSWITCH Verto WS
    ("Verto-TLS",      8082, "tcp", "tcp-connect"),  # FreeSWITCH Verto WSS
    # Admin panels / REST APIs
    ("3CX-HTTPS",      5001, "tcp", "tcp-connect"),
    ("OpenSIPS-MI",    8888, "tcp", "tcp-connect"),
    ("FreeSwitch-ESL", 8021, "tcp", "tcp-connect"),
    # RTSP — IP cameras that double as SIP endpoints (e.g., Hikvision, Dahua)
    ("RTSP",            554, "tcp", "tcp-connect"),
]


@dataclass
class Host:
    ip: str
    open_ports: list[dict] = field(default_factory=list)  # {service, port, proto, banner}
    sip: dict | None = None  # populated by SIP OPTIONS probe


def expand_target(target: str) -> list[str]:
    """Accept IP, CIDR, or hostname; return a list of IPv4 strings."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 4096:
            raise ValueError(
                f"Refusing to expand {target} ({net.num_addresses} hosts). "
                "Narrow the scope or edit discovery.expand_target."
            )
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        try:
            return [socket.gethostbyname(target)]
        except socket.gaierror:
            return []


def _tcp_connect(ip: str, port: int, timeout: float) -> tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # Try a grab for HTTP; otherwise short read
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(512)
            return True, data.decode("utf-8", errors="replace").strip()
        except OSError:
            return True, ""
    except OSError:
        return False, ""
    finally:
        s.close()


def _udp_probe(ip: str, port: int, timeout: float, probe: bytes = b"\x00") -> str:
    """UDP is connectionless. Returns 'open' if we actually got data back,
    'maybe' on silence (open|filtered), 'closed' on ICMP unreachable."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(probe, (ip, port))
        try:
            s.recvfrom(4096)
            return "open"
        except socket.timeout:
            return "maybe"
        except OSError:
            return "closed"
    except OSError:
        return "closed"
    finally:
        s.close()


def scan_host(
    ip: str,
    ports: list[tuple[str, int, str, str]],
    timeout: float,
    rate: RateLimiter,
    traffic_log=None,
) -> Host:
    host = Host(ip=ip)
    local_ip = local_ip_for(ip)
    for service, port, proto, kind in ports:
        rate.wait()
        entry = {"service": service, "port": port, "proto": proto, "banner": ""}
        if kind == "tcp-connect" or kind == "http-banner":
            ok, banner = _tcp_connect(ip, port, timeout)
            if ok:
                entry["banner"] = banner[:256]
                host.open_ports.append(entry)
        elif kind == "udp-connect":
            state = _udp_probe(ip, port, timeout)
            if state == "open":
                entry["banner"] = "udp responded"
                host.open_ports.append(entry)
            # 'maybe'/'closed' are skipped — too noisy for UDP with no real probe
        elif kind == "sip-options":
            resp = sip.options_probe(
                ip, port, local_ip=local_ip, local_port=0, timeout=timeout,
                traffic_log=traffic_log,
            )
            if resp:
                entry["banner"] = f"{resp.status_code} {resp.reason} | {resp.server}"
                host.open_ports.append(entry)
                if host.sip is None:
                    host.sip = {
                        "status": resp.status_code,
                        "reason": resp.reason,
                        "server": resp.server,
                        "headers": resp.headers,
                    }
    return host


def sweep(
    targets: list[str],
    timeout: float,
    rate_per_second: float,
    workers: int = 16,
    traffic_log=None,
    ports: list | None = None,
) -> list[Host]:
    rate = RateLimiter(rate_per_second)
    ports = ports or VOIP_PORTS
    results: list[Host] = []
    bus.emit("discovery.start",
             {"targets": len(targets), "rate": rate_per_second})
    # Per-host wall-clock budget: port-list × per-probe timeout + 30 s headroom.
    # Guards against hangs when a host accepts TCP then never sends data.
    per_host_timeout = len(ports) * (timeout or 3.0) + 30

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(scan_host, ip, ports, timeout, rate, traffic_log): ip
            for ip in targets
        }
        for fut in as_completed(futs, timeout=per_host_timeout):
            try:
                h = fut.result()
            except Exception as e:
                h = Host(ip=futs[fut])
                h.open_ports.append({"service": "error", "port": 0, "proto": "",
                                     "banner": f"scan error: {e}"})
            # Only include a host if we have real evidence: SIP OPTIONS response,
            # any TCP banner, or a UDP port that actually returned data.
            has_evidence = bool(h.sip) or any(
                p["proto"] == "tcp" or p.get("banner") for p in h.open_ports
            )
            if has_evidence:
                results.append(h)
                bus.emit("discovery.host_found", {
                    "ip": h.ip,
                    "sip_server": (h.sip or {}).get("server", "") if h.sip else "",
                    "services": [
                        {"service": p["service"], "port": p["port"],
                         "proto": p["proto"]}
                        for p in h.open_ports
                    ],
                })
    bus.emit("discovery.done", {"hosts_found": len(results)})
    return sorted(results, key=lambda x: tuple(int(p) for p in x.ip.split(".")))
