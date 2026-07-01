"""NAT traversal — UPnP/IGD port mapping, NAT type detection, reflexive port tracking.

Automatically manoeuvres firewalls and NAT devices so the PBX can route SIP
responses (BYE ack, 200 OK to re-INVITE) back to the scanner through NAT.

Three techniques, applied in order of availability:
  1. UPnP/IGD — SSDP discovery + SOAP AddPortMapping punches a pinhole on the
     upstream router.  Works on ~90 % of home/SME routers.
  2. Reflexive port tracking — reads the external port from STUN rport so the
     scanner's Contact header advertises the NAT-translated port, not the
     ephemeral internal one (fixes "BYE not acknowledged" under port-preserving NAT).
  3. NAT type detection — classifies the topology; symmetric NAT triggers an
     automatic TCP transport upgrade since UPnP/STUN-port tricks do not help.

No external dependencies; UPnP uses raw SSDP multicast + SOAP over HTTP.
"""
from __future__ import annotations

import re
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Literal

NatType = Literal["direct", "full_cone", "restricted", "port_restricted", "symmetric", "unknown"]

_SSDP_ADDR  = "239.255.255.250"
_SSDP_PORT  = 1900
_SSDP_TTL   = 4
_IGD_ST     = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]

_STUN_MAGIC   = 0x2112A442
_STUN_BINDING = 0x0001
_STUN_RESP    = 0x0101
_ATTR_XOR_MAP = 0x0020
_ATTR_MAP     = 0x0001

_PUBLIC_STUN_PAIRS: list[tuple[str, int]] = [
    ("stun.l.google.com",   19302),
    ("stun1.l.google.com",  19302),
    ("stun.cloudflare.com", 3478),
    ("stun.ekiga.net",      3478),
]


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class NatContext:
    """NAT topology + active port mappings for this scan session."""
    local_ip:        str      = ""
    public_ip:       str      = ""
    nat_type:        NatType  = "unknown"
    upnp_available:  bool     = False
    upnp_control_url: str     = ""
    upnp_service_type: str    = ""
    # internal_port → external_port (UPnP mappings added this session)
    mapped_ports: dict[int, int] = field(default_factory=dict)
    # local_port → stun-reflexive_port
    reflexive_ports: dict[int, int] = field(default_factory=dict)
    setup_log: list[str] = field(default_factory=list)

    @property
    def is_behind_nat(self) -> bool:
        return bool(self.local_ip and self.public_ip and
                    self.local_ip != self.public_ip)

    @property
    def prefers_tcp(self) -> bool:
        return self.nat_type in ("symmetric", "port_restricted")

    def summary(self) -> str:
        parts = [f"NAT={self.nat_type}"]
        if self.local_ip:
            parts.append(f"local={self.local_ip}")
        if self.public_ip and self.public_ip != self.local_ip:
            parts.append(f"public={self.public_ip}")
        if self.upnp_available:
            n = len(self.mapped_ports)
            parts.append(f"UPnP=OK({n} mapped)" if n else "UPnP=OK")
        elif self.nat_type not in ("direct", "unknown"):
            parts.append("UPnP=unavail")
        return "  ".join(parts)


# ---------------------------------------------------------------------------
# STUN helpers (minimal — enough for NAT type + reflexive port)
# ---------------------------------------------------------------------------

def _stun_binding(host: str, port: int,
                  local_port: int = 0,
                  timeout: float = 2.5) -> tuple[str, int] | None:
    """Send STUN Binding Request; return (reflexive_ip, reflexive_port) or None."""
    import os as _os
    tid = _os.urandom(12)
    pkt = struct.pack("!HHI", _STUN_BINDING, 0, _STUN_MAGIC) + tid
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if local_port:
            try:
                s.bind(("", local_port))
            except OSError:
                s.bind(("", 0))
        else:
            s.bind(("", 0))
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(4096)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()

    if len(data) < 20:
        return None
    msg_type, msg_len, magic = struct.unpack_from("!HHI", data, 0)
    resp_tid = data[8:20]
    if msg_type != _STUN_RESP or magic != _STUN_MAGIC or resp_tid != tid:
        return None

    pos, end = 20, 20 + msg_len
    xor_res = mapped_res = None
    while pos + 4 <= end and pos + 4 <= len(data):
        atype, alen = struct.unpack_from("!HH", data, pos)
        val = data[pos + 4: pos + 4 + alen]
        pos += 4 + alen + (4 - alen % 4) % 4
        if atype == _ATTR_XOR_MAP and len(val) >= 8 and val[1] == 0x01:
            xport = struct.unpack_from("!H", val, 2)[0] ^ (_STUN_MAGIC >> 16)
            xip   = struct.unpack_from("!I", val, 4)[0] ^ _STUN_MAGIC
            xor_res = (socket.inet_ntoa(struct.pack("!I", xip)), xport)
        elif atype == _ATTR_MAP and len(val) >= 8 and val[1] == 0x01:
            mport = struct.unpack_from("!H", val, 2)[0]
            mip   = socket.inet_ntoa(val[4:8])
            mapped_res = (mip, mport)
    return xor_res or mapped_res


def get_reflexive_address(local_port: int = 0,
                          stun_server: str | None = None,
                          timeout: float = 2.5) -> tuple[str, int] | None:
    """Return (public_ip, public_port) for local_port via STUN, or None."""
    servers = []
    if stun_server:
        if ":" in stun_server:
            h, p = stun_server.rsplit(":", 1)
            servers = [(h, int(p))]
        else:
            servers = [(stun_server, 3478)]
    else:
        servers = _PUBLIC_STUN_PAIRS[:2]

    for host, port in servers:
        try:
            result = _stun_binding(host, port, local_port=local_port, timeout=timeout)
            if result:
                return result
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# NAT type detection
# ---------------------------------------------------------------------------

def detect_nat_type(timeout: float = 3.0) -> NatType:
    """Classify NAT type using two STUN transactions from the same socket.

    Simplified RFC 3489 test:
      - Test I:   Send to server A → get (ext_ip_A, ext_port_A)
      - Test II:  Send to server B from same local port → get (ext_ip_B, ext_port_B)
      - If ext_port_A != ext_port_B → symmetric NAT (different mapping per destination)
      - If ext_ip_A != local IP → behind NAT; classify as full_cone/restricted (pass)
      - If direct (ext_ip == local) → direct/no NAT
    """
    import os as _os
    if len(_PUBLIC_STUN_PAIRS) < 2:
        return "unknown"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind(("", 0))
        local_port = s.getsockname()[1]

        # Test I
        tid1 = _os.urandom(12)
        pkt1 = struct.pack("!HHI", _STUN_BINDING, 0, _STUN_MAGIC) + tid1
        h1, p1 = _PUBLIC_STUN_PAIRS[0]
        try:
            s.sendto(pkt1, (h1, p1))
            d1, _ = s.recvfrom(4096)
        except (socket.timeout, OSError):
            return "unknown"

        r1 = _parse_mapped(d1, tid1)
        if not r1:
            return "unknown"
        ext_ip1, ext_port1 = r1

        # Detect if behind NAT at all
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            local_ip = ""
        if ext_ip1 == local_ip:
            return "direct"

        # Test II — different STUN server from same socket
        tid2 = _os.urandom(12)
        pkt2 = struct.pack("!HHI", _STUN_BINDING, 0, _STUN_MAGIC) + tid2
        h2, p2 = _PUBLIC_STUN_PAIRS[1]
        try:
            s.sendto(pkt2, (h2, p2))
            d2, _ = s.recvfrom(4096)
        except (socket.timeout, OSError):
            return "restricted"   # can't confirm but not symmetric

        r2 = _parse_mapped(d2, tid2)
        if not r2:
            return "restricted"

        _, ext_port2 = r2

        if ext_port1 != ext_port2:
            return "symmetric"

        # Same external port on two different destinations → full_cone or restricted.
        # Full differentiation requires server-initiated packets (not available from
        # public STUN) — report as "restricted" which triggers TCP upgrade if needed.
        return "restricted"
    finally:
        s.close()


def _parse_mapped(data: bytes, tid: bytes) -> tuple[str, int] | None:
    if len(data) < 20:
        return None
    msg_type, msg_len, magic = struct.unpack_from("!HHI", data, 0)
    if msg_type != _STUN_RESP or magic != _STUN_MAGIC or data[8:20] != tid:
        return None
    pos, end = 20, 20 + msg_len
    xor_res = mapped_res = None
    while pos + 4 <= end and pos + 4 <= len(data):
        atype, alen = struct.unpack_from("!HH", data, pos)
        val = data[pos + 4: pos + 4 + alen]
        pos += 4 + alen + (4 - alen % 4) % 4
        if atype == _ATTR_XOR_MAP and len(val) >= 8 and val[1] == 0x01:
            xport = struct.unpack_from("!H", val, 2)[0] ^ (_STUN_MAGIC >> 16)
            xip   = struct.unpack_from("!I", val, 4)[0] ^ _STUN_MAGIC
            xor_res = (socket.inet_ntoa(struct.pack("!I", xip)), xport)
        elif atype == _ATTR_MAP and len(val) >= 8 and val[1] == 0x01:
            mport = struct.unpack_from("!H", val, 2)[0]
            mip   = socket.inet_ntoa(val[4:8])
            mapped_res = (mip, mport)
    return xor_res or mapped_res


# ---------------------------------------------------------------------------
# UPnP/IGD SSDP discovery + SOAP port mapping
# ---------------------------------------------------------------------------

def _ssdp_discover(st: str, timeout: float) -> list[str]:
    """Send SSDP M-SEARCH and collect Location headers from responding devices."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        f"ST: {st}\r\n"
        "MX: 2\r\n"
        "\r\n"
    ).encode()

    locations: list[str] = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, _SSDP_TTL)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (_SSDP_ADDR, _SSDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _ = s.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                m = re.search(r"(?i)location:\s*(\S+)", text)
                if m and m.group(1) not in locations:
                    locations.append(m.group(1))
            except socket.timeout:
                break
            except OSError:
                break
    finally:
        s.close()
    return locations


def _fetch_url(url: str, timeout: float = 5.0) -> str:
    """Fetch a URL and return its text body, or empty string on error."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def _safe_fetch_url(url, timeout=5.0):
    import urllib.parse as _up
    parsed = _up.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return ""
    try:
        host = parsed.hostname or ""
        ip = socket.gethostbyname(host)
        import ipaddress as _ipa
        addr = _ipa.ip_address(ip)
        if addr.is_loopback:
            return ""
    except Exception:
        pass
    return _fetch_url(url, timeout)


def _find_wan_service(location_url: str) -> tuple[str, str] | None:
    """Parse IGD device XML; return (control_url, service_type) for WAN*Connection."""
    xml = _safe_fetch_url(location_url)
    if not xml:
        return None

    base = "/".join(location_url.split("/")[:3])

    for stype in (
        "WANIPConnection:2", "WANIPConnection:1",
        "WANPPPConnection:1", "WANPPPConnection:2",
    ):
        pat = (
            rf"<serviceType>[^<]*{re.escape(stype)}[^<]*</serviceType>"
            r".*?<controlURL>([^<]+)</controlURL>"
        )
        m = re.search(pat, xml, re.DOTALL | re.IGNORECASE)
        if m:
            ctrl = m.group(1).strip()
            if not ctrl.startswith("http"):
                ctrl = base + ("" if ctrl.startswith("/") else "/") + ctrl
            full_stype = f"urn:schemas-upnp-org:service:{stype}"
            return ctrl, full_stype
    return None


def _soap_action(control_url: str, service_type: str,
                 action: str, args_xml: str, timeout: float = 5.0) -> str:
    """Send a SOAP action to a UPnP service control URL."""
    if not control_url.startswith(("http://", "https://")):
        return "blocked"
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{service_type}">'
        f"{args_xml}"
        f"</u:{action}>"
        "</s:Body>"
        "</s:Envelope>"
    )
    body_bytes = body.encode("utf-8")
    req = urllib.request.Request(
        control_url, data=body_bytes,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction":   f'"{service_type}#{action}"',
            "Content-Length": str(len(body_bytes)),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read().decode("utf-8", errors="replace")
        except Exception:
            return f"HTTP {e.code}"
    except Exception as exc:
        return str(exc)


def discover_upnp_gateway(timeout: float = 3.0) -> tuple[str, str] | None:
    """Return (control_url, service_type) for the first IGD found, or None."""
    for st in _IGD_ST:
        for loc in _ssdp_discover(st, timeout=min(timeout, 2.0)):
            result = _find_wan_service(loc)
            if result:
                return result
    return None


def add_port_mapping(
    control_url: str,
    service_type: str,
    internal_ip: str,
    internal_port: int,
    external_port: int,
    protocol: str = "UDP",
    description: str = "VoIPScan",
    duration: int = 3600,
) -> bool:
    """AddPortMapping via UPnP SOAP. Returns True on success."""
    args = (
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{external_port}</NewExternalPort>"
        f"<NewProtocol>{protocol.upper()}</NewProtocol>"
        f"<NewInternalPort>{internal_port}</NewInternalPort>"
        f"<NewInternalClient>{internal_ip}</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        f"<NewPortMappingDescription>{description}</NewPortMappingDescription>"
        f"<NewLeaseDuration>{duration}</NewLeaseDuration>"
    )
    resp = _soap_action(control_url, service_type, "AddPortMapping", args)
    return "errorCode" not in resp and "fault" not in resp.lower()


def delete_port_mapping(
    control_url: str,
    service_type: str,
    external_port: int,
    protocol: str = "UDP",
) -> bool:
    """DeletePortMapping via UPnP SOAP. Returns True on success."""
    args = (
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{external_port}</NewExternalPort>"
        f"<NewProtocol>{protocol.upper()}</NewProtocol>"
    )
    resp = _soap_action(control_url, service_type, "DeletePortMapping", args)
    return "errorCode" not in resp and "fault" not in resp.lower()


def get_external_ip(control_url: str, service_type: str) -> str | None:
    """GetExternalIPAddress via UPnP SOAP."""
    resp = _soap_action(control_url, service_type, "GetExternalIPAddress", "")
    m = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", resp)
    return m.group(1).strip() if m else None


# ---------------------------------------------------------------------------
# High-level setup
# ---------------------------------------------------------------------------

def setup(
    ports_to_map: list[int],
    local_ip: str = "",
    public_ip: str = "",
    stun_server: str | None = None,
    enable_upnp: bool = True,
    timeout: float = 3.0,
) -> NatContext:
    """Discover NAT topology and map scanner ports through UPnP if available.

    ports_to_map: list of UDP ports the scanner will listen on (SIP, SIP-alt).
    Returns a populated NatContext; always succeeds even if UPnP/STUN fail.
    """
    ctx = NatContext(local_ip=local_ip, public_ip=public_ip)
    log = ctx.setup_log

    # ── 1. NAT type detection ──────────────────────────────────────────────
    try:
        ctx.nat_type = detect_nat_type(timeout=timeout)
        log.append(f"NAT type detected: {ctx.nat_type}")
    except Exception as exc:
        log.append(f"NAT type detection failed: {exc}")

    # ── 2. Reflexive port tracking ─────────────────────────────────────────
    for lp in ports_to_map:
        try:
            ref = get_reflexive_address(local_port=lp, stun_server=stun_server,
                                         timeout=timeout)
            if ref:
                ctx.reflexive_ports[lp] = ref[1]
                if not ctx.public_ip:
                    ctx.public_ip = ref[0]
                log.append(f"Reflexive port for {lp}: {ref[0]}:{ref[1]}")
        except Exception as exc:
            log.append(f"Reflexive port probe for {lp} failed: {exc}")

    if not enable_upnp:
        return ctx

    # ── 3. UPnP/IGD discovery ─────────────────────────────────────────────
    try:
        gw = discover_upnp_gateway(timeout=timeout)
        if gw:
            ctx.upnp_available = True
            ctx.upnp_control_url, ctx.upnp_service_type = gw
            log.append(f"UPnP gateway found: {ctx.upnp_control_url}")

            # Prefer the UPnP-reported external IP if available
            try:
                upnp_ext = get_external_ip(ctx.upnp_control_url, ctx.upnp_service_type)
                if upnp_ext and upnp_ext != "0.0.0.0":
                    ctx.public_ip = upnp_ext
                    log.append(f"UPnP external IP: {upnp_ext}")
            except Exception:
                pass

            # Map each scanner port
            int_ip = ctx.local_ip or local_ip or _default_local_ip()
            for lp in ports_to_map:
                ext_port = ctx.reflexive_ports.get(lp, lp)  # prefer STUN-observed port
                ok = add_port_mapping(
                    ctx.upnp_control_url, ctx.upnp_service_type,
                    internal_ip=int_ip,
                    internal_port=lp,
                    external_port=ext_port,
                    protocol="UDP",
                    description="VoIPScan",
                    duration=7200,
                )
                if ok:
                    ctx.mapped_ports[lp] = ext_port
                    log.append(f"UPnP mapped UDP {int_ip}:{lp} → :{ext_port}")
                else:
                    log.append(f"UPnP mapping {lp} failed (may already exist)")
        else:
            log.append("UPnP: no IGD gateway discovered on local network")
    except Exception as exc:
        log.append(f"UPnP discovery failed: {exc}")

    return ctx


def teardown(ctx: NatContext) -> None:
    """Remove UPnP port mappings added during this session."""
    if not (ctx.upnp_available and ctx.upnp_control_url):
        return
    for lp, ext_port in list(ctx.mapped_ports.items()):
        try:
            delete_port_mapping(
                ctx.upnp_control_url, ctx.upnp_service_type,
                external_port=ext_port, protocol="UDP",
            )
        except Exception:
            pass
    ctx.mapped_ports.clear()


def _default_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
