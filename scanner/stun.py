"""Minimal STUN client (RFC 5389) — resolves public/mapped IP when behind NAT.

Only the Binding Request/Response exchange is implemented; enough to discover
the reflexive (NAT-translated) IP before sending SIP messages that embed a
local_ip in Via and Contact headers.

Public STUN servers work fine for this; the caller can also point at a
private STUN server with --stun <host[:port]>.
"""
from __future__ import annotations

import os
import socket
import struct

# ---- STUN constants -------------------------------------------------------
STUN_MAGIC   = 0x2112A442          # RFC 5389 magic cookie
STUN_BINDING = 0x0001               # Binding Request type
STUN_RESP    = 0x0101               # Binding Response (Success)
STUN_ATTR_XOR_MAPPED = 0x0020       # XOR-Mapped-Address (RFC 5389)
STUN_ATTR_MAPPED     = 0x0001       # Mapped-Address    (RFC 3489, fallback)

# Well-known public STUN servers (tried in order until one responds)
PUBLIC_STUN_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com",    19302),
    ("stun1.l.google.com",   19302),
    ("stun.cloudflare.com",  3478),
    ("stun.ekiga.net",       3478),
]


def _build_binding_request() -> tuple[bytes, bytes]:
    """Return (packet, transaction_id)."""
    tid = os.urandom(12)                         # 96-bit random transaction ID
    # 20-byte header: type(2) + length(2) + magic(4) + tid(12)
    pkt = struct.pack("!HHI", STUN_BINDING, 0, STUN_MAGIC) + tid
    return pkt, tid


def _parse_binding_response(data: bytes, tid: bytes) -> str | None:
    """Extract the reflexive IP from a STUN success response."""
    if len(data) < 20:
        return None
    msg_type, msg_len, magic = struct.unpack_from("!HHI", data, 0)
    resp_tid = data[8:20]
    if msg_type != STUN_RESP or magic != STUN_MAGIC or resp_tid != tid:
        return None

    # Walk TLV attributes
    pos = 20
    end = 20 + msg_len
    xor_ip: str | None = None
    mapped_ip: str | None = None

    while pos + 4 <= end and pos + 4 <= len(data):
        attr_type, attr_len = struct.unpack_from("!HH", data, pos)
        val = data[pos + 4: pos + 4 + attr_len]
        pos += 4 + attr_len
        if attr_len % 4:                         # 4-byte padding
            pos += 4 - (attr_len % 4)

        if attr_type == STUN_ATTR_XOR_MAPPED and len(val) >= 8:
            # XOR-Mapped-Address: family(1)pad(1)port⊕(magic>>16)(2)ip⊕magic(4)
            family = val[1]
            if family == 0x01:                   # IPv4 only
                raw_ip = struct.unpack_from("!I", val, 4)[0] ^ STUN_MAGIC
                xor_ip = socket.inet_ntoa(struct.pack("!I", raw_ip))

        elif attr_type == STUN_ATTR_MAPPED and len(val) >= 8:
            family = val[1]
            if family == 0x01:
                mapped_ip = socket.inet_ntoa(val[4:8])

    return xor_ip or mapped_ip


def resolve_public_ip(
    stun_server: str | None = None,
    stun_port: int = 3478,
    timeout: float = 3.0,
    retries: int = 2,
) -> str | None:
    """Return the public/reflexive IP visible from the STUN server, or None.

    stun_server: hostname or 'host:port'. If omitted, tries PUBLIC_STUN_SERVERS.
    """
    if stun_server:
        if ":" in stun_server:
            host_s, port_s = stun_server.rsplit(":", 1)
            servers = [(host_s, int(port_s))]
        else:
            servers = [(stun_server, stun_port)]
    else:
        servers = PUBLIC_STUN_SERVERS

    for host, port in servers:
        for _ in range(retries):
            try:
                pkt, tid = _build_binding_request()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                try:
                    s.sendto(pkt, (host, port))
                    data, _ = s.recvfrom(4096)
                finally:
                    s.close()
                ip = _parse_binding_response(data, tid)
                if ip:
                    return ip
            except (socket.timeout, OSError):
                continue

    return None
