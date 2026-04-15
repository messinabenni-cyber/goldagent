"""RFC 5389 STUN client — discover external NAT address and port.

Used to determine the public-facing IP and port when the tool is run from
behind NAT.  All logic is pure stdlib; no third-party dependencies.

Typical usage::

    from modules.stun import discover_external_address, get_public_ip

    addr = discover_external_address()   # -> ("1.2.3.4", 54321) or None
    ip   = get_public_ip()               # -> "1.2.3.4" or None

Thread safety
-------------
No module-level mutable state is used.  Every function creates and tears
down its own socket, so multiple threads may call these functions concurrently
without interference.
"""
from __future__ import annotations

import os
import random
import socket
import struct
from typing import Optional

# ---------------------------------------------------------------------------
# RFC 5389 constants
# ---------------------------------------------------------------------------

_MAGIC_COOKIE: int = 0x2112A442          # mandatory per §6
_BINDING_REQUEST: int = 0x0001
_BINDING_RESPONSE_SUCCESS: int = 0x0101
_BINDING_RESPONSE_ERROR: int = 0x0111

# Attribute types (§15)
_ATTR_MAPPED_ADDRESS: int = 0x0001
_ATTR_XOR_MAPPED_ADDRESS: int = 0x0020

# Address family
_FAMILY_IPV4: int = 0x01

# Default STUN servers tried in order
_DEFAULT_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com", 3478),
    ("stun1.l.google.com", 3478),
    ("stun.cloudflare.com", 3478),
]

# STUN message header: type(2) + length(2) + magic(4) + transaction-id(12)
_HEADER_FMT = "!HHI12s"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 20 bytes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_binding_request() -> tuple[bytes, bytes]:
    """Return (raw_packet, transaction_id).

    The transaction ID is 12 random bytes generated with os.urandom so it is
    cryptographically unpredictable, satisfying the RFC §6 requirement that
    each request have a unique transaction ID.
    """
    transaction_id: bytes = os.urandom(12)
    # Message type + length (0 attrs) + magic cookie + transaction ID
    packet = struct.pack(
        _HEADER_FMT,
        _BINDING_REQUEST,
        0,                    # length — no attributes in a Binding Request
        _MAGIC_COOKIE,
        transaction_id,
    )
    return packet, transaction_id


def _parse_mapped_address(data: bytes) -> Optional[tuple[str, int]]:
    """Parse a MAPPED-ADDRESS attribute value (§15.1).

    The value layout is: 1-byte zero, 1-byte family, 2-byte port, 4-byte IPv4.
    Returns (ip_str, port) or None if the data is malformed.
    """
    if len(data) < 8:
        return None
    _reserved, family, port = struct.unpack("!BBH", data[:4])
    if family != _FAMILY_IPV4:
        return None  # IPv6 not handled in this tool
    ip_bytes = data[4:8]
    if len(ip_bytes) < 4:
        return None
    ip_str = socket.inet_ntoa(ip_bytes)
    return ip_str, port


def _parse_xor_mapped_address(data: bytes, transaction_id: bytes) -> Optional[tuple[str, int]]:
    """Parse an XOR-MAPPED-ADDRESS attribute value (§15.2).

    Port is XOR-ed with the high 16 bits of the magic cookie.
    IPv4 address is XOR-ed with the magic cookie (big-endian 32-bit).
    Returns (ip_str, port) or None if the data is malformed.
    """
    if len(data) < 8:
        return None
    _reserved, family, x_port = struct.unpack("!BBH", data[:4])
    if family != _FAMILY_IPV4:
        return None
    port = x_port ^ (_MAGIC_COOKIE >> 16)
    x_addr_bytes = data[4:8]
    if len(x_addr_bytes) < 4:
        return None
    x_addr_int = struct.unpack("!I", x_addr_bytes)[0]
    addr_int = x_addr_int ^ _MAGIC_COOKIE
    ip_str = socket.inet_ntoa(struct.pack("!I", addr_int))
    return ip_str, port


def _parse_attributes(
    payload: bytes,
    transaction_id: bytes,
) -> Optional[tuple[str, int]]:
    """Walk the TLV attribute list and return the first usable mapped address.

    XOR-MAPPED-ADDRESS is preferred over MAPPED-ADDRESS when both are present,
    but we return as soon as we find a valid XOR-MAPPED-ADDRESS and fall back to
    any valid MAPPED-ADDRESS encountered along the way.
    """
    fallback: Optional[tuple[str, int]] = None
    offset = 0
    while offset + 4 <= len(payload):
        attr_type, attr_len = struct.unpack("!HH", payload[offset: offset + 4])
        offset += 4
        attr_value = payload[offset: offset + attr_len]
        # Attributes are padded to 4-byte boundaries; skip padding
        padded_len = (attr_len + 3) & ~3
        offset += padded_len

        if attr_type == _ATTR_XOR_MAPPED_ADDRESS:
            result = _parse_xor_mapped_address(attr_value, transaction_id)
            if result is not None:
                return result  # prefer XOR variant; return immediately
        elif attr_type == _ATTR_MAPPED_ADDRESS:
            if fallback is None:
                fallback = _parse_mapped_address(attr_value)

    return fallback


def _send_binding_request(
    host: str,
    port: int,
    timeout: float,
) -> Optional[tuple[str, int]]:
    """Send a single STUN Binding Request to *host:port* and parse the reply.

    Creates its own UDP socket; resolves the host; sends the request; waits up
    to *timeout* seconds for a response.  Returns (ip, port) or None.

    Raises no exceptions — all socket/network errors are caught and logged only
    in debug mode.  Callers should treat None as "this server did not respond."
    """
    packet, transaction_id = _build_binding_request()

    try:
        resolved = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror:
        return None

    if not resolved:
        return None

    _family, _type, _proto, _canonname, sockaddr = resolved[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, sockaddr)
        response, _addr = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()

    # Minimum valid response is 20-byte header
    if len(response) < _HEADER_SIZE:
        return None

    msg_type, msg_len, magic, resp_txid = struct.unpack_from(_HEADER_FMT, response)

    # Verify this is a success response for our transaction
    if msg_type != _BINDING_RESPONSE_SUCCESS:
        return None
    if magic != _MAGIC_COOKIE:
        return None
    if resp_txid != transaction_id:
        return None

    payload = response[_HEADER_SIZE: _HEADER_SIZE + msg_len]
    return _parse_attributes(payload, transaction_id)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_external_address(
    stun_host: str = "stun.l.google.com",
    stun_port: int = 3478,
    timeout: float = 3.0,
) -> Optional[tuple[str, int]]:
    """Discover this host's external (post-NAT) IP address and UDP port.

    Sends an RFC 5389 STUN Binding Request to *stun_host:stun_port* and
    parses the XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS attribute
    from the response.

    Parameters
    ----------
    stun_host:
        Hostname of the STUN server to query.  Defaults to
        ``stun.l.google.com`` (Google's public STUN server).
    stun_port:
        UDP port of the STUN server.  Defaults to 3478 (standard STUN port).
    timeout:
        Socket receive timeout in seconds.  Defaults to 3.0.

    Returns
    -------
    tuple[str, int]
        ``(external_ip, external_port)`` as seen by the STUN server, or
        ``None`` if the server could not be reached or returned an error.

    Notes
    -----
    - The local UDP port chosen by the OS for this call will be reflected back
      as *external_port*, so it represents the NAT mapping for *this specific
      ephemeral socket*, not a stable port.
    - Thread-safe: each call creates and destroys its own socket.
    """
    return _send_binding_request(stun_host, stun_port, timeout)


def discover_external_address_multi(
    servers: list[tuple[str, int]] | None = None,
    timeout: float = 3.0,
) -> Optional[tuple[str, int]]:
    """Try multiple STUN servers in order, returning the first success.

    Parameters
    ----------
    servers:
        List of ``(host, port)`` tuples to try.  Defaults to the built-in
        list: ``stun.l.google.com:3478``, ``stun1.l.google.com:3478``,
        ``stun.cloudflare.com:3478``.
    timeout:
        Per-server socket timeout in seconds.

    Returns
    -------
    tuple[str, int] | None
        Result from the first responsive server, or ``None`` if all fail.
    """
    if servers is None:
        servers = list(_DEFAULT_SERVERS)

    for host, port in servers:
        result = _send_binding_request(host, port, timeout)
        if result is not None:
            return result
    return None


def get_public_ip(timeout: float = 3.0) -> Optional[str]:
    """Return this host's public (post-NAT) IPv4 address, or None on failure.

    Tries the default STUN server list in order:
    ``stun.l.google.com:3478``, ``stun1.l.google.com:3478``,
    ``stun.cloudflare.com:3478``.

    Parameters
    ----------
    timeout:
        Per-server socket timeout in seconds.

    Returns
    -------
    str | None
        The public IPv4 address string (e.g. ``"203.0.113.42"``), or
        ``None`` if no STUN server responded successfully.

    Example
    -------
    ::

        ip = get_public_ip()
        if ip:
            print(f"Public IP: {ip}")
        else:
            print("Could not determine public IP via STUN")
    """
    result = discover_external_address_multi(timeout=timeout)
    return result[0] if result is not None else None
