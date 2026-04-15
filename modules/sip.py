"""SIP message construction + parsing + digest auth.

Deliberately minimal — enough for OPTIONS, REGISTER, INVITE, ACK, BYE. Not a
full stack. Uses UDP unless socktype=SOCK_STREAM is passed.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass, field

from .utils import md5hex, rand_branch, rand_call_id, rand_tag


SIP_VERSION = "SIP/2.0"
DEFAULT_USER_AGENT = "VoIPScan-Pro/2.0"  # more professional, less identifiable


def sha256hex(s: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class SipResponse:
    status_code: int
    reason: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: bytes = b""

    @property
    def server(self) -> str:
        return self.headers.get("server") or self.headers.get("user-agent", "")

    @property
    def is_auth_required(self) -> bool:
        return self.status_code in (401, 407)

    @property
    def auth_params(self) -> dict[str, str]:
        """Parse WWW-Authenticate or Proxy-Authenticate header."""
        h = self.headers.get("www-authenticate") or self.headers.get(
            "proxy-authenticate", ""
        )
        if not h:
            return {}
        # Strip the scheme ("Digest ")
        parts = h.split(" ", 1)
        if len(parts) != 2:
            return {}
        params: dict[str, str] = {}
        # param=value or param="value", comma-separated
        for m in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', parts[1]):
            key = m.group(1).lower()
            params[key] = m.group(2) if m.group(2) is not None else m.group(3)
        return params


def parse_response(data: bytes) -> SipResponse | None:
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        if not lines:
            return None
        status_line = lines[0]
        m = re.match(r"SIP/2\.0\s+(\d{3})\s*(.*)", status_line)
        if not m:
            return None
        code = int(m.group(1))
        reason = m.group(2).strip()
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return SipResponse(
            status_code=code,
            reason=reason,
            headers=headers,
            body=body.decode("utf-8", errors="replace"),
            raw=data,
        )
    except (UnicodeDecodeError, ValueError, AttributeError, IndexError):
        return None


def build_message(
    method: str,
    request_uri: str,
    from_user: str,
    to_user: str,
    host: str,
    port: int,
    local_ip: str,
    local_port: int,
    call_id: str,
    cseq: int,
    from_tag: str,
    to_tag: str | None = None,
    branch: str | None = None,
    auth_header: str | None = None,
    body: str = "",
    extra_headers: list[str] | None = None,
    user_agent: str = DEFAULT_USER_AGENT,
    transport: str = "UDP",
) -> bytes:
    branch = branch or rand_branch()
    # Validate port to prevent socket errors from bad config
    if not (1 <= port <= 65535):
        raise ValueError(f"SIP port out of range: {port}")
    # Guard against header injection via auth_header
    if auth_header and ("\r" in auth_header or "\n" in auth_header):
        raise ValueError("auth_header contains invalid CR/LF characters")
    # Select the correct Via transport token (RFC 3261 §20.42)
    transport_upper = transport.upper()
    if transport_upper == "TLS":
        via_transport = "SIP/2.0/TLS"
    elif transport_upper == "TCP":
        via_transport = "SIP/2.0/TCP"
    else:
        via_transport = "SIP/2.0/UDP"
    lines = [
        f"{method} {request_uri} {SIP_VERSION}",
        f"Via: {via_transport} {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        # RFC 3261 §8.1.1.1: From/To use the domain (realm), not local IP.
        # This ensures the AoR looks like ext@pbx-host which PBXes expect.
        f"From: <sip:{from_user}@{host}>;tag={from_tag}",
        f"To: <sip:{to_user}@{host}>" + (f";tag={to_tag}" if to_tag else ""),
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        f"Contact: <sip:{from_user}@{local_ip}:{local_port};rport>",
        f"User-Agent: {user_agent}",
    ]
    if auth_header:
        lines.append(auth_header)
    if extra_headers:
        lines.extend(extra_headers)
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    msg = "\r\n".join(lines) + "\r\n" + body
    return msg.encode("utf-8")


def build_auth_header(
    username: str,
    password: str,
    method: str,
    uri: str,
    params: dict[str, str],
    header_name: str = "Authorization",
) -> str:
    """Build Digest auth header. Supports qop=auth (with cnonce/nc) and no qop.

    Supported algorithms (RFC 2617 + RFC 7616):
      MD5, MD5-SESS, SHA-256, SHA-256-SESS
    """
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    algorithm = params.get("algorithm", "MD5").upper()
    qop = params.get("qop", "")
    opaque = params.get("opaque")

    if algorithm not in ("MD5", "MD5-SESS", "SHA-256", "SHA-256-SESS"):
        raise ValueError(
            f"Server requires {algorithm} digest auth — only MD5 and SHA-256 are "
            "supported. Upgrade to a library that implements the required algorithm "
            "or manually configure credentials."
        )

    # Choose hash function based on algorithm family (RFC 7616 §4)
    use_sha256 = "SHA-256" in algorithm

    if use_sha256:
        _hex = sha256hex
    else:
        _hex = md5hex

    nc = "00000001"
    # RFC 7616 §3.1: cnonce must be cryptographically unpredictable.
    # 16 bytes from os.urandom → 128 bits entropy, encoded as 32 hex chars.
    import os as _os
    cnonce = _os.urandom(16).hex()

    # Compute HA1 — for *-SESS variants fold in nonce + cnonce (RFC 2617 §3.2.2.2)
    ha1_base = _hex(f"{username}:{realm}:{password}")
    if algorithm in ("MD5-SESS", "SHA-256-SESS"):
        ha1 = _hex(f"{ha1_base}:{nonce}:{cnonce}")
    else:
        ha1 = ha1_base

    ha2 = _hex(f"{method}:{uri}")

    # RFC 2617 §1.2 allows "qop=auth, auth-int" with whitespace; strip each token
    if "auth" in [q.strip() for q in qop.split(",")]:
        qop_used = "auth"
        response = _hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop_used}:{ha2}")
    else:
        qop_used = ""
        response = _hex(f"{ha1}:{nonce}:{ha2}")

    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f'algorithm={algorithm}',
    ]
    if qop_used:
        parts += [f'qop={qop_used}', f'nc={nc}', f'cnonce="{cnonce}"']
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return f"{header_name}: Digest " + ", ".join(parts)


def send_and_recv(
    datagram: bytes,
    host: str,
    port: int,
    local_port: int,
    timeout: float = 3.0,
    recv_size: int = 65535,
    traffic_log=None,
) -> bytes | None:
    """Send a UDP SIP datagram, return first response or None on timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind(("", local_port))
    except OSError:
        s.bind(("", 0))
        local_port = s.getsockname()[1]
    try:
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", datagram)
        s.sendto(datagram, (host, port))
        data, _ = s.recvfrom(recv_size)
        if traffic_log:
            traffic_log.log("IN", f"{host}:{port}", data)
        return data
    except socket.timeout:
        return None
    except OSError:
        return None
    finally:
        s.close()


def send_and_recv_tcp(
    message: bytes,
    host: str,
    port: int,
    timeout: float = 5.0,
    use_tls: bool = False,
    recv_size: int = 65535,
    traffic_log=None,
) -> bytes | None:
    """Send a SIP message over TCP or TLS, return first response.

    SIP over TCP uses stream framing — a complete response is delimited by
    the double CRLF separating headers from body.  After finding the header
    boundary we read the number of bytes specified by Content-Length (if
    present) so the full message is returned.
    """
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    try:
        raw_sock.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            # Allow self-signed certs common on PBX equipment — the caller can
            # pass a stricter context if needed by wrapping the socket themselves.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", message)

        sock.sendall(message)

        # Accumulate data until we have a complete SIP response.
        # A complete response requires at minimum the double CRLF header
        # terminator.  Once found, honour Content-Length for the body.
        buf = b""
        while True:
            try:
                chunk = sock.recv(recv_size)
            except socket.timeout:
                break
            if not chunk:
                # Remote closed the connection
                break
            buf += chunk

            # Look for end of headers
            header_end = buf.find(b"\r\n\r\n")
            if header_end == -1:
                # Haven't received full headers yet
                continue

            # Extract Content-Length from the headers we have so far
            headers_raw = buf[:header_end].decode("utf-8", errors="replace")
            cl_match = re.search(
                r"(?i)^content-length\s*:\s*(\d+)", headers_raw, re.MULTILINE
            )
            if cl_match:
                content_length = int(cl_match.group(1))
            else:
                content_length = 0

            body_start = header_end + 4  # skip \r\n\r\n
            body_received = len(buf) - body_start
            if body_received >= content_length:
                # We have the full response
                break
            # else: keep reading body bytes

        if traffic_log and buf:
            traffic_log.log("IN", f"{host}:{port}", buf)

        return buf if buf else None

    except (socket.timeout, OSError, ssl.SSLError):
        return None
    finally:
        raw_sock.close()


def options_probe(
    host: str,
    port: int = 5060,
    local_ip: str | None = None,
    local_port: int = 5062,
    timeout: float = 3.0,
    traffic_log=None,
) -> SipResponse | None:
    """Send a SIP OPTIONS request — standard, unauthenticated probe.

    The response may include an Allow: header listing supported methods
    (INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, INFO, REFER, SUBSCRIBE,
    NOTIFY, PRACK, UPDATE, MESSAGE) — useful for PBX capability mapping.
    """
    if not local_ip:
        from .utils import local_ip_for
        local_ip = local_ip_for(host)
    call_id = rand_call_id()
    tag = rand_tag()
    msg = build_message(
        "OPTIONS",
        f"sip:{host}",
        from_user="scanner",
        to_user="scanner",
        host=host,
        port=port,
        local_ip=local_ip,
        local_port=local_port,
        call_id=call_id,
        cseq=1,
        from_tag=tag,
        extra_headers=["Accept: application/sdp", "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER"],
    )
    data = send_and_recv(msg, host, port, local_port, timeout, traffic_log=traffic_log)
    if not data:
        return None
    return parse_response(data)


def parse_allowed_methods(resp: "SipResponse") -> list[str]:
    """Extract supported SIP methods from the Allow header (or Allow-Events)."""
    allow = resp.headers.get("allow", "")
    if not allow:
        return []
    return [m.strip().upper() for m in allow.split(",") if m.strip()]


def subscribe_probe(
    host: str,
    ext: str,
    event_type: str = "message-summary",
    port: int = 5060,
    local_ip: str | None = None,
    timeout: float = 3.0,
    traffic_log=None,
) -> SipResponse | None:
    """Send a SIP SUBSCRIBE request to detect presence/voicemail status.

    Useful for passive extension enumeration — a 200 or 202 means the
    extension exists and the PBX supports presence (RFC 6665).
    A 489 Bad Event means extension exists but event unsupported.
    A 404 means no such extension.

    Common event types:
      message-summary  — MWI (Message Waiting Indicator), RFC 3842
      presence         — User presence status, RFC 3856
      dialog           — Dialog/call state, RFC 4235
    """
    if not local_ip:
        from .utils import local_ip_for
        local_ip = local_ip_for(host)
    call_id = rand_call_id()
    tag = rand_tag()
    msg = build_message(
        "SUBSCRIBE",
        f"sip:{ext}@{host}",
        from_user=ext,
        to_user=ext,
        host=host,
        port=port,
        local_ip=local_ip,
        local_port=0,
        call_id=call_id,
        cseq=1,
        from_tag=tag,
        extra_headers=[
            f"Event: {event_type}",
            "Expires: 0",
            f"Accept: application/simple-message-summary",
        ],
    )
    data = send_and_recv(msg, host, port, 0, timeout, traffic_log=traffic_log)
    if not data:
        return None
    return parse_response(data)


def message_probe(
    host: str,
    ext: str,
    body_text: str = "VoIPScan assessment",
    port: int = 5060,
    local_ip: str | None = None,
    timeout: float = 3.0,
    traffic_log=None,
) -> SipResponse | None:
    """Send a SIP MESSAGE (instant message, RFC 3428) to probe extension.

    A 200/202 confirms the extension exists and accepts IM.
    A 404 confirms extension does not exist.
    A 405 Method Not Allowed means MESSAGE unsupported (but SIP is live).
    """
    if not local_ip:
        from .utils import local_ip_for
        local_ip = local_ip_for(host)
    call_id = rand_call_id()
    tag = rand_tag()
    msg = build_message(
        "MESSAGE",
        f"sip:{ext}@{host}",
        from_user=ext,
        to_user=ext,
        host=host,
        port=port,
        local_ip=local_ip,
        local_port=0,
        call_id=call_id,
        cseq=1,
        from_tag=tag,
        extra_headers=["Content-Type: text/plain"],
        body=body_text,
    )
    data = send_and_recv(msg, host, port, 0, timeout, traffic_log=traffic_log)
    if not data:
        return None
    return parse_response(data)
