"""SIP message construction, parsing, and digest auth.

Deliberately minimal — enough for OPTIONS, REGISTER, INVITE, ACK, BYE,
CANCEL, INFO, SUBSCRIBE, MESSAGE. Not a full stack.

Identity headers (PAI / Diversion / Privacy / Remote-Party-ID / from_display)
are first-class on every builder — they're the toll-fraud spoof primitives.
All caller-supplied header values are CRLF-injection guarded before emission.
"""
from __future__ import annotations

import hmac
import os
import re
import socket
import ssl
from dataclasses import dataclass, field

from .utils import md5hex, rand_branch, rand_call_id, rand_tag, sha256hex


DEFAULT_UA = "VoIPScan/3.0"
SIP_VERSION = "SIP/2.0"

# RFC 3323 §4.2 valid Privacy tokens
PRIVACY_TOKENS = {"id", "header", "session", "user", "none", "critical", "history"}


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

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
        h = (self.headers.get("www-authenticate")
             or self.headers.get("proxy-authenticate", ""))
        if not h:
            return {}
        parts = h.split(" ", 1)
        if len(parts) != 2:
            return {}
        params: dict[str, str] = {}
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
        m = re.match(r"SIP/2\.0\s+(\d{3})\s*(.*)", lines[0])
        if not m:
            return None
        code = int(m.group(1))
        reason = m.group(2).strip()
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return SipResponse(code, reason, headers,
                           body.decode("utf-8", errors="replace"), data)
    except (UnicodeDecodeError, ValueError, AttributeError, IndexError):
        return None


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------

def _no_crlf(value: str, label: str) -> None:
    if value and ("\r" in value or "\n" in value):
        raise ValueError(f"{label} contains invalid CR/LF characters")


def _wrap_uri(value: str) -> str:
    """Return value as an angle-bracketed URI. Idempotent."""
    if "<" in value:
        return value
    return f"<{value}>" if value.startswith("sip:") else f"<sip:{value}>"


def build_message(
    method: str,
    request_uri: str,
    *,
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
    user_agent: str = DEFAULT_UA,
    transport: str = "UDP",
    # Identity / spoof primitives (toll-fraud demos)
    pai: str | None = None,
    diversion: str | None = None,
    privacy: str | None = None,
    remote_party_id: str | None = None,
    from_display: str | None = None,
) -> bytes:
    """Build a SIP request as UTF-8 bytes."""
    if not (1 <= port <= 65535):
        raise ValueError(f"SIP port out of range: {port}")

    # CRLF guards on every caller-supplied header value
    for name, value in [
        ("auth_header", auth_header or ""),
        ("pai", pai or ""),
        ("diversion", diversion or ""),
        ("privacy", privacy or ""),
        ("remote_party_id", remote_party_id or ""),
        ("from_display", from_display or ""),
    ]:
        _no_crlf(value, name)

    # Privacy token validation (RFC 3323)
    if privacy:
        tokens = [t.strip().lower() for t in privacy.split(";") if t.strip()]
        bad = [t for t in tokens if t not in PRIVACY_TOKENS]
        if bad:
            raise ValueError(
                f"Invalid Privacy token(s): {bad}. "
                f"Must be from {sorted(PRIVACY_TOKENS)} per RFC 3323."
            )

    branch = branch or rand_branch()
    transport_upper = transport.upper()
    via_transport = {
        "TLS": "SIP/2.0/TLS",
        "TCP": "SIP/2.0/TCP",
    }.get(transport_upper, "SIP/2.0/UDP")

    # From header — display name must have quotes + backslashes escaped
    if from_display:
        safe_display = from_display.replace("\\", "\\\\").replace('"', '\\"')
        from_hdr = f'From: "{safe_display}" <sip:{from_user}@{host}>;tag={from_tag}'
    else:
        from_hdr = f"From: <sip:{from_user}@{host}>;tag={from_tag}"

    to_hdr = f"To: <sip:{to_user}@{host}>"
    if to_tag:
        to_hdr += f";tag={to_tag}"

    lines = [
        f"{method} {request_uri} {SIP_VERSION}",
        f"Via: {via_transport} {local_ip}:{local_port};branch={branch};rport",
        "Max-Forwards: 70",
        from_hdr,
        to_hdr,
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        f"Contact: <sip:{from_user}@{local_ip}:{local_port};rport>",
        f"User-Agent: {user_agent}",
    ]
    if pai:
        lines.append(f"P-Asserted-Identity: {_wrap_uri(pai)}")
    if remote_party_id:
        lines.append(f"Remote-Party-ID: {_wrap_uri(remote_party_id)}")
    if diversion:
        lines.append(f"Diversion: {_wrap_uri(diversion)}")
    if privacy:
        lines.append(f"Privacy: {privacy}")
    if auth_header:
        lines.append(auth_header)
    if extra_headers:
        lines.extend(extra_headers)
    if body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("")

    return ("\r\n".join(lines) + "\r\n" + body).encode("utf-8")


# ---------------------------------------------------------------------------
# Digest authentication (RFC 2617 + RFC 7616)
# ---------------------------------------------------------------------------

def build_auth_header(
    username: str,
    password: str,
    method: str,
    uri: str,
    params: dict[str, str],
    header_name: str = "Authorization",
) -> str:
    """Build Digest auth response. Supports MD5, MD5-SESS, SHA-256, SHA-256-SESS."""
    realm = params.get("realm", "")
    nonce = params.get("nonce", "")
    algorithm = params.get("algorithm", "MD5").upper()
    qop = params.get("qop", "")
    opaque = params.get("opaque")

    if algorithm not in ("MD5", "MD5-SESS", "SHA-256", "SHA-256-SESS"):
        raise ValueError(
            f"Unsupported digest algorithm: {algorithm}. "
            "Supported: MD5, MD5-SESS, SHA-256, SHA-256-SESS."
        )

    _hex = sha256hex if "SHA-256" in algorithm else md5hex
    cnonce = os.urandom(16).hex()
    nc = "00000001"

    ha1_base = _hex(f"{username}:{realm}:{password}")
    ha1 = _hex(f"{ha1_base}:{nonce}:{cnonce}") if "SESS" in algorithm else ha1_base
    ha2 = _hex(f"{method}:{uri}")

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
        f"algorithm={algorithm}",
    ]
    if qop_used:
        parts += [f"qop={qop_used}", f"nc={nc}", f'cnonce="{cnonce}"']
    if opaque:
        parts.append(f'opaque="{opaque}"')

    return f"{header_name}: Digest " + ", ".join(parts)


# ---------------------------------------------------------------------------
# Transport — UDP / TCP / TLS
# ---------------------------------------------------------------------------

def send_and_recv(
    datagram: bytes,
    host: str,
    port: int,
    local_port: int,
    timeout: float = 3.0,
    recv_size: int = 65535,
    traffic_log=None,
    source_ip: str = "",
    source_port_range: tuple[int, int] | None = None,
) -> bytes | None:
    """Send one UDP datagram, return first response or None on timeout/error.

    source_port_range: (lo, hi) inclusive — walks the range until one binds.
    """
    if source_port_range:
        lo, hi = source_port_range
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(
                f"source_port_range must satisfy 1 <= lo <= hi <= 65535, "
                f"got ({lo}, {hi})"
            )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    bound = False
    if source_port_range:
        lo, hi = source_port_range
        for p in range(lo, hi + 1):
            try:
                s.bind((source_ip, p))
                local_port = p
                bound = True
                break
            except OSError:
                continue
    if not bound:
        try:
            s.bind((source_ip, local_port))
        except OSError:
            s.bind((source_ip, 0))
            local_port = s.getsockname()[1]

    try:
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", datagram)
        s.sendto(datagram, (host, port))
        data, _ = s.recvfrom(recv_size)
        if traffic_log:
            traffic_log.log("IN", f"{host}:{port}", data)
        return data
    except (socket.timeout, OSError):
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
    tls_verify: bool = False,
    tls_ca_bundle: str | None = None,
    source_ip: str = "",
    source_port_range: tuple[int, int] | None = None,
) -> bytes | None:
    """Send a SIP message over TCP or TLS; return the full response.

    tls_verify=True validates the server cert against the system trust store
    (or tls_ca_bundle if provided). Default False because self-signed certs
    are common on PBX gear.
    """
    if source_port_range:
        lo, hi = source_port_range
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(
                f"source_port_range must satisfy 1 <= lo <= hi <= 65535, "
                f"got ({lo}, {hi})"
            )

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    try:
        if source_ip or source_port_range:
            bound = False
            if source_port_range:
                lo, hi = source_port_range
                for p in range(lo, hi + 1):
                    try:
                        raw_sock.bind((source_ip, p))
                        bound = True
                        break
                    except OSError:
                        continue
            if not bound and source_ip:
                try:
                    raw_sock.bind((source_ip, 0))
                except OSError:
                    pass

        raw_sock.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context(cafile=tls_ca_bundle) \
                if tls_ca_bundle else ssl.create_default_context()
            if tls_verify:
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
            else:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", message)
        sock.sendall(message)

        buf = b""
        while True:
            try:
                chunk = sock.recv(recv_size)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            header_end = buf.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            headers_text = buf[:header_end].decode("utf-8", errors="replace")
            cl_match = re.search(
                r"(?i)^content-length\s*:\s*(\d+)", headers_text, re.MULTILINE
            )
            content_length = int(cl_match.group(1)) if cl_match else 0
            body_received = len(buf) - (header_end + 4)
            if body_received >= content_length:
                break

        if traffic_log and buf:
            traffic_log.log("IN", f"{host}:{port}", buf)
        return buf if buf else None

    except (socket.timeout, OSError, ssl.SSLError):
        return None
    finally:
        raw_sock.close()


# ---------------------------------------------------------------------------
# Convenience probes
# ---------------------------------------------------------------------------

def options_probe(
    host: str,
    port: int = 5060,
    local_ip: str | None = None,
    local_port: int = 5062,
    timeout: float = 3.0,
    traffic_log=None,
) -> SipResponse | None:
    """Standard SIP OPTIONS probe."""
    if not local_ip:
        from .utils import local_ip_for
        local_ip = local_ip_for(host)
    msg = build_message(
        "OPTIONS", f"sip:{host}",
        from_user="scanner", to_user="scanner",
        host=host, port=port,
        local_ip=local_ip, local_port=local_port,
        call_id=rand_call_id(), cseq=1, from_tag=rand_tag(),
        extra_headers=["Accept: application/sdp"],
    )
    data = send_and_recv(msg, host, port, local_port, timeout, traffic_log=traffic_log)
    return parse_response(data) if data else None


def parse_allowed_methods(resp: SipResponse) -> list[str]:
    allow = resp.headers.get("allow", "")
    return [m.strip().upper() for m in allow.split(",") if m.strip()]
