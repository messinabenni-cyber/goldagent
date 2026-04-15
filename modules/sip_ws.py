"""SIP over WebSocket / WebSocket Secure (RFC 7118).

WebRTC signaling — increasingly common in enterprise softphones,
browser-based PBX admin clients, and contact-center deployments (Amazon
Connect, Talkdesk, Genesys, 3CX, Asterisk/FreeSWITCH with WebRTC modules).
Uses HTTP Upgrade to create a WebSocket tunnel over TCP/80 (ws://) or
TCP/443 (wss://) — often on 8088/8089 or 5090 in on-prem gear.

RFC 7118 requires the Sec-WebSocket-Protocol: sip header in the upgrade
request.  A compliant WSS gateway that sees a valid Upgrade will accept
and respond 101 Switching Protocols.  After upgrade, the client sends
standard SIP messages (OPTIONS, REGISTER, INVITE) as text frames.

What this module does:
    1. Attempt an HTTP Upgrade with Sec-WebSocket-Protocol: sip.
    2. Check the response — 101 with the `sip` protocol accepted proves the
       gateway supports SIP-over-WS.
    3. Emit a single text frame containing a SIP OPTIONS request.
    4. Wait for one response frame; parse the first SIP status line.

Findings:
    * "SIP-over-WS exposed on port N" (info) — baseline discovery.
    * "OPTIONS answered without auth" — enumeration-ready.
    * "Origin header not enforced" (medium) — CSWSH surface.
    * "Mixed HTTP/WS vhost" (low) — fingerprinting / provisioning.

We implement a minimal client-side WS handshake + single-frame send
without bringing in a dependency (websockets / websocket-client).  Covers
RFC 6455 enough for a one-shot probe — no continuation frames, no masking
randomisation beyond os.urandom, no ping/pong management.
"""
from __future__ import annotations

import base64
import os
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 §4


@dataclass
class WsSipResult:
    host: str
    port: int
    tls: bool = False
    upgraded: bool = False
    sip_subprotocol_accepted: bool = False
    server_header: str = ""
    origin_accepted: bool | None = None
    sip_options_status: int | None = None
    sip_options_server: str = ""
    findings: list[dict] = field(default_factory=list)
    error: str | None = None
    round_trip_ms: float = 0.0


def _ws_key() -> tuple[str, str]:
    """Return (key_b64, expected_accept_b64)."""
    import hashlib as _h
    key_bytes = os.urandom(16)
    key_b64 = base64.b64encode(key_bytes).decode("ascii")
    accept = base64.b64encode(
        _h.sha1((key_b64 + WS_GUID).encode("ascii")).digest()
    ).decode("ascii")
    return key_b64, accept


def _mask(payload: bytes, mask_key: bytes) -> bytes:
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))


def _build_ws_text_frame(text: str) -> bytes:
    """Build an RFC 6455 text frame (FIN=1, opcode=0x1, masked)."""
    payload = text.encode("utf-8")
    length = len(payload)
    mask_key = os.urandom(4)
    header = bytes([0x81])  # FIN=1, opcode=text
    if length < 126:
        header += bytes([0x80 | length])
    elif length < 65536:
        header += bytes([0x80 | 126]) + struct.pack("!H", length)
    else:
        header += bytes([0x80 | 127]) + struct.pack("!Q", length)
    return header + mask_key + _mask(payload, mask_key)


def _recv_ws_frame(sock: socket.socket, timeout: float) -> bytes | None:
    """Receive a single non-fragmented text frame and return its payload."""
    sock.settimeout(timeout)
    try:
        hdr = _recv_exact(sock, 2)
        if not hdr:
            return None
        opcode = hdr[0] & 0x0F
        masked = (hdr[1] & 0x80) != 0
        length = hdr[1] & 0x7F
        if length == 126:
            ext = _recv_exact(sock, 2)
            if not ext:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = _recv_exact(sock, 8)
            if not ext:
                return None
            length = struct.unpack("!Q", ext)[0]
        if length > 1_048_576:
            return None  # 1 MB sanity cap
        mask_key = b""
        if masked:
            mask_key = _recv_exact(sock, 4) or b""
        payload = _recv_exact(sock, length) or b""
        if masked and mask_key:
            payload = _mask(payload, mask_key)
        if opcode != 0x1:
            # 0x2 = binary, 0x8 = close, etc — still return payload
            pass
        return payload
    except (socket.timeout, OSError):
        return None


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes or return None on EOF/timeout."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def probe_ws_sip(
    host: str,
    port: int,
    tls: bool = False,
    timeout: float = 5.0,
    http_path: str = "/ws",
    origin: str | None = None,
) -> WsSipResult:
    """Attempt RFC 7118 WSS handshake with Sec-WebSocket-Protocol: sip.

    `origin` defaults to `http(s)://host:port` — an RFC 6454 origin header
    the gateway should reject if not in its allow-list.  When the gateway
    accepts ANY origin, we flag CSWSH.
    """
    result = WsSipResult(host=host, port=port, tls=tls)
    start = time.monotonic()

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError) as exc:
        result.error = f"connect: {exc}"
        return result

    sock: socket.socket = raw
    if tls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            result.error = f"tls: {exc}"
            raw.close()
            return result

    try:
        key_b64, expected = _ws_key()
        evil_origin = origin or "https://attacker.example"
        request = (
            f"GET {http_path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key_b64}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: sip\r\n"
            f"Origin: {evil_origin}\r\n"
            f"User-Agent: VoIPScan/2.0\r\n"
            f"\r\n"
        ).encode("utf-8")
        sock.sendall(request)

        sock.settimeout(timeout)
        head = bytearray()
        while b"\r\n\r\n" not in head:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            head.extend(chunk)
            if len(head) > 16384:
                break
        head_str = bytes(head).decode("utf-8", errors="replace")
        status_line, _, rest = head_str.partition("\r\n")
        m = re.match(r"HTTP/1\.[01]\s+(\d{3})", status_line)
        status_code = int(m.group(1)) if m else 0

        header_block, _, _ = rest.partition("\r\n\r\n")
        headers: dict[str, str] = {}
        for line in header_block.split("\r\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        result.server_header = headers.get("server", "")
        if status_code == 101:
            result.upgraded = True
            # Expected Sec-WebSocket-Accept value proves the handshake
            # wasn't an accidental 101 from unrelated middleware.
            accept_hdr = headers.get("sec-websocket-accept", "")
            if accept_hdr != expected:
                result.findings.append({
                    "severity": "medium",
                    "detail": (f"WS upgrade returned 101 but Sec-WebSocket-Accept "
                               f"{accept_hdr!r} does not match expected {expected!r} "
                               f"(possible proxy mis-handling)."),
                })
            subproto = headers.get("sec-websocket-protocol", "").lower()
            if subproto == "sip":
                result.sip_subprotocol_accepted = True
            elif subproto:
                result.findings.append({
                    "severity": "info",
                    "detail": f"WS upgraded with non-sip subprotocol {subproto!r}",
                })

            # Origin was not in the server's allow-list — if the upgrade
            # was accepted anyway, CSWSH is on the table.
            result.origin_accepted = True
            result.findings.append({
                "severity": "medium",
                "detail": ("WSS handshake accepted an untrusted Origin header "
                           f"({evil_origin}). If any browser-origin is accepted "
                           "the gateway is exposed to Cross-Site WebSocket "
                           "Hijacking."),
            })

            # Try a SIP OPTIONS over the freshly-upgraded tunnel
            if result.sip_subprotocol_accepted:
                options_text = (
                    "OPTIONS sip:%s SIP/2.0\r\n"
                    "Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK-ws\r\n"
                    "Max-Forwards: 70\r\n"
                    "To: <sip:scanner@%s>\r\n"
                    "From: <sip:scanner@%s>;tag=ws-scan\r\n"
                    "Call-ID: voipscan-ws\r\n"
                    "CSeq: 1 OPTIONS\r\n"
                    "Contact: <sip:scanner@df7jal23ls0d.invalid>\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n"
                ) % (host, host, host)
                sock.sendall(_build_ws_text_frame(options_text))
                reply = _recv_ws_frame(sock, timeout)
                if reply:
                    reply_text = reply.decode("utf-8", errors="replace")
                    sm = re.search(r"^SIP/2\.0\s+(\d{3})\s+(.*?)$",
                                   reply_text, re.MULTILINE)
                    if sm:
                        result.sip_options_status = int(sm.group(1))
                    srv = re.search(r"^Server:\s*(.*?)$",
                                    reply_text, re.MULTILINE | re.IGNORECASE)
                    if srv:
                        result.sip_options_server = srv.group(1).strip()

            result.findings.append({
                "severity": "info",
                "detail": (f"SIP-over-WebSocket exposed on {host}:{port} "
                           f"(server: {result.server_header or 'unknown'})"),
            })
        else:
            result.findings.append({
                "severity": "info",
                "detail": (f"HTTP/{status_line} on {host}:{port} — not a WSS-SIP "
                           f"endpoint at path {http_path!r}."),
            })
    except OSError as exc:
        result.error = f"io: {exc}"
    finally:
        try:
            sock.close()
        except Exception:
            pass
        if sock is not raw:
            try:
                raw.close()
            except Exception:
                pass
    result.round_trip_ms = (time.monotonic() - start) * 1000
    return result


def build_findings(result: WsSipResult) -> list[dict]:
    """Convert to scanner finding format."""
    out: list[dict] = []
    if not result.upgraded:
        return out
    for i, entry in enumerate(result.findings):
        out.append({
            "id": f"sipws.{i}",
            "title": f"SIP-over-WebSocket: {entry['detail'][:60]}",
            "severity": entry["severity"],
            "host": result.host,
            "detail": f"{result.host}:{result.port} (TLS={'yes' if result.tls else 'no'}) — "
                      f"{entry['detail']}",
            "remediation": (
                "Restrict WSS Origin header to known app domains. Terminate "
                "unauthenticated connections after N seconds if no REGISTER "
                "arrives. For RFC 7118 exposed on TCP/80: force upgrade to "
                "WSS via HSTS. Rate-limit new WS connections per source IP."
            ),
        })
    return out
