"""SCCP (Skinny Client Control Protocol) probe.

Cisco's pre-SIP phone control protocol, still present on:
  * Cisco CUCM / Unified Communications Manager deployments (tens of
    thousands of sites globally — most keep both SCCP and SIP enabled).
  * Cisco Business Edition 6000 / 7000.
  * Cisco Call Manager Express (CME) on IOS routers.

Transport:  TCP / 2000 (unencrypted), TCP / 2443 (TLS).
Framing:    little-endian length-prefixed messages, each message
            carrying a 4-byte reserved + 4-byte message ID + payload.

Wire format per message (all LE):
    uint32  length          (# bytes after this field, excluding itself)
    uint32  reserved / header version (typically 0 or 0x11)
    uint32  message ID
    bytes   payload         (length - 8 bytes)

Message IDs we care about for discovery:
    0x0000  KeepAliveMessage        — client heartbeat
    0x0001  RegisterMessage         — phone registers with CUCM
    0x0081  RegisterAckMessage      — success
    0x009D  RegisterRejectMessage   — rejection w/ text
    0x0083  KeepAliveAckMessage

What we do (passive/active, non-destructive):
  * Open TCP to the SCCP port and send a KeepAlive (0x0000).  A CUCM that
    is listening for SCCP will reply with KeepAliveAck (0x0083) or drop
    the connection immediately if it's HTTPS/SIP on a reused port.
  * Send a Register with a decoy MAC & model — collect the reject text
    (CUCM reveals version + policy text in RegisterReject).

We do not enumerate valid extensions here — the reject text is enough to
identify the CUCM version and confirm SCCP is live without noise.  Actual
extension enumeration belongs in a separate module because CUCM rate-
limits RegisterReject after ~10 attempts.

No third-party deps.  Pure stdlib.
"""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field


SCCP_PORT = 2000
SCCP_TLS_PORT = 2443

MSG_KEEPALIVE        = 0x0000
MSG_REGISTER         = 0x0001
MSG_REGISTER_ACK     = 0x0081
MSG_REGISTER_REJECT  = 0x009D
MSG_KEEPALIVE_ACK    = 0x0083
MSG_VERSION_REQ      = 0x000A  # from phone to CUCM — requests firmware file name
MSG_VERSION_RESP     = 0x0092


@dataclass
class SccpProbeResult:
    target: str
    port: int
    sccp_detected: bool = False
    keepalive_ack: bool = False
    register_reject_text: str = ""
    cucm_version_hint: str = ""
    raw_messages: list[tuple[int, bytes]] = field(default_factory=list)
    error: str | None = None


def _build_sccp(message_id: int, payload: bytes = b"") -> bytes:
    """Build an SCCP message.  length = reserved(4) + msgid(4) + payload."""
    reserved = 0x00000000
    total_len = 8 + len(payload)
    return struct.pack("<III", total_len, reserved, message_id) + payload


def _read_messages(sock: socket.socket, timeout: float = 2.0,
                   max_messages: int = 4) -> list[tuple[int, bytes]]:
    """Read up to N messages or until the far end quiets/closes.  Each
    element is (message_id, payload_bytes)."""
    sock.settimeout(timeout)
    messages: list[tuple[int, bytes]] = []
    buf = bytearray()
    deadline = time.monotonic() + timeout
    while len(messages) < max_messages and time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf.extend(chunk)
        # Parse as many complete messages as we have in buf
        while len(buf) >= 4:
            length = struct.unpack("<I", buf[0:4])[0]
            # Sanity cap — SCCP messages rarely exceed a few KB
            if length > 65536 or length < 8:
                return messages
            frame_total = 4 + length  # include the length field itself
            if len(buf) < frame_total:
                break  # wait for more
            frame = bytes(buf[0:frame_total])
            del buf[0:frame_total]
            if len(frame) < 12:
                continue
            mid = struct.unpack("<I", frame[8:12])[0]
            messages.append((mid, frame[12:]))
    return messages


def probe_sccp(
    host: str,
    port: int = SCCP_PORT,
    timeout: float = 3.0,
    decoy_mac: str = "001122334455",
    decoy_model: int = 115,  # Cisco 7970 — broadly accepted
    traffic_log=None,
) -> SccpProbeResult:
    """Open TCP to the SCCP port, send KeepAlive + Register, parse reply.

    Non-destructive: we only send two messages and close.  CUCM logs the
    attempt but doesn't count it against registration limits.
    """
    result = SccpProbeResult(target=host, port=port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except (socket.timeout, OSError) as exc:
        result.error = f"connect: {exc}"
        sock.close()
        return result

    try:
        # 1. KeepAlive — should elicit KeepAliveAck (0x0083) on any live
        #    SCCP endpoint, including ones that would reject a Register.
        ka = _build_sccp(MSG_KEEPALIVE)
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", ka)
        sock.sendall(ka)

        # 2. Register — CUCM will respond RegisterReject for unknown MACs
        #    with a descriptive text field (CUCM version, message, and
        #    policy reason).  Payload structure:
        #       char    deviceName[16]   — ASCII, zero-padded
        #       uint32  stationUserId    — typically 0
        #       uint32  stationInstance  — 1
        #       uint32  ipAddress        — our IP (0 is fine for a probe)
        #       uint32  deviceType       — model ID (see _decoy_model)
        #       uint32  maxStreams       — 1
        #       (rest is version-dependent)
        device_name = decoy_mac.ljust(16, "\x00")[:16].encode("ascii", errors="replace")
        reg_payload = (
            device_name
            + struct.pack("<I", 0)           # stationUserId
            + struct.pack("<I", 1)           # stationInstance
            + struct.pack("<I", 0)           # ipAddress
            + struct.pack("<I", decoy_model) # deviceType
            + struct.pack("<I", 1)           # maxStreams
        )
        reg = _build_sccp(MSG_REGISTER, reg_payload)
        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", reg)
        sock.sendall(reg)

        messages = _read_messages(sock, timeout=timeout, max_messages=4)
        for mid, payload in messages:
            result.raw_messages.append((mid, payload[:64]))
            if mid == MSG_KEEPALIVE_ACK:
                result.keepalive_ack = True
                result.sccp_detected = True
            elif mid == MSG_REGISTER_REJECT:
                result.sccp_detected = True
                # Reject payload: text string (sometimes length-prefixed),
                # then optional int fields.  We take the initial printable
                # block as the reject message.
                text = payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                result.register_reject_text = text
                # CUCM frequently embeds "Firmware load for this device
                # type not found" or "Device not found in database" plus a
                # build-version substring.  We scrape for "CUCM" / "CM /
                # Call Manager" hints.
                for token in ("CUCM", "Cisco", "Call Manager", "Unified"):
                    if token.lower() in text.lower():
                        result.cucm_version_hint = text
                        break
            elif mid == MSG_REGISTER_ACK:
                result.sccp_detected = True
                # Registering without creds succeeded — a serious finding
                # all by itself.
                result.register_reject_text = "REGISTER_ACK (unauthenticated register accepted!)"
            if traffic_log:
                traffic_log.log("IN", f"{host}:{port}", struct.pack("<I", mid) + payload[:64])

        if not result.sccp_detected and messages:
            # Something replied but wasn't SCCP — keep raw so it's visible
            result.error = "unexpected protocol on SCCP port"
    except OSError as exc:
        result.error = f"io: {exc}"
    finally:
        sock.close()
    return result


def build_findings(result: SccpProbeResult) -> list[dict]:
    out: list[dict] = []
    if not result.sccp_detected:
        return out
    out.append({
        "id": "sccp.exposed",
        "severity": "low",
        "host": result.target,
        "title": f"Cisco SCCP (Skinny) service on TCP/{result.port}",
        "detail": (
            f"SCCP probe on {result.target}:{result.port} elicited a Skinny "
            f"reply ("
            f"{'KeepAlive Ack' if result.keepalive_ack else 'RegisterReject'}). "
            f"{'Server version hint: ' + result.cucm_version_hint if result.cucm_version_hint else ''}"
        ),
        "remediation": (
            "If SIP is the primary registration protocol, disable SCCP in "
            "CUCM (System → Security → Security Profiles and phone device "
            "types). SCCP lacks per-message authentication and is vulnerable "
            "to call hijacking on the same LAN segment."
        ),
    })
    if result.register_reject_text.startswith("REGISTER_ACK"):
        out.append({
            "id": "sccp.anon_register",
            "severity": "critical",
            "host": result.target,
            "title": "SCCP accepted unauthenticated Register",
            "detail": (
                f"Sending a Register with a decoy MAC to {result.target}:{result.port} "
                "produced a RegisterAck (0x0081) — the CUCM accepts "
                "unauthenticated phone registrations on the probed interface."
            ),
            "remediation": (
                "Enable Device Security Profile with 'Authentication Mode: "
                "Authenticated' or 'Encrypted' (Cisco CUCM 9+). Disable "
                "auto-registration when in production."
            ),
        })
    return out
