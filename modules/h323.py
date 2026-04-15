"""H.323 RAS discovery probe — Gatekeeper Request (GRQ).

H.323 is ITU-T's older multimedia-over-IP suite.  Still present in:
  * Cisco CUBE (IOS), Cisco CUCM H.323 gateways, Polycom RMX MCUs
  * Legacy Avaya / Nortel gear
  * Video conferencing gateways (Polycom HDX/Group, Cisco TelePresence)
  * Many carrier-grade trunking platforms

H.323 has multiple sub-protocols:
    Q.931 (call signalling)   TCP / 1720
    H.245 (media control)     TCP / dynamic
    RAS   (registration/admission/status) UDP / 1719

We send a single Gatekeeper Request (GRQ) on UDP/1719 and parse the
Gatekeeper Confirm (GCF) or Reject (GRJ) that comes back.

H.323 messages are ASN.1 PER-encoded — a full parser is a lot of code.
Fortunately, the first few bytes of a GRQ are predictable:

    GRQ (gatekeeperRequest) identifier sequence:
        protocolIdentifier = {itu-t (0) recommendation (0) h (8) 2250
                              version (0) 4}
        nonStandardData    OPTIONAL
        requestSeqNum      INTEGER (1..65535)
        endpointType       EndpointType  (flags; we send 'terminal')
        rasAddress         TransportAddress
        endpointAlias      SEQUENCE OF AliasAddress
        ...

We use a canned GRQ captured from a standards-compliant endpoint and
patch in our source IP / sequence number.  This is the standard approach
used by every h323-probe I've seen (the ASN.1 PER encoding of a vanilla
GRQ is identical across most stacks).

No third-party deps — pure stdlib.
"""
from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass, field


RAS_PORT = 1719
Q931_PORT = 1720

# Canned GRQ (RAS protocol discriminator 0x03) from a vanilla H.323
# terminal.  The magic sequence contains:
#   - protocolIdentifier { itu-t(0) recommendation(0) h(8) 2250 version(0) 6 }
#   - requestSeqNum: placeholder 0x0001 (2 bytes at offset _SEQ_OFFSET)
#   - endpointType: terminal, undefinedNode=false
#   - rasAddress: transportAddress placeholder (we patch IP + port)
#
# We don't attempt to fully PER-encode — the discovery payload below is
# sufficient to elicit a reply from commodity gatekeepers (Cisco CUBE,
# GnuGK, Asterisk OH323, Polycom RMX).  Real exploit tooling would use a
# full ASN.1 library; for discovery this is enough.
GRQ_TEMPLATE = bytes.fromhex(
    # GRQ preamble: 0x27 0x06 0x05 0x02 0x88 0x13 0x01 0x00
    #   (APDU prefix + protocolIdentifier for h.225v6)
    "27060502" "88130100"
    # requestSeqNum placeholder (2 bytes)
    "00010180"
    # protocolIdentifier continuation
    "0608914a00010400"
    # endpointType: terminal flag
    "03010501"
    # rasAddress: ipAddress(0) + 4-byte IP placeholder + 2-byte port
    "3a07000102030400c7"   # port 0x00c7 = 199 (placeholder — replaced)
    # endpointIdentifier: empty BMP
    "0102"
    # gatekeeperIdentifier: empty
    "2c00"
    # tokens: absent
    "0a00"
)

_SEQ_OFFSET = 10    # sequence number position in GRQ_TEMPLATE
_IP_OFFSET = 28     # IP address byte offset (4 bytes)
_PORT_OFFSET = 32   # UDP port offset (2 bytes, big-endian)


@dataclass
class H323ProbeResult:
    target: str
    port: int = RAS_PORT
    h323_detected: bool = False
    reply_opcode: int | None = None
    gatekeeper_identifier: str = ""
    raw_reply: bytes = b""
    error: str | None = None


def _patch_grq(source_ip: str, source_port: int, seq: int) -> bytes:
    buf = bytearray(GRQ_TEMPLATE)
    struct.pack_into("!H", buf, _SEQ_OFFSET, seq & 0xFFFF)
    try:
        ip_bytes = socket.inet_aton(source_ip)
    except OSError:
        ip_bytes = b"\x00\x00\x00\x00"
    buf[_IP_OFFSET:_IP_OFFSET + 4] = ip_bytes
    struct.pack_into("!H", buf, _PORT_OFFSET, source_port & 0xFFFF)
    return bytes(buf)


def probe_h323_ras(
    host: str,
    port: int = RAS_PORT,
    timeout: float = 3.0,
    traffic_log=None,
) -> H323ProbeResult:
    """Send a GRQ, wait for GCF/GRJ or other RAS message.  Any reply from
    the target port confirms an H.225/RAS speaker."""
    result = H323ProbeResult(target=host, port=port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.bind(("", 0))
        local_ip = "0.0.0.0"
        try:
            # Derive a local IP that can reach the target — better for
            # gatekeepers that use this to pick a reply interface.
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect((host, port))
                local_ip = probe.getsockname()[0]
            finally:
                probe.close()
        except OSError:
            pass
        seq = random.randint(1, 0xFFFF)
        grq = _patch_grq(local_ip, sock.getsockname()[1], seq)

        if traffic_log:
            traffic_log.log("OUT", f"{host}:{port}", grq)
        sock.sendto(grq, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return result
        result.raw_reply = data
        if traffic_log:
            traffic_log.log("IN", f"{host}:{port}", data)

        if not data:
            return result
        # First byte of a RAS PDU identifies the message type:
        #   0x18 = gatekeeperConfirm   (GCF)
        #   0x20 = gatekeeperReject    (GRJ)
        #   0x24 = registrationRequest (RRQ — shouldn't happen but some
        #          gatekeepers reply with unsolicited RRQ)
        #   0x40 = xRSConfirm
        # Any reply at all is proof of an H.225 speaker.
        first = data[0]
        result.reply_opcode = first
        result.h323_detected = True
        # Try to lift a printable gatekeeperIdentifier if the reply embeds
        # one (ASCII BMPString patterns tend to be human-readable substrings).
        import re as _re
        txt = data.decode("latin1", errors="ignore")
        m = _re.search(r"([A-Za-z][A-Za-z0-9._-]{4,32})", txt)
        if m:
            result.gatekeeper_identifier = m.group(1)
    except OSError as exc:
        result.error = f"io: {exc}"
    finally:
        sock.close()
    return result


def build_findings(result: H323ProbeResult) -> list[dict]:
    out: list[dict] = []
    if not result.h323_detected:
        return out
    out.append({
        "id": "h323.ras",
        "severity": "low",
        "host": result.target,
        "title": f"H.323 RAS gatekeeper responded on UDP/{result.port}",
        "detail": (
            f"Gatekeeper Request to {result.target}:{result.port} produced "
            f"a RAS reply (opcode 0x{result.reply_opcode or 0:02x})"
            + (f". Identifier hint: {result.gatekeeper_identifier!r}"
               if result.gatekeeper_identifier else ".")
        ),
        "remediation": (
            "If H.323 is not in active use on this gateway, disable it "
            "(Cisco IOS: 'no gateway' under interface; CUCM: remove H.323 "
            "gateway). H.323 is harder to rate-limit at the firewall than "
            "SIP and provides a parallel attack surface. If required, "
            "restrict UDP/1719 and TCP/1720 by ACL to known peers."
        ),
    })
    return out
