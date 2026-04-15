"""PCAP export for SIP/RTP traffic — stdlib only, no scapy/dpkt.

Writes libpcap format files (magic 0xa1b2c3d4) with fake Ethernet + IPv4 +
UDP framing so Wireshark can open them directly.  Intended as a report
artifact for client SOC teams.

Packet structure (per datagram):
  - libpcap global header  (24 bytes, written once at file open)
  - per-packet header      (16 bytes each)
  - Ethernet header        (14 bytes): fake MACs + 0x0800 ethertype
  - IPv4 header            (20 bytes, no options, checksum=0)
  - UDP header             (8 bytes, checksum=0)
  - payload                (variable)
"""
from __future__ import annotations

import re
import socket
import struct
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PCAP_MAGIC = 0xA1B2C3D4          # native byte-order (little-endian on most hosts)
_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4
_PCAP_THISZONE = 0                 # GMT
_PCAP_SIGFIGS = 0
_PCAP_SNAPLEN = 65535
_PCAP_LINKTYPE = 1                 # LINKTYPE_ETHERNET

_FAKE_SRC_MAC = b"\x00\x11\x22\x33\x44\x55"
_FAKE_DST_MAC = b"\x00\xaa\xbb\xcc\xdd\xee"
_ETHERTYPE_IPV4 = 0x0800

_IP_VERSION_IHL = 0x45             # version=4, IHL=5 (20-byte header, no options)
_IP_TOS = 0
_IP_TTL = 64
_IP_PROTO_UDP = 17
_IP_FLAGS_DF = 0x4000              # Don't Fragment


class PcapWriter:
    """Write raw SIP/RTP datagrams into a libpcap file."""

    def __init__(self, path: str) -> None:
        self._fh = open(path, "wb")
        self._write_global_header()

    def _write_global_header(self) -> None:
        hdr = struct.pack(
            "<IHHiIII",
            _PCAP_MAGIC,
            _PCAP_VERSION_MAJOR,
            _PCAP_VERSION_MINOR,
            _PCAP_THISZONE,
            _PCAP_SIGFIGS,
            _PCAP_SNAPLEN,
            _PCAP_LINKTYPE,
        )
        self._fh.write(hdr)

    def write_packet(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        timestamp: float | None = None,
        proto: str = "udp",
    ) -> None:
        """Build Ethernet+IP+UDP frame around payload and write to pcap."""
        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)

        udp_payload_len = 8 + len(payload)          # UDP header + data
        ip_total_len = 20 + udp_payload_len          # IP header + UDP

        # UDP header (8 bytes): src_port, dst_port, length, checksum=0
        udp_hdr = struct.pack(">HHHH",
                               src_port & 0xFFFF,
                               dst_port & 0xFFFF,
                               udp_payload_len & 0xFFFF,
                               0)

        # IPv4 header (20 bytes, no options)
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack(
            ">BBHHHBBH4s4s",
            _IP_VERSION_IHL,
            _IP_TOS,
            ip_total_len & 0xFFFF,
            0,                       # identification = 0
            _IP_FLAGS_DF,
            _IP_TTL,
            _IP_PROTO_UDP,
            0,                       # checksum = 0 (Wireshark accepts this)
            src_ip_bytes,
            dst_ip_bytes,
        )

        # Ethernet header (14 bytes)
        eth_hdr = _FAKE_DST_MAC + _FAKE_SRC_MAC + struct.pack(">H", _ETHERTYPE_IPV4)

        frame = eth_hdr + ip_hdr + udp_hdr + payload
        frame_len = len(frame)

        # Per-packet pcap header (16 bytes)
        pkt_hdr = struct.pack("<IIII",
                               ts_sec,
                               ts_usec,
                               frame_len,    # incl_len
                               frame_len)    # orig_len

        self._fh.write(pkt_hdr + frame)

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *_) -> None:
        self.close()


# ---------------------------------------------------------------------------
# TrafficLog → PCAP converter
# ---------------------------------------------------------------------------

# Pattern matches lines like: === 2026-04-14T12:34:56 OUT sip://1.2.3.4:5060 ===
_LOG_HEADER_RE = re.compile(
    r"^===\s+(\d{4}-\d{2}-\d{2}T[\d:]+)\s+(IN|OUT)\s+(\S+)\s+===\s*$"
)


def _parse_peer(peer_str: str) -> tuple[str, int]:
    """Extract IP and port from a peer string like '1.2.3.4:5060' or 'sip://1.2.3.4:5060'."""
    # Strip scheme if present
    peer_str = re.sub(r"^sip://", "", peer_str)
    if ":" in peer_str:
        ip_part, _, port_part = peer_str.rpartition(":")
        try:
            return ip_part, int(port_part)
        except ValueError:
            pass
    return peer_str, 5060


def _parse_timestamp(ts_str: str) -> float:
    """Parse ISO-ish timestamp 2026-04-14T12:34:56 → float epoch."""
    import datetime
    try:
        dt = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
        return dt.timestamp()
    except ValueError:
        return time.time()


def pcap_from_traffic_log(
    traffic_log_path: str,
    pcap_path: str,
    our_ip: str = "10.0.0.1",
    peer_ip: str = "10.0.0.2",
) -> int:
    """Parse a TrafficLog file and write each SIP datagram to a pcap file.

    The TrafficLog format uses separator lines:
        === 2026-04-14T12:34:56 OUT sip://1.2.3.4:5060 ===

    followed by the raw SIP payload until the next separator.

    Direction OUT → src=our_ip:5060, dst=peer:5060
    Direction IN  → src=peer:5060, dst=our_ip:5060

    Returns the number of packets written.
    """
    packets_written = 0

    with open(traffic_log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    writer = PcapWriter(pcap_path)
    try:
        current_ts: float | None = None
        current_direction: str | None = None
        current_peer_ip: str = peer_ip
        current_peer_port: int = 5060
        payload_lines: list[str] = []

        def flush_packet() -> None:
            nonlocal packets_written
            if current_direction is None or not payload_lines:
                return
            payload_text = "".join(payload_lines).rstrip("\n")
            if not payload_text.strip():
                return
            data = payload_text.encode("utf-8", errors="replace")
            ts = current_ts if current_ts is not None else time.time()
            if current_direction == "OUT":
                writer.write_packet(
                    data,
                    src_ip=our_ip, dst_ip=current_peer_ip,
                    src_port=5060, dst_port=current_peer_port,
                    timestamp=ts,
                )
            else:
                writer.write_packet(
                    data,
                    src_ip=current_peer_ip, dst_ip=our_ip,
                    src_port=current_peer_port, dst_port=5060,
                    timestamp=ts,
                )
            packets_written += 1

        for line in lines:
            m = _LOG_HEADER_RE.match(line)
            if m:
                flush_packet()
                payload_lines = []
                current_ts = _parse_timestamp(m.group(1))
                current_direction = m.group(2)
                parsed_ip, parsed_port = _parse_peer(m.group(3))
                # Use the parsed IP if it looks like a real address, else fall back
                try:
                    socket.inet_aton(parsed_ip)
                    current_peer_ip = parsed_ip
                    current_peer_port = parsed_port
                except OSError:
                    current_peer_ip = peer_ip
                    current_peer_port = parsed_port
            else:
                payload_lines.append(line)

        # Flush the last packet
        flush_packet()

    finally:
        writer.close()

    return packets_written
