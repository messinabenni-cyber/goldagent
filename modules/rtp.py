"""RTP packet building + SDP parsing/building + paced streaming."""
from __future__ import annotations

import random
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass


FRAME_MS = 20                # G.711 standard: 20ms per packet
SAMPLES_PER_FRAME = 160      # 8000 Hz * 0.020 s
PAYLOAD_PCMU = 0
PAYLOAD_PCMA = 8


@dataclass
class RemoteMedia:
    ip: str
    port: int
    payload_type: int
    codec: str  # 'PCMU' or 'PCMA' typically


def build_sdp_offer(local_ip: str, rtp_port: int) -> str:
    """SDP offer: PCMU + PCMA, sendrecv."""
    return (
        "v=0\r\n"
        f"o=voip-demo {random.randint(1,1<<31)} {random.randint(1,1<<31)} IN IP4 {local_ip}\r\n"
        "s=voip-demo-session\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP 0 8 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\n"
        "a=fmtp:101 0-15\r\n"
        "a=sendrecv\r\n"
        f"a=ptime:{FRAME_MS}\r\n"
    )


def parse_sdp_answer(body: str) -> RemoteMedia | None:
    """Extract remote RTP IP/port + negotiated payload type from SDP."""
    ip = None
    port = None
    chosen_pt: int | None = None
    rtpmap: dict[int, str] = {}
    # Session-level c= can be overridden by media-level c=; we walk top-to-bottom.
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("c=IN IP4 "):
            ip = line.split()[2]
        elif line.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    port = int(parts[1])
                except ValueError:
                    port = None
                # pick first listed payload type; if a later a=rtpmap for PCMU/PCMA
                # matches, we'll stick with our offered codecs.
                try:
                    chosen_pt = int(parts[3])
                except ValueError:
                    chosen_pt = None
        elif line.startswith("a=rtpmap:"):
            m = re.match(r"a=rtpmap:(\d+)\s+([^/]+)/", line)
            if m:
                rtpmap[int(m.group(1))] = m.group(2).upper()

    if not ip or not port:
        return None
    # Prefer PCMU, else PCMA, else whatever
    for pt, codec in rtpmap.items():
        if codec == "PCMU":
            chosen_pt = pt
            return RemoteMedia(ip=ip, port=port, payload_type=pt, codec="PCMU")
    for pt, codec in rtpmap.items():
        if codec == "PCMA":
            return RemoteMedia(ip=ip, port=port, payload_type=pt, codec="PCMA")
    if chosen_pt is None:
        chosen_pt = 0
    codec = rtpmap.get(chosen_pt, "PCMU" if chosen_pt == 0 else "PCMA")
    return RemoteMedia(ip=ip, port=port, payload_type=chosen_pt, codec=codec)


def _rtp_header(seq: int, timestamp: int, ssrc: int,
                payload_type: int, marker: bool) -> bytes:
    first = 0x80  # V=2, P=0, X=0, CC=0
    second = (0x80 if marker else 0) | (payload_type & 0x7F)
    return struct.pack(
        "!BBHII",
        first, second,
        seq & 0xFFFF,
        timestamp & 0xFFFFFFFF,
        ssrc & 0xFFFFFFFF,
    )


class RtpStreamer:
    """Streams μ-law frames to a remote endpoint at 50 packets/sec. Can be
    stopped by setting .stop = True. Runs in a background thread.

    Sends silence when the payload is exhausted, so the call stays open until
    the controlling thread tears it down."""

    def __init__(
        self,
        sock: socket.socket,
        remote_ip: str,
        remote_port: int,
        payload_type: int = PAYLOAD_PCMU,
        ulaw_payload: bytes = b"",
    ):
        if payload_type not in (PAYLOAD_PCMU, PAYLOAD_PCMA, 101):
            raise ValueError(
                f"Unsupported payload_type {payload_type}; expected 0 (PCMU), "
                "8 (PCMA), or 101 (telephone-event)"
            )
        self.sock = sock
        self.remote = (remote_ip, remote_port)
        self.payload_type = payload_type
        self.ulaw = ulaw_payload
        self.stop = False
        self._packets_lock = threading.Lock()
        self._packets_sent = 0
        self._thread: threading.Thread | None = None
        # Optional: let caller preset SSRC/seq/ts so DTMF and audio share
        # a single RTP stream (improves PBX compatibility — some strict
        # implementations reject mid-dialog SSRC changes).
        self._ssrc_override: int | None = None
        self._seq_override: int | None = None
        self._ts_override: int | None = None

    @property
    def packets_sent(self) -> int:
        with self._packets_lock:
            return self._packets_sent

    @packets_sent.setter
    def packets_sent(self, value: int) -> None:
        with self._packets_lock:
            self._packets_sent = value

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def _run(self) -> None:
        ssrc = self._ssrc_override if self._ssrc_override is not None \
            else random.randint(0, 0xFFFFFFFF)
        seq = self._seq_override if self._seq_override is not None \
            else random.randint(0, 0xFFFF)
        ts = self._ts_override if self._ts_override is not None \
            else random.randint(0, 0xFFFFFFFF)
        # Silence encoding depends on codec:
        #   PCMU (μ-law): linear 0 encodes to 0xFF
        #   PCMA (A-law): linear 0 encodes to 0xD5 (sign-bit XOR 0x55)
        silence_byte = b"\xd5" if self.payload_type == PAYLOAD_PCMA else b"\xff"
        silence = silence_byte * SAMPLES_PER_FRAME
        # Chop payload into 160-byte frames
        frames: list[bytes] = [
            self.ulaw[i:i + SAMPLES_PER_FRAME]
            for i in range(0, len(self.ulaw), SAMPLES_PER_FRAME)
        ] or [silence]
        # Pad the last frame if short (use the correct codec silence byte)
        if frames and len(frames[-1]) < SAMPLES_PER_FRAME:
            pad_len = SAMPLES_PER_FRAME - len(frames[-1])
            frames[-1] = frames[-1] + silence_byte * pad_len

        interval = FRAME_MS / 1000.0
        next_send = time.monotonic()
        idx = 0
        first = True
        while not self.stop:
            if idx < len(frames):
                frame = frames[idx]
                idx += 1
            else:
                frame = silence
            hdr = _rtp_header(seq, ts, ssrc, self.payload_type, marker=first)
            first = False
            try:
                self.sock.sendto(hdr + frame, self.remote)
                with self._packets_lock:
                    self._packets_sent += 1
            except OSError:
                return
            seq = (seq + 1) & 0xFFFF
            ts = (ts + SAMPLES_PER_FRAME) & 0xFFFFFFFF
            next_send += interval
            sleep_for = next_send - time.monotonic()
            if sleep_for > 0:
                time.sleep(sleep_for)
            else:
                # If we fell behind (GC pause, etc), reset the clock
                next_send = time.monotonic()


def bind_rtp_socket(local_port_hint: int = 0) -> tuple[socket.socket, int]:
    """Return (sock, actual_port). RTP ports are conventionally even."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", local_port_hint))
    except OSError:
        s.bind(("", 0))
    port = s.getsockname()[1]
    return s, port
