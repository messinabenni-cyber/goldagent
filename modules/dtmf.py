"""RFC 2833 / RFC 4733 DTMF events over RTP.

Used to navigate the target PBX's IVR during a client demo — e.g. send `0`
to reach the operator, `*97` to hit voicemail, or a PIN to unlock a service.
This is pure signalling (the PBX interprets the events); no in-band audio
tones are produced.

Payload format (4 bytes):
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     event     |E|R| volume    |          duration             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The tool sends DTMF BEFORE starting audio streaming (so the IVR can react
without audio interference) and resumes streaming once DTMF is complete.
"""
from __future__ import annotations

import random
import re
import socket
import struct
import time


# RFC 4733 event codes. 0-9 and *, #, A-D plus rare extensions.
DTMF_EVENTS: dict[str, int] = {
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
    "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
    "*": 10, "#": 11,
    "A": 12, "B": 13, "C": 14, "D": 15,
    "flash": 16,
}

SAMPLE_RATE = 8000
FRAME_SAMPLES = 160   # 20 ms @ 8 kHz


def build_payload(event: int, end: bool, duration_samples: int,
                  volume_dbm: int = 10) -> bytes:
    """4-byte telephone-event payload per RFC 4733."""
    b0 = event & 0xFF
    b1 = (0x80 if end else 0) | (volume_dbm & 0x3F)
    return struct.pack("!BBH", b0, b1, duration_samples & 0xFFFF)


def rtp_header(seq: int, timestamp: int, ssrc: int,
               payload_type: int, marker: bool) -> bytes:
    first = 0x80  # V=2
    second = (0x80 if marker else 0) | (payload_type & 0x7F)
    return struct.pack("!BBHII",
                       first, second,
                       seq & 0xFFFF,
                       timestamp & 0xFFFFFFFF,
                       ssrc & 0xFFFFFFFF)


class DtmfSender:
    """Emit RFC 4733 events on an existing RTP socket. Blocking — caller
    controls the timeline. Designed to run before the RtpStreamer starts
    streaming audio, so the IVR hears only signalling."""

    def __init__(
        self,
        sock: socket.socket,
        remote_ip: str,
        remote_port: int,
        payload_type: int = 101,
        ssrc: int | None = None,
        seq_start: int | None = None,
        ts_start: int | None = None,
    ):
        if not (1 <= remote_port <= 65535):
            raise ValueError(f"Invalid DTMF remote port: {remote_port}")
        self.sock = sock
        self.remote = (remote_ip, remote_port)
        self.pt = payload_type
        self.ssrc = ssrc if ssrc is not None else random.randint(0, 0xFFFFFFFF)
        self.seq = seq_start if seq_start is not None else random.randint(0, 0xFFFF)
        self.ts = ts_start if ts_start is not None else 0
        self.digits_sent: list[str] = []
        self.packets_sent = 0

    def send_digit(self, digit: str, duration_ms: int = 200,
                   volume: int = 10) -> None:
        """Send one DTMF digit with end-of-event redundancy (3 repeats
        per RFC 4733 §2.5.2.2). Blocks for `duration_ms` + ~60 ms."""
        if digit not in DTMF_EVENTS:
            return
        event = DTMF_EVENTS[digit]
        # RFC 4733 §3: duration field is 16-bit → max 65535 samples = ~8.19 s
        duration_ms = min(duration_ms, 8191)   # clamp to safe max (8191 ms)
        total_samples = int(duration_ms * SAMPLE_RATE / 1000)
        if total_samples > 0xFFFF:
            total_samples = 0xFFFF
        start_ts = self.ts
        sent = 0
        first = True
        while sent < total_samples:
            is_last = (sent + FRAME_SAMPLES) >= total_samples
            duration_so_far = min(sent + FRAME_SAMPLES, total_samples)
            payload = build_payload(event, is_last, duration_so_far, volume)
            hdr = rtp_header(self.seq, start_ts, self.ssrc, self.pt, first)
            first = False
            try:
                self.sock.sendto(hdr + payload, self.remote)
                self.packets_sent += 1
            except OSError:
                return
            self.seq = (self.seq + 1) & 0xFFFF
            sent += FRAME_SAMPLES
            time.sleep(0.020)
        # End-of-event redundancy — 3 packets with E bit
        for _ in range(3):
            hdr = rtp_header(self.seq, start_ts, self.ssrc, self.pt, False)
            payload = build_payload(event, True, total_samples, volume)
            try:
                self.sock.sendto(hdr + payload, self.remote)
                self.packets_sent += 1
            except OSError:
                break
            self.seq = (self.seq + 1) & 0xFFFF
            time.sleep(0.020)
        self.ts = (start_ts + total_samples) & 0xFFFFFFFF
        self.digits_sent.append(digit)

    def send_sequence(self, seq_spec: str, digit_ms: int = 200,
                      gap_ms: int = 100) -> None:
        """Send a sequence. Supports pauses with 'p500' (500 ms) tokens.
        Example: '012p500#' sends 0,1,2, waits 500 ms, sends #."""
        tokens = re.findall(r"p\d+|[0-9*#A-Dflash]", seq_spec)
        for t in tokens:
            if t.startswith("p"):
                try:
                    pause_ms = min(int(t[1:]), 60_000)   # cap at 60 s
                    time.sleep(pause_ms / 1000.0)
                except ValueError:
                    pass
                continue
            self.send_digit(t, digit_ms)
            time.sleep(gap_ms / 1000.0)
