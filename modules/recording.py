"""Passive RTP recorder — captures the far-end audio during a live call and
writes it to a WAV file for the client briefing report.

Runs in a background thread on the same UDP socket the tool already uses
for sending RTP (Python sockets are full-duplex, so sending and receiving
don't conflict). Decodes μ-law or A-law payloads on the fly; ignores other
payload types (DTMF, comfort-noise) so the WAV stays playable.

For the pentest demo this is the 'kill shot' evidence: the client doesn't
just read a trace — they hear their own PBX carrying the unauthorized call.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

from . import audio


class RtpRecorder:
    """Receive RTP on a bound UDP socket, decode, write WAV on stop()."""

    def __init__(
        self,
        sock: socket.socket,
        wav_path: str,
        codec: str = "PCMU",
        expected_ssrc: int | None = None,
        sample_rate: int = 8000,
    ):
        self.sock = sock
        self.wav_path = wav_path
        self.codec = (codec or "PCMU").upper()
        self.expected_ssrc = expected_ssrc
        self.sample_rate = sample_rate
        self.stop = False
        self.packets_received = 0
        self.audio_packets = 0
        self.dtmf_packets = 0
        self.bytes_received = 0
        self.first_packet_at: float | None = None
        self.last_packet_at: float | None = None
        self._samples: list[int] = []
        self._thread: threading.Thread | None = None
        self._prev_seq: int | None = None
        self.lost_packets = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def join(self, timeout: float | None = 1.5) -> None:
        if self._thread:
            self._thread.join(timeout)
        self._finalize()

    def _run(self) -> None:
        # Use a short timeout so .stop is checked frequently
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 12:
                continue
            self.packets_received += 1
            self.bytes_received += len(data)
            now = time.monotonic()
            if self.first_packet_at is None:
                self.first_packet_at = now
            self.last_packet_at = now
            # Parse RTP header
            first, second, seq, ts, ssrc = struct.unpack("!BBHII", data[:12])
            version = (first >> 6) & 0x3
            if version != 2:
                continue
            cc = first & 0x0F
            payload_offset = 12 + cc * 4
            if payload_offset > len(data):
                continue   # truncated packet — skip
            ext = (first >> 4) & 0x1
            if ext:
                if len(data) < payload_offset + 4:
                    continue   # extension header would overflow — skip
                _, ext_len_words = struct.unpack(
                    "!HH", data[payload_offset:payload_offset + 4])
                payload_offset += 4 + ext_len_words * 4
                if payload_offset > len(data):
                    continue   # extension body overflows packet — skip
            if len(data) <= payload_offset:
                continue
            pt = second & 0x7F
            payload = data[payload_offset:]
            # Sequence gap tracking
            if self._prev_seq is not None:
                expected = (self._prev_seq + 1) & 0xFFFF
                if seq != expected:
                    diff = (seq - expected) & 0xFFFF
                    if diff < 0x8000:  # don't count reordering as loss
                        self.lost_packets += diff
            self._prev_seq = seq
            # Decode
            if pt == 0:
                # PT 0 = PCMU (static, per RFC 3551)
                self.audio_packets += 1
                self._samples.extend(audio.ulaw_to_linear16(payload))
            elif pt == 8:
                self.audio_packets += 1
                self._samples.extend(audio.alaw_to_linear16(payload))
            elif pt == 101:
                self.dtmf_packets += 1
            else:
                # Unknown payload type — skip silently
                pass

    def _finalize(self) -> None:
        """Write collected samples to WAV.  Logs failures rather than
        silently swallowing them so the caller can see recording problems."""
        import logging
        try:
            audio.write_wav_samples(self.wav_path, self._samples, self.sample_rate)
        except Exception as exc:
            logging.warning("RtpRecorder._finalize: WAV write failed for %r: %s",
                            self.wav_path, exc)

    def summary(self) -> dict:
        dur = 0.0
        if self.first_packet_at and self.last_packet_at:
            dur = self.last_packet_at - self.first_packet_at
        return {
            "wav_path": self.wav_path,
            "codec": self.codec,
            "packets_received": self.packets_received,
            "audio_packets": self.audio_packets,
            "dtmf_packets": self.dtmf_packets,
            "lost_packets": self.lost_packets,
            "bytes_received": self.bytes_received,
            "audio_seconds": round(len(self._samples) / self.sample_rate, 2),
            "wall_seconds": round(dur, 2),
        }
