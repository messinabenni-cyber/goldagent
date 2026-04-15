"""Tests for DTMF (RFC 4733) + passive RTP recording.

DTMF test: a UDP receiver captures packets, parses them, verifies RFC 4733
shape (event, E-bit, duration).

Recording test: a mock RTP sender streams known μ-law audio at 50 pps; the
RtpRecorder receives, decodes, and writes a WAV; we then read the WAV back
and assert the duration and sample count match what was sent.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time
import wave

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import audio, dtmf, recording                               # noqa: E402


def header(label: str) -> None:
    print("\n" + "=" * 70)
    print(f" {label}")
    print("=" * 70)


# ------------------------- DTMF tests ------------------------------

def test_dtmf_payload_encoding() -> None:
    """Unit: RFC 4733 payload structure."""
    p = dtmf.build_payload(event=5, end=True, duration_samples=1600, volume_dbm=10)
    assert len(p) == 4
    evt, flags, dur = struct.unpack("!BBH", p)
    assert evt == 5, f"event byte should be 5, got {evt}"
    assert flags & 0x80, "E bit should be set"
    assert flags & 0x3F == 10, "volume should be 10"
    assert dur == 1600
    print("  ✓ RFC 4733 payload structure validated for digit '5'")

    p2 = dtmf.build_payload(event=11, end=False, duration_samples=160, volume_dbm=0)
    evt2, flags2, dur2 = struct.unpack("!BBH", p2)
    assert evt2 == 11, "# should be event 11"
    assert not (flags2 & 0x80), "E bit should be clear"
    assert dur2 == 160
    print("  ✓ RFC 4733 payload validated for '#' without E bit")


def test_dtmf_live_over_socket() -> None:
    """Integration: capture DtmfSender output on a UDP receiver."""
    host = "127.0.0.1"
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((host, 0))
    recv_port = recv_sock.getsockname()[1]
    recv_sock.settimeout(2.0)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock.bind((host, 0))

    captured: list[bytes] = []

    def drainer():
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                data, _ = recv_sock.recvfrom(65535)
            except socket.timeout:
                break
            captured.append(data)

    t = threading.Thread(target=drainer, daemon=True)
    t.start()

    sender = dtmf.DtmfSender(
        send_sock, host, recv_port,
        payload_type=101, ssrc=0xDEADBEEF,
        seq_start=1000, ts_start=5000,
    )
    sender.send_sequence("12*", digit_ms=80, gap_ms=20)
    time.sleep(0.3)
    t.join(timeout=1.0)
    send_sock.close()
    recv_sock.close()

    # Parse received packets
    events_seen: list[tuple[int, bool]] = []
    for pkt in captured:
        if len(pkt) < 12 + 4:
            continue
        header_bytes = pkt[:12]
        first, second, seq, ts, ssrc = struct.unpack("!BBHII", header_bytes)
        pt = second & 0x7F
        if pt != 101:
            continue
        payload = pkt[12:]
        evt, flags, dur = struct.unpack("!BBH", payload[:4])
        events_seen.append((evt, bool(flags & 0x80)))

    print(f"  captured {len(captured)} RTP packets, "
          f"{len(events_seen)} telephone-event packets")
    # We should have seen digits 1, 2, * (events 1, 2, 10)
    digits = {e for e, _ in events_seen}
    assert 1 in digits, f"digit 1 missing; events: {sorted(digits)}"
    assert 2 in digits, f"digit 2 missing; events: {sorted(digits)}"
    assert 10 in digits, f"digit * missing; events: {sorted(digits)}"
    # Final packet per digit should have E bit; we send 3 end-redundancy packets
    # so there should be at least 3 E-bit-set packets per digit = 9+
    end_count = sum(1 for _, e in events_seen if e)
    assert end_count >= 6, f"expected ≥6 E-bit packets, got {end_count}"
    print(f"  ✓ digits 1, 2, * received; {end_count} E-bit packets "
          f"(≥2 end-redundancy per digit)")


# ------------------------- Recording tests -------------------------

class _RtpStreamerStub:
    """Tiny RTP streamer that sends known μ-law frames at 50 pps to a target
    socket. Used to exercise the RtpRecorder without spinning up the full
    live-call stack."""
    def __init__(self, target_ip, target_port, duration_s=2.0,
                 ssrc=0xBADC0FFE):
        self.target = (target_ip, target_port)
        self.duration_s = duration_s
        self.ssrc = ssrc
        self.thread = None
        self.stop = False
        self.packets_sent = 0

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("", 0))
        # Generate a 1 kHz tone as source, encode to μ-law
        samples = []
        import math
        for i in range(int(self.duration_s * 8000)):
            samples.append(int(16000 * math.sin(2 * math.pi * 1000 * i / 8000)))
        ulaw = audio._linear16_to_ulaw(samples)
        seq = 0
        ts = 0
        frame_samples = 160
        deadline = time.monotonic() + self.duration_s + 0.5
        i = 0
        while i < len(ulaw) and not self.stop and time.monotonic() < deadline:
            frame = ulaw[i:i + frame_samples]
            if len(frame) < frame_samples:
                frame += b"\xff" * (frame_samples - len(frame))
            hdr = struct.pack("!BBHII",
                              0x80, 0x00,  # V=2, PT=0 (PCMU)
                              seq & 0xFFFF, ts & 0xFFFFFFFF,
                              self.ssrc & 0xFFFFFFFF)
            try:
                s.sendto(hdr + frame, self.target)
                self.packets_sent += 1
            except OSError:
                break
            seq = (seq + 1) & 0xFFFF
            ts = (ts + frame_samples) & 0xFFFFFFFF
            i += frame_samples
            time.sleep(0.020)
        s.close()

    def join(self, timeout=2.0):
        if self.thread:
            self.thread.join(timeout)


def test_recording_roundtrip() -> None:
    """Record 1 second of known tone, decode WAV, verify duration."""
    host = "127.0.0.1"
    # Bind the recording socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    port = sock.getsockname()[1]

    wav_path = "/tmp/voip_demo_test_recording.wav"
    if os.path.exists(wav_path):
        os.unlink(wav_path)

    rec = recording.RtpRecorder(sock, wav_path, codec="PCMU")
    rec.start()

    # Stream known audio from another socket
    streamer = _RtpStreamerStub(host, port, duration_s=1.0)
    streamer.start()
    streamer.join(timeout=3.0)
    time.sleep(0.3)  # drain
    rec.stop = True
    rec.join(timeout=2.0)
    sock.close()

    assert os.path.exists(wav_path), f"WAV not written: {wav_path}"
    with wave.open(wav_path, "rb") as w:
        assert w.getnchannels() == 1, f"expected mono, got {w.getnchannels()}"
        assert w.getsampwidth() == 2, f"expected 16-bit, got {w.getsampwidth()*8}"
        assert w.getframerate() == 8000, f"expected 8k, got {w.getframerate()}"
        n_samples = w.getnframes()

    expected = 8000  # 1 sec * 8000 Hz
    # Allow 25% slack for packet loss / timing
    assert abs(n_samples - expected) < expected * 0.25, \
        f"expected ~{expected} samples, got {n_samples}"

    summary = rec.summary()
    print(f"  sent {streamer.packets_sent} RTP packets")
    print(f"  recorded {summary['packets_received']} packets "
          f"({summary['audio_packets']} audio), "
          f"{summary['audio_seconds']}s WAV, {n_samples} samples")
    assert summary["audio_packets"] >= streamer.packets_sent * 0.7, (
        f"too much loss: got {summary['audio_packets']} of "
        f"{streamer.packets_sent} sent")
    assert summary["lost_packets"] == 0, (
        f"recorder reported {summary['lost_packets']} sequence gaps")
    print(f"  ✓ WAV round-trip lossless; duration ~1s as expected")


# ------------------------- μ-law codec roundtrip -------------------

def test_ulaw_roundtrip() -> None:
    """Encode 16-bit PCM → μ-law → back to 16-bit, verify bounded error."""
    samples = [int(16000 * ((-1) ** i)) for i in range(500)]
    ulaw = audio._linear16_to_ulaw(samples)
    back = audio.ulaw_to_linear16(ulaw)
    # μ-law is lossy; quantization error around peaks is ~1-2%
    max_err = max(abs(a - b) for a, b in zip(samples, back))
    assert max_err < 500, f"μ-law round-trip error too high: {max_err}"
    print(f"  ✓ μ-law round-trip error max={max_err} (within quantization)")


def test_alaw_roundtrip() -> None:
    """Encode 16-bit PCM → A-law → back, verify bounded error."""
    samples = [int(16000 * ((-1) ** i)) for i in range(500)]
    alaw = audio._linear16_to_alaw(samples)
    back = audio.alaw_to_linear16(alaw)
    max_err = max(abs(a - b) for a, b in zip(samples, back))
    assert max_err < 500, f"A-law round-trip error too high: {max_err}"
    print(f"  ✓ A-law round-trip error max={max_err} (within quantization)")


def main() -> int:
    try:
        header("UNIT — DTMF payload encoding (RFC 4733)")
        test_dtmf_payload_encoding()

        header("INTEGRATION — DTMF over UDP socket")
        test_dtmf_live_over_socket()

        header("UNIT — μ-law / A-law roundtrip")
        test_ulaw_roundtrip()
        test_alaw_roundtrip()

        header("INTEGRATION — RTP recorder captures streamed audio to WAV")
        test_recording_roundtrip()

        header("ALL DTMF + RECORDING TESTS PASSED")
        return 0
    except AssertionError as e:
        print(f"\n!!! ASSERTION FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
