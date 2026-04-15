"""Audio generation and G.711 μ-law encoding for RTP streaming.

No third-party dependencies. Python 3.13+ removed the stdlib `audioop` module
so we implement μ-law encoding directly. Three sources of audio supported:
  - WAV file (8 kHz mono 16-bit PCM required; resample beforehand)
  - Spoken message via macOS `say` (or Linux `espeak` if present)
  - Synthesized sine tone (fallback, always works)
"""
from __future__ import annotations

import math
import os
import shutil
import struct
import subprocess
import tempfile
import wave


DEFAULT_MESSAGE = (
    "This is an authorized penetration test. "
    "Your VoIP system accepted this call without proper authentication. "
    "Please contact your security team immediately."
)


def _read_wav_pcm16_8k_mono(path: str) -> list[int]:
    """Read a WAV file, return list of signed 16-bit samples at 8 kHz mono.
    Refuses to load anything that isn't already in that format — resample
    upstream with ffmpeg/sox/afconvert if needed."""
    with wave.open(path, "rb") as w:
        if w.getnchannels() != 1:
            raise ValueError(f"{path}: must be mono (got {w.getnchannels()} channels)")
        if w.getsampwidth() != 2:
            raise ValueError(f"{path}: must be 16-bit PCM (got {w.getsampwidth()*8}-bit)")
        if w.getframerate() != 8000:
            raise ValueError(f"{path}: must be 8000 Hz (got {w.getframerate()} Hz)")
        n = w.getnframes()
        raw = w.readframes(n)
    return list(struct.unpack(f"<{n}h", raw))


def _generate_tone(duration_s: float, freq: float = 440.0,
                   sample_rate: int = 8000, amplitude: int = 16000) -> list[int]:
    """Generate a mono 16-bit PCM sine wave."""
    n = int(duration_s * sample_rate)
    two_pi_f = 2.0 * math.pi * freq
    return [
        int(amplitude * math.sin(two_pi_f * i / sample_rate))
        for i in range(n)
    ]


def _tts_to_pcm16_8k(text: str) -> list[int] | None:
    """Use `say` (macOS) or `espeak` (Linux) to produce a spoken message
    as 8 kHz mono 16-bit PCM. Returns None if no TTS engine is available."""
    tmpdir = tempfile.mkdtemp(prefix="voip-demo-")
    wav_path = os.path.join(tmpdir, "msg.wav")
    try:
        if shutil.which("say"):
            # macOS: output WAV directly at 8 kHz mono 16-bit LE
            subprocess.run(
                ["say", "-o", wav_path,
                 "--data-format=LEI16@8000", "--channels=1", text],
                check=True, stderr=subprocess.DEVNULL,
            )
        elif shutil.which("espeak") or shutil.which("espeak-ng"):
            binary = shutil.which("espeak-ng") or shutil.which("espeak")
            subprocess.run(
                [binary, "-w", wav_path, "-s", "160", text],
                check=True, stderr=subprocess.DEVNULL,
            )
            # espeak outputs 22050 Hz by default; try to resample via ffmpeg if needed
            try:
                with wave.open(wav_path, "rb") as w:
                    if w.getframerate() != 8000 and shutil.which("ffmpeg"):
                        resampled = os.path.join(tmpdir, "msg_8k.wav")
                        subprocess.run(
                            ["ffmpeg", "-y", "-i", wav_path, "-ar", "8000",
                             "-ac", "1", "-sample_fmt", "s16", resampled],
                            check=True, stderr=subprocess.DEVNULL,
                        )
                        wav_path = resampled
            except Exception:
                return None
        else:
            return None
        return _read_wav_pcm16_8k_mono(wav_path)
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
        return None
    finally:
        try:
            for f in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)
        except OSError:
            pass


def _linear16_to_ulaw(samples: list[int]) -> bytes:
    """G.711 μ-law encoder (ITU-T G.711 Annex A). Input: signed 16-bit PCM."""
    out = bytearray(len(samples))
    BIAS = 0x84
    CLIP = 32635
    for i, s in enumerate(samples):
        if s > 32767:
            s = 32767
        elif s < -32768:
            s = -32768
        sign = 0
        if s < 0:
            s = -s
            sign = 0x80
        if s > CLIP:
            s = CLIP
        s += BIAS
        exponent = 7
        mask = 0x4000
        while (s & mask) == 0 and exponent > 0:
            exponent -= 1
            mask >>= 1
        mantissa = (s >> (exponent + 3)) & 0x0F
        out[i] = (~(sign | (exponent << 4) | mantissa)) & 0xFF
    return bytes(out)


def ulaw_to_linear16(payload: bytes) -> list[int]:
    """Inverse of _linear16_to_ulaw — decode μ-law bytes to 16-bit PCM."""
    BIAS = 0x84
    out: list[int] = []
    for b in payload:
        bv = (~b) & 0xFF
        sign = bv & 0x80
        exponent = (bv >> 4) & 0x07
        mantissa = bv & 0x0F
        sample = ((mantissa << 3) + BIAS) << exponent
        sample -= BIAS
        if sign:
            sample = -sample
        out.append(sample)
    return out


def alaw_to_linear16(payload: bytes) -> list[int]:
    """Inverse of _linear16_to_alaw — decode A-law bytes to 16-bit PCM."""
    out: list[int] = []
    for b in payload:
        bv = b ^ 0x55
        sign = bv & 0x80
        exponent = (bv >> 4) & 0x07
        mantissa = bv & 0x0F
        if exponent == 0:
            sample = (mantissa << 4) + 8
        else:
            sample = ((mantissa << 4) + 0x108) << (exponent - 1)
        if sign == 0:
            sample = -sample
        out.append(sample)
    return out


def write_wav_samples(path: str, samples: list[int], sample_rate: int = 8000) -> None:
    """Write 16-bit mono PCM samples to a WAV file."""
    import struct
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        if samples:
            w.writeframes(struct.pack(f"<{len(samples)}h",
                                      *[max(-32768, min(32767, s)) for s in samples]))


def _linear16_to_alaw(samples: list[int]) -> bytes:
    """G.711 A-law encoder (ITU-T G.711 Annex B). Input: signed 16-bit PCM.

    A-law is the European / most-of-world complement of μ-law — offered by
    default alongside PCMU in our SDP so PBXes which prefer PCMA can select
    it. Output bytes are XOR'd with 0x55 per the spec (sign-bit toggling
    to keep consecutive zeroes out of the serial line)."""
    out = bytearray(len(samples))
    CLIP = 32635
    for i, s in enumerate(samples):
        if s > 32767:
            s = 32767
        elif s < -32768:
            s = -32768
        sign = 0x80
        if s < 0:
            s = -s - 1 if s > -32768 else 32767
            sign = 0x00
        if s > CLIP:
            s = CLIP
        if s >= 256:
            exponent = 7
            mask = 0x4000
            while (s & mask) == 0 and exponent > 0:
                exponent -= 1
                mask >>= 1
            mantissa = (s >> (exponent + 3)) & 0x0F
            alaw = (exponent << 4) | mantissa
        else:
            alaw = s >> 4
        out[i] = (alaw | sign) ^ 0x55
    return bytes(out)


def build_payload(
    wav_file: str | None = None,
    message: str | None = None,
    tone_seconds: float = 15.0,
    tone_freq: float = 440.0,
    loop_to_seconds: float | None = None,
) -> dict:
    """Build audio payload in every codec we might negotiate.

    Precedence for source: wav_file > message (TTS) > tone.
    Returns a dict with:
        "PCMU"  -> bytes (μ-law, PT=0, universal)
        "PCMA"  -> bytes (A-law, PT=8, European default)
        "label" -> str   (human-readable source)
    """
    samples: list[int] | None = None
    label = ""
    if wav_file:
        samples = _read_wav_pcm16_8k_mono(wav_file)
        label = f"wav:{os.path.basename(wav_file)}"
    elif message:
        samples = _tts_to_pcm16_8k(message)
        label = "tts:system-tts" if samples else "tts:unavailable"
    if not samples:
        samples = _generate_tone(tone_seconds, tone_freq)
        label = label or f"tone:{int(tone_freq)}Hz"
    if loop_to_seconds:
        # Hard cap: 2 hours. Prevents a bad config / compromised caller from
        # allocating multi-GB audio buffers. 2h @ 8kHz mono PCM16 = ~115 MB.
        _MAX_LOOP_SECONDS = 7200
        if loop_to_seconds > _MAX_LOOP_SECONDS:
            loop_to_seconds = _MAX_LOOP_SECONDS
        target = int(loop_to_seconds * 8000)
        if len(samples) < target:
            silence = [0] * 4000
            padded: list[int] = []
            while len(padded) < target:
                padded.extend(samples)
                padded.extend(silence)
            samples = padded[:target]
    return {
        "PCMU": _linear16_to_ulaw(samples),
        "PCMA": _linear16_to_alaw(samples),
        "label": label,
    }


def build_ulaw_payload(
    wav_file: str | None = None,
    message: str | None = None,
    tone_seconds: float = 15.0,
    tone_freq: float = 440.0,
    loop_to_seconds: float | None = None,
) -> tuple[bytes, str]:
    """Back-compat shim — returns only the μ-law bytes + label."""
    p = build_payload(wav_file, message, tone_seconds, tone_freq, loop_to_seconds)
    return p["PCMU"], p["label"]
