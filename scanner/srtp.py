"""SRTP via SDES key exchange (RFC 3711 + RFC 4568).

Implements AES_CM_128_HMAC_SHA1_80 — the cipher suite that virtually every
PBX supports. Used by the scanner to detect SRTP downgrade attacks: we
offer SRTP, see what comes back. If the PBX downgrades to plain RTP
silently, that's a finding.

The `cryptography` library is imported lazily so the scanner degrades to
plain-RTP scanning when the dependency isn't installed.
"""
from __future__ import annotations

import base64
import hmac
import os
import struct
from dataclasses import dataclass
from hashlib import sha1


SRTP_SUITE = "AES_CM_128_HMAC_SHA1_80"
SRTP_MASTER_KEY_LEN = 16
SRTP_MASTER_SALT_LEN = 14
SRTP_AUTH_TAG_LEN = 10


def _aes_cm_keystream(key: bytes, iv: bytes, nbytes: int) -> bytes:
    """AES-128 in CTR mode."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc = cipher.encryptor()
    return enc.update(b"\x00" * nbytes) + enc.finalize()


def _kdf(master_key: bytes, master_salt: bytes,
         label: int, length: int) -> bytes:
    """SRTP key-derivation (RFC 3711 §4.3.1), simplified for single-call use."""
    x = bytearray(master_salt) + b"\x00\x00"
    x[7] ^= label
    return _aes_cm_keystream(master_key, bytes(x), length)


@dataclass
class SrtpContext:
    """One-direction SRTP session state."""
    master_key: bytes
    master_salt: bytes
    session_key: bytes
    session_salt: bytes
    auth_key: bytes
    roc: int = 0
    last_seq: int | None = None

    @classmethod
    def from_master(cls, master_key: bytes, master_salt: bytes) -> "SrtpContext":
        if len(master_key) != SRTP_MASTER_KEY_LEN:
            raise ValueError(
                f"master_key must be {SRTP_MASTER_KEY_LEN} bytes, "
                f"got {len(master_key)}"
            )
        if len(master_salt) != SRTP_MASTER_SALT_LEN:
            raise ValueError(
                f"master_salt must be {SRTP_MASTER_SALT_LEN} bytes, "
                f"got {len(master_salt)}"
            )
        return cls(
            master_key=master_key,
            master_salt=master_salt,
            session_key=_kdf(master_key, master_salt, 0x00, 16),
            session_salt=_kdf(master_key, master_salt, 0x02, 14),
            auth_key=_kdf(master_key, master_salt, 0x01, 20),
        )

    def _packet_iv(self, ssrc: int, packet_index: int) -> bytes:
        salt_padded = self.session_salt + b"\x00\x00"
        xor_val = (b"\x00\x00\x00\x00"
                   + struct.pack("!I", ssrc)
                   + struct.pack("!Q", (packet_index << 16) & 0xFFFFFFFFFFFFFFFF))
        return bytes(a ^ b for a, b in zip(salt_padded, xor_val))

    def protect(self, rtp_packet: bytes) -> bytes:
        if len(rtp_packet) < 12:
            raise ValueError("RTP packet shorter than 12-byte header")
        header = rtp_packet[:12]
        payload = rtp_packet[12:]
        seq = struct.unpack("!H", header[2:4])[0]
        ssrc = struct.unpack("!I", header[8:12])[0]

        if self.last_seq is not None and seq < self.last_seq - 32768:
            self.roc = (self.roc + 1) & 0xFFFFFFFF
        self.last_seq = seq
        packet_index = (self.roc << 16) | seq

        iv = self._packet_iv(ssrc, packet_index)
        keystream = _aes_cm_keystream(self.session_key, iv, len(payload))
        encrypted = bytes(a ^ b for a, b in zip(payload, keystream))

        auth_input = header + encrypted + struct.pack("!I", self.roc)
        tag = hmac.new(self.auth_key, auth_input, sha1) \
                  .digest()[:SRTP_AUTH_TAG_LEN]
        return header + encrypted + tag

    def unprotect(self, srtp_packet: bytes) -> bytes | None:
        if len(srtp_packet) < 12 + SRTP_AUTH_TAG_LEN:
            return None
        tag = srtp_packet[-SRTP_AUTH_TAG_LEN:]
        body = srtp_packet[:-SRTP_AUTH_TAG_LEN]
        header = body[:12]
        encrypted = body[12:]

        seq = struct.unpack("!H", header[2:4])[0]
        ssrc = struct.unpack("!I", header[8:12])[0]
        if self.last_seq is not None and seq < self.last_seq - 32768:
            self.roc = (self.roc + 1) & 0xFFFFFFFF
        self.last_seq = seq
        packet_index = (self.roc << 16) | seq

        auth_input = header + encrypted + struct.pack("!I", self.roc)
        expected = hmac.new(self.auth_key, auth_input, sha1) \
                       .digest()[:SRTP_AUTH_TAG_LEN]
        if not hmac.compare_digest(expected, tag):
            return None
        iv = self._packet_iv(ssrc, packet_index)
        keystream = _aes_cm_keystream(self.session_key, iv, len(encrypted))
        payload = bytes(a ^ b for a, b in zip(encrypted, keystream))
        return header + payload

    def wipe(self) -> None:
        """Best-effort key zeroisation. Python immutables limit this — but the
        live SrtpContext won't expose plaintext keys after wipe()."""
        self.master_key = b"\x00" * len(self.master_key)
        self.master_salt = b"\x00" * len(self.master_salt)
        self.session_key = b"\x00" * len(self.session_key)
        self.session_salt = b"\x00" * len(self.session_salt)
        self.auth_key = b"\x00" * len(self.auth_key)


def generate_sdes_key() -> tuple[bytes, bytes]:
    """Return (master_key, master_salt) suitable for AES_CM_128_HMAC_SHA1_80."""
    return os.urandom(SRTP_MASTER_KEY_LEN), os.urandom(SRTP_MASTER_SALT_LEN)


def sdes_crypto_attribute(tag: int, master_key: bytes,
                          master_salt: bytes) -> str:
    """Build an SDP `a=crypto:<tag> <suite> inline:<b64>` line."""
    inline = base64.b64encode(master_key + master_salt).decode("ascii")
    return f"a=crypto:{tag} {SRTP_SUITE} inline:{inline}"


def parse_sdes_attribute(line: str) -> tuple[int, bytes, bytes] | None:
    """Parse `a=crypto:` from SDP. Returns (tag, master_key, master_salt)
    or None on unsupported suite / malformed input."""
    s = line.strip()
    if not s.lower().startswith("a=crypto:"):
        return None
    body = s.split(":", 1)[1].strip()
    parts = body.split()
    if len(parts) < 3:
        return None
    try:
        tag = int(parts[0])
    except ValueError:
        return None
    if parts[1] != SRTP_SUITE:
        return None
    inline_param = parts[2]
    if not inline_param.lower().startswith("inline:"):
        return None
    inline_b64 = inline_param.split(":", 1)[1].split("|", 1)[0]
    try:
        raw = base64.b64decode(inline_b64)
    except (ValueError, base64.binascii.Error):
        return None
    if len(raw) != SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN:
        return None
    return tag, raw[:SRTP_MASTER_KEY_LEN], raw[SRTP_MASTER_KEY_LEN:]
