"""Tests for scanner.srtp (SDES key exchange + protect/unprotect)."""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# Skip the whole module if cryptography isn't available — SRTP is optional
pytest.importorskip("cryptography")


class TestSdesAttribute:
    def test_keygen_correct_lengths(self):
        from scanner.srtp import generate_sdes_key
        mk, ms = generate_sdes_key()
        assert len(mk) == 16
        assert len(ms) == 14

    def test_attribute_roundtrip(self):
        from scanner.srtp import (generate_sdes_key, sdes_crypto_attribute,
                                    parse_sdes_attribute)
        mk, ms = generate_sdes_key()
        line = sdes_crypto_attribute(1, mk, ms)
        parsed = parse_sdes_attribute(line)
        assert parsed is not None
        tag, mk2, ms2 = parsed
        assert tag == 1
        assert mk2 == mk
        assert ms2 == ms

    def test_rejects_wrong_suite(self):
        from scanner.srtp import parse_sdes_attribute
        assert parse_sdes_attribute(
            "a=crypto:1 AES_CM_256_HMAC_SHA1_80 inline:Zm9v"
        ) is None

    def test_rejects_bad_key_length(self):
        from scanner.srtp import parse_sdes_attribute
        # 'too short' is way less than 30 bytes after b64 decode
        assert parse_sdes_attribute(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:dG9vc2hvcnQ="
        ) is None


class TestProtectUnprotect:
    def test_roundtrip(self):
        from scanner.srtp import SrtpContext, generate_sdes_key
        mk, ms = generate_sdes_key()
        enc = SrtpContext.from_master(mk, ms)
        dec = SrtpContext.from_master(mk, ms)
        pkt = (b"\x80\x00"
               + struct.pack("!H", 42)
               + struct.pack("!I", 12345)
               + struct.pack("!I", 0xDEADBEEF)
               + b"hello srtp" * 10)
        protected = enc.protect(pkt)
        assert len(protected) == len(pkt) + 10
        recovered = dec.unprotect(protected)
        assert recovered == pkt

    def test_tamper_detection(self):
        from scanner.srtp import SrtpContext, generate_sdes_key
        mk, ms = generate_sdes_key()
        enc = SrtpContext.from_master(mk, ms)
        pkt = (b"\x80\x00"
               + struct.pack("!H", 42)
               + struct.pack("!I", 12345)
               + struct.pack("!I", 0xDEADBEEF)
               + b"payload")
        protected = bytearray(enc.protect(pkt))
        protected[-3] ^= 0xFF
        # New context for clean state
        dec = SrtpContext.from_master(mk, ms)
        assert dec.unprotect(bytes(protected)) is None

    def test_wipe_zeroises(self):
        from scanner.srtp import SrtpContext, generate_sdes_key
        mk, ms = generate_sdes_key()
        ctx = SrtpContext.from_master(mk, ms)
        assert ctx.master_key != b"\x00" * 16
        ctx.wipe()
        assert ctx.master_key == b"\x00" * 16
        assert ctx.session_key == b"\x00" * 16
        assert ctx.auth_key == b"\x00" * 20
