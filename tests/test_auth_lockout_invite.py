"""Tests for auth.py: lockout detection and INVITE-method spray."""
from __future__ import annotations

import os
import re
import tempfile
import threading
from unittest.mock import patch

import pytest

from scanner.auth import CredHit, spray, _try_register
from tests.mock_pbx import MockPbx


# ---------------------------------------------------------------------------
# Unit test: LOCKOUT-SUSPECTED stops the extension immediately and
# does not increment fail_counts for further attempts.
# ---------------------------------------------------------------------------

def test_lockout_stops_extension_immediately():
    """_try_register returning LOCKOUT-SUSPECTED must set stop_for_ext on first call."""
    lockout_ev = "LOCKOUT-SUSPECTED: 403 after 401 challenge -- extension may be locked"

    call_count = {"n": 0}

    def fake_try_register(host, ext, u, p, **kw):
        call_count["n"] += 1
        return False, lockout_ev

    with patch("scanner.auth._try_register", side_effect=fake_try_register):
        hits = spray(
            "127.0.0.1",
            ["1001"],
            [("admin", "admin"), ("admin", "password"), ("admin", "1234")],
            port=5060,
            timeout=0.1,
            max_workers=1,
            smart_self_password=False,
            max_failures_per_ext=3,
            method="REGISTER",
        )

    # No successful hits
    assert hits == []
    # The LOCKOUT signal should have stopped further attempts after the first call.
    # With smart_self_password=False, cred_pairs produces 3 combos (u,p) + (ext,p)*3.
    # After first LOCKOUT the ext is stopped — only 1 call should be made.
    assert call_count["n"] == 1


def test_lockout_hit_not_in_results():
    """LOCKOUT CredHit is not appended to returned hits list (success=False)."""
    lockout_ev = "LOCKOUT-SUSPECTED: 403 after 401 challenge -- extension may be locked"

    with patch("scanner.auth._try_register", return_value=(False, lockout_ev)):
        hits = spray(
            "127.0.0.1",
            ["1001"],
            [("u", "p")],
            port=5060,
            timeout=0.1,
            max_workers=1,
            smart_self_password=False,
            max_failures_per_ext=3,
            method="REGISTER",
        )

    # No successful hits returned
    assert all(not h.success for h in hits)


# ---------------------------------------------------------------------------
# Integration test: spray() with method='INVITE' sends INVITE messages.
# ---------------------------------------------------------------------------

def test_spray_invite_sends_invite_messages():
    """spray(method='INVITE') must send INVITE requests, not REGISTER."""
    pbx = MockPbx(responses={
        "INVITE": (
            "401 Unauthorized",
            'WWW-Authenticate: Digest realm="pbx.test", nonce="deadbeef", algorithm=MD5\r\n',
        ),
    })
    pbx.start()
    try:
        hits = spray(
            pbx.host,
            ["1001"],
            [("1001", "wrongpassword")],
            port=pbx.port,
            timeout=1.0,
            max_workers=1,
            smart_self_password=False,
            max_failures_per_ext=3,
            method="INVITE",
        )
        # Verify mock PBX received at least one INVITE
        invite_msgs = [
            m for m in pbx.received
            if m.split(b"\r\n", 1)[0].startswith(b"INVITE")
        ]
        assert len(invite_msgs) >= 1, "No INVITE messages were sent"
        # Verify no REGISTER was accidentally sent
        register_msgs = [
            m for m in pbx.received
            if m.split(b"\r\n", 1)[0].startswith(b"REGISTER")
        ]
        assert len(register_msgs) == 0, "REGISTER sent when method=INVITE"
    finally:
        pbx.stop()


def test_spray_register_sends_register_messages():
    """Default spray() (method='REGISTER') must send REGISTER requests."""
    pbx = MockPbx(responses={
        "REGISTER": (
            "401 Unauthorized",
            'WWW-Authenticate: Digest realm="pbx.test", nonce="deadbeef", algorithm=MD5\r\n',
        ),
    })
    pbx.start()
    try:
        hits = spray(
            pbx.host,
            ["1001"],
            [("1001", "wrongpassword")],
            port=pbx.port,
            timeout=1.0,
            max_workers=1,
            smart_self_password=False,
            max_failures_per_ext=3,
        )
        register_msgs = [
            m for m in pbx.received
            if m.split(b"\r\n", 1)[0].startswith(b"REGISTER")
        ]
        assert len(register_msgs) >= 1, "No REGISTER messages were sent"
    finally:
        pbx.stop()


# ---------------------------------------------------------------------------
# Unit test: hash_log_path produces hashcat-11400 lines on 401 challenge
# ---------------------------------------------------------------------------

def test_try_register_writes_hashcat_hash_line():
    """_try_register must write a hashcat-11400 line when hash_log_path is set."""
    pbx = MockPbx(responses={
        "REGISTER": (
            "401 Unauthorized",
            'WWW-Authenticate: Digest realm="pbxtest", nonce="aabbccdd1122", algorithm=MD5\r\n',
        ),
    })
    pbx.start()
    try:
        with tempfile.NamedTemporaryFile(mode="r", suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            _try_register(
                pbx.host, "1001", "1001", "wrongpassword",
                port=pbx.port, timeout=1.0,
                hash_log_path=tmp_path,
            )
            with open(tmp_path) as f:
                lines = [l.strip() for l in f if l.strip()]
            assert len(lines) >= 1, "No hash line written"
            pattern = re.compile(r'\w+\*\w+\*[0-9a-f]+\*sip:.*\*[0-9a-fA-F]{32,64}')
            assert pattern.match(lines[0]), f"Hash line did not match expected format: {lines[0]!r}"
        finally:
            os.unlink(tmp_path)
    finally:
        pbx.stop()
