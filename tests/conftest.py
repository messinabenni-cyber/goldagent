"""Shared pytest fixtures for goldagent tests."""
from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Generator
from typing import Any

import pytest

from tests.mock_pbx import MockPbx


# ---------------------------------------------------------------------------
# mock_pbx_factory
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_pbx_factory() -> Generator[Any, None, None]:
    """Yield a factory that creates and starts MockPbx instances.

    Each instance is automatically stopped at the end of the test.

    Usage::

        def test_something(mock_pbx_factory):
            pbx = mock_pbx_factory(responses={
                "OPTIONS": ("200 OK", "Server: Asterisk PBX 18.1\\r\\n"),
            })
            # pbx.host and pbx.port are available immediately
    """
    created: list[MockPbx] = []

    def _factory(responses: dict[str, tuple[str, str]] | None = None) -> MockPbx:
        pbx = MockPbx(responses=responses)
        pbx.start()
        created.append(pbx)
        return pbx

    yield _factory

    for pbx in created:
        pbx.stop()


# ---------------------------------------------------------------------------
# ami_banner
# ---------------------------------------------------------------------------

@pytest.fixture
def ami_banner() -> bytes:
    """Return bytes of a typical Asterisk AMI banner as seen on TCP connect."""
    return b"Asterisk Call Manager/2.10.4\r\n"


# ---------------------------------------------------------------------------
# sip_401_challenge
# ---------------------------------------------------------------------------

@pytest.fixture
def sip_401_challenge() -> bytes:
    """Return bytes of a SIP 401 Unauthorized response with Digest challenge.

    The nonce, realm and algorithm fields match what Asterisk 18.x sends by
    default so tests can exercise the full Digest auth flow.
    """
    return (
        b"SIP/2.0 401 Unauthorized\r\n"
        b"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n"
        b"From: <sip:scanner@pbx.test>;tag=abc123\r\n"
        b"To: <sip:1000@pbx.test>\r\n"
        b"Call-ID: challenge-test@scanner\r\n"
        b"CSeq: 1 REGISTER\r\n"
        b'WWW-Authenticate: Digest realm="pbx.test", '
        b'nonce="deadbeef1234", algorithm=MD5\r\n'
        b"Content-Length: 0\r\n\r\n"
    )


# ---------------------------------------------------------------------------
# tmp_credentials_file
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_credentials_file() -> Generator[str, None, None]:
    """Create a temporary file containing test username:password pairs.

    Yields the path to the file.  The file is deleted after the test.

    Format is one ``username:password`` entry per line, matching the
    convention used throughout the scanner credential-loading helpers.
    """
    pairs = [
        "admin:admin",
        "admin:password",
        "admin:amp111",
        "1001:1001",
        "user:1234",
    ]
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="goldagent_creds_")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(pairs) + "\n")
        yield path
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# caplog_at_debug
# ---------------------------------------------------------------------------

@pytest.fixture
def caplog_at_debug(caplog: pytest.LogCaptureFixture) -> Generator[pytest.LogCaptureFixture, None, None]:
    """Set root logging level to DEBUG for the duration of the test.

    Yields the standard *caplog* fixture so callers can inspect records::

        def test_verbose(caplog_at_debug):
            do_something()
            assert any("expected message" in r.message for r in caplog_at_debug.records)
    """
    with caplog.at_level(logging.DEBUG):
        yield caplog
