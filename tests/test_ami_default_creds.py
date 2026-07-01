"""Unit tests for scanner.ami.probe_ami_default_creds."""
from __future__ import annotations

import socket
import threading
from unittest.mock import MagicMock, call, patch


# ---------------------------------------------------------------------------
# Mock socket factory
# ---------------------------------------------------------------------------

def _make_mock_sock(recv_data: list[bytes]) -> MagicMock:
    """Return a mock socket that serves *recv_data* chunks in sequence."""
    sock = MagicMock()
    recv_iter = iter(recv_data)

    def _recv(size):
        try:
            return next(recv_iter)
        except StopIteration:
            raise socket.timeout("mock timeout")

    sock.recv.side_effect = _recv
    return sock


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProbeAmiDefaultCreds:
    def _import(self):
        from scanner.ami import probe_ami_default_creds
        return probe_ami_default_creds

    def test_no_connection_returns_empty(self):
        """When the TCP connect fails, return []."""
        probe = self._import()
        with patch("socket.socket") as MockSock:
            instance = MockSock.return_value
            instance.connect.side_effect = OSError("Connection refused")
            result = probe("127.0.0.1", port=5038, timeout=0.5)
        assert result == []

    def test_non_ami_banner_returns_empty(self):
        """Non-AMI banner (e.g. SSH) causes early return of []."""
        probe = self._import()
        with patch("socket.socket") as MockSock:
            instance = MockSock.return_value
            instance.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
            result = probe("127.0.0.1", port=5038, timeout=0.5)
        assert result == []

    def test_all_creds_rejected_returns_empty(self):
        """All credential pairs return 'Response: Error' — no finding returned."""
        from scanner.ami import _PROBE_CREDS
        probe = self._import()

        # We need separate socket instances: one for banner read, then one per cred pair.
        sockets_issued: list[MagicMock] = []

        ami_banner = b"Asterisk Call Manager/2.10.4\r\n"
        error_resp = b"Response: Error\r\nMessage: Authentication failed\r\n\r\n"

        def _new_sock(*args, **kwargs):
            if not sockets_issued:
                # First socket: banner read
                sock = _make_mock_sock([ami_banner])
            else:
                # Subsequent sockets: banner + error response
                sock = _make_mock_sock([ami_banner, error_resp])
            sockets_issued.append(sock)
            return sock

        with patch("socket.socket", side_effect=_new_sock):
            result = probe("127.0.0.1", port=5038, timeout=0.5)

        assert result == []
        # Consumed: 1 banner socket + len(creds) login sockets
        assert len(sockets_issued) == 1 + len(_PROBE_CREDS)

    def test_first_cred_succeeds_returns_critical_finding(self):
        """admin/amp111 succeeds on first attempt — one CRITICAL CveResult returned."""
        probe = self._import()

        ami_banner = b"Asterisk Call Manager/2.10.4\r\n"
        login_ok = b"Response: Success\r\nMessage: Authentication accepted\r\n\r\n"
        sip_peers_output = (
            b"Response: Follows\r\n"
            b"Output: 1001/1001  192.168.1.2  D  5060  OK (24 ms)\r\n"
            b"Output: 1 sip peers\r\n\r\n"
        )

        sockets_issued: list[MagicMock] = []

        def _new_sock(*args, **kwargs):
            if not sockets_issued:
                sock = _make_mock_sock([ami_banner])
            else:
                sock = _make_mock_sock([ami_banner, login_ok, sip_peers_output])
            sockets_issued.append(sock)
            return sock

        with patch("socket.socket", side_effect=_new_sock):
            result = probe("127.0.0.1", port=5038, timeout=0.5)

        assert len(result) == 1
        r = result[0]
        assert r.cve_id == "CONFIG-AMI-DEFAULT-CREDS"
        assert r.severity == "critical"
        assert r.host == "127.0.0.1"
        assert r.port == 5038
        assert "admin" in r.evidence
        assert "amp111" in r.evidence

    def test_finding_evidence_contains_peer_list_snippet(self):
        """Evidence string must include the captured sip show peers output."""
        probe = self._import()

        ami_banner = b"Asterisk Call Manager/2.10.4\r\n"
        login_ok = b"Response: Success\r\nMessage: Authentication accepted\r\n\r\n"
        peer_data = b"Output: 1001/1001  192.168.1.2  D  5060  OK\r\nOutput: 1 sip peers\r\n\r\n"

        sockets_issued: list[MagicMock] = []

        def _new_sock(*args, **kwargs):
            if not sockets_issued:
                sock = _make_mock_sock([ami_banner])
            else:
                sock = _make_mock_sock([ami_banner, login_ok, peer_data])
            sockets_issued.append(sock)
            return sock

        with patch("socket.socket", side_effect=_new_sock):
            result = probe("127.0.0.1", port=5038, timeout=0.5)

        assert len(result) == 1
        assert "1001" in result[0].evidence

    def test_second_cred_pair_succeeds_after_first_fails(self):
        """admin/amp111 fails then admin/admin succeeds — still one critical finding."""
        probe = self._import()

        ami_banner = b"Asterisk Call Manager/2.10.4\r\n"
        login_err = b"Response: Error\r\nMessage: Authentication failed\r\n\r\n"
        login_ok = b"Response: Success\r\nMessage: Authentication accepted\r\n\r\n"
        peer_data = b"Output: 0 sip peers\r\n\r\n"

        call_count = [0]

        def _new_sock(*args, **kwargs):
            n = call_count[0]
            call_count[0] += 1
            if n == 0:
                return _make_mock_sock([ami_banner])
            elif n == 1:
                # admin/amp111 fails
                return _make_mock_sock([ami_banner, login_err])
            else:
                # admin/admin succeeds
                return _make_mock_sock([ami_banner, login_ok, peer_data])

        with patch("socket.socket", side_effect=_new_sock):
            result = probe("127.0.0.1", port=5038, timeout=0.5)

        assert len(result) == 1
        r = result[0]
        assert r.cve_id == "CONFIG-AMI-DEFAULT-CREDS"
        assert r.severity == "critical"
        assert "admin" in r.evidence

    def test_returns_only_one_finding_on_success(self):
        """probe_ami_default_creds stops after the first success and returns exactly 1 result."""
        probe = self._import()

        ami_banner = b"Asterisk Call Manager/2.10.4\r\n"
        login_ok = b"Response: Success\r\nMessage: Authentication accepted\r\n\r\n"
        peer_data = b"Output: 0 sip peers\r\n\r\n"

        call_count = [0]
        sockets_created = [0]

        def _new_sock(*args, **kwargs):
            n = call_count[0]
            call_count[0] += 1
            sockets_created[0] += 1
            if n == 0:
                return _make_mock_sock([ami_banner])
            else:
                return _make_mock_sock([ami_banner, login_ok, peer_data])

        with patch("socket.socket", side_effect=_new_sock):
            result = probe("127.0.0.1", port=5038, timeout=0.5)

        assert len(result) == 1
        # Only banner + one login session should have been created (stopped on first success)
        assert sockets_created[0] == 2
