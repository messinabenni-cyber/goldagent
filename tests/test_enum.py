"""Tests for scanner.enumeration."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


class TestExpandExtRange:
    def test_range_works(self):
        from scanner.enumeration import expand_ext_range
        assert expand_ext_range("100-109") == [str(x) for x in range(100, 110)]

    def test_at_limit_passes(self):
        from scanner.enumeration import expand_ext_range
        result = expand_ext_range("0-9999")
        assert len(result) == 10_000

    def test_too_large_raises(self):
        from scanner.enumeration import expand_ext_range
        with pytest.raises(ValueError, match="entries"):
            expand_ext_range("0-10000")

    def test_path_traversal_rejected(self):
        from scanner.enumeration import expand_ext_range
        with pytest.raises(ValueError, match="Unsafe"):
            expand_ext_range("file:../../etc/passwd")

    def test_absolute_path_rejected(self):
        from scanner.enumeration import expand_ext_range
        with pytest.raises(ValueError, match="Unsafe"):
            expand_ext_range("file:/etc/passwd")

    def test_csv_list(self):
        from scanner.enumeration import expand_ext_range
        assert expand_ext_range("1000,2000,3000") == ["1000", "2000", "3000"]

    def test_csv_with_range(self):
        from scanner.enumeration import expand_ext_range
        result = expand_ext_range("100-102, 200, 300-301")
        assert result == ["100", "101", "102", "200", "300", "301"]


class TestProbeAgainstMock:
    def test_401_marks_extension_exists_auth_required(self):
        from scanner import enumeration
        from tests.mock_pbx import MockPbx
        pbx = MockPbx(responses={
            "REGISTER": ("401 Unauthorized",
                         'WWW-Authenticate: Digest realm="pbx",'
                         ' nonce="n", algorithm=MD5\r\n'),
        })
        pbx.start()
        try:
            r = enumeration.probe(pbx.host, "1000", port=pbx.port,
                                   local_ip="127.0.0.1", timeout=1.0)
            assert r.exists
            assert r.auth_required
        finally:
            pbx.stop()

    def test_404_marks_extension_missing(self):
        from scanner import enumeration
        from tests.mock_pbx import MockPbx
        pbx = MockPbx(responses={
            "REGISTER": ("404 Not Found", ""),
        })
        pbx.start()
        try:
            r = enumeration.probe(pbx.host, "9999", port=pbx.port,
                                   local_ip="127.0.0.1", timeout=1.0)
            assert not r.exists
        finally:
            pbx.stop()

    def test_invite_200_marks_anonymous_invite(self):
        from scanner import enumeration
        from tests.mock_pbx import MockPbx
        pbx = MockPbx(responses={
            "INVITE": ("200 OK", ""),
        })
        pbx.start()
        try:
            r = enumeration.probe(pbx.host, "1000", port=pbx.port,
                                   local_ip="127.0.0.1", timeout=1.0,
                                   method="INVITE")
            assert r.exists
            assert r.anonymous_invite
        finally:
            pbx.stop()
