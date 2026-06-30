"""Tests for scanner.call.discover_dialplan_prefix."""
from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_result(reached=False, success=False):
    from scanner.call import CallResult
    return CallResult(
        success=success, reached_dialplan=reached,
        status_code=180 if reached else 404,
        reason="Ringing" if reached else "Not Found",
        evidence="test", sip_trace=[],
    )


class TestDiscoverDialplanPrefix:
    def test_bare_number_works(self):
        from scanner.call import discover_dialplan_prefix
        results = [_make_result(reached=True)]
        with patch("scanner.call.place_call", side_effect=results):
            prefix, dest = discover_dialplan_prefix(
                "10.0.0.1", "+447900900900", "1000",
                prefixes=[""],
            )
        assert prefix == ""
        assert dest == "+447900900900"

    def test_prefix_9_selected(self):
        from scanner.call import discover_dialplan_prefix
        # First call (bare) fails, second (prefix "9") succeeds
        results = [
            _make_result(reached=False),
            _make_result(reached=True),
        ]
        with patch("scanner.call.place_call", side_effect=results):
            prefix, dest = discover_dialplan_prefix(
                "10.0.0.1", "447900900900", "1000",
                prefixes=["", "9"],
            )
        assert prefix == "9"
        assert dest == "9447900900900"

    def test_no_prefix_works(self):
        from scanner.call import discover_dialplan_prefix
        results = [_make_result(reached=False), _make_result(reached=False)]
        with patch("scanner.call.place_call", side_effect=results):
            prefix, dest = discover_dialplan_prefix(
                "10.0.0.1", "+447900900900", "1000",
                prefixes=["", "9"],
            )
        assert prefix is None
        assert dest == "+447900900900"

    def test_default_prefixes_used_when_none(self):
        from scanner.call import discover_dialplan_prefix, DIALPLAN_PREFIXES
        # Just verify it tries DIALPLAN_PREFIXES when prefixes=None
        call_count = []
        def fake_place(*a, **kw):
            call_count.append(1)
            return _make_result(reached=False)

        with patch("scanner.call.place_call", side_effect=fake_place):
            discover_dialplan_prefix("10.0.0.1", "+1234567890", "1000")

        assert len(call_count) == len(DIALPLAN_PREFIXES)
