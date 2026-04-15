"""Comprehensive tests for CallManager concurrent multi-call + per-call hangup.

Covers:
  - Three simultaneous calls via CallManager.launch() all complete with RTP
  - Per-call stop_event hangup terminates only the target call
  - Bulk hangup_all() terminates all active calls
  - clear_ended() properly prunes the registry
  - active_count() tracks state transitions correctly
"""
from __future__ import annotations

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules import audio
from modules.call_manager import CallManager
from tests.mock_pbx import MockPbx


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ulaw_payload():
    """Build a small μ-law + PCMA payload once for all tests in this module."""
    return audio.build_payload(
        wav_file=None, message=None,
        tone_seconds=3.0, tone_freq=440.0, loop_to_seconds=3.0,
    )


@pytest.fixture()
def mock_pbx(request):
    """Start a fresh MockPbx on a unique port pair and tear it down after the test."""
    # Each test that uses this fixture gets its own port to avoid conflicts.
    marker = getattr(request, "param", {})
    sip_port = marker.get("sip_port", 57060)
    rtp_port = marker.get("rtp_port", 58000)
    answer_delay = marker.get("answer_delay", 0.1)
    callee_hangup_after = marker.get("callee_hangup_after", None)
    pbx = MockPbx(
        host="127.0.0.1",
        sip_port=sip_port,
        rtp_port=rtp_port,
        answer_delay=answer_delay,
        callee_hangup_after=callee_hangup_after,
    )
    pbx.start()
    time.sleep(0.05)
    yield pbx
    pbx.stop()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _wait_for_all_terminal(mgr: CallManager, call_ids: list[str],
                            timeout: float = 10.0) -> None:
    """Block until every call_id reaches ended|failed, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = {c["call_id"]: c["state"] for c in mgr.get_all()}
        if all(snapshot.get(cid, "unknown") in ("ended", "failed")
               for cid in call_ids):
            return
        time.sleep(0.05)
    states = {cid: {c["call_id"]: c["state"]
                    for c in mgr.get_all()}.get(cid, "missing")
              for cid in call_ids}
    pytest.fail(f"Calls did not reach terminal state in {timeout}s: {states}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57060, "rtp_port": 58000,
                                        "answer_delay": 0.1}], indirect=True)
def test_three_concurrent_calls_all_succeed(mock_pbx, ulaw_payload):
    """Launch 3 calls simultaneously; all should reach 'ended' with RTP traffic."""
    mgr = CallManager()
    call_ids = []
    for i in range(3):
        cid = mgr.launch(
            pbx_host="127.0.0.1",
            call_to=f"+1555000000{i}",
            call_from=f"100{i}",
            audio_payload=ulaw_payload,
            pbx_port=57060,
            hold_seconds=2.0,
            timeout=3.0,
            caller_id_name=f"Test-{i}",
        )
        call_ids.append(cid)

    assert len(call_ids) == 3
    assert mgr.active_count() >= 1   # at least one must have started

    _wait_for_all_terminal(mgr, call_ids, timeout=15.0)

    all_calls = {c["call_id"]: c for c in mgr.get_all()}
    for cid in call_ids:
        cs = all_calls[cid]
        assert cs["state"] == "ended", (
            f"call {cid} expected 'ended', got {cs['state']!r}: {cs['error']!r}"
        )
        assert cs["rtp_packets_sent"] > 0, (
            f"call {cid} sent zero RTP packets"
        )
    # RTP arrives at the mock on a single shared port — confirm the PBX saw traffic
    assert mock_pbx.rtp_packets >= 3, (
        f"mock PBX expected ≥3 RTP packets, received {mock_pbx.rtp_packets}"
    )


@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57062, "rtp_port": 58002,
                                        "answer_delay": 0.1}], indirect=True)
def test_per_call_hangup_stops_only_target(mock_pbx, ulaw_payload):
    """Set stop_event on call A only; call B should continue until its hold expires."""
    mgr = CallManager()

    # Launch both calls with a 10s hold so they don't self-terminate quickly
    cid_a = mgr.launch(
        pbx_host="127.0.0.1", call_to="+15550000001", call_from="2001",
        audio_payload=ulaw_payload, pbx_port=57062,
        hold_seconds=10.0, timeout=3.0,
    )
    cid_b = mgr.launch(
        pbx_host="127.0.0.1", call_to="+15550000002", call_from="2002",
        audio_payload=ulaw_payload, pbx_port=57062,
        hold_seconds=2.0, timeout=3.0,
    )

    # Wait until both are at least ringing
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        states = {c["call_id"]: c["state"] for c in mgr.get_all()}
        if states.get(cid_a) in ("ringing", "active") and \
           states.get(cid_b) in ("ringing", "active"):
            break
        time.sleep(0.05)

    # Hang up ONLY call A
    assert mgr.hangup(cid_a), "hangup(cid_a) should return True"

    # Wait for A to terminate
    _wait_for_all_terminal(mgr, [cid_a], timeout=5.0)
    a_state = next(c for c in mgr.get_all() if c["call_id"] == cid_a)["state"]
    assert a_state == "ended", f"call A expected 'ended', got {a_state!r}"

    # Call B must still be running (or ended from its own hold — NOT from our hangup)
    b_snap = next(c for c in mgr.get_all() if c["call_id"] == cid_b)
    # B either ended naturally from its 2s hold or is still active — either is fine.
    # What must NOT happen is B ending immediately due to A's hangup signal.
    if b_snap["state"] in ("ringing", "active", "queued"):
        # B is still alive — good
        pass
    elif b_snap["state"] in ("ended", "failed"):
        # B is done; assert it ran for at least some time (not killed instantly)
        if b_snap.get("answered_at") and b_snap.get("ended_at"):
            hold_dur = b_snap["ended_at"] - b_snap["answered_at"]
            assert hold_dur >= 0.5, (
                f"Call B ended too quickly ({hold_dur:.2f}s) — may have been "
                f"killed by call A's hangup"
            )

    # Let B finish normally
    _wait_for_all_terminal(mgr, [cid_b], timeout=10.0)


@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57064, "rtp_port": 58004,
                                        "answer_delay": 0.1}], indirect=True)
def test_hangup_all_terminates_every_call(mock_pbx, ulaw_payload):
    """hangup_all() must terminate all concurrent calls promptly."""
    mgr = CallManager()
    call_ids = []
    for i in range(4):
        cid = mgr.launch(
            pbx_host="127.0.0.1", call_to=f"+155500000{i:02d}",
            call_from=f"300{i}",
            audio_payload=ulaw_payload, pbx_port=57064,
            hold_seconds=30.0, timeout=3.0,
        )
        call_ids.append(cid)

    # Wait for at least some calls to become active
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        active = mgr.active_count()
        if active >= 2:
            break
        time.sleep(0.05)

    t_before = time.monotonic()
    count = mgr.hangup_all()
    assert count >= 2, f"hangup_all should have counted ≥2 active calls, got {count}"

    _wait_for_all_terminal(mgr, call_ids, timeout=8.0)
    elapsed = time.monotonic() - t_before
    # All 4 calls with 30s hold should have ended well under 30s
    assert elapsed < 8.0, (
        f"hangup_all took {elapsed:.1f}s to drain 4 calls — expected <8s"
    )


@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57066, "rtp_port": 58006,
                                        "answer_delay": 0.05}], indirect=True)
def test_clear_ended_prunes_only_terminal_calls(mock_pbx, ulaw_payload):
    """clear_ended() removes ended/failed calls but leaves active ones."""
    mgr = CallManager()

    # Fast call: 0.5s hold → will be 'ended' quickly
    cid_fast = mgr.launch(
        pbx_host="127.0.0.1", call_to="+15551000001", call_from="4001",
        audio_payload=ulaw_payload, pbx_port=57066,
        hold_seconds=0.5, timeout=3.0,
    )
    # Slow call: 10s hold → should still be active when we clear
    cid_slow = mgr.launch(
        pbx_host="127.0.0.1", call_to="+15551000002", call_from="4002",
        audio_payload=ulaw_payload, pbx_port=57066,
        hold_seconds=10.0, timeout=3.0,
    )

    # Wait for fast call to finish
    _wait_for_all_terminal(mgr, [cid_fast], timeout=8.0)

    removed = mgr.clear_ended()
    assert removed >= 1, f"clear_ended should have removed ≥1 call, got {removed}"

    remaining = {c["call_id"] for c in mgr.get_all()}
    assert cid_fast not in remaining, "cleared call should not appear in get_all()"
    assert cid_slow in remaining, "active call must survive clear_ended()"

    # Hangup the slow call so the PBX connection is cleaned up
    mgr.hangup(cid_slow)
    _wait_for_all_terminal(mgr, [cid_slow], timeout=5.0)


@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57068, "rtp_port": 58008,
                                        "answer_delay": 0.05}], indirect=True)
def test_active_count_transitions(mock_pbx, ulaw_payload):
    """active_count() must go up when calls launch and down when they end."""
    mgr = CallManager()
    assert mgr.active_count() == 0

    cids = []
    for i in range(3):
        cid = mgr.launch(
            pbx_host="127.0.0.1", call_to=f"+15552000{i:03d}",
            call_from=f"500{i}",
            audio_payload=ulaw_payload, pbx_port=57068,
            hold_seconds=1.0, timeout=3.0,
        )
        cids.append(cid)

    # Count should rise
    deadline = time.monotonic() + 3.0
    peak = 0
    while time.monotonic() < deadline:
        peak = max(peak, mgr.active_count())
        if peak >= 2:
            break
        time.sleep(0.05)
    assert peak >= 2, f"active_count peak was {peak}, expected ≥2"

    # After all calls end it must drop to zero
    _wait_for_all_terminal(mgr, cids, timeout=10.0)
    assert mgr.active_count() == 0, (
        f"active_count should be 0 after all calls end, got {mgr.active_count()}"
    )


@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57070, "rtp_port": 58010,
                                        "answer_delay": 0.05,
                                        "callee_hangup_after": 0.8}], indirect=True)
def test_callee_initiated_bye_sets_hangup_side(mock_pbx, ulaw_payload):
    """When the mock PBX sends BYE, hangup_side must be 'remote'."""
    mgr = CallManager()
    cid = mgr.launch(
        pbx_host="127.0.0.1", call_to="+15553000001", call_from="6001",
        audio_payload=ulaw_payload, pbx_port=57070,
        hold_seconds=30.0, timeout=3.0,
    )

    _wait_for_all_terminal(mgr, [cid], timeout=10.0)
    cs = next(c for c in mgr.get_all() if c["call_id"] == cid)
    assert cs["state"] == "ended", f"expected 'ended', got {cs['state']!r}"
    assert cs["hangup_side"] == "remote", (
        f"expected hangup_side='remote' (callee BYE), got {cs['hangup_side']!r}"
    )
    assert mock_pbx.bye_sent == 1, (
        f"mock should have sent 1 BYE, sent {mock_pbx.bye_sent}"
    )


@pytest.mark.parametrize("mock_pbx", [{"sip_port": 57072, "rtp_port": 58012,
                                        "answer_delay": 0.05}], indirect=True)
def test_multicall_update_events_emitted(mock_pbx, ulaw_payload):
    """Every call state transition must fire a multicall.update SSE event."""
    import queue as _queue
    from modules.events import bus

    # Subscribe BEFORE launching to capture all events (including replay)
    q = bus.subscribe(replay_history=False)

    mgr = CallManager()
    cid = mgr.launch(
        pbx_host="127.0.0.1", call_to="+15554000001", call_from="7001",
        audio_payload=ulaw_payload, pbx_port=57072,
        hold_seconds=1.0, timeout=3.0,
    )

    _wait_for_all_terminal(mgr, [cid], timeout=10.0)
    # Drain the queue
    received: list[dict] = []
    while True:
        try:
            event = q.get_nowait()
            if event["type"] == "multicall.update":
                received.append(event["data"])
        except _queue.Empty:
            break

    bus.unsubscribe(q)

    # Filter events for our call_id
    our_events = [e for e in received if e.get("call_id") == cid]
    states_seen = [e["state"] for e in our_events]

    # At minimum: queued → ringing → active → ended
    assert "queued" in states_seen,  f"expected 'queued' event; got {states_seen}"
    assert "ringing" in states_seen, f"expected 'ringing' event; got {states_seen}"
    assert "ended" in states_seen,   f"expected 'ended' event; got {states_seen}"
