"""End-to-end loopback test: run the full live-call pipeline against a mock
PBX running on localhost. Proves that discovery → enumeration → live call
with RTP streaming → BYE teardown actually works.

Run:
    python3 tests/test_livecall.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import audio, discovery, enumeration, live_call            # noqa: E402
from modules.utils import TrafficLog                                     # noqa: E402
from tests.mock_pbx import MockPbx                                       # noqa: E402


def header(label: str) -> None:
    print("\n" + "=" * 70)
    print(f" {label}")
    print("=" * 70)


def main() -> int:
    host = "127.0.0.1"
    sip_port = 55060
    rtp_port = 56000

    pbx = MockPbx(host=host, sip_port=sip_port, rtp_port=rtp_port,
                  answer_delay=0.2)
    pbx.start()
    time.sleep(0.1)
    traffic_log = TrafficLog("/tmp/voip_demo_test_traffic.log")
    try:
        # ---- Phase 1: discovery (custom port list for the mock) ----
        header("PHASE 1 — discovery against mock PBX")
        port_list = [("SIP", sip_port, "udp", "sip-options")]
        hosts = discovery.sweep(
            [host], timeout=1.0, rate_per_second=50, workers=1,
            traffic_log=traffic_log, ports=port_list,
        )
        assert hosts, "discovery should find mock PBX"
        h = hosts[0]
        assert h.sip is not None, f"expected SIP info, got {h.sip}"
        assert "MockPBX" in (h.sip.get("server", "")), h.sip
        print(f"  ✓ found {h.ip}  server={h.sip['server']!r}")

        # ---- Phase 2: enumerate one extension ----
        header("PHASE 2 — enumeration (INVITE method)")
        found = enumeration.enumerate_range(
            host, ["1000"], port=sip_port, method="INVITE",
            timeout=2.0, rate_per_second=50, traffic_log=traffic_log,
        )
        assert found, "enumeration should find ext 1000"
        ext = found[0]
        assert ext.exists, ext
        # Mock replies 100 Trying first, so scanner classifies as anon_invite
        assert ext.anonymous_invite, f"expected anonymous_invite=True, got {ext}"
        print(f"  ✓ ext {ext.extension} anonymous_invite={ext.anonymous_invite} "
              f"evidence={ext.evidence!r}")

        # ---- Phase 3: build small audio payload (avoid TTS for test stability) ----
        header("PHASE 3 — audio payload")
        # Use a pure tone to keep the test deterministic (no TTS dependency).
        # tone_seconds=3, loop to 3 for a short call
        ulaw, label = audio.build_ulaw_payload(
            wav_file=None, message=None,
            tone_seconds=3.0, tone_freq=440.0, loop_to_seconds=3.0,
        )
        print(f"  ✓ payload: {len(ulaw)} bytes, label={label!r}")
        assert 8000 * 2.5 < len(ulaw) < 8000 * 4.0, "μ-law payload size sanity"

        # ---- Phase 4: live call ----
        header("PHASE 4 — live call with RTP streaming")
        result = live_call.place_live_call(
            pbx_host=host,
            call_to="+15551234567",
            call_from="1000",
            audio_payload=ulaw,
            audio_label=label,
            pbx_port=sip_port,
            hold_seconds=2.5,
            timeout=2.0,
            traffic_log=traffic_log,
            caller_id_name="Test Harness",
        )
        print(f"  success         : {result.success}")
        print(f"  status          : {result.status_code} {result.reason}")
        print(f"  codec           : {result.codec}")
        print(f"  duration        : {result.duration_s:.2f}s")
        print(f"  RTP packets sent: {result.rtp_packets_sent}")
        print(f"  hangup side     : {result.hangup_side}")
        print(f"  audio source    : {result.audio_source}")
        print(f"  evidence        : {result.evidence}")
        print("  SIP trace:")
        for ln in result.sip_trace:
            print(f"    {ln}")

        # ---- Assertions ----
        header("ASSERTIONS")
        assert result.success, f"call should succeed: {result.evidence}"
        assert result.status_code == 200
        assert result.codec == "PCMU"
        assert result.rtp_packets_sent > 100, (
            f"expected ~125 packets for ~2.5s of 20ms frames, got "
            f"{result.rtp_packets_sent}")
        # Mock PBX should have received a proportional number of RTP packets
        # (loopback; allow some loss tolerance just in case)
        assert pbx.rtp_packets >= result.rtp_packets_sent * 0.8, (
            f"mock received {pbx.rtp_packets} RTP packets, expected "
            f">= {int(result.rtp_packets_sent * 0.8)}")
        assert pbx.rtp_first_payload_type == 0, (
            f"expected PT=0 (PCMU), got {pbx.rtp_first_payload_type}")
        assert pbx.invites_received >= 2, (
            f"expected at least 2 INVITEs (enum + live), got {pbx.invites_received}")
        assert pbx.ack_received >= 1, "mock should have received ACK"
        assert pbx.bye_received == 1, (
            f"expected 1 BYE, got {pbx.bye_received}")

        print(f"  ✓ {pbx.rtp_packets} RTP packets arrived at mock "
              f"({pbx.rtp_bytes} bytes)")
        print(f"  ✓ payload type received: {pbx.rtp_first_payload_type} (PCMU)")
        print(f"  ✓ signaling: INVITEs={pbx.invites_received}, "
              f"ACK={pbx.ack_received}, BYE={pbx.bye_received}")
        print(f"  ✓ call torn down cleanly, hangup={result.hangup_side}")

        header("ALL TESTS PASSED")
        return 0
    except AssertionError as e:
        print(f"\n!!! ASSERTION FAILED: {e}", file=sys.stderr)
        return 1
    finally:
        traffic_log.close()
        pbx.stop()


if __name__ == "__main__":
    sys.exit(main())
