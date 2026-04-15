"""Prove the tool ends the call the moment the callee (your mobile) hangs up.

The mock PBX is configured to send an in-dialog BYE to the caller 1 second
after answering (simulating you pressing End on your mobile). The tool should:
  - detect the inbound BYE
  - reply 200 OK
  - stop RTP streaming immediately
  - return hangup_side == 'remote'
  - NOT wait for --hold to elapse

The --hold is set to 30s intentionally — test fails if the tool waits for it.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import audio, live_call                                    # noqa: E402
from modules.utils import TrafficLog                                     # noqa: E402
from tests.mock_pbx import MockPbx                                       # noqa: E402


def header(label: str) -> None:
    print("\n" + "=" * 70)
    print(f" {label}")
    print("=" * 70)


def main() -> int:
    host = "127.0.0.1"
    sip_port = 55062       # different port to avoid conflicts with other tests
    rtp_port = 56002

    # Mock PBX will send BYE to us 1.0s after answering — simulating the
    # "you hang up your mobile" scenario.
    pbx = MockPbx(host=host, sip_port=sip_port, rtp_port=rtp_port,
                  answer_delay=0.2, callee_hangup_after=1.0)
    pbx.start()
    time.sleep(0.1)
    traffic_log = TrafficLog("/tmp/voip_demo_remote_hangup_traffic.log")

    try:
        header("simulating callee (mobile) hangup 1s after answer "
               "with --hold=30s")
        ulaw, label = audio.build_ulaw_payload(
            wav_file=None, message=None,
            tone_seconds=5.0, tone_freq=440.0, loop_to_seconds=30.0,
        )
        heartbeats: list[int] = []

        def on_answered(remote_media, max_hold):
            print(f"  on_answered fired  codec={remote_media.codec}  "
                  f"max_hold={max_hold}s")

        def on_heartbeat(elapsed, max_hold, pkts):
            heartbeats.append(int(elapsed))
            print(f"  heartbeat t={elapsed:.1f}s pkts={pkts}")

        t0 = time.monotonic()
        result = live_call.place_live_call(
            pbx_host=host, call_to="+15551234567", call_from="1000",
            audio_payload=ulaw, audio_label=label,
            pbx_port=sip_port,
            hold_seconds=30.0,          # 30s cap — test must NOT wait this long
            timeout=2.0,
            traffic_log=traffic_log,
            caller_id_name="Hangup Test",
            on_answered=on_answered,
            on_heartbeat=on_heartbeat,
        )
        elapsed = time.monotonic() - t0

        print(f"\n  SIP trace:")
        for ln in result.sip_trace:
            print(f"    {ln}")
        print(f"\n  success      : {result.success}")
        print(f"  hangup_side  : {result.hangup_side}")
        print(f"  total elapsed: {elapsed:.2f}s  (vs --hold=30s)")
        print(f"  RTP sent     : {result.rtp_packets_sent}")
        print(f"  mock BYE sent: {pbx.bye_sent}")

        header("ASSERTIONS")
        assert result.success, f"call should complete: {result.evidence}"
        assert result.hangup_side == "remote", (
            f"expected hangup_side='remote' (callee hung up), "
            f"got {result.hangup_side!r}")
        assert pbx.bye_sent == 1, f"mock should have sent 1 BYE, sent {pbx.bye_sent}"
        # Tool must have ended well before the 30s --hold cap (within ~3s of
        # the 1s hangup_after + handshake)
        assert elapsed < 5.0, (
            f"call should end near the 1s mark, not the 30s cap; got {elapsed:.2f}s")
        # Confirm we DID stream RTP for a meaningful slice (>30 packets in ~1s)
        assert result.rtp_packets_sent > 30, (
            f"expected RTP streaming during the ~1s active call, "
            f"got {result.rtp_packets_sent}")
        # A 200 OK response to the inbound BYE must appear in the trace
        assert any("200 OK (to BYE)" in ln for ln in result.sip_trace), (
            "SIP trace must show the 200 OK we sent to the inbound BYE")

        print("  ✓ hangup_side = 'remote'")
        print(f"  ✓ total time {elapsed:.2f}s << --hold 30s")
        print(f"  ✓ streamed {result.rtp_packets_sent} RTP packets before end")
        print(f"  ✓ 200 OK to inbound BYE present in trace")

        header("ALL REMOTE-HANGUP TESTS PASSED")
        return 0
    except AssertionError as e:
        print(f"\n!!! ASSERTION FAILED: {e}", file=sys.stderr)
        return 1
    finally:
        traffic_log.close()
        pbx.stop()


if __name__ == "__main__":
    sys.exit(main())
