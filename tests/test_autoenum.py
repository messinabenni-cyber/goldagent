"""End-to-end test of the auto-enumerate flow.

Starts a mock SIP PBX + mock AMI on localhost, then verifies:
  - Discovery sees both SIP and AMI
  - auto_enumerate pwns AMI with default creds (admin:amp111)
  - Every AMI-dumped extension gets INVITE-probed and classified
  - The attack matrix identifies anon-INVITE capability
  - A live call via the discovered path completes with RTP
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import (audio, auth_test, discovery, enumeration,          # noqa: E402
                     live_call)
from modules.utils import TrafficLog                                     # noqa: E402
from tests.mock_pbx import MockAmi, MockPbx                              # noqa: E402


def header(label: str) -> None:
    print("\n" + "=" * 70)
    print(f" {label}")
    print("=" * 70)


def main() -> int:
    host = "127.0.0.1"
    sip_port = 55060
    rtp_port = 56000
    ami_port = 55038
    mock_extensions = ["1000", "1001", "1002", "2005"]

    pbx = MockPbx(host=host, sip_port=sip_port, rtp_port=rtp_port,
                  answer_delay=0.2)
    ami = MockAmi(host=host, port=ami_port,
                  accept_creds=("admin", "amp111"),
                  extensions=mock_extensions)
    pbx.start()
    ami.start()
    time.sleep(0.1)
    traffic_log = TrafficLog("/tmp/voip_demo_autoenum_traffic.log")

    try:
        # ---- Phase 1: discovery should see BOTH SIP + AMI ----
        header("PHASE 1 — discovery (SIP + AMI)")
        port_list = [
            ("SIP", sip_port, "udp", "sip-options"),
            ("Asterisk-AMI", ami_port, "tcp", "tcp-connect"),
        ]
        hosts = discovery.sweep(
            [host], timeout=1.0, rate_per_second=100, workers=1,
            traffic_log=traffic_log, ports=port_list,
        )
        assert hosts, "discovery should find mock PBX"
        h = hosts[0]
        assert h.sip is not None
        svc_seen = {p["service"] for p in h.open_ports}
        assert "SIP" in svc_seen, f"SIP not detected: {svc_seen}"
        assert "Asterisk-AMI" in svc_seen, f"AMI not detected: {svc_seen}"
        ami_hint = True
        print(f"  ✓ host {h.ip}  services: {', '.join(sorted(svc_seen))}")

        # ---- Phase 2: auto-enumerate — should pwn AMI and list all ext ----
        header("PHASE 2 — auto-enumerate (AMI → adaptive sweep → specials)")
        auto = enumeration.auto_enumerate(
            h.ip, port=sip_port,
            fingerprint="Asterisk",    # we'd fingerprint from banner in prod
            try_ami=ami_hint,
            ami_port=ami_port,
            include_specials=False,     # keep the test fast
            custom_ranges=[(1000, 1050)],  # small range for test speed
            coarse_step=10, fill_radius=9,
            timeout=1.5, rate_per_second=200,
            traffic_log=traffic_log,
        )
        print(f"  method         : {auto.method}")
        print(f"  AMI succeeded? : {bool(auto.ami and auto.ami.success)}")
        if auto.ami:
            print(f"  AMI creds      : {auto.ami.username}:{auto.ami.password}")
            print(f"  AMI dump count : {len(auto.ami.extensions)}")
        print(f"  total extensions discovered: {len(auto.extensions)}")
        for e in auto.extensions:
            flags = []
            if e.anonymous_invite: flags.append("ANON-INVITE")
            if e.open_register:    flags.append("OPEN-REGISTER")
            print(f"    {e.extension:<12} [{','.join(flags) or 'exists'}]")

        # ---- Assertions on enumeration ----
        found_exts = {e.extension for e in auto.extensions}
        assert auto.ami and auto.ami.success, "AMI should have pwned"
        assert auto.ami.username == "admin" and auto.ami.password == "amp111"
        # Every mock extension should be in the final list
        for ext in mock_extensions:
            assert ext in found_exts, f"missing {ext} from AMI dump"
        # Because mock replies 100 Trying to all INVITEs, all should show
        # anonymous_invite=True after the follow-up probe
        anon_exts = {e.extension for e in auto.extensions if e.anonymous_invite}
        assert anon_exts >= set(mock_extensions), (
            f"expected all {mock_extensions} to show anonymous_invite, "
            f"got {anon_exts}"
        )
        # Also confirm mock AMI saw the right login
        assert ami.successful_logins == 1, (
            f"expected 1 successful AMI login, got {ami.successful_logins}")
        print(f"  ✓ assertions pass — AMI ext list matches, anon-INVITE "
              f"flagged on all")

        # ---- Phase 3: live call using the first discovered path ----
        header("PHASE 3 — live call via auto-discovered extension")
        target_ext = sorted(anon_exts, key=lambda x: (len(x), x))[0]
        ulaw, label = audio.build_ulaw_payload(
            wav_file=None, message=None,
            tone_seconds=2.0, tone_freq=440.0, loop_to_seconds=2.0,
        )
        result = live_call.place_live_call(
            pbx_host=h.ip, call_to="+15551234567",
            call_from=target_ext,
            audio_payload=ulaw, audio_label=label,
            pbx_port=sip_port, hold_seconds=2.0,
            timeout=2.0, traffic_log=traffic_log,
            caller_id_name="AutoEnum Test",
        )
        print(f"  call_from={target_ext}  success={result.success}  "
              f"codec={result.codec}  rtp_pkts={result.rtp_packets_sent}")
        assert result.success, f"live call should succeed: {result.evidence}"
        assert result.rtp_packets_sent >= 80, (
            f"expected ~100 RTP packets, got {result.rtp_packets_sent}")
        assert pbx.bye_received == 1, "mock should have received BYE"

        header("ALL AUTO-ENUM TESTS PASSED")
        return 0
    except AssertionError as e:
        print(f"\n!!! ASSERTION FAILED: {e}", file=sys.stderr)
        return 1
    finally:
        traffic_log.close()
        pbx.stop()
        ami.stop()


if __name__ == "__main__":
    sys.exit(main())
