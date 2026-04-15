"""Dial-plan probe tests.

Two flavours:
 - Unit tests for `generate_candidates` (pure function, no network)
 - Integration test: mock PBX that only routes `9011...` format; probe must
   find this format without rubber-stamping the call through.
"""
from __future__ import annotations

import os
import re
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import dial_plan                                            # noqa: E402
from modules.utils import TrafficLog                                     # noqa: E402


def header(label: str) -> None:
    print("\n" + "=" * 70)
    print(f" {label}")
    print("=" * 70)


def test_generate_candidates() -> None:
    cands = dial_plan.generate_candidates("+447700900123")
    print("Candidates for +447700900123:")
    for c in cands:
        print(f"  {c}")
    # Must contain key variants
    assert "+447700900123" in cands, "must include original"
    assert "447700900123" in cands, "must include digits-only"
    assert "9+447700900123" in cands or "9447700900123" in cands, \
        "must include outside-line + number"
    assert "00447700900123" in cands, "must include 00 international"
    assert "011447700900123" in cands, "must include 011 NANP international"
    assert "900447700900123" in cands, "must include 9 + 00 + digits"
    assert "9011447700900123" in cands, "must include 9 + 011 + digits"
    # No duplicates
    assert len(cands) == len(set(cands)), f"duplicates found: {cands}"
    print(f"  ✓ {len(cands)} unique candidates, all common variants present")


class _SelectivePBX:
    """Mock PBX that responds with different codes based on the Request-URI.
    Only the `expected` format gets `100 Trying` (routed); everything else
    gets `404 Not Found` (rejected). Lets us prove the probe picks the right
    format without actually ringing anything.
    """
    def __init__(self, host="127.0.0.1", port=55064, expected="9011447700900123"):
        self.host = host
        self.port = port
        self.expected = expected
        self.running = False
        self.sock: socket.socket | None = None
        self.seen: list[str] = []
        self.cancels = 0

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(0.2)
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False
        time.sleep(0.1)
        if self.sock:
            self.sock.close()

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            parts = head.split()
            if len(parts) < 2:
                continue
            method = parts[0]
            uri = parts[1]          # e.g. sip:9011447700900123@127.0.0.1
            m = re.match(r"sip:([^@]+)@", uri)
            target = m.group(1) if m else ""
            if method == "CANCEL":
                self.cancels += 1
                self._respond(data, addr, 200, "OK")
                continue
            if method != "INVITE":
                continue
            self.seen.append(target)
            if target == self.expected:
                # Routed — send 100 Trying
                self._respond(data, addr, 100, "Trying")
            else:
                self._respond(data, addr, 404, "Not Found")

    def _respond(self, request, addr, code, reason):
        head, _, _ = request.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", errors="replace").splitlines()
        out = [f"SIP/2.0 {code} {reason}"]
        for line in lines[1:]:
            lo = line.lower()
            if (lo.startswith("via:") or lo.startswith("from:")
                    or lo.startswith("call-id:") or lo.startswith("cseq:")
                    or lo.startswith("to:")):
                out.append(line)
        out.append("Content-Length: 0")
        out.append("")
        msg = ("\r\n".join(out) + "\r\n").encode("utf-8")
        try:
            self.sock.sendto(msg, addr)
        except OSError:
            pass


def test_probe_finds_right_prefix() -> None:
    host = "127.0.0.1"
    port = 55064
    expected = "9011447700900123"
    pbx = _SelectivePBX(host=host, port=port, expected=expected)
    pbx.start()
    time.sleep(0.1)
    tl = TrafficLog("/tmp/voip_demo_dialplan_traffic.log")
    try:
        winner, probes = dial_plan.find_working_prefix(
            host, "+447700900123", pbx_port=port,
            from_user="1000", timeout=0.8,
            rate_per_second=100, traffic_log=tl,
        )
        print("\n" + dial_plan.format_probe_table(probes))
        print(f"\nWinner: {winner!r}")
        print(f"PBX saw {len(pbx.seen)} INVITE(s) + {pbx.cancels} CANCEL(s)")
        assert winner == expected, f"expected winner {expected!r}, got {winner!r}"
        # The winning format should be exactly one of the probes, and classified "routed"
        winning_probe = next(p for p in probes if p.candidate == winner)
        assert winning_probe.status == "routed"
        # CANCEL must have been sent for the winning (routed) probe so the
        # mock phone doesn't stay "ringing" in state machines
        assert pbx.cancels >= 1, "must CANCEL the routed probe"
        # Early candidates got 404; make sure we correctly classified them
        rejected = [p for p in probes if p.status == "rejected"]
        assert rejected, "at least one candidate should have been rejected"
        assert all(p.status_code == 404 for p in rejected), \
            f"rejected probes should be 404; got {[p.status_code for p in rejected]}"
        print(f"  ✓ winner {winner!r} found in {len(probes)} probe(s)")
        print(f"  ✓ {len(rejected)} candidate(s) correctly rejected with 404")
        print(f"  ✓ CANCEL sent to tear down routed probe")
    finally:
        tl.close()
        pbx.stop()


def main() -> int:
    try:
        header("UNIT — generate_candidates")
        test_generate_candidates()

        header("INTEGRATION — probe finds 9011 prefix against selective PBX")
        test_probe_finds_right_prefix()

        header("ALL DIAL-PLAN TESTS PASSED")
        return 0
    except AssertionError as e:
        print(f"\n!!! ASSERTION FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
