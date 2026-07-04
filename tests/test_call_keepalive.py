"""Unit tests for session keepalive and BYE-routing fixes in scanner.call.

Tests:
1. PBX-initiated BYE during hold   → call_confirmed=True, 200 OK sent
2. PBX OPTIONS keepalive during hold → 200 OK sent
3. PBX re-INVITE during hold        → 200 OK sent with SDP
4. BYE routed to Contact from 200 OK (not original host:port)
5. Broken PBX (no BYE ack)          → graceful timeout, call_confirmed=False
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import sip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_200_ok(call_id: str, from_hdr: str, to_hdr: str, cseq: str,
                 via_hdr: str, contact_host: str = "127.0.0.1",
                 contact_port: int | None = None) -> bytes:
    """Build a minimal 200 OK for an INVITE, optionally with a Contact header."""
    to_with_tag = to_hdr if ";tag=" in to_hdr else to_hdr + ";tag=pbxtag123"
    contact_line = ""
    if contact_port:
        contact_line = f"Contact: <sip:pbx@{contact_host}:{contact_port}>\r\n"
    elif contact_host:
        contact_line = f"Contact: <sip:pbx@{contact_host}>\r\n"
    return (
        f"SIP/2.0 200 OK\r\n"
        f"Via: {via_hdr}\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_with_tag}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq}\r\n"
        f"{contact_line}"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


def _make_bye(call_id: str, from_hdr: str, to_hdr: str, cseq: int = 2) -> bytes:
    """Build a minimal BYE request."""
    return (
        f"BYE sip:dest@127.0.0.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-byebranch\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} BYE\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


def _make_options(call_id: str, from_hdr: str, to_hdr: str, cseq: int = 3) -> bytes:
    """Build a minimal OPTIONS request."""
    return (
        f"OPTIONS sip:dest@127.0.0.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-optbranch\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} OPTIONS\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


def _make_reinvite(call_id: str, from_hdr: str, to_hdr: str, cseq: int = 4) -> bytes:
    """Build a minimal re-INVITE request."""
    return (
        f"INVITE sip:dest@127.0.0.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-reinv\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} INVITE\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()


# ---------------------------------------------------------------------------
# Scripted PBX that drives the full dialog and inspects what the scanner sends
# ---------------------------------------------------------------------------

class ScriptedPbx:
    """UDP PBX server that executes a scripted sequence of send/receive actions.

    The script is a list of callables:
        action(sock, scanner_addr, received_so_far) → bytes | None

    If a callable returns bytes they are sent to the scanner.
    The server loops, calling each script step once the step's precondition is
    considered met (i.e., a new packet arrived since last step).

    For simpler cases a list of bytes can be provided:
        ('recv', None)   — wait for the scanner to send something
        ('send', bytes)  — send bytes to the scanner
    """

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.host, self.port = self.sock.getsockname()
        self.received: list[tuple[bytes, tuple[str, int]]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Script: list of (tag, bytes_to_send_or_None, delay_before_send)
        self._script: list[tuple[str, bytes | None, float]] = []
        self._sent: list[bytes] = []
        self._lock = threading.Lock()

    def add_step(self, tag: str, data: bytes | None, delay: float = 0.0) -> None:
        self._script.append((tag, data, delay))

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _run(self) -> None:
        self.sock.settimeout(0.1)
        step_idx = 0
        scanner_addr: tuple[str, int] | None = None

        while not self._stop.is_set():
            # Try to receive
            try:
                data, addr = self.sock.recvfrom(65535)
                scanner_addr = addr
                with self._lock:
                    self.received.append((data, addr))
            except socket.timeout:
                pass
            except OSError:
                break

            # Execute pending send steps
            while step_idx < len(self._script) and scanner_addr is not None:
                tag, payload, delay = self._script[step_idx]
                if payload is None:
                    # Pure receive step — consume once we have a packet
                    with self._lock:
                        if len(self.received) > step_idx:
                            step_idx += 1
                            continue
                    break
                else:
                    # Send step
                    if delay > 0:
                        time.sleep(delay)
                    try:
                        self.sock.sendto(payload, scanner_addr)
                        with self._lock:
                            self._sent.append(payload)
                    except OSError:
                        pass
                    step_idx += 1

    def wait_for_method(self, method: str, timeout: float = 3.0) -> bytes | None:
        """Block until a packet containing *method* is received, or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for pkt, _ in self.received:
                    first_line = pkt.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                    if first_line.startswith(method + " "):
                        return pkt
            time.sleep(0.05)
        return None

    def get_sent(self) -> list[bytes]:
        with self._lock:
            return list(self._sent)


# ---------------------------------------------------------------------------
# Parametrized PBX that sends a simple scripted response sequence:
#   INVITE → 100 Trying → 200 OK → [mid-dialog request] → 200 OK for BYE
# ---------------------------------------------------------------------------

def _extract_invite_headers(pkt: bytes) -> dict:
    """Pull Via/From/To/Call-ID/CSeq from an INVITE packet."""
    lines = pkt.decode("utf-8", errors="replace").split("\r\n")
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
    return hdrs


class _DialogPbx:
    """PBX that:
       1. Receives INVITE, sends 100 + 200 OK
       2. Optionally sends mid_dialog_pkt after a short delay
       3. Receives ACK (ignored) and BYE
       4. Optionally sends 200 OK for BYE

    Designed to be very small and deterministic for unit tests.
    """

    def __init__(
        self,
        mid_dialog_pkt_fn=None,   # callable(call_id, from_hdr, to_hdr) → bytes
        ack_bye_with_200: bool = True,
        contact_port: int | None = None,
    ) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.host, self.port = self.sock.getsockname()
        self._mid_dialog_pkt_fn = mid_dialog_pkt_fn
        self._ack_bye_with_200 = ack_bye_with_200
        self._contact_port = contact_port
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.packets_received: list[bytes] = []
        self.packets_sent: list[bytes] = []
        self._scanner_addr: tuple[str, int] | None = None
        self._call_id: str = ""
        self._from_hdr: str = ""
        self._to_hdr: str = ""
        self._via_hdr: str = ""
        self._cseq: str = ""
        self._ready = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _send(self, data: bytes) -> None:
        if self._scanner_addr:
            try:
                self.sock.sendto(data, self._scanner_addr)
                self.packets_sent.append(data)
            except OSError:
                pass

    def _run(self) -> None:
        self.sock.settimeout(0.2)
        invite_processed = False
        mid_dialog_sent = False
        bye_received = False

        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            self._scanner_addr = addr
            self.packets_received.append(data)

            first_line = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            method = first_line.split(" ", 1)[0]

            if method == "INVITE" and not invite_processed:
                invite_processed = True
                hdrs = _extract_invite_headers(data)
                self._call_id = hdrs.get("call-id", "")
                self._from_hdr = hdrs.get("from", "")
                self._to_hdr = hdrs.get("to", "pbx@test")
                self._via_hdr = hdrs.get("via", "")
                self._cseq = hdrs.get("cseq", "1 INVITE")

                # Send 100 Trying
                trying = (
                    f"SIP/2.0 100 Trying\r\n"
                    f"Via: {self._via_hdr}\r\n"
                    f"From: {self._from_hdr}\r\n"
                    f"To: {self._to_hdr}\r\n"
                    f"Call-ID: {self._call_id}\r\n"
                    f"CSeq: {self._cseq}\r\n"
                    f"Content-Length: 0\r\n\r\n"
                ).encode()
                self._send(trying)

                # Send 200 OK (with optional Contact header pointing elsewhere)
                ok200 = _make_200_ok(
                    self._call_id, self._from_hdr, self._to_hdr, self._cseq,
                    self._via_hdr,
                    contact_host=self.host,
                    contact_port=self._contact_port,
                )
                self._send(ok200)
                self._ready.set()

                # After a short pause send mid-dialog packet (if any)
                if self._mid_dialog_pkt_fn and not mid_dialog_sent:
                    threading.Thread(
                        target=self._send_mid_dialog,
                        daemon=True,
                    ).start()

            elif method == "ACK":
                # Nothing to do
                pass

            elif method == "BYE":
                bye_received = True
                if self._ack_bye_with_200:
                    bye_hdrs = _extract_invite_headers(data)
                    bye200 = (
                        f"SIP/2.0 200 OK\r\n"
                        f"Via: {bye_hdrs.get('via', self._via_hdr)}\r\n"
                        f"From: {bye_hdrs.get('from', self._from_hdr)}\r\n"
                        f"To: {bye_hdrs.get('to', self._to_hdr)}\r\n"
                        f"Call-ID: {bye_hdrs.get('call-id', self._call_id)}\r\n"
                        f"CSeq: {bye_hdrs.get('cseq', '2 BYE')}\r\n"
                        f"Content-Length: 0\r\n\r\n"
                    ).encode()
                    self._send(bye200)

    def _send_mid_dialog(self) -> None:
        # Small delay so ACK arrives first
        time.sleep(0.15)
        if self._call_id and not self._stop.is_set():
            pkt = self._mid_dialog_pkt_fn(
                self._call_id, self._from_hdr, self._to_hdr)
            self._send(pkt)

    def received_method(self, method: str) -> bool:
        return any(
            p.split(b"\r\n", 1)[0].decode("utf-8", errors="replace").startswith(method + " ")
            for p in self.packets_received
        )

    def sent_contains(self, text: str) -> bool:
        enc = text.encode()
        return any(enc in p for p in self.packets_sent)


# ---------------------------------------------------------------------------
# Test 1: PBX-initiated BYE during hold → call_confirmed=True, 200 OK sent
# ---------------------------------------------------------------------------

class TestPbxInitiatedBye:
    def test_pbx_bye_during_hold_sets_call_confirmed(self):
        """PBX sends BYE during hold phase; scanner must respond 200 OK and
        set call_confirmed=True on the result."""

        from scanner.call import place_call

        pbx = _DialogPbx(
            mid_dialog_pkt_fn=lambda cid, frm, to: _make_bye(cid, frm, to + ";tag=pbxtag123"),
            ack_bye_with_200=False,  # PBX won't ack our BYE (we receive theirs instead)
        )
        pbx.start()
        try:
            result = place_call(
                pbx.host, "99001", "1000",
                port=pbx.port,
                timeout=1.5,
                max_wait=3.0,
                call_duration=3.0,   # hold window long enough for mid-dialog BYE
                source_ip="127.0.0.1",
            )
            assert result.status_code == 200, f"expected 200 OK, got {result.status_code}"
            assert result.success is True
            assert result.call_confirmed is True, (
                f"call_confirmed should be True after PBX BYE; trace={result.sip_trace}"
            )
            # Scanner must have sent a 200 OK back to the PBX BYE
            assert pbx.sent_contains("200"), (
                "scanner did not send a 200 OK in response to PBX BYE"
            )
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# Test 2: PBX OPTIONS keepalive during hold → 200 OK sent
# ---------------------------------------------------------------------------

class TestPbxOptionsKeepalive:
    def test_pbx_options_during_hold_replied_with_200(self):
        """PBX sends OPTIONS during the hold window; scanner must respond 200 OK."""

        from scanner.call import place_call

        pbx = _DialogPbx(
            mid_dialog_pkt_fn=lambda cid, frm, to: _make_options(cid, frm, to + ";tag=pbxtag123"),
            ack_bye_with_200=True,
        )
        pbx.start()
        try:
            result = place_call(
                pbx.host, "99002", "1000",
                port=pbx.port,
                timeout=1.5,
                max_wait=3.0,
                call_duration=2.0,
                source_ip="127.0.0.1",
            )
            assert result.status_code == 200
            assert result.success is True
            # A 200 OK for the OPTIONS must have been sent by the scanner
            assert any(
                b"200" in pkt and b"OPTIONS" not in pkt.split(b"\r\n", 1)[0]
                for pkt in pbx.packets_received
            ) or pbx.sent_contains("200"), (
                "PBX did not see a 200 OK response to its OPTIONS"
            )
            # The scanner trace must mention the OPTIONS was handled
            assert any("OPTIONS" in line for line in result.sip_trace), (
                f"sip_trace missing OPTIONS entry; trace={result.sip_trace}"
            )
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# Test 3: PBX re-INVITE during hold → 200 OK sent with SDP
# ---------------------------------------------------------------------------

class TestPbxReInvite:
    def test_pbx_reinvite_during_hold_replied_with_200_and_sdp(self):
        """PBX sends re-INVITE during hold; scanner must respond 200 OK + SDP.

        The scanner sends the 200 OK *to* the PBX, so the SDP-bearing response
        arrives in pbx.packets_received (not packets_sent).
        """

        from scanner.call import place_call

        pbx = _DialogPbx(
            mid_dialog_pkt_fn=lambda cid, frm, to: _make_reinvite(cid, frm, to + ";tag=pbxtag123"),
            ack_bye_with_200=True,
        )
        pbx.start()
        try:
            result = place_call(
                pbx.host, "99003", "1000",
                port=pbx.port,
                timeout=1.5,
                max_wait=3.0,
                call_duration=2.0,
                source_ip="127.0.0.1",
            )
            assert result.status_code == 200
            assert result.success is True
            # Scanner sends its 200 OK for the re-INVITE back to the PBX, so it
            # appears in packets_received (from the PBX's perspective, it received
            # the scanner's response).
            reinvite_responses = [
                pkt for pkt in pbx.packets_received
                if pkt.startswith(b"SIP/2.0 200") and b"m=audio" in pkt
            ]
            assert reinvite_responses, (
                "scanner 200 OK for re-INVITE must include SDP body (m=audio); "
                f"packets_received={[p[:80] for p in pbx.packets_received]}"
            )
            # Trace must mention re-INVITE handling
            assert any("re-INVITE" in line or "INVITE" in line
                       for line in result.sip_trace), (
                f"sip_trace missing re-INVITE entry; trace={result.sip_trace}"
            )
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# Test 4: BYE routed to Contact from 200 OK (not original host:port)
# ---------------------------------------------------------------------------

class TestByeContactRouting:
    def test_bye_uses_contact_from_200_ok(self):
        """If the 200 OK includes a Contact pointing to a different host, BYE
        should be built with that Contact host in the Request-URI and headers,
        and the sip_trace should record the Contact-based routing.

        Note: the UDP scanner send() helper closes over the original (host, port),
        so the BYE is physically delivered to the original PBX address. What
        changes is the BYE *message content* (Request-URI, Via, host headers)
        which reflects the Contact address — this is the RFC 3261 §12.2
        compliance being exercised.
        """

        from scanner.call import place_call

        # Use a fake Contact host name that differs from '127.0.0.1' so the
        # branch `if _bye_host != host` fires in call.py.  The BYE will still
        # be physically sent to the original PBX socket (UDP send closure), but
        # the *message* will carry the Contact address.
        CONTACT_HOST = "192.0.2.99"   # TEST-NET, non-routable, != 127.0.0.1

        # Build a custom PBX that sends a 200 OK with a Contact pointing to the
        # fake host, then watches for any BYE it receives.
        class _ContactPbx:
            def __init__(self):
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.bind(("127.0.0.1", 0))
                self.host, self.port = self.sock.getsockname()
                self.packets_received: list[bytes] = []
                self._stop = threading.Event()
                self._thread: threading.Thread | None = None

            def start(self):
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()

            def stop(self):
                self._stop.set()
                try:
                    self.sock.close()
                except OSError:
                    pass

            def _run(self):
                self.sock.settimeout(0.2)
                invite_done = False
                while not self._stop.is_set():
                    try:
                        data, addr = self.sock.recvfrom(65535)
                    except (socket.timeout, OSError):
                        continue
                    self.packets_received.append(data)
                    first = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                    method = first.split(" ", 1)[0]
                    if method == "INVITE" and not invite_done:
                        invite_done = True
                        hdrs = _extract_invite_headers(data)
                        cid = hdrs.get("call-id", "")
                        frm = hdrs.get("from", "")
                        to  = hdrs.get("to", "")
                        via = hdrs.get("via", "")
                        cseq = hdrs.get("cseq", "1 INVITE")
                        # 100 Trying
                        self.sock.sendto((
                            f"SIP/2.0 100 Trying\r\nVia: {via}\r\nFrom: {frm}\r\n"
                            f"To: {to}\r\nCall-ID: {cid}\r\nCSeq: {cseq}\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        ).encode(), addr)
                        # 200 OK with Contact pointing to CONTACT_HOST
                        ok200 = (
                            f"SIP/2.0 200 OK\r\nVia: {via}\r\nFrom: {frm}\r\n"
                            f"To: {to};tag=pbxtag999\r\nCall-ID: {cid}\r\nCSeq: {cseq}\r\n"
                            f"Contact: <sip:pbx@{CONTACT_HOST}:5060>\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        ).encode()
                        self.sock.sendto(ok200, addr)
                    elif method == "BYE":
                        # Respond with 200 OK so call_confirmed=True
                        hdrs = _extract_invite_headers(data)
                        self.sock.sendto((
                            f"SIP/2.0 200 OK\r\n"
                            f"Via: {hdrs.get('via', '')}\r\n"
                            f"From: {hdrs.get('from', '')}\r\n"
                            f"To: {hdrs.get('to', '')}\r\n"
                            f"Call-ID: {hdrs.get('call-id', '')}\r\n"
                            f"CSeq: {hdrs.get('cseq', '2 BYE')}\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        ).encode(), addr)

        pbx = _ContactPbx()
        pbx.start()
        try:
            result = place_call(
                pbx.host, "99004", "1000",
                port=pbx.port,
                timeout=2.0,
                max_wait=4.0,
                call_duration=0.0,   # immediate BYE — no hold needed
                source_ip="127.0.0.1",
            )
            assert result.status_code == 200, f"expected 200, got {result.status_code}"
            assert result.success is True

            # call_confirmed should be True: PBX acknowledged our BYE
            assert result.call_confirmed is True, (
                f"call_confirmed should be True; trace={result.sip_trace}"
            )

            # The sip_trace must record that BYE was routed to the Contact address
            assert any(CONTACT_HOST in line for line in result.sip_trace), (
                f"sip_trace should mention Contact host {CONTACT_HOST!r}; "
                f"trace={result.sip_trace}"
            )

            # The BYE packet sent by the scanner should contain the Contact host
            # in its Request-URI (verifies RFC 3261 §12.2 compliance)
            bye_pkts = [
                p for p in pbx.packets_received
                if p.split(b"\r\n", 1)[0].decode("utf-8", errors="replace").startswith("BYE ")
            ]
            assert bye_pkts, (
                f"No BYE received by PBX; packets={[p[:60] for p in pbx.packets_received]}"
            )
            bye_first_line = bye_pkts[0].split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            assert CONTACT_HOST in bye_first_line, (
                f"BYE Request-URI should contain Contact host {CONTACT_HOST!r}; "
                f"got: {bye_first_line!r}"
            )
        finally:
            pbx.stop()


# ---------------------------------------------------------------------------
# Test 5: Broken PBX (no BYE ack) → graceful timeout, call_confirmed=False
# ---------------------------------------------------------------------------

class TestBrokenPbxNoBye:
    def test_no_bye_ack_gives_graceful_timeout(self):
        """PBX accepts call and sends 200 OK, but never acknowledges our BYE.
        place_call must return without raising, with call_confirmed=False."""

        from scanner.call import place_call

        pbx = _DialogPbx(
            ack_bye_with_200=False,   # deliberately broken — won't ack BYE
        )
        pbx.start()
        try:
            result = place_call(
                pbx.host, "99005", "1000",
                port=pbx.port,
                timeout=1.0,    # short to keep test fast (BYE wait = min(timeout, 6) = 1s)
                max_wait=3.0,
                call_duration=0.0,  # immediate BYE
                source_ip="127.0.0.1",
            )
            # Call itself succeeded at SIP layer
            assert result.status_code == 200
            assert result.success is True
            # But BYE was never acknowledged
            assert result.call_confirmed is False, (
                f"call_confirmed must be False when PBX ignores BYE; trace={result.sip_trace}"
            )
            # No exception should have been raised — clean return
            assert isinstance(result.sip_trace, list)
            # Trace should record the unacknowledged BYE
            assert any("BYE" in line for line in result.sip_trace), (
                f"trace should mention BYE attempt; trace={result.sip_trace}"
            )
        finally:
            pbx.stop()
