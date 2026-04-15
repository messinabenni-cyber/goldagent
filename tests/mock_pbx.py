"""Minimal mock SIP PBX + AMI for loopback testing of voip_demo.

Accepts OPTIONS and INVITE, walks the call through 100 → 180 → 200 OK,
advertises its own RTP port in the answer SDP, receives RTP on that port
and counts packets, handles BYE. Also includes a mock Asterisk Manager
Interface (AMI) that accepts configured credentials and responds to
SIPpeers/PJSIPShowEndpoints for AMI-pwn testing.
"""
from __future__ import annotations

import re
import socket
import threading
import time


class MockPbx:
    def __init__(self, host: str = "127.0.0.1", sip_port: int = 55060,
                 rtp_port: int = 56000, answer_delay: float = 0.3,
                 callee_hangup_after: float | None = None):
        self.host = host
        self.sip_port = sip_port
        self.rtp_port = rtp_port
        self.answer_delay = answer_delay
        # If set, the mock simulates the CALLEE (mobile) hanging up N seconds
        # after answering, by sending an in-dialog BYE back to the caller.
        self.callee_hangup_after = callee_hangup_after
        self.sip_sock: socket.socket | None = None
        self.rtp_sock: socket.socket | None = None
        self.running = False
        self.rtp_packets = 0
        self.rtp_first_payload_type: int | None = None
        self.rtp_bytes = 0
        self.invites_received = 0
        self.options_received = 0
        self.ack_received = 0
        self.bye_received = 0
        self.bye_sent = 0
        self._threads: list[threading.Thread] = []
        # Stash the last dialog state so we can emit BYE from the callee side
        self._dialog: dict | None = None

    def start(self) -> None:
        self.sip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sip_sock.bind((self.host, self.sip_port))
        self.sip_sock.settimeout(0.2)
        self.rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_sock.bind((self.host, self.rtp_port))
        self.rtp_sock.settimeout(0.2)
        self.running = True
        t1 = threading.Thread(target=self._sip_loop, daemon=True)
        t2 = threading.Thread(target=self._rtp_loop, daemon=True)
        t1.start(); t2.start()
        self._threads = [t1, t2]

    def stop(self) -> None:
        self.running = False
        for t in self._threads:
            t.join(timeout=1.0)
        if self.sip_sock:
            self.sip_sock.close()
        if self.rtp_sock:
            self.rtp_sock.close()

    def _rtp_loop(self) -> None:
        assert self.rtp_sock is not None
        while self.running:
            try:
                data, _ = self.rtp_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            self.rtp_packets += 1
            self.rtp_bytes += len(data)
            if self.rtp_first_payload_type is None and len(data) >= 2:
                self.rtp_first_payload_type = data[1] & 0x7F

    def _sip_loop(self) -> None:
        assert self.sip_sock is not None
        while self.running:
            try:
                data, addr = self.sip_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._handle(data, addr)
            except Exception as e:
                print(f"[mock-pbx] error handling datagram: {e}")

    # ---- Request dispatch ----
    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        head, _, _ = data.partition(b"\r\n\r\n")
        first_line = head.decode("utf-8", errors="replace").splitlines()[0]
        parts = first_line.split()
        if len(parts) < 2:
            return
        method = parts[0]
        hdrs = _parse_headers(data)

        if method == "OPTIONS":
            self.options_received += 1
            self._send_response(data, addr, 200, "OK", extra_headers={
                "Server": "MockPBX/1.0 (testing)",
                "Allow": "INVITE, ACK, CANCEL, BYE, OPTIONS",
            })
        elif method == "INVITE":
            self.invites_received += 1
            # 100 Trying
            self._send_response(data, addr, 100, "Trying")
            # 180 Ringing (with a to-tag; real PBXes often add one here)
            to_tag = f"mockto{int(time.time()*1000) & 0xFFFFF:x}"
            self._send_response(data, addr, 180, "Ringing",
                                to_tag=to_tag)
            # Answer delay
            threading.Thread(
                target=self._answer_after_delay,
                args=(data, addr, to_tag),
                daemon=True,
            ).start()
        elif method == "ACK":
            self.ack_received += 1
        elif method == "BYE":
            self.bye_received += 1
            self._send_response(data, addr, 200, "OK")
        elif method == "CANCEL":
            self._send_response(data, addr, 200, "OK")
        elif method == "REGISTER":
            # For completeness, not used by voip_demo directly
            self._send_response(data, addr, 200, "OK", extra_headers={
                "Contact": f"<sip:{hdrs.get('from','').split('<')[-1].split('>')[0] or 'user'}>;expires=60"
            })

    def _answer_after_delay(self, request: bytes, addr: tuple[str, int],
                            to_tag: str) -> None:
        time.sleep(self.answer_delay)
        if not self.running:
            return
        sdp = (
            "v=0\r\n"
            f"o=mockpbx 1 1 IN IP4 {self.host}\r\n"
            "s=mock\r\n"
            f"c=IN IP4 {self.host}\r\n"
            "t=0 0\r\n"
            f"m=audio {self.rtp_port} RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=sendrecv\r\n"
            "a=ptime:20\r\n"
        )
        self._send_response(
            request, addr, 200, "OK",
            to_tag=to_tag,
            extra_headers={
                "Contact": f"<sip:mock@{self.host}:{self.sip_port}>",
                "Content-Type": "application/sdp",
            },
            body=sdp,
        )
        # Capture dialog state so we can BYE the caller if asked to simulate
        # a callee-initiated hangup (the mobile hanging up)
        self._dialog = {
            "request": request, "addr": addr, "to_tag": to_tag,
        }
        if self.callee_hangup_after is not None:
            threading.Thread(
                target=self._callee_hangup,
                args=(float(self.callee_hangup_after),),
                daemon=True,
            ).start()

    def _callee_hangup(self, after: float) -> None:
        """Simulate the callee (your mobile) hanging up after `after` seconds.
        Sends an in-dialog BYE back to the caller."""
        time.sleep(after)
        if not self.running or not self._dialog:
            return
        orig = self._dialog["request"]
        addr = self._dialog["addr"]
        to_tag = self._dialog["to_tag"]
        # Build BYE using the original request's dialog identifiers, swapping
        # From/To so WE are the caller-of-this-request.
        head, _, _ = orig.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", errors="replace").splitlines()
        hdrs = _parse_headers(orig)
        # Extract original From/To/Call-ID/CSeq and flip the roles
        from_hdr_orig = hdrs.get("from", "")
        to_hdr_orig = hdrs.get("to", "")
        if ";tag=" not in to_hdr_orig:
            to_hdr_orig = f"{to_hdr_orig};tag={to_tag}"
        call_id = hdrs.get("call-id", "mock-call-id")
        via = f"SIP/2.0/UDP {self.host}:{self.sip_port};branch=z9hG4bK-mockbye;rport"
        # When the mock (callee) sends a BYE, our From = original To
        # and our To = original From.
        bye_lines = [
            f"BYE {from_hdr_orig.split('<',1)[1].split('>',1)[0] if '<' in from_hdr_orig else 'sip:caller'} SIP/2.0",
            f"Via: {via}",
            "Max-Forwards: 70",
            f"From: {to_hdr_orig}",
            f"To: {from_hdr_orig}",
            f"Call-ID: {call_id}",
            "CSeq: 101 BYE",
            f"Contact: <sip:mock@{self.host}:{self.sip_port}>",
            "Content-Length: 0",
            "",
        ]
        msg = ("\r\n".join(bye_lines) + "\r\n").encode("utf-8")
        try:
            assert self.sip_sock is not None
            self.sip_sock.sendto(msg, addr)
            self.bye_sent += 1
        except OSError:
            pass

    # ---- Response builder ----
    def _send_response(
        self,
        request: bytes,
        addr: tuple[str, int],
        code: int,
        reason: str,
        to_tag: str | None = None,
        extra_headers: dict[str, str] | None = None,
        body: str = "",
    ) -> None:
        assert self.sip_sock is not None
        head, _, _ = request.partition(b"\r\n\r\n")
        in_lines = head.decode("utf-8", errors="replace").splitlines()
        out = [f"SIP/2.0 {code} {reason}"]
        for line in in_lines[1:]:
            lo = line.lower()
            if lo.startswith("via:") or lo.startswith("from:") or \
               lo.startswith("call-id:") or lo.startswith("cseq:"):
                out.append(line)
            elif lo.startswith("to:"):
                if to_tag and ";tag=" not in line:
                    out.append(f"{line};tag={to_tag}")
                else:
                    out.append(line)
        if extra_headers:
            for k, v in extra_headers.items():
                out.append(f"{k}: {v}")
        out.append(f"Content-Length: {len(body)}")
        out.append("")
        msg = ("\r\n".join(out) + "\r\n" + body).encode("utf-8")
        try:
            self.sip_sock.sendto(msg, addr)
        except OSError:
            pass


def _parse_headers(data: bytes) -> dict[str, str]:
    head, _, _ = data.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", errors="replace").splitlines()
    out: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


class MockAmi:
    """Mock Asterisk Manager Interface — TCP banner + login + extension dump."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55038,
        accept_creds: tuple[str, str] = ("admin", "amp111"),
        extensions: list[str] | None = None,
        banner: str = "Asterisk Call Manager/5.0.3",
    ):
        self.host = host
        self.port = port
        self.accept_creds = accept_creds
        self.extensions = list(extensions or ["1000", "1001", "1002", "2000"])
        self.banner = banner
        self.sock: socket.socket | None = None
        self.running = False
        self.login_attempts: list[tuple[str, str]] = []
        self.successful_logins = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self.sock is not None
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle_conn, args=(conn,), daemon=True
            ).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            conn.sendall((self.banner + "\r\n").encode())
            authenticated = False
            buf = b""
            conn.settimeout(3.0)
            while self.running:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\r\n\r\n" in buf:
                    block, _, buf = buf.partition(b"\r\n\r\n")
                    fields = _ami_parse(block.decode("utf-8", errors="replace"))
                    action = fields.get("Action", "").lower()
                    if action == "login":
                        creds = (fields.get("Username", ""),
                                 fields.get("Secret", ""))
                        self.login_attempts.append(creds)
                        if creds == self.accept_creds:
                            self.successful_logins += 1
                            conn.sendall(
                                b"Response: Success\r\n"
                                b"Message: Authentication accepted\r\n\r\n"
                            )
                            authenticated = True
                        else:
                            conn.sendall(
                                b"Response: Error\r\n"
                                b"Message: Authentication failed\r\n\r\n"
                            )
                            return
                    elif action == "sippeers" and authenticated:
                        for ext in self.extensions:
                            entry = (
                                "Event: PeerEntry\r\n"
                                "Channeltype: SIP\r\n"
                                f"ObjectName: {ext}\r\n"
                                "ChanObjectType: peer\r\n"
                                "IPaddress: -none-\r\n"
                                "Status: Unmonitored\r\n\r\n"
                            )
                            conn.sendall(entry.encode())
                        tail = (
                            "Event: PeerlistComplete\r\n"
                            f"ListItems: {len(self.extensions)}\r\n\r\n"
                        )
                        conn.sendall(tail.encode())
                    elif action == "pjsipshowendpoints" and authenticated:
                        # Emit 0 endpoints (we already exposed them via
                        # SIPpeers); prove the client handles empty lists.
                        conn.sendall(
                            b"Response: Success\r\n"
                            b"EventList: start\r\n"
                            b"Message: A listing of Endpoints follows, "
                            b"presented as EndpointList events\r\n\r\n"
                        )
                        conn.sendall(
                            b"Event: EndpointListComplete\r\n"
                            b"EventList: Complete\r\n"
                            b"ListItems: 0\r\n\r\n"
                        )
                    elif action == "logoff":
                        conn.sendall(
                            b"Response: Goodbye\r\n"
                            b"Message: Thanks for all the fish.\r\n\r\n"
                        )
                        return
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _ami_parse(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            k, _, v = line.partition(": ")
            fields[k.strip()] = v.strip()
    return fields
