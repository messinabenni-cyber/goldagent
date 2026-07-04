"""Minimal mock PBX for end-to-end testing without touching real targets."""
from __future__ import annotations

import socket
import threading


class MockPbx:
    """In-process UDP SIP server that returns scripted responses.

    Usage:
        pbx = MockPbx(responses={
            "OPTIONS": ("200 OK", "Server: Asterisk PBX 18.1\\r\\n"),
            "REGISTER": ("401 Unauthorized",
                         'WWW-Authenticate: Digest realm="pbx", '
                         'nonce="abc123", algorithm=MD5\\r\\n'),
        })
        pbx.start()
        # ... do stuff against pbx.host, pbx.port ...
        pbx.stop()
    """

    def __init__(self, responses: dict[str, tuple[str, str]] | None = None):
        self.responses = responses or {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.host, self.port = self.sock.getsockname()
        self.received: list[bytes] = []
        self.stop_evt = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_evt.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self.stop_evt.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            self.received.append(data)
            self._respond(data, addr)

    def _respond(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            method = head.split(" ", 1)[0]
        except Exception:
            return
        resp = self.responses.get(method)
        if resp is None:
            return
        status_line, extra_headers = resp
        # Echo Via, From, To, Call-ID, CSeq from the request for routing
        echoed: list[str] = []
        for line in data.decode("utf-8", errors="replace").split("\r\n"):
            lo = line.lower()
            if (lo.startswith("via:") or lo.startswith("from:")
                    or lo.startswith("to:") or lo.startswith("call-id:")
                    or lo.startswith("cseq:")):
                echoed.append(line)

        reply = (
            f"SIP/2.0 {status_line}\r\n"
            + "\r\n".join(echoed) + "\r\n"
            + extra_headers
            + "Content-Length: 0\r\n\r\n"
        ).encode("utf-8")
        try:
            self.sock.sendto(reply, addr)
        except OSError:
            pass
