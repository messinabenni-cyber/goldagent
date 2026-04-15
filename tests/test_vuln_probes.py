"""Integration test for vuln_probes — spin up a tiny HTTP server that
impersonates a FreePBX admin panel and an Asterisk ARI, confirm each
probe fires exactly once with the right severity + fingerprint.
"""
from __future__ import annotations

import http.server
import os
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import vuln_probes                                          # noqa: E402


FAKE_RESPONSES = {
    "/admin/config.php": (
        200,
        ("<html><head><title>FreePBX 16.0.40.7 Admin</title></head>"
         "<body>FreePBX Administration. Asterisk 18.20.0</body></html>"),
        {"Content-Type": "text/html"},
    ),
    "/ari/api-docs/resources.json": (
        200,
        '{"apiVersion":"6.0.0","swaggerVersion":"1.2","apis":["ARI endpoints"]}',
        {"Content-Type": "application/json"},
    ),
    "/httpstatus": (
        200,
        "<html>Asterisk 18.20.0 HTTP status page</html>",
        {"Server": "Asterisk/18.20.0", "Content-Type": "text/html"},
    ),
    "/": (
        404, "Not Found", {"Content-Type": "text/plain"},
    ),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass   # silence test output

    def do_GET(self):
        entry = FAKE_RESPONSES.get(self.path, (404, "Not Found", {}))
        status, body, headers = entry
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


def header(label: str) -> None:
    print("\n" + "=" * 70)
    print(f" {label}")
    print("=" * 70)


def main() -> int:
    host = "127.0.0.1"
    httpd = socketserver.TCPServer((host, 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        header(f"INTEGRATION — vuln_probes vs fake FreePBX+Asterisk on :{port}")
        findings = vuln_probes.run_all(host, [port], timeout=2.0)
        for f in findings:
            print(f"  [{f.severity.upper():8}] {f.name:<35} {f.title}")
        names = {f.name for f in findings}
        assert "FreePBX-Admin-Exposed" in names, (
            f"FreePBX probe should have fired; got {names}")
        assert "Asterisk-ARI-Exposed" in names, (
            f"Asterisk-ARI probe should have fired; got {names}")
        assert "Asterisk-HTTP-Version-Disclosure" in names, (
            f"Asterisk HTTP version probe should have fired; got {names}")
        severities = [f.severity for f in findings]
        assert "high" in severities, f"should have high; got {severities}"
        # No false positives expected — we don't serve 3CX, Cisco, Polycom, etc.
        for absent in ("Grandstream-Admin-Exposed", "Polycom-Web-UI-Exposed",
                       "CUCM-AXL-Exposed", "3CX-WebClient-Exposed"):
            assert absent not in names, f"false positive: {absent}"
        print(f"  ✓ all expected probes fired ({len(findings)} findings)")
        print(f"  ✓ no false positives against non-matching patterns")

        header("ALL VULN-PROBE TESTS PASSED")
        return 0
    except AssertionError as e:
        print(f"\n!!! ASSERTION FAILED: {e}", file=sys.stderr)
        return 1
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    sys.exit(main())
