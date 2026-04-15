"""
voip_gui.py — One-key launcher for VoIPScan Pro.

Usage:
    python3 voip_gui.py                   # standard (opens browser)
    python3 voip_gui.py --port 9000       # custom port
    python3 voip_gui.py --no-browser      # headless / CI
    python3 voip_gui.py --shodan-key XYZ  # pre-load API keys

For authorized penetration testing engagements only.
"""

import argparse
import os
import time
import webbrowser

from gui.server import start, _api_config, _api_config_lock


_BANNER = r"""
  ╔══════════════════════════════════════════════════════╗
  ║  VoIPScan Pro  v2.0  — Professional PBX Assessment  ║
  ║  For authorized engagements only.                    ║
  ╚══════════════════════════════════════════════════════╝

  Features:
    • SHA-256 + MD5 SIP Digest Auth (RFC 7616)
    • STUN NAT traversal (automatic external IP discovery)
    • TLS/TCP transport support
    • OSINT pre-scan via Shodan + Censys
    • AI-powered exploit advisor (Claude API)
    • LLM-guided extension fuzzing
    • Real-time traffic anomaly detection
    • Call persistence engine (auto-redial)
    • Executive report with embedded audio evidence

  API keys can be set with --shodan-key, --anthropic-key, etc.
  or through the ⚙ Settings panel in the GUI.
"""


def main():
    parser = argparse.ArgumentParser(
        description="VoIPScan Pro — Professional PBX Security Assessment Platform"
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765,
                        help="Bind port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not auto-open browser")
    parser.add_argument("--shodan-key", default="",
                        help="Shodan API key (can also be set in GUI Settings)")
    parser.add_argument("--censys-id", default="",
                        help="Censys API ID")
    parser.add_argument("--censys-secret", default="",
                        help="Censys API Secret")
    parser.add_argument("--anthropic-key", default="",
                        help="Anthropic API key for AI advisor / fuzzer")
    parser.add_argument("--no-stun", action="store_true",
                        help="Disable STUN NAT traversal")
    args = parser.parse_args()

    # Pre-load API keys from CLI args or environment
    with _api_config_lock:
        if args.shodan_key:
            _api_config["shodan_key"] = args.shodan_key
        if args.censys_id:
            _api_config["censys_id"] = args.censys_id
        if args.censys_secret:
            _api_config["censys_secret"] = args.censys_secret
        if args.anthropic_key:
            _api_config["anthropic_key"] = args.anthropic_key
        if args.no_stun:
            _api_config["use_stun"] = False

    print(_BANNER)
    url = f"http://{args.host}:{args.port}"
    print(f"  Starting server on {url}")

    # Report pre-loaded integrations
    with _api_config_lock:
        integrations = []
        if _api_config.get("shodan_key"):
            integrations.append("Shodan OSINT")
        if _api_config.get("censys_id"):
            integrations.append("Censys OSINT")
        if _api_config.get("anthropic_key"):
            integrations.append("Claude AI Advisor")
        if _api_config.get("use_stun"):
            integrations.append("STUN NAT")
    if integrations:
        print(f"  Integrations active: {', '.join(integrations)}")
    else:
        print("  No API keys loaded — set them in the ⚙ Settings panel")

    print("  Press Ctrl+C to stop.\n")

    srv = start(args.host, args.port)

    if not args.no_browser:
        time.sleep(0.5)
        webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Stopping VoIPScan Pro...")
        srv.shutdown()
        print("  Stopped.")


if __name__ == "__main__":
    main()
