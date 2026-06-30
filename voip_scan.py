#!/usr/bin/env python3.12
"""voip_scan.py — VoIP penetration testing scanner.

Tuned for FreePBX / Asterisk / Grandstream engagements on internet-facing
targets. One CLI, one HTML report, one job: prove the toll-fraud risk.

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORISED TO TEST.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from dataclasses import asdict

from scanner import ami, auth, call, discovery, enumeration, http_probes, report
from scanner.utils import TrafficLog, hash_file


BANNER = r"""
  __      __   ___ ____    ____
  \ \    / /__|_ _|  _ \  / ___|  ___ __ _ _ __  _ __   ___ _ __
   \ \  / / _ \| || |_) | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \ \/ / (_) | ||  __/   ___) | (_| (_| | | | | | | |  __/ |
     \__/ \___/___|_|     |____/ \___\__,_|_| |_|_| |_|\___|_|

  v3.0 — FreePBX / Asterisk / Grandstream  |  Authorised use only
"""


# ---------------------------------------------------------------------------
# Authorisation gate
# ---------------------------------------------------------------------------

def authorize(args) -> tuple[str, str | None]:
    """Returns (operator, scope_sha256 or None). Exits on refusal."""
    operator = args.operator or getpass.getuser()

    scope_hash = None
    if args.scope_file:
        if not os.path.exists(args.scope_file):
            print(f"ERROR: scope file not found: {args.scope_file}",
                  file=sys.stderr)
            sys.exit(2)
        scope_hash = hash_file(args.scope_file)

    intrusive = any([args.enum, args.spray, args.call_test, args.full,
                     args.ami_attack])
    if intrusive and not args.scope_file:
        # No scope file → require interactive confirmation
        if not args.i_have_authorization:
            print("")
            print("AUTHORISATION REQUIRED")
            print("-" * 60)
            print(f"  Operator       : {operator}")
            print(f"  Target         : {args.target}")
            print(f"  Scope file     : (none provided)")
            print(f"  Intrusive tests: {intrusive}")
            if args.call_test:
                print(f"  CALL PLACEMENT : YES → {args.call_to} from {args.call_from}")
            print("")
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
        description="VoIP pentest scanner — discovery, enumeration, "
                    "credential testing, optional toll-fraud PoC. Tuned for "
                    "FreePBX / Asterisk / Grandstream.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  voip_scan.py --target 1.2.3.0/24 --full --scope-file sow.pdf "
               "--call-test --call-to +447900900900 --call-dry-run",
    )
    p.add_argument("--target", required=True,
                   help="IP, CIDR, hostname, or file:hosts.txt")
    p.add_argument("--operator",
                   help="Name/handle of the operator (defaults to $USER)")
    p.add_argument("--scope-file",
                   help="Path to signed scope-of-work; SHA-256 logged")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="Skip interactive auth prompt (still requires "
                        "scope-file for record)")

    g = p.add_argument_group("Checks (default: discover only)")
    g.add_argument("--enum", action="store_true",
                   help="Enumerate extensions via REGISTER+INVITE")
    g.add_argument("--ext-range",
                   help="Extension range: 1000-1099 | 100,200 | file:path")
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
                   help="Brute-force AMI (TCP/5038) with default credentials")
    g.add_argument("--full", action="store_true",
                   help="Equivalent to --enum --spray --ami-attack")

    c = p.add_argument_group("Toll-fraud call PoC")
    c.add_argument("--call-test", action="store_true",
                   help="Place a proof-of-concept outbound call")
    c.add_argument("--call-to",
                   help="Destination number (YOU must own it)")
    c.add_argument("--call-from",
                   help="From extension (defaults to first valid extension)")
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
    c.add_argument("--call-dtmf",
                   help='DTMF sequence after answer (e.g. "1p500#"; pN = N-ms pause)')

    t = p.add_argument_group("Tuning")
    t.add_argument("--rate", type=float, default=50.0,
                   help="Max requests per second (default 50)")
    t.add_argument("--timeout", type=float, default=3.0,
                   help="Socket timeout in seconds (default 3)")
    t.add_argument("--workers", type=int, default=32,
                   help="Parallel workers for sweeps (default 32)")
    t.add_argument("--port", type=int, default=5060,
                   help="SIP port (default 5060)")
    t.add_argument("--ami-port", type=int, default=5038,
                   help="AMI port (default 5038)")
    t.add_argument("--source-ip", default="",
                   help="Bind local sockets to this IP (for multi-NIC hosts)")
    t.add_argument("--source-port-range",
                   help="Bind within port range, inclusive (e.g. '5060-5099')")
    t.add_argument("--max-failures-per-ext", type=int, default=5,
                   help="Stop spraying an extension after N failed attempts (default 5)")

    o = p.add_argument_group("Output")
    o.add_argument("--report-dir",
                   help="Directory for report.html and report.json "
                        "(default reports/<timestamp>)")

    return p.parse_args()


def _parse_port_range(spec: str | None) -> tuple[int, int] | None:
    if not spec:
        return None
    try:
        lo_s, hi_s = spec.split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
    except ValueError:
        raise SystemExit(
            f"ERROR: --source-port-range must be 'low-high', got {spec!r}"
        )
    if not (1 <= lo <= hi <= 65535):
        raise SystemExit(f"ERROR: --source-port-range out of bounds: {spec}")
    return (lo, hi)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(BANNER)
    args = parse_args()

    if args.full:
        args.enum = True
        args.spray = True
        args.ami_attack = True

    if args.call_test and not args.call_to:
        print("ERROR: --call-test requires --call-to (a number YOU control)",
              file=sys.stderr)
        return 2

    source_port_range = _parse_port_range(args.source_port_range)

    operator, scope_sha = authorize(args)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report_dir = args.report_dir or os.path.join("reports", stamp)
    os.makedirs(report_dir, exist_ok=True)
    traffic_log = TrafficLog(os.path.join(report_dir, "traffic.log"))

    # ---- Phase 1: discovery ----
    targets = discovery.expand_target(args.target)
    if not targets:
        print(f"ERROR: could not resolve target: {args.target}", file=sys.stderr)
        return 2
    print(f"[+] Scanning {len(targets)} host(s) for VoIP services...")
    # Add the user's --port to discovery if it's non-standard so OPTIONS probes
    # find PBXes on non-default ports too.
    extra_udp = [args.port] if args.port != 5060 else None
    hosts = discovery.sweep(
        targets, timeout=args.timeout, rate_per_second=args.rate,
        workers=args.workers, traffic_log=traffic_log,
        extra_udp_ports=extra_udp,
    )
    print(f"[+] {len(hosts)} host(s) responded.")

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
            "ami": None,
            "call_test": None,
        }

        # ---- HTTP probes ----
        tcp_ports = sorted({p["port"] for p in h.open_ports
                             if p["proto"] == "tcp"})
        if tcp_ports:
            findings = http_probes.run_all(h.ip, tcp_ports,
                                            timeout=args.timeout)
            hr["http_findings"] = [
                {"name": f.name, "severity": f.severity, "target": f.target,
                 "title": f.title, "evidence": f.evidence,
                 "remediation": f.remediation}
                for f in findings
            ]
            for f in findings:
                print(f"    [{f.severity.upper():8}] {f.name}: {f.title}")

        if not h.sip:
            host_reports.append(hr)
            continue

        # ---- AMI attack ----
        if args.ami_attack:
            ami_open = any(p["service"] == "Asterisk-AMI" for p in h.open_ports)
            if ami_open:
                print(f"[+] {h.ip}: trying AMI default credentials...")
                ami_res = ami.attack(h.ip, port=args.ami_port,
                                      timeout=args.timeout,
                                      traffic_log=traffic_log)
                hr["ami"] = asdict(ami_res)
                if ami_res.success:
                    print(f"    [!] AMI pwned: {ami_res.username}/{ami_res.password}  "
                          f"({len(ami_res.extensions)} extensions dumped)")

        # ---- Extension enumeration ----
        ami_dumped_exts: list[str] = (hr.get("ami") or {}).get("extensions") or []
        if args.enum:
            if args.ext_range:
                ext_list = enumeration.expand_ext_range(args.ext_range)
            elif ami_dumped_exts:
                # AMI gave us ground truth — skip wordlist
                ext_list = ami_dumped_exts
            else:
                ext_list = enumeration.expand_ext_range(f"file:{args.ext_wordlist}")
            print(f"[+] {h.ip}: enumerating {len(ext_list)} extensions...")
            found = enumeration.sweep(
                h.ip, ext_list, port=args.port,
                timeout=args.timeout, max_workers=args.workers,
                traffic_log=traffic_log,
            )
            # Also INVITE-probe to capture anonymous-call acceptance
            if found:
                inv_map = enumeration.probe_invite_acceptance(
                    h.ip, [r.extension for r in found], port=args.port,
                    timeout=args.timeout, max_workers=args.workers,
                    traffic_log=traffic_log,
                )
                for r in found:
                    inv = inv_map.get(r.extension)
                    if inv:
                        r.anonymous_invite = r.anonymous_invite or inv.anonymous_invite
                        # auth_required: weakest view — if either method got
                        # through without auth, mark as not-auth-required
                        r.auth_required = r.auth_required and inv.auth_required
            hr["extensions"] = [asdict(x) for x in found]
            print(f"    {len(found)} extension(s) found  "
                  f"(anonymous_invite: "
                  f"{sum(1 for x in found if x.anonymous_invite)})")

        # ---- Credential spray ----
        if args.spray and hr["extensions"]:
            creds = auth.load_credentials(args.cred_file)
            if args.grandstream_creds or h.fingerprint == "Grandstream":
                gs_path = os.path.join(os.path.dirname(args.cred_file),
                                        "grandstream.txt")
                if os.path.exists(gs_path):
                    creds.extend(auth.load_credentials(gs_path))
            targets_for_spray = [e["extension"] for e in hr["extensions"]
                                  if e.get("auth_required")]
            if targets_for_spray:
                print(f"[+] {h.ip}: spraying {len(creds)} cred pairs against "
                      f"{len(targets_for_spray)} extension(s)...")
                hits = auth.spray(
                    h.ip, targets_for_spray, creds,
                    port=args.port, timeout=args.timeout,
                    max_workers=min(args.workers, 10),
                    max_failures_per_ext=args.max_failures_per_ext,
                    traffic_log=traffic_log,
                )
                successes = [asdict(c) for c in hits if c.success]
                hr["credentials_found"] = successes
                print(f"    {len(successes)} credential(s) cracked")

        # ---- Toll-fraud PoC ----
        if args.call_test:
            call_from = args.call_from
            username = password = None
            if hr["credentials_found"]:
                chosen = hr["credentials_found"][0]
                call_from = call_from or chosen["extension"]
                username = chosen["username"]
                password = chosen["password"]
            elif hr["extensions"]:
                openish = [e for e in hr["extensions"]
                            if e.get("anonymous_invite") or e.get("open_register")]
                if openish:
                    call_from = call_from or openish[0]["extension"]
            call_from = call_from or "1000"

            print(f"[+] {h.ip}: placing PoC call {call_from} → {args.call_to} "
                  f"(dry_run={args.call_dry_run})")
            result = call.place_call(
                h.ip, args.call_to, call_from,
                port=args.port,
                username=username, password=password,
                timeout=args.timeout, dry_run=args.call_dry_run,
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
                "call_to": args.call_to, "call_from": call_from,
                "success": result.success,
                "reached_dialplan": result.reached_dialplan,
                "status_code": result.status_code,
                "reason": result.reason,
                "evidence": result.evidence,
                "trace": result.sip_trace,
                "srtp_state": result.srtp_state,
                "dtmf_digits_sent": result.dtmf_digits_sent,
            }
            verdict = "SUCCESS" if result.success else (
                "DIALPLAN ENGAGED" if result.reached_dialplan else "REJECTED"
            )
            print(f"    [{verdict}] {result.status_code} {result.reason}")

        host_reports.append(hr)

    # ---- Report ----
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

    print("")
    print("=" * 60)
    for k, p in paths.items():
        print(f"  {k:<6} : {p}")
    print(f"  traffic: {os.path.join(report_dir, 'traffic.log')}")
    counts = final_report.get("severity_counts", {})
    print(f"Findings: critical={counts.get('critical', 0)}  "
          f"high={counts.get('high', 0)}  "
          f"medium={counts.get('medium', 0)}  "
          f"low={counts.get('low', 0)}  "
          f"info={counts.get('info', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
