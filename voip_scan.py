#!/usr/bin/env python3
"""voip_scan.py — VoIP pentest scanner.

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.
See README.md for authorization requirements and scope-of-work template.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from dataclasses import asdict

from modules import (auth_test, call_test, discovery, enumeration, reporter,
                     sip, vuln_probes)
from modules.utils import TrafficLog, hash_file, severity_score


BANNER = r"""
  __      __   ___ ____    ____
  \ \    / /__|_ _|  _ \  / ___|  ___ __ _ _ __  _ __   ___ _ __
   \ \  / / _ \| || |_) | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \ \/ / (_) | ||  __/   ___) | (_| (_| | | | | | | |  __/ |
     \__/ \___/___|_|     |____/ \___\__,_|_| |_|_| |_|\___|_|

  VoIP Penetration Testing Scanner  |  Authorized use only
"""


def authorize(args: argparse.Namespace) -> tuple[str, str | None]:
    """Returns (operator_ack, scope_sha256 or None). Exits on refusal."""
    operator = args.operator or getpass.getuser()
    scope_hash = None
    if args.scope_file:
        if not os.path.exists(args.scope_file):
            print(f"ERROR: scope file not found: {args.scope_file}", file=sys.stderr)
            sys.exit(2)
        scope_hash = hash_file(args.scope_file)

    needs_prompt = True
    if args.i_have_authorization and args.scope_file:
        needs_prompt = False

    # Anything beyond --discover requires a scope file or the interactive prompt
    intrusive = any([args.enum_extensions, args.test_creds, args.call_test, args.full])
    if intrusive and not (args.scope_file or needs_prompt):
        print("ERROR: intrusive tests require --scope-file (signed authorization).",
              file=sys.stderr)
        sys.exit(2)

    if needs_prompt:
        print("")
        print("AUTHORIZATION REQUIRED")
        print("-" * 60)
        print(f"  Operator       : {operator}")
        print(f"  Target         : {args.target}")
        print(f"  Scope file     : {args.scope_file or '(none provided)'}")
        if scope_hash:
            print(f"  Scope sha256   : {scope_hash}")
        print(f"  Intrusive tests: {intrusive}")
        if args.call_test:
            print(f"  CALL PLACEMENT : YES -> {args.call_to} from {args.call_from}")
        print("")
        print("I confirm I am authorized by the asset owner to perform this test,")
        print("the scope file (if any) has been countersigned, and I accept full")
        print("responsibility for any impact to the target environment.")
        ans = input("Type 'yes' to proceed: ").strip().lower()
        if ans != "yes":
            print("Aborted.")
            sys.exit(1)
    return operator, scope_hash


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="VoIP pentest scanner — discovery, enumeration, "
                    "credential testing, optional call proof-of-concept.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See README.md for usage examples and authorization requirements.",
    )
    p.add_argument("--target", required=True,
                   help="IP, CIDR, or hostname. E.g. 192.168.1.0/24 or 10.0.0.50")
    p.add_argument("--operator", help="Name/handle of person running the scan "
                                      "(defaults to $USER; recorded in report)")
    p.add_argument("--scope-file", help="Path to signed authorization/scope document")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="Skip the interactive auth prompt. Requires --scope-file.")

    g = p.add_argument_group("Checks (default: discover only)")
    g.add_argument("--discover", action="store_true",
                   help="Host/port discovery + SIP OPTIONS (safe, default)")
    g.add_argument("--enum-extensions", action="store_true",
                   help="Enumerate SIP extensions via REGISTER")
    g.add_argument("--enum-method", choices=["REGISTER", "INVITE"],
                   default="REGISTER",
                   help="Method used for extension enumeration (default REGISTER)")
    g.add_argument("--ext-range",
                   help="Extension range: 1000-1099 | 100,200 | file:path.txt")
    g.add_argument("--ext-wordlist",
                   default=os.path.join(os.path.dirname(__file__),
                                        "wordlists/common_extensions.txt"),
                   help="Wordlist for default enumeration (used if --ext-range omitted)")
    g.add_argument("--test-creds", action="store_true",
                   help="Try default credentials against discovered extensions")
    g.add_argument("--cred-file",
                   default=os.path.join(os.path.dirname(__file__),
                                        "wordlists/default_credentials.txt"),
                   help="Credential wordlist (username:password per line)")
    g.add_argument("--full", action="store_true",
                   help="Run discover + enum + test-creds (NOT call-test)")

    c = p.add_argument_group("Call proof-of-concept")
    c.add_argument("--call-test", action="store_true",
                   help="Place a proof-of-concept outbound call (hangs up immediately)")
    c.add_argument("--call-to", help="Destination number for PoC call (YOU must own it)")
    c.add_argument("--call-from",
                   help="From-number / extension. Defaults to first valid extension found.")
    c.add_argument("--call-dry-run", action="store_true",
                   help="Stop at provisional response (no 200 OK / no connection).")

    t = p.add_argument_group("Tuning")
    t.add_argument("--rate", type=float, default=50.0,
                   help="Max SIP packets per second (default 50)")
    t.add_argument("--timeout", type=float, default=3.0,
                   help="Socket timeout, seconds (default 3)")
    t.add_argument("--workers", type=int, default=16,
                   help="Parallel hosts during sweep (default 16)")
    t.add_argument("--port", type=int, default=5060,
                   help="SIP port for per-host checks (default 5060)")

    o = p.add_argument_group("Output")
    o.add_argument("--report-dir",
                   help="Directory to write reports (default reports/<timestamp>)")
    return p.parse_args()


def main() -> int:
    print(BANNER)
    args = parse_args()

    if args.call_test and not args.call_to:
        print("ERROR: --call-test requires --call-to (a number YOU control).",
              file=sys.stderr)
        return 2

    operator, scope_sha = authorize(args)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report_dir = args.report_dir or os.path.join("reports", stamp)
    os.makedirs(report_dir, exist_ok=True)
    traffic_log = TrafficLog(os.path.join(report_dir, "traffic.log"))

    # --- Phase 1: discovery ---
    targets = discovery.expand_target(args.target)
    if not targets:
        print(f"ERROR: could not resolve target: {args.target}", file=sys.stderr)
        return 2
    print(f"[+] Scanning {len(targets)} host(s) for VoIP services...")
    hosts = discovery.sweep(
        targets,
        timeout=args.timeout,
        rate_per_second=args.rate,
        workers=args.workers,
        traffic_log=traffic_log,
    )
    print(f"[+] {len(hosts)} host(s) responded with VoIP services.")

    run_enum = args.enum_extensions or args.full
    run_creds = args.test_creds or args.full
    run_call = args.call_test

    host_reports: list[dict] = []
    for h in hosts:
        hr: dict = {
            "ip": h.ip,
            "open_ports": h.open_ports,
            "sip": h.sip,
            "pbx_fingerprint": enumeration.fingerprint(
                (h.sip or {}).get("server", "") if h.sip else ""
            ),
            "extensions": [],
            "credentials_found": [],
            "vuln_findings": [],
            "call_test": None,
        }

        # CVE-targeted HTTP probes against management surfaces
        http_ports = sorted({p["port"] for p in h.open_ports
                             if p["proto"] == "tcp"})
        if http_ports:
            vulns = vuln_probes.run_all(h.ip, http_ports, timeout=args.timeout)
            for v in vulns:
                hr["vuln_findings"].append({
                    "name": v.name, "severity": v.severity,
                    "target": v.target, "title": v.title,
                    "evidence": v.evidence, "remediation": v.remediation,
                })
                print(f"    [{v.severity.upper():8}] {v.name}  {v.title}")

        has_sip = bool(h.sip)
        if run_enum and has_sip:
            if args.ext_range:
                ext_list = enumeration.expand_ext_range(args.ext_range)
            else:
                ext_list = enumeration.expand_ext_range(f"file:{args.ext_wordlist}")
            print(f"[+] {h.ip}: enumerating {len(ext_list)} extensions via {args.enum_method}...")
            found = enumeration.enumerate_range(
                h.ip, ext_list, port=args.port,
                method=args.enum_method,
                timeout=args.timeout,
                rate_per_second=args.rate,
                traffic_log=traffic_log,
            )
            hr["extensions"] = [asdict(x) for x in found]
            print(f"[+] {h.ip}: {len(found)} extension(s) discovered.")

        if run_creds and has_sip:
            creds = auth_test.load_credentials(args.cred_file)
            # Only test against auth-required extensions (avoid noise)
            targets_for_cred = [
                e["extension"] for e in hr["extensions"] if e.get("auth_required")
            ]
            # If no enum was done, fall back to the wordlist
            if not targets_for_cred and not run_enum:
                targets_for_cred = enumeration.expand_ext_range(
                    f"file:{args.ext_wordlist}"
                )
            print(f"[+] {h.ip}: spraying {len(creds)} cred pairs against "
                  f"{len(targets_for_cred)} extension(s)...")
            spray = auth_test.spray(
                h.ip, targets_for_cred, creds,
                port=args.port,
                timeout=args.timeout,
                rate_per_second=max(2.0, args.rate / 10),  # softer for auth
                traffic_log=traffic_log,
            )
            successes = [asdict(c) for c in spray if c.success]
            hr["credentials_found"] = successes
            print(f"[+] {h.ip}: {len(successes)} credential(s) found.")

        if run_call and has_sip:
            call_from = args.call_from
            username = password = None
            if hr["credentials_found"]:
                chosen = hr["credentials_found"][0]
                call_from = call_from or chosen["extension"]
                username = chosen["username"]
                password = chosen["password"]
            elif hr["extensions"]:
                # Try anonymous if one of the extensions looked open
                openish = [e for e in hr["extensions"]
                           if e.get("anonymous_invite") or e.get("open_register")]
                if openish:
                    call_from = call_from or openish[0]["extension"]
            call_from = call_from or "1000"
            print(f"[+] {h.ip}: placing PoC call {call_from} -> {args.call_to} "
                  f"(dry_run={args.call_dry_run})")
            result = call_test.place_call(
                h.ip, args.call_to, call_from,
                port=args.port,
                username=username, password=password,
                timeout=args.timeout,
                dry_run=args.call_dry_run,
                traffic_log=traffic_log,
            )
            hr["call_test"] = {
                "call_to": args.call_to,
                "call_from": call_from,
                "success": result.success,
                "reached_dialplan": result.reached_dialplan,
                "status_code": result.status_code,
                "reason": result.reason,
                "evidence": result.evidence,
                "trace": result.sip_trace,
            }

        host_reports.append(hr)

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operator": operator,
        "target": args.target,
        "scope_file": args.scope_file,
        "scope_sha256": scope_sha,
        "args": {k: v for k, v in vars(args).items()},
        "hosts": host_reports,
    }
    # severity_counts is filled after findings are built, but need placeholder
    report["severity_counts"] = {}
    paths = reporter.write_all(report_dir, report)
    # Re-read to get counts after findings built
    report["severity_counts"] = severity_score(report["findings"])
    # Re-write HTML/TXT with the counts now populated
    reporter.write_all(report_dir, report)

    traffic_log.close()

    print("")
    print("=" * 60)
    print(f"Reports written to: {report_dir}")
    for k, p in paths.items():
        print(f"  {k:<4} : {p}")
    print(f"  traffic log: {os.path.join(report_dir, 'traffic.log')}")
    counts = report["severity_counts"]
    print(f"Findings: critical={counts.get('critical',0)}  "
          f"high={counts.get('high',0)}  med={counts.get('medium',0)}  "
          f"low={counts.get('low',0)}  info={counts.get('info',0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
