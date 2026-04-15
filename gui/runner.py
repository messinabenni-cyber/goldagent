"""GUI-driven scan runner. Same flow as voip_demo.py but consumes a config
dict (from the web form) instead of argparse, and puts every meaningful
state change on the event bus so the dashboard updates live."""
from __future__ import annotations

import os
import sys
import time
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import (audio, auth_test, dial_plan, discovery, enumeration,
                     live_call, reporter, vuln_probes)
from modules.control import controller
from modules.events import bus
from modules.utils import TrafficLog, hash_file, severity_score

# Optional capability imports — gracefully degraded if modules not yet present
try:
    from modules.osint import run_osint
    _OSINT_AVAILABLE = True
except ImportError:
    _OSINT_AVAILABLE = False

try:
    from modules.ai_advisor import analyse_scan as _ai_analyse
    _AI_AVAILABLE = True
except ImportError:
    _AI_AVAILABLE = False

try:
    from modules.hashcat_export import capture_and_export as _hashcat_capture
    _HASHCAT_AVAILABLE = True
except ImportError:
    _HASHCAT_AVAILABLE = False

try:
    from modules import pcap_export as _pcap_export
    _PCAP_AVAILABLE = True
except ImportError:
    _PCAP_AVAILABLE = False

try:
    from modules.stun import get_public_ip as _stun_get_ip
    _STUN_AVAILABLE = True
except ImportError:
    _STUN_AVAILABLE = False

try:
    from modules import rtp_bleed as _rtp_bleed
    _RTP_BLEED_AVAILABLE = True
except ImportError:
    _RTP_BLEED_AVAILABLE = False

try:
    from modules import method_fuzzer as _method_fuzzer
    _METHOD_FUZZ_AVAILABLE = True
except ImportError:
    _METHOD_FUZZ_AVAILABLE = False

try:
    from modules import iax2 as _iax2
    _IAX2_AVAILABLE = True
except ImportError:
    _IAX2_AVAILABLE = False

try:
    from modules import tls_audit as _tls_audit
    _TLS_AUDIT_AVAILABLE = True
except ImportError:
    _TLS_AUDIT_AVAILABLE = False

try:
    from modules import tftp_loot as _tftp_loot
    _TFTP_LOOT_AVAILABLE = True
except ImportError:
    _TFTP_LOOT_AVAILABLE = False

try:
    from modules import sip_ws as _sip_ws
    _SIP_WS_AVAILABLE = True
except ImportError:
    _SIP_WS_AVAILABLE = False

try:
    from modules import sccp as _sccp
    _SCCP_AVAILABLE = True
except ImportError:
    _SCCP_AVAILABLE = False

try:
    from modules import h323 as _h323
    _H323_AVAILABLE = True
except ImportError:
    _H323_AVAILABLE = False


# Ports that commonly speak TLS on VoIP infrastructure — SIPS, PBX admin
# HTTPS, WebRTC-WSS, 3CX/Asterisk admin.  Used by the TLS audit step to
# target every plausible TLS surface.
_TLS_CANDIDATE_PORTS = {5061, 443, 8089, 5001, 7189, 8082}

# WebSocket(S) ports worth probing for SIP-over-WS (RFC 7118)
_WS_CANDIDATE_PORTS = {8088, 8089, 5090, 7188, 7189, 8081, 8082}


DEFAULT_CONFIG = {
    "target": "",
    "ring": "",
    "scope_file": "",
    "mode": "standard",
    "rate": None,
    "timeout": None,
    "port": 5060,
    "ami_port": 5038,
    "workers": 16,
    "hold": 1800.0,
    "caller_id_name": "Pentest Demo",
    "audio_message": audio.DEFAULT_MESSAGE,
    "audio_file": None,
    "dtmf": None,
    "dtmf_digit_ms": 200,
    "record": True,
    "record_path": None,
    "dial_prefix": None,
    "no_dialplan_probe": False,
    "ext_range": None,
    "skip_ami": False,
    "skip_specials": False,
    "skip_creds": False,
    "vendor_creds": True,
    "probe_vulns": True,
    "coarse_step": 10,
    "fill_radius": 9,
    "stop_at_first": True,
    "all_paths": False,
    "dry_ring": False,
    "operator": os.environ.get("USER", "gui"),
    "report_dir": None,
    # New God Tier options
    "run_osint": False,
    "shodan_key": "",
    "censys_id": "",
    "censys_secret": "",
    "anthropic_key": "",
    "ai_auto_analyse": False,
    "use_stun": True,
    "use_tls": False,
    "ai_model": "claude-3-5-haiku-20241022",
}


def _apply_mode(cfg: dict) -> None:
    """Same semantics as voip_demo._apply_mode_preset."""
    if cfg["mode"] == "aggressive":
        if cfg["rate"] is None:    cfg["rate"] = 500.0
        if cfg["timeout"] is None: cfg["timeout"] = 1.5
        if not cfg["ext_range"]:   cfg["ext_range"] = "100-9999"
        cfg["vendor_creds"] = True
        cfg["probe_vulns"] = True
    elif cfg["mode"] == "stealth":
        if cfg["rate"] is None:    cfg["rate"] = 5.0
        if cfg["timeout"] is None: cfg["timeout"] = 2.5
        cfg["skip_ami"] = True
        cfg["probe_vulns"] = False
        cfg["coarse_step"] = max(cfg["coarse_step"], 20)
    else:
        if cfg["rate"] is None:    cfg["rate"] = 50.0
        if cfg["timeout"] is None: cfg["timeout"] = 3.0


def _rank_paths(host_report: dict) -> list[dict]:
    paths: list[dict] = []
    for e in host_report["extensions"]:
        if e.get("anonymous_invite"):
            paths.append({"rank": 1, "extension": e["extension"],
                          "label": f"anonymous INVITE on ext {e['extension']}"})
    for e in host_report["extensions"]:
        if e.get("open_register"):
            paths.append({"rank": 2, "extension": e["extension"],
                          "label": f"open REGISTER on ext {e['extension']}"})
    for c in host_report["credentials_found"]:
        paths.append({"rank": 3, "extension": c["extension"],
                      "username": c["username"], "password": c["password"],
                      "label": f"weak creds {c['username']}:{c['password']} "
                               f"on ext {c['extension']}"})
    paths.sort(key=lambda p: p["rank"])
    return paths


def run_scan(user_config: dict) -> dict:
    """Execute the full scan flow. Emits events. Returns the report dict.
    Respects controller.scan_cancel for graceful aborts."""
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(user_config or {})
    _apply_mode(cfg)

    # Basic validation
    import re as _re
    if not cfg["target"]:
        bus.emit("scan.error", {"reason": "target is required"})
        return {"error": "target is required"}
    if not cfg["ring"]:
        bus.emit("scan.error", {"reason": "ring number is required"})
        return {"error": "ring number is required"}
    # Ring number must look like a phone number or SIP URI — not a file path or
    # random string that would silently place a call to a garbage destination.
    _ring_ok = _re.match(
        r'^(\+?[\d\s\-\(\)]{4,20}|sip:[^@]+@\S+|[0-9]{1,20})$',
        str(cfg["ring"]).strip()
    )
    if not _ring_ok:
        bus.emit("scan.error", {"reason": "ring number format invalid"})
        return {"error": "ring number format invalid (use E.164 or SIP URI)"}
    # Scope file is optional — it's an authorization document whose SHA-256
    # hash is stored in the report as an audit trail. If not provided the
    # scan still runs; the report just omits the scope reference.
    scope_file = cfg.get("scope_file", "")
    if scope_file and not os.path.exists(scope_file):
        bus.emit("log", {"level": "warn",
                         "msg": f"Scope file not found: {scope_file!r} — continuing without it"})
        scope_file = ""

    controller.reset()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    report_dir = cfg["report_dir"] or os.path.join("reports", f"gui-{stamp}")
    os.makedirs(report_dir, exist_ok=True)
    traffic_log = TrafficLog(os.path.join(report_dir, "traffic.log"))
    scope_sha = hash_file(scope_file) if scope_file else ""
    cfg["scope_file"] = scope_file   # normalise for downstream use

    # ---- STUN: discover external IP when behind NAT ----
    external_ip: str | None = None
    if cfg.get("use_stun") and _STUN_AVAILABLE:
        bus.emit("phase", {"name": "stun", "detail": "Discovering external IP via STUN"})
        try:
            external_ip = _stun_get_ip(timeout=3.0)
            if external_ip:
                bus.emit("stun.discovered", {"external_ip": external_ip})
        except Exception:
            pass

    bus.emit("scan.start", {
        "target": cfg["target"], "ring": cfg["ring"],
        "mode": cfg["mode"], "report_dir": report_dir,
        "external_ip": external_ip,
    })

    # ---- OSINT pre-scan: passive intelligence gathering ----
    osint_results: dict = {}
    if cfg.get("run_osint") and _OSINT_AVAILABLE:
        bus.emit("phase", {"name": "osint",
                           "detail": f"Gathering OSINT intelligence on {cfg['target']}"})
        try:
            result = run_osint(
                cfg["target"],
                shodan_key=cfg.get("shodan_key") or None,
                censys_id=cfg.get("censys_id") or None,
                censys_secret=cfg.get("censys_secret") or None,
                timeout=5.0,
            )
            osint_results = result.__dict__ if hasattr(result, "__dict__") else {}
            bus.emit("osint.complete", {
                "ip": cfg["target"],
                "risk_score": osint_results.get("risk_score", 0),
                "cves": osint_results.get("cves", []),
                "known_ports": osint_results.get("known_ports", []),
                "org": osint_results.get("org", ""),
                "country": osint_results.get("country", ""),
                "summary": osint_results.get("summary", ""),
            })
        except Exception as _exc:
            bus.emit("log", {"level": "warn",
                             "msg": f"OSINT failed: {_exc}"})

    # ---- Audio ----
    audio_loop_cap = cfg["hold"] if cfg["hold"] > 0 else 3600
    payload = audio.build_payload(
        wav_file=cfg["audio_file"],
        message=cfg["audio_message"],
        loop_to_seconds=audio_loop_cap,
    )
    bus.emit("audio.prepared", {
        "source": payload["label"],
        "ulaw_bytes": len(payload["PCMU"]),
        "alaw_bytes": len(payload["PCMA"]),
    })

    # ---- Phase 1: discovery ----
    bus.emit("phase", {"name": "discovery"})
    targets = discovery.expand_target(cfg["target"])
    if not targets:
        bus.emit("scan.error", {"reason": f"cannot resolve {cfg['target']}"})
        traffic_log.close()
        return {"error": "target not resolvable"}
    hosts = discovery.sweep(
        targets, timeout=cfg["timeout"], rate_per_second=cfg["rate"],
        workers=cfg["workers"], traffic_log=traffic_log,
    )

    if controller.scan_cancel.is_set() or not hosts:
        report = _finalize_report(cfg, report_dir, [], None, scope_sha,
                                  traffic_log, payload["label"], stamp,
                                  osint_results=osint_results)
        bus.emit("scan.done", {"hosts": 0, "findings": len(report.get("findings", [])),
                               "report_dir": report_dir})
        return report

    host_reports: list[dict] = []
    demo_call_result: dict | None = None

    for h in hosts:
        if controller.scan_cancel.is_set():
            break
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
            "call_test": None,
            "live_call": None,
        }

        # ---- vuln probes ----
        if cfg["probe_vulns"]:
            bus.emit("phase", {"name": "vuln_probes", "host": h.ip})
            tcp_ports = sorted({p["port"] for p in h.open_ports
                                if p["proto"] == "tcp"})
            if tcp_ports:
                for v in vuln_probes.run_all(h.ip, tcp_ports, timeout=cfg["timeout"]):
                    hr["vuln_findings"].append({
                        "name": v.name, "severity": v.severity,
                        "target": v.target, "title": v.title,
                        "evidence": v.evidence, "remediation": v.remediation,
                    })

            # ---- RTP Bleed probe (CVE-2017-11527) ----
            # Only meaningful on SIP-speaking hosts, and only if a call is
            # currently bridging — we still record "info" if clean so the
            # operator knows the probe ran.
            if _RTP_BLEED_AVAILABLE and h.sip:
                bus.emit("phase", {"name": "rtp_bleed", "host": h.ip})
                try:
                    bleed = _rtp_bleed.probe_rtp_bleed(
                        h.ip, traffic_log=traffic_log,
                    )
                    hr["rtp_bleed"] = {
                        "detected": bleed.bleed_detected,
                        "probed_ports": bleed.probed_ports,
                        "packets_sent": bleed.packets_sent,
                        "bleeding_ports": bleed.bleeding_ports,
                        "elapsed_s": round(bleed.elapsed_s, 2),
                    }
                    finding = _rtp_bleed.build_finding(bleed)
                    if finding:
                        finding["host"] = h.ip
                        hr["vuln_findings"].append({
                            "name": finding["id"],
                            "severity": finding["severity"],
                            "target": h.ip,
                            "title": finding["title"],
                            "evidence": finding["detail"],
                            "remediation": finding["remediation"],
                        })
                        bus.emit("vuln.found", {
                            "host": h.ip, "title": finding["title"],
                            "severity": finding["severity"],
                        })
                except Exception as exc:
                    bus.emit("log", {"level": "warn",
                                     "msg": f"rtp_bleed probe failed: {exc}"})

            # ---- SIP method fuzzer ----
            if _METHOD_FUZZ_AVAILABLE and h.sip:
                bus.emit("phase", {"name": "method_fuzz", "host": h.ip})
                try:
                    fuzz = _method_fuzzer.fuzz_methods(
                        h.ip, port=cfg["port"], timeout=cfg["timeout"],
                        traffic_log=traffic_log,
                    )
                    hr["method_fuzz"] = {
                        "probes": len(fuzz.probes),
                        "anomalies": fuzz.anomalies,
                        "elapsed_s": round(fuzz.elapsed_s, 2),
                    }
                    for mf in _method_fuzzer.build_findings(fuzz):
                        if mf["severity"] == "info":
                            continue  # already surfaced via method_fuzz dict
                        hr["vuln_findings"].append({
                            "name": mf["id"],
                            "severity": mf["severity"],
                            "target": h.ip,
                            "title": mf["title"],
                            "evidence": mf["detail"],
                            "remediation": mf["remediation"],
                        })
                        bus.emit("vuln.found", {
                            "host": h.ip, "title": mf["title"],
                            "severity": mf["severity"],
                        })
                except Exception as exc:
                    bus.emit("log", {"level": "warn",
                                     "msg": f"method_fuzz failed: {exc}"})

            # ---- IAX2 probe (UDP/4569) ----
            # Detect IAX2 speakers regardless of whether the UDP port was
            # scanned — POKE doesn't require pre-discovery.
            if _IAX2_AVAILABLE:
                iax2_seen = any(
                    p.get("service", "").upper() == "IAX2"
                    or p.get("port") == _iax2.IAX2_PORT
                    for p in h.open_ports
                )
                if iax2_seen or cfg["mode"] == "aggressive":
                    bus.emit("phase", {"name": "iax2_probe", "host": h.ip})
                    try:
                        poke = _iax2.probe_poke(
                            h.ip, traffic_log=traffic_log,
                            timeout=cfg["timeout"],
                        )
                        if poke.pong_received:
                            hr["iax2"] = {
                                "pong": True,
                                "rtt_ms": round(poke.round_trip_ms, 1),
                                "server_info": poke.server_info,
                            }
                            for f in _iax2.build_findings(poke, None):
                                hr["vuln_findings"].append({
                                    "name": f["id"],
                                    "severity": f["severity"],
                                    "target": h.ip,
                                    "title": f["title"],
                                    "evidence": f["detail"],
                                    "remediation": f["remediation"],
                                })
                                bus.emit("vuln.found", {
                                    "host": h.ip, "title": f["title"],
                                    "severity": f["severity"],
                                })
                    except Exception as exc:
                        bus.emit("log", {"level": "warn",
                                         "msg": f"iax2 probe failed: {exc}"})

            # ---- TLS / SIPS cipher + certificate audit ----
            # Run against every TLS-capable port we saw open on this host.
            # VoIP gear is notorious for expired certs and weak cipher bundles,
            # so the audit is worthwhile even on "healthy" endpoints.
            if _TLS_AUDIT_AVAILABLE:
                tls_targets = sorted({
                    p["port"] for p in h.open_ports
                    if p.get("proto") == "tcp"
                    and p.get("port") in _TLS_CANDIDATE_PORTS
                })
                for tls_port in tls_targets:
                    bus.emit("phase", {"name": "tls_audit",
                                       "host": h.ip, "port": tls_port})
                    try:
                        ta = _tls_audit.audit_tls(
                            h.ip, tls_port, timeout=cfg["timeout"],
                        )
                        hr.setdefault("tls_audits", []).append({
                            "port": tls_port,
                            "connected": ta.connected,
                            "tls_version": ta.tls_version,
                            "cipher": ta.cipher,
                            "cert_subject": ta.cert_subject,
                            "cert_issuer": ta.cert_issuer,
                            "cert_not_after": ta.cert_not_after,
                            "cert_days_until_expiry": ta.cert_days_until_expiry,
                            "cert_self_signed": ta.cert_self_signed,
                            "cert_hostname_match": ta.cert_hostname_match,
                        })
                        for f in _tls_audit.build_findings(ta):
                            hr["vuln_findings"].append({
                                "name": f["id"],
                                "severity": f["severity"],
                                "target": f"{h.ip}:{tls_port}",
                                "title": f["title"],
                                "evidence": f["detail"],
                                "remediation": f["remediation"],
                            })
                            bus.emit("vuln.found", {
                                "host": h.ip, "title": f["title"],
                                "severity": f["severity"],
                            })
                    except Exception as exc:
                        bus.emit("log", {"level": "warn",
                                         "msg": f"tls_audit on {h.ip}:{tls_port} failed: {exc}"})

            # ---- TFTP provisioning loot (UDP/69) ----
            # When discovery turned up a TFTP server we attempt to pull the
            # standard IP-phone config filenames.  Non-destructive RRQs only.
            if _TFTP_LOOT_AVAILABLE:
                tftp_open = any(
                    p.get("port") == _tftp_loot.TFTP_PORT
                    and p.get("proto") == "udp"
                    for p in h.open_ports
                )
                if tftp_open:
                    bus.emit("phase", {"name": "tftp_loot", "host": h.ip})
                    try:
                        loot = _tftp_loot.loot_tftp(
                            h.ip, timeout=cfg["timeout"],
                            max_files=20 if cfg["mode"] != "stealth" else 8,
                        )
                        hr["tftp_loot"] = {
                            "files_fetched": [
                                {"filename": f.filename,
                                 "bytes": f.bytes_received,
                                 "credentials_suspected": f.credentials_suspected,
                                 "excerpt": f.content_excerpt[:200]}
                                for f in loot.files_fetched
                            ],
                            "files_missing": loot.files_missing[:20],
                            "elapsed_s": round(loot.elapsed_s, 2),
                        }
                        if loot.any_success and report_dir:
                            try:
                                _tftp_loot.save_loot(loot, report_dir)
                            except Exception:
                                pass
                        for f in _tftp_loot.build_findings(loot):
                            hr["vuln_findings"].append({
                                "name": f["id"],
                                "severity": f["severity"],
                                "target": h.ip,
                                "title": f["title"],
                                "evidence": f["detail"],
                                "remediation": f["remediation"],
                            })
                            bus.emit("vuln.found", {
                                "host": h.ip, "title": f["title"],
                                "severity": f["severity"],
                            })
                    except Exception as exc:
                        bus.emit("log", {"level": "warn",
                                         "msg": f"tftp_loot failed: {exc}"})

            # ---- SIP over WebSocket (RFC 7118) ----
            # Probe every candidate WS/WSS port that came back open so we can
            # flag CSWSH exposure + fingerprint WebRTC gateways.
            if _SIP_WS_AVAILABLE:
                ws_targets = sorted({
                    p["port"] for p in h.open_ports
                    if p.get("proto") == "tcp"
                    and p.get("port") in _WS_CANDIDATE_PORTS
                })
                for ws_port in ws_targets:
                    ws_tls = ws_port in {8089, 7189, 8082, 5001}
                    bus.emit("phase", {"name": "sip_ws",
                                       "host": h.ip, "port": ws_port,
                                       "tls": ws_tls})
                    try:
                        ws_res = _sip_ws.probe_ws_sip(
                            h.ip, ws_port, tls=ws_tls,
                            timeout=cfg["timeout"],
                        )
                        hr.setdefault("sip_ws", []).append({
                            "port": ws_port, "tls": ws_tls,
                            "upgraded": ws_res.upgraded,
                            "sip_subprotocol": ws_res.sip_subprotocol_accepted,
                            "server": ws_res.server_header,
                            "origin_accepted": ws_res.origin_accepted,
                            "options_status": ws_res.sip_options_status,
                        })
                        for f in _sip_ws.build_findings(ws_res):
                            hr["vuln_findings"].append({
                                "name": f["id"],
                                "severity": f["severity"],
                                "target": f"{h.ip}:{ws_port}",
                                "title": f["title"],
                                "evidence": f["detail"],
                                "remediation": f["remediation"],
                            })
                            if f["severity"] not in ("info", "low"):
                                bus.emit("vuln.found", {
                                    "host": h.ip, "title": f["title"],
                                    "severity": f["severity"],
                                })
                    except Exception as exc:
                        bus.emit("log", {"level": "warn",
                                         "msg": f"sip_ws on {h.ip}:{ws_port} failed: {exc}"})

            # ---- Cisco SCCP / Skinny (TCP/2000) ----
            if _SCCP_AVAILABLE:
                sccp_ports = sorted({
                    p["port"] for p in h.open_ports
                    if p.get("proto") == "tcp"
                    and p.get("port") in (_sccp.SCCP_PORT, _sccp.SCCP_TLS_PORT)
                })
                for sccp_port in sccp_ports:
                    bus.emit("phase", {"name": "sccp_probe",
                                       "host": h.ip, "port": sccp_port})
                    try:
                        sc = _sccp.probe_sccp(
                            h.ip, port=sccp_port, timeout=cfg["timeout"],
                            traffic_log=traffic_log,
                        )
                        if sc.sccp_detected:
                            hr.setdefault("sccp", []).append({
                                "port": sccp_port,
                                "keepalive_ack": sc.keepalive_ack,
                                "register_reject_text": sc.register_reject_text,
                                "cucm_version_hint": sc.cucm_version_hint,
                            })
                        for f in _sccp.build_findings(sc):
                            hr["vuln_findings"].append({
                                "name": f["id"],
                                "severity": f["severity"],
                                "target": f"{h.ip}:{sccp_port}",
                                "title": f["title"],
                                "evidence": f["detail"],
                                "remediation": f["remediation"],
                            })
                            bus.emit("vuln.found", {
                                "host": h.ip, "title": f["title"],
                                "severity": f["severity"],
                            })
                    except Exception as exc:
                        bus.emit("log", {"level": "warn",
                                         "msg": f"sccp probe failed: {exc}"})

            # ---- H.323 RAS gatekeeper discovery (UDP/1719) ----
            if _H323_AVAILABLE:
                h323_seen = any(
                    p.get("port") == _h323.RAS_PORT and p.get("proto") == "udp"
                    for p in h.open_ports
                )
                if h323_seen or cfg["mode"] == "aggressive":
                    bus.emit("phase", {"name": "h323_probe", "host": h.ip})
                    try:
                        h323 = _h323.probe_h323_ras(
                            h.ip, timeout=cfg["timeout"],
                            traffic_log=traffic_log,
                        )
                        if h323.h323_detected:
                            hr["h323"] = {
                                "reply_opcode": h323.reply_opcode,
                                "gatekeeper_identifier": h323.gatekeeper_identifier,
                            }
                        for f in _h323.build_findings(h323):
                            hr["vuln_findings"].append({
                                "name": f["id"],
                                "severity": f["severity"],
                                "target": h.ip,
                                "title": f["title"],
                                "evidence": f["detail"],
                                "remediation": f["remediation"],
                            })
                            bus.emit("vuln.found", {
                                "host": h.ip, "title": f["title"],
                                "severity": f["severity"],
                            })
                    except Exception as exc:
                        bus.emit("log", {"level": "warn",
                                         "msg": f"h323 probe failed: {exc}"})

        if not h.sip:
            host_reports.append(hr)
            continue

        # ---- Phase 2: auto-enumerate ----
        bus.emit("phase", {"name": "enumerate", "host": h.ip})
        fingerprint = hr["pbx_fingerprint"]
        ami_hint = any(p["service"] == "Asterisk-AMI"
                       for p in h.open_ports) and not cfg["skip_ami"]
        if cfg["ext_range"]:
            ext_list = enumeration.expand_ext_range(cfg["ext_range"])
            # Parallel enumeration — 10-20× faster than serial in fast/aggressive modes
            enum_workers = (
                min(50, cfg["workers"] * 2)
                if cfg["mode"] in ("aggressive", "standard") else 5
            )
            swept = enumeration.enumerate_range_parallel(
                h.ip, ext_list, port=cfg["port"], method="REGISTER",
                timeout=cfg["timeout"], max_workers=enum_workers,
                traffic_log=traffic_log,
            )
            invite_map = enumeration.probe_extensions_invite(
                h.ip, [r.extension for r in swept],
                port=cfg["port"], timeout=cfg["timeout"],
                rate_per_second=cfg["rate"], traffic_log=traffic_log,
            )
            for r in swept:
                inv = invite_map.get(r.extension)
                if inv:
                    r.anonymous_invite = r.anonymous_invite or inv.anonymous_invite
                    r.open_register = r.open_register or inv.open_register
                    r.auth_required = r.auth_required and inv.auth_required
            found = swept
            hr["auto_enum"] = {"method": "manual"}
        else:
            auto = enumeration.auto_enumerate(
                h.ip, port=cfg["port"], fingerprint=fingerprint,
                try_ami=ami_hint, ami_port=cfg["ami_port"],
                include_specials=not cfg["skip_specials"],
                coarse_step=cfg["coarse_step"],
                fill_radius=cfg["fill_radius"],
                timeout=cfg["timeout"], rate_per_second=cfg["rate"],
                traffic_log=traffic_log,
            )
            found = auto.extensions
            hr["auto_enum"] = {
                "method": auto.method,
                "ami_success": bool(auto.ami and auto.ami.success),
                "ami_creds": (f"{auto.ami.username}:{auto.ami.password}"
                              if auto.ami and auto.ami.success else ""),
                "ranges": [f"{a}-{b}" for a, b in auto.ranges_probed],
            }
            if auto.ami and auto.ami.success:
                hr["ami_post_exploit"] = {
                    "voicemail": auto.ami.voicemail_boxes,
                    "channels": auto.ami.active_channels,
                    "registrations": auto.ami.sip_registrations,
                }
        hr["extensions"] = [asdict(x) for x in found]
        bus.emit("enum.progress", {
            "host": h.ip,
            "total": len(ext_list) if cfg["ext_range"] else len(found),
            "found": sum(1 for e in found if e.exists),
            "auth_required": sum(1 for e in found if e.auth_required),
            "anon": sum(1 for e in found
                        if e.anonymous_invite or e.open_register),
        })
        for e in found:
            bus.emit("enum.extension", {
                "host": h.ip, "extension": e.extension,
                "anonymous_invite": e.anonymous_invite,
                "open_register": e.open_register,
                "auth_required": e.auth_required,
            })

        # ---- Phase 3: spray ----
        if not cfg["skip_creds"] and not controller.scan_cancel.is_set():
            bus.emit("phase", {"name": "spray", "host": h.ip})
            wl_dir = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "wordlists")
            cred_sources = [os.path.join(wl_dir, "default_credentials.txt")]
            if cfg["vendor_creds"]:
                cred_sources.extend(
                    enumeration.cred_files_for_fingerprint(fingerprint, wl_dir))
            creds: list = []
            for src in cred_sources:
                try:
                    creds.extend(auth_test.load_credentials(src))
                except OSError:
                    pass
            # Deduplicate
            seen: set = set()
            creds = [(u, p) for u, p in creds
                     if (u, p) not in seen and not seen.add((u, p))]
            auth_targets = [e.extension for e in found if e.auth_required]
            # Use parallel spray in aggressive/standard mode for 10-20× speedup
            if cfg["mode"] in ("aggressive", "standard") and len(auth_targets) > 3:
                spray_workers = min(20, max(5, cfg["workers"]))
                spray = auth_test.spray_parallel(
                    h.ip, auth_targets, creds,
                    port=cfg["port"], timeout=cfg["timeout"],
                    max_workers=spray_workers,
                    traffic_log=traffic_log,
                    stop_on_first=cfg.get("stop_at_first", True),
                )
            else:
                spray = auth_test.spray(
                    h.ip, auth_targets, creds,
                    port=cfg["port"], timeout=cfg["timeout"],
                    rate_per_second=max(2.0, cfg["rate"] / 10),
                    traffic_log=traffic_log,
                )
            hr["credentials_found"] = [asdict(c) for c in spray if c.success]
            bus.emit("spray.progress", {
                "host": h.ip,
                "extensions_tried": len(auth_targets),
                "creds_attempted": len(auth_targets) * len(creds),
                "creds_found": sum(1 for c in spray if c.success),
            })

            # ---- Hashcat export: capture digest hashes from auth-required extensions ----
            if auth_targets and _HASHCAT_AVAILABLE and report_dir:
                try:
                    cap = _hashcat_capture(
                        h.ip, auth_targets[:50],  # cap to 50 to avoid DoS
                        port=cfg["port"], timeout=cfg["timeout"],
                        output_dir=report_dir,
                    )
                    if cap.captures:
                        bus.emit("log", {
                            "level": "info",
                            "msg": (f"[hashcat] Captured {len(cap.captures)} SIP digest "
                                    f"hash(es) from {h.ip} → sip_hashes_hashcat.txt"),
                        })
                        hr["hashcat_hashes"] = cap.hashes
                except Exception:
                    pass

        # ---- Phase 4: rank + attack matrix ----
        attack_paths = _rank_paths(hr)
        bus.emit("attack_matrix", {
            "host": h.ip,
            "extensions": hr["extensions"],
            "credentials_found": hr["credentials_found"],
            "paths": attack_paths,
        })
        if not attack_paths:
            host_reports.append(hr)
            continue

        # ---- Phase 5: live call ----
        live_results: list[dict] = []
        for path in attack_paths:
            if controller.scan_cancel.is_set():
                break
            if cfg["dry_ring"]:
                live_results.append({**path, "dry_ring": True})
                continue
            # Dial-plan probe
            dial_target = cfg["ring"]
            probes_trace: list = []
            if cfg["dial_prefix"]:
                dial_target = cfg["dial_prefix"] + cfg["ring"].lstrip("+")
            elif not cfg["no_dialplan_probe"]:
                bus.emit("phase", {"name": "dial_probe", "host": h.ip})
                winner, probes = dial_plan.find_working_prefix(
                    h.ip, cfg["ring"], pbx_port=cfg["port"],
                    from_user=path["extension"], timeout=1.5,
                    rate_per_second=20, traffic_log=traffic_log,
                )
                probes_trace = [{"candidate": p.candidate,
                                 "status": p.status,
                                 "status_code": p.status_code,
                                 "reason": p.reason}
                                for p in probes]
                for p in probes:
                    bus.emit("dial.probe", {"candidate": p.candidate,
                                            "status": p.status,
                                            "code": p.status_code})
                if winner:
                    dial_target = winner
                    bus.emit("dial.winner", {"candidate": winner})

            bus.emit("phase", {"name": "live_call", "host": h.ip,
                               "target": dial_target, "via_ext": path["extension"]})

            rec_path = None
            if cfg["record"]:
                rec_path = cfg["record_path"] or os.path.join(
                    report_dir,
                    f"call_{h.ip.replace('.','_')}_{path['extension']}.wav")

            result = live_call.place_live_call(
                pbx_host=h.ip, call_to=dial_target,
                call_from=path["extension"],
                audio_payload=payload,
                audio_label=payload["label"],
                pbx_port=cfg["port"],
                username=path.get("username"),
                password=path.get("password"),
                hold_seconds=cfg["hold"], timeout=cfg["timeout"],
                traffic_log=traffic_log,
                caller_id_name=cfg["caller_id_name"],
                dtmf_sequence=cfg["dtmf"],
                dtmf_digit_ms=cfg["dtmf_digit_ms"],
                record_path=rec_path,
            )
            entry = {
                **path,
                "call_to": cfg["ring"],
                "dial_target": dial_target,
                "dial_probes": probes_trace,
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
            if result.success:
                demo_call_result = {"pbx": h.ip, **entry}
                if cfg["stop_at_first"] and not cfg["all_paths"]:
                    break
        hr["live_call"] = live_results
        host_reports.append(hr)
        if demo_call_result and cfg["stop_at_first"] and not cfg["all_paths"]:
            break

    report = _finalize_report(cfg, report_dir, host_reports,
                              demo_call_result, scope_sha,
                              traffic_log, payload["label"], stamp,
                              osint_results=osint_results)
    bus.emit("scan.done", {"hosts": len(host_reports),
                           "findings": len(report["findings"]),
                           "report_dir": report_dir})
    return report


# ---------------------------------------------------------------------------
# Continuous / persistent re-scan
# ---------------------------------------------------------------------------

def run_continuous_scan(
    user_config: dict,
    initial_report: dict,
    stop_event,             # threading.Event — set() to stop
    interval_s: float = 300.0,
) -> None:
    """Run lightweight re-probe rounds forever (until stop_event is set).

    Each round:
      1. Re-runs vuln probes against every known HTTP port (fast, parallel)
      2. Re-probes all known auth-only extensions for silent anonymous-INVITE changes
      3. Re-sprays any auth-only extensions with the credential list (catches
         password changes / newly added weak accounts)
      4. Sweeps a ±fill_radius window around every known extension to catch
         newly provisioned extensions
      5. Emits continuous.round_done with a delta summary
    """
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(user_config or {})
    _apply_mode(cfg)

    import concurrent.futures as _cf
    round_num = 0

    # Per-host processing timeout: if a host goes offline mid-scan we don't
    # want the whole continuous loop to stall.  Give each host at most 60 s.
    _HOST_TIMEOUT_S = 60.0

    # Build a compact representation of what we already know
    known_hosts: list[dict] = initial_report.get("hosts", [])

    while not stop_event.is_set():
        round_num += 1
        bus.emit("continuous.round_start", {"round": round_num})

        new_findings: list[str] = []

        for hr in known_hosts:
            if stop_event.is_set():
                break
            ip = hr.get("ip", "")
            port = cfg["port"]
            # Per-host deadline: if the host is offline, individual probes will
            # block until their timeouts expire.  We enforce an absolute ceiling
            # so the continuous loop never stalls longer than _HOST_TIMEOUT_S
            # per host regardless of how many extensions/ports are probed.
            host_deadline = time.monotonic() + _HOST_TIMEOUT_S

            try:
                known_exts = {e["extension"] for e in hr.get("extensions", [])}
                auth_only = [e["extension"] for e in hr.get("extensions", [])
                             if e.get("auth_required") and not e.get("anonymous_invite")]

                # 1. Vuln probes (parallel — fast)
                # 1. Vuln probes (parallel — fast)
                if cfg["probe_vulns"] and time.monotonic() < host_deadline:
                    tcp_ports = sorted({p["port"] for p in hr.get("open_ports", [])
                                        if p.get("proto") == "tcp"})
                    if tcp_ports and not stop_event.is_set():
                        for v in vuln_probes.run_all(ip, tcp_ports,
                                                      timeout=cfg["timeout"]):
                            key = v.name + "|" + v.target
                            existing = {f["name"] + "|" + f["target"]
                                        for f in hr.get("vuln_findings", [])}
                            if key not in existing:
                                hr.setdefault("vuln_findings", []).append({
                                    "name": v.name, "severity": v.severity,
                                    "target": v.target, "title": v.title,
                                    "evidence": v.evidence,
                                    "remediation": v.remediation,
                                })
                                new_findings.append(
                                    f"new vuln: {v.name} on {v.target}")

                if stop_event.is_set() or time.monotonic() >= host_deadline:
                    continue   # move to next host

                # 2. Re-check auth-only extensions for silent mode change
                if auth_only:
                    invite_map = enumeration.probe_extensions_invite(
                        ip, auth_only, port=port, timeout=cfg["timeout"],
                        rate_per_second=cfg["rate"],
                    )
                    for e in hr.get("extensions", []):
                        inv = invite_map.get(e["extension"])
                        if inv and inv.anonymous_invite and not e.get("anonymous_invite"):
                            e["anonymous_invite"] = True
                            new_findings.append(
                                f"ext {e['extension']} now accepts anonymous INVITE!")
                            bus.emit("continuous.new_anon", {
                                "host": ip, "extension": e["extension"],
                                "round": round_num,
                            })

                if stop_event.is_set() or time.monotonic() >= host_deadline:
                    continue

                # 3. Credential re-spray on auth-only extensions
                if not cfg["skip_creds"] and auth_only:
                    wl_dir = os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), "wordlists")
                    cred_sources = [os.path.join(wl_dir, "default_credentials.txt")]
                    if cfg["vendor_creds"]:
                        fp = hr.get("pbx_fingerprint", "")
                        cred_sources.extend(
                            enumeration.cred_files_for_fingerprint(fp, wl_dir))
                    creds: list = []
                    for src in cred_sources:
                        try:
                            creds.extend(auth_test.load_credentials(src))
                        except OSError:
                            pass
                    already_cracked = {c["extension"]
                                       for c in hr.get("credentials_found", [])}
                    fresh_targets = [e for e in auth_only if e not in already_cracked]
                    if fresh_targets:
                        spray_results = auth_test.spray(
                            ip, fresh_targets, creds,
                            port=port, timeout=cfg["timeout"],
                            rate_per_second=max(1.0, cfg["rate"] / 20),
                        )
                        for res in spray_results:
                            if res.success:
                                hr.setdefault("credentials_found", []).append({
                                    "extension": res.extension,
                                    "username": res.username,
                                    "password": res.password,
                                    "evidence": res.evidence,
                                })
                                new_findings.append(
                                    f"cracked ext {res.extension} "
                                    f"({res.username}:{res.password})")
                                bus.emit("spray.hit", {
                                    "host": ip, "extension": res.extension,
                                    "username": res.username,
                                    "password": res.password,
                                })

                if stop_event.is_set() or time.monotonic() >= host_deadline:
                    continue

                # 4. Sweep ±fill_radius around each known extension for new ones
                neighbors: set[str] = set()
                for ext_str in known_exts:
                    try:
                        base = int(ext_str)
                        for n in range(base - cfg["fill_radius"],
                                       base + cfg["fill_radius"] + 1):
                            if n > 0:
                                neighbors.add(str(n))
                    except ValueError:
                        pass
                novel = [e for e in sorted(neighbors) if e not in known_exts]
                if novel[:100]:   # cap sweep at 100 new candidates per round
                    swept = enumeration.enumerate_range(
                        ip, novel[:100], port=port, method="REGISTER",
                        timeout=cfg["timeout"], rate_per_second=cfg["rate"],
                    )
                    for res in swept:
                        if res.exists and res.extension not in known_exts:
                            known_exts.add(res.extension)
                            hr.setdefault("extensions", []).append({
                                "extension": res.extension,
                                "exists": True,
                                "auth_required": res.auth_required,
                                "anonymous_invite": res.anonymous_invite,
                                "open_register": res.open_register,
                            })
                            new_findings.append(f"new extension: {res.extension}")
                            bus.emit("enum.extension", {
                                "host": ip, "extension": res.extension,
                                "anonymous_invite": res.anonymous_invite,
                                "open_register": res.open_register,
                                "auth_required": res.auth_required,
                            })

            except Exception as _exc:  # noqa: BLE001
                # Host went offline or raised unexpectedly — log and skip it
                import logging as _log
                _log.warning("continuous scan: host %s raised %s: %s",
                             ip, type(_exc).__name__, _exc)

        bus.emit("continuous.round_done", {
            "round": round_num,
            "new_findings": len(new_findings),
            "details": new_findings[:20],   # cap payload
        })

        # Wait for next round (interruptible)
        stop_event.wait(timeout=interval_s)

    bus.emit("continuous.stopped", {"rounds_completed": round_num})


def _finalize_report(cfg, report_dir, host_reports, demo_call_result,
                     scope_sha, traffic_log, audio_label, stamp,
                     osint_results: dict | None = None) -> dict:
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "operator": cfg.get("operator") or os.environ.get("USER", "gui"),
        "target": cfg["target"],
        "scope_file": cfg["scope_file"],
        "scope_sha256": scope_sha,
        "args": {k: v for k, v in cfg.items() if not callable(v)},
        "audio_source": audio_label,
        "hosts": host_reports,
        "demo_call": demo_call_result,
        "osint": osint_results or {},
    }
    report["severity_counts"] = {}

    # Write standard reports (txt, json, html via existing reporter)
    try:
        reporter.write_all(report_dir, report)
        report["severity_counts"] = severity_score(report.get("findings", []))
        reporter.write_all(report_dir, report)
    except Exception as exc:
        bus.emit("scan.error", {"reason": f"report write failed: {exc}"})

    # Generate enhanced HTML report with embedded audio + executive summary
    try:
        from modules.reporter import generate_html_report as _gen_html
        enhanced_html = _gen_html(report, report_dir)
        enhanced_path = os.path.join(report_dir, "report_enhanced.html")
        with open(enhanced_path, "w", encoding="utf-8") as _fh:
            _fh.write(enhanced_html)
        bus.emit("report.enhanced_ready", {"path": enhanced_path})
    except Exception as exc:
        bus.emit("log", {"level": "warn",
                         "msg": f"Enhanced HTML report failed: {exc}"})

    # Auto AI analysis if configured
    if cfg.get("ai_auto_analyse") and _AI_AVAILABLE:
        try:
            ai_result = _ai_analyse(
                report,
                api_key=cfg.get("anthropic_key") or None,
                model=cfg.get("ai_model", "claude-3-5-haiku-20241022"),
            )
            report["ai_advisor"] = ai_result.__dict__ if hasattr(ai_result, "__dict__") else {}
            bus.emit("ai.advice_ready", {
                "priority_attack": report["ai_advisor"].get("priority_attack", ""),
                "recommendations": report["ai_advisor"].get("recommendations", [])[:3],
                "risk_summary": report["ai_advisor"].get("risk_summary", ""),
            })
        except Exception as exc:
            bus.emit("log", {"level": "warn",
                             "msg": f"AI analysis failed: {exc}"})

    traffic_log.close()

    # Convert traffic.log → traffic.pcap for Wireshark analysis
    if _PCAP_AVAILABLE:
        tlog_path = os.path.join(report_dir, "traffic.log")
        pcap_path = os.path.join(report_dir, "traffic.pcap")
        if os.path.exists(tlog_path):
            try:
                n = _pcap_export.pcap_from_traffic_log(tlog_path, pcap_path)
                bus.emit("log", {
                    "level": "info",
                    "msg": f"[pcap] Wrote {n} packet(s) → traffic.pcap",
                })
            except Exception as _pcap_exc:
                bus.emit("log", {
                    "level": "warn",
                    "msg": f"[pcap] Failed to write traffic.pcap: {_pcap_exc}",
                })

    report["report_dir"] = report_dir
    return report
