"""SIP message intelligence extraction — harvests credentials and topology
data embedded inside SIP responses and SDP bodies.

Far faster than credential spraying: a single REGISTER or INVITE probe
per extension can reveal:
  - SRTP/SDES master keys (a=crypto: in SDP — plaintext session keys)
  - Basic-Auth credentials (Authorization: Basic base64 in ATAs)
  - Internal topology (Via chain, Record-Route, private IPs)
  - Realm/domain leakage (WWW-Authenticate, Proxy-Authenticate)
  - Extension-to-name mapping (From display names, P-Called-Party-ID)
  - Platform default-credential hints (User-Agent banner lookup)

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORISED TO TEST.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Literal

from .sip import SipResponse

# ── SRTP cipher suites that expose keys in SDP ──────────────────────────────
_SRTP_SUITES = {
    "AES_CM_128_HMAC_SHA1_80",
    "AES_CM_128_HMAC_SHA1_32",
    "AES_256_CM_HMAC_SHA1_80",
    "AES_256_CM_HMAC_SHA1_32",
    "F8_128_HMAC_SHA1_80",
    "AEAD_AES_128_GCM",
    "AEAD_AES_256_GCM",
}

# ── RFC 1918 / private IP patterns ──────────────────────────────────────────
_PRIVATE_NETS_RE = re.compile(
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|100\.6[4-9]\.\d{1,3}\.\d{1,3}"   # CGNAT
    r"|100\.[7-9]\d\.\d{1,3}\.\d{1,3}"
    r"|100\.1[01]\d\.\d{1,3}\.\d{1,3}"
    r"|100\.12[0-7]\.\d{1,3}\.\d{1,3})"
)

# ── Platform → default credential hint table ────────────────────────────────
_PLATFORM_HINTS: dict[str, list[str]] = {
    "asterisk":    ["admin:admin", "admin:amp111", "admin:asterisk", "admin:password"],
    "freepbx":     ["admin:admin", "admin:amp111", "admin:freepbx", "admin:sangoma"],
    "grandstream": ["admin:admin", "admin:admingswave", "admin:grandstream"],
    "3cx":         ["admin:Admin1234!", "admin:3cx", "admin:admin1234"],
    "cisco":       ["admin:cisco", "admin:Cisco123", "CCMAdministrator:cisco"],
    "avaya":       ["admin:avaya", "craft:crftpw", "dadmin:dadmin01"],
    "mitel":       ["admin:mitel", "admin:sysadmin"],
    "kamailio":    [],
    "opensips":    [],
    "freeswitch":  ["admin:cluecon", "freeswitch:works"],
    "yealink":     ["admin:admin"],
    "polycom":     ["admin:456", "user:123"],
    "snom":        ["admin:0000"],
    "cisco spa":   ["admin:", "admin:cisco"],
}


@dataclass
class SipIntel:
    """Structured intelligence extracted from a SIP message exchange."""

    # Credential finds —————————————————————————————————————————————
    srtp_keys: list[dict] = field(default_factory=list)
    # [{suite, key_b64, lifetime, mki, stream_type}]

    basic_auth_creds: list[dict] = field(default_factory=list)
    # [{username, password, source_header}]

    digest_realm: str = ""
    # Realm from WWW-Authenticate / Proxy-Authenticate

    # Topology ——————————————————————————————————————————————————————
    internal_ips: list[str] = field(default_factory=list)
    via_chain: list[str] = field(default_factory=list)
    record_routes: list[str] = field(default_factory=list)

    # Identity ——————————————————————————————————————————————————————
    display_names: list[str] = field(default_factory=list)
    called_party_id: str = ""
    asserted_identity: str = ""

    # Platform ——————————————————————————————————————————————————————
    platform_hint: str = ""
    default_cred_hints: list[str] = field(default_factory=list)
    user_agent: str = ""

    # Severity flags ————————————————————————————————————————————————
    plaintext_sip: bool = False   # no TLS in use
    sdes_srtp_detected: bool = False  # SRTP keys in plaintext SDP
    basic_auth_detected: bool = False

    def has_findings(self) -> bool:
        return bool(
            self.srtp_keys or self.basic_auth_creds or self.digest_realm
            or self.internal_ips or self.display_names or self.called_party_id
            or self.asserted_identity or self.default_cred_hints
        )

    def severity(self) -> Literal["critical", "high", "medium", "low", "info"]:
        if self.basic_auth_detected:
            return "critical"
        if self.sdes_srtp_detected:
            return "high"
        if self.internal_ips or self.digest_realm:
            return "medium"
        return "info"


def extract_sip_intel(
    response: SipResponse,
    transport: str = "UDP",
) -> SipIntel:
    """Extract all intelligence from a parsed SIP response.

    Pass the raw SipResponse from sip.parse_response().
    transport: 'UDP' or 'TCP' or 'TLS' — marks plaintext_sip=True for non-TLS.
    """
    intel = SipIntel()
    intel.plaintext_sip = transport.upper() != "TLS"

    # ── User-Agent / Server banner ──────────────────────────────────────────
    ua = (response.headers.get("user-agent") or
          response.headers.get("server") or "").lower()
    intel.user_agent = ua
    for platform, hints in _PLATFORM_HINTS.items():
        if platform in ua:
            intel.platform_hint = platform
            intel.default_cred_hints = hints[:]
            break

    # ── Digest realm (WWW-Authenticate / Proxy-Authenticate) ────────────────
    for hdr in ("www-authenticate", "proxy-authenticate"):
        val = response.headers.get(hdr, "")
        if val:
            m = re.search(r'realm="([^"]+)"', val, re.IGNORECASE)
            if m:
                intel.digest_realm = m.group(1)
                break

    # ── Basic Auth in Authorization/Proxy-Authorization ─────────────────────
    # Some embedded ATAs and IP phones send Basic auth headers in REGISTER
    for hdr in ("authorization", "proxy-authorization"):
        val = response.headers.get(hdr, "")
        if val.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(val[6:].strip()).decode("utf-8", errors="replace")
                if ":" in decoded:
                    user, _, pw = decoded.partition(":")
                    intel.basic_auth_creds.append({
                        "username": user,
                        "password": pw,
                        "source_header": hdr,
                    })
                    intel.basic_auth_detected = True
            except Exception:
                pass

    # ── Internal IP leakage from Via chain ──────────────────────────────────
    # Multi-Value Via headers — collect all
    via_raw = []
    for k, v in response.headers.items():
        if k.lower() == "via" or k.lower() == "v":
            via_raw.append(v)
    # Also check raw response text for additional Via: lines
    if response.raw:
        for line in response.raw.decode("utf-8", errors="replace").split("\r\n"):
            lk = line.lower()
            if lk.startswith("via:") or lk.startswith("v:"):
                val = line.split(":", 1)[1].strip()
                if val not in via_raw:
                    via_raw.append(val)

    intel.via_chain = via_raw
    for v in via_raw:
        for ip in _PRIVATE_NETS_RE.findall(v):
            if ip not in intel.internal_ips:
                intel.internal_ips.append(ip)

    # ── Record-Route ─────────────────────────────────────────────────────────
    rr = response.headers.get("record-route", "")
    if rr:
        intel.record_routes = [r.strip() for r in rr.split(",") if r.strip()]
        for r in intel.record_routes:
            for ip in _PRIVATE_NETS_RE.findall(r):
                if ip not in intel.internal_ips:
                    intel.internal_ips.append(ip)

    # ── Identity headers ────────────────────────────────────────────────────
    pai = response.headers.get("p-asserted-identity", "")
    if pai:
        intel.asserted_identity = pai

    cpid = response.headers.get("p-called-party-id", "")
    if cpid:
        intel.called_party_id = cpid

    # Display name from From header
    from_hdr = response.headers.get("from", "")
    if from_hdr:
        m = re.match(r'"([^"]+)"\s*<', from_hdr)
        if m and m.group(1) not in ("", "anonymous", "Anonymous"):
            dn = m.group(1)
            if dn not in intel.display_names:
                intel.display_names.append(dn)

    # ── SDP body analysis ────────────────────────────────────────────────────
    body = response.body or ""
    if body.strip():
        _extract_sdp_intel(body, intel)

    return intel


def _extract_sdp_intel(sdp: str, intel: SipIntel) -> None:
    """Parse SDP body for SRTP keys and topology leakage."""
    current_media = "audio"
    for line in sdp.split("\n"):
        line = line.strip()

        if line.startswith("m="):
            current_media = line.split("=", 1)[1].split()[0]

        # a=crypto: SDES key exchange — master key in plaintext Base64
        # Format: a=crypto:<tag> <suite> inline:<key_b64>[|<lifetime>[|<mki>]]
        if line.startswith("a=crypto:"):
            intel.sdes_srtp_detected = True
            m = re.match(
                r"a=crypto:(\d+)\s+([A-Z0-9_]+)\s+inline:([A-Za-z0-9+/=]+)"
                r"(?:\|([^\s|]+))?(?:\|([^\s]+))?",
                line,
            )
            if m:
                suite = m.group(2)
                key_b64 = m.group(3)
                lifetime = m.group(4) or ""
                mki = m.group(5) or ""
                intel.srtp_keys.append({
                    "tag": m.group(1),
                    "suite": suite,
                    "key_b64": key_b64,
                    "lifetime": lifetime,
                    "mki": mki,
                    "stream_type": current_media,
                    "key_bytes": len(base64.b64decode(key_b64 + "==")) * 8,
                })

        # c= connection line — reveals PBX media IP
        if line.startswith("c=IN IP4 "):
            ip = line.split()[-1]
            m2 = _PRIVATE_NETS_RE.match(ip)
            if m2 and ip not in intel.internal_ips:
                intel.internal_ips.append(ip)


def extract_from_raw(raw_sip: bytes, transport: str = "UDP") -> SipIntel:
    """Convenience wrapper: parse raw SIP bytes then extract intel."""
    from .sip import parse_response
    resp = parse_response(raw_sip)
    if resp is None:
        return SipIntel()
    return extract_sip_intel(resp, transport=transport)


def format_intel_findings(intel: SipIntel, extension: str = "") -> list[str]:
    """Return human-readable finding strings for the given intel object."""
    findings: list[str] = []
    prefix = f"[ext {extension}] " if extension else ""

    if intel.basic_auth_creds:
        for c in intel.basic_auth_creds:
            findings.append(
                f"{prefix}CRITICAL: Basic-Auth credential in {c['source_header']}: "
                f"{c['username']}:{c['password']}"
            )

    if intel.sdes_srtp_detected:
        for k in intel.srtp_keys:
            findings.append(
                f"{prefix}HIGH: SRTP/SDES master key exposed in SDP ({k['stream_type']}): "
                f"{k['suite']} inline:{k['key_b64'][:16]}... "
                f"({k['key_bytes']}-bit) — media decryptable by passive observer"
            )

    if intel.digest_realm:
        findings.append(f"{prefix}MEDIUM: Digest realm leakage: {intel.digest_realm!r}")

    if intel.internal_ips:
        findings.append(
            f"{prefix}MEDIUM: Internal IPs leaked in SIP headers: "
            + ", ".join(intel.internal_ips)
        )

    if intel.asserted_identity:
        findings.append(
            f"{prefix}INFO: P-Asserted-Identity: {intel.asserted_identity}"
        )

    if intel.called_party_id:
        findings.append(f"{prefix}INFO: P-Called-Party-ID: {intel.called_party_id}")

    if intel.display_names:
        findings.append(
            f"{prefix}INFO: Display name(s) in From header: "
            + ", ".join(intel.display_names)
        )

    return findings
