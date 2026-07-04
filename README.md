# goldagent — VoIP PBX Security Scanner

```
  __      __   ___ ____    ____
  \ \    / /__|_ _|  _ \  / ___|  ___ __ _ _ __  _ __   ___ _ __
   \ \  / / _ \| || |_) | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \ \/ / (_) | ||  __/   ___) | (_| (_| | | | | | | |  __/ |
     \__/ \___/___|_|     |____/ \___\__,_|_| |_|_| |_|\___|_|

  v4.0 — FreePBX / Asterisk / Grandstream / 3CX  |  Elite Auto-Mode
```

## WARNING: Authorisation Required

goldagent is a professional penetration testing tool designed exclusively for
authorised security assessments. **USE ONLY ON SYSTEMS YOU OWN OR ARE
EXPLICITLY AUTHORISED TO TEST.** Unauthorised use against systems you do not
own or have written permission to test is illegal under the Computer Fraud and
Abuse Act (USA), the Computer Misuse Act (UK), and equivalent legislation in
most jurisdictions. Before running any intrusive flag (`--enum`, `--spray`,
`--ami-attack`, `--call-test`, `--full`, `--auto`) you must obtain a signed
scope-of-work from the asset owner. The SHA-256 hash of the scope document is
logged in every report as a permanent audit record. The authors accept no
liability for any use of this tool outside a properly authorised engagement.

## Overview

goldagent is a full-lifecycle VoIP and PBX penetration testing platform tuned
for internet-facing FreePBX, Asterisk, Grandstream UCM, 3CX, and Mitel
installations. A single command discovers, fingerprints, enumerates, cracks,
and demonstrates toll-fraud risk — producing an HTML report, JSON findings
file, and complete SIP traffic log ready for client delivery.

Key capabilities:

- **Intelligent discovery** — SIP OPTIONS sweep across UDP and TCP transports
  with automatic PBX vendor fingerprinting (FreePBX, Asterisk, Grandstream,
  3CX, Mitel) and version extraction from server banners
- **17 CVE and configuration checks** — live, response-verified probes against
  known vulnerabilities across all supported platforms, including CVSS 9.8
  critical findings
- **Asterisk Manager Interface (AMI) attack** — default credential brute-force
  against TCP/5038 and the Asterisk HTTP rawman API, with full loot dump of
  extensions and voicemail boxes on success
- **SIP extension enumeration** — REGISTER-based 200/404/403 response analysis
  with adaptive platform-specific ranges, priority wordlists, and an INVITE
  acceptance probe to identify anonymous call vectors
- **Credential spray** — SIP Digest authentication spray with a built-in
  lockout guard, Grandstream-specific credential list support, and automatic
  offline hash cracking of captured challenges via hashcat/john
- **Toll-fraud call proof-of-concept** — authenticated and anonymous INVITE
  with full SIP identity header spoofing (PAI, Diversion, Privacy,
  Remote-Party-ID), DTMF traversal, configurable call duration, and AMI
  Originate as an alternative path
- **NAT auto-traversal** — STUN reflexive IP resolution, UPnP/IGD port
  mapping, symmetric NAT detection, and automatic SIP transport recovery
  across 13 port and transport combinations
- **STUN/TURN misconfiguration detection** — live probes for CVE-2026-27624
  (coturn SSRF bypass) and related relay infrastructure weaknesses
- **Adaptive inter-phase intelligence** — cracked passwords and discovered
  extensions are immediately fed into subsequent phases via live CRACK_POOL
  and EXTENSION_LIST pools, maximising hit rate without redundant probing
- **Enterprise-grade output** — HTML report (print to PDF for client
  delivery), machine-readable JSON findings, complete SIP traffic log, and
  captured SIP Digest hashes in hashcat-compatible format

## Features

### SIP Discovery and Fingerprinting

Sweeps targets (single IP, CIDR, hostname, or host file) for active SIP
services across UDP/5060, TCP/5060, SIP/TLS/5061, and non-standard ports.
Extracts PBX vendor and version from `Server:` and `User-Agent:` headers.
Supported platforms: FreePBX, Asterisk, Grandstream UCM, 3CX, Mitel MiCollab.

When the primary transport returns no response, an automatic reachability
probe cycles through 13 transport/port combinations (UDP, TCP, TLS, WS, WSS
on ports 5060–5090, 5160, 8088, 8089) and patches all subsequent scan phases
to use the discovered transport — no manual retry required.

### 17 CVE and Configuration Checks

All checks are live, response-verified probes. Version-based findings are
clearly labelled `[VERSION-BASED]`.

| ID | Platform | CVSS | Description |
|----|----------|------|-------------|
| CVE-2019-19006 | FreePBX | High | Unauthenticated userman module user data exposure |
| CVE-2021-45461 | FreePBX | High | Voicemail SQL injection indicator (error string leakage) |
| CVE-2022-2347 | FreePBX | Medium | Authenticated path traversal (versions < 16.0.19.9) |
| CVE-2025-57819 | FreePBX | 9.8 Critical | EPM module unauthenticated SQL injection + RCE |
| CVE-2025-66039 | FreePBX | 9.8 Critical | Admin panel auth bypass in webserver auth mode |
| CVE-2025-57767 | Asterisk | 7.5 High | SIP auth NULL pointer dereference / crash DoS |
| CVE-2021-37748 | Grandstream | High | UCM unauthenticated SIP configuration disclosure |
| CVE-2023-37315 | Grandstream | High | UCM unauthenticated SIP account listing |
| CVE-2024-41713 | Mitel | 9.8 Critical | MiCollab NuPoint path traversal |
| CVE-2026-27624 | coturn | High | STUN/TURN SSRF bypass via IPv4-mapped IPv6 |
| CONFIG-SIP-TLS | Generic | Medium | Unencrypted SIP signaling (no TLS, RFC 3261 §26) |
| CONFIG-SIP-WS-PLAIN | Generic | Medium | SIP-over-WebSocket without TLS (RFC 7118) |
| CONFIG-SIP-WSS-CSWSH | Generic | Medium | Cross-Site WebSocket Hijacking on SIP/WSS |
| AST-AMI-NOTLS | Asterisk | Medium | AMI accessible without TLS encryption |
| CONFIG-VERSION | Generic | Info | Verbose SIP version disclosure in server banner |
| CONFIG-RECORDING | FreePBX/Asterisk | High | Unauthenticated call recording file exposure |
| CONFIG-MODULES | FreePBX | Medium | Module endpoint information disclosure |

### Asterisk Manager Interface (AMI) Attack

Brute-forces AMI on TCP/5038 using an internal default credential list plus
the Asterisk HTTP rawman API on port 8088. On success: dumps all extensions,
voicemail boxes, and active channels; extracts the AMI password into the
CRACK_POOL for immediate reuse in SIP spray; and optionally places a
proof-of-concept toll-fraud call via AMI Originate (bypassing SIP entirely).
Includes a credential-reuse check that tries cracked SIP passwords against AMI
`admin` and `asterisk` accounts.

### SIP Extension Enumeration

Sends SIP REGISTER messages and classifies responses: `200 OK` (valid,
authenticated), `401/403` (valid, auth required), `404` (invalid extension).
Adaptive full-scan mode uses platform-specific ranges derived from the PBX
fingerprint, a priority wordlist of high-value extensions (operator panels,
voicemail, IVRs), and a special-extension probe list (100, 200, operator, vmb)
before performing range sweeps. Extensions discovered by AMI dump skip the
REGISTER sweep and proceed directly to INVITE acceptance probing.

### Credential Spray

Sprays `(username, password)` pairs from `wordlists/credentials.txt` (and
optionally `wordlists/grandstream.txt`) against all auth-required extensions.
A configurable per-extension failure limit (`--max-failures-per-ext`) prevents
account lockout. Captured SIP Digest challenges are written to
`sip_hashes.txt` in hashcat format (`username*realm*nonce*uri*response`).
Phase 6b automatically invokes offline hash cracking on captured challenges,
extends CRACK_POOL with newly discovered passwords, and re-sprays only the
uncracked extensions — all in the same scan run.

### Toll-Fraud Call Proof-of-Concept

Places a live outbound PSTN call from the target PBX to a number you control.
Supports:

- Authenticated INVITE (using cracked extension credentials)
- Anonymous INVITE (demonstrating open dial-out misconfiguration)
- AMI Originate path (when SIP is blocked but AMI is accessible)
- Full SIP identity header spoofing: `P-Asserted-Identity`, `Diversion`,
  `Privacy`, `Remote-Party-ID`, custom `From` display name
- Dial-plan prefix auto-discovery (9 for external, 0, + etc.)
- DTMF tone injection via `SIP-INFO` after call answer (IVR traversal)
- SRTP offer with downgrade detection
- Configurable hold duration before `BYE`
- `--call-dry-run` stops at a provisional response for non-destructive testing

### STUN/TURN Misconfiguration Detection

Probes for open STUN (UDP/3478, UDP/3479) and TURNS (TCP/5349) services.
Checks for CVE-2026-27624 (coturn SSRF bypass via IPv4-mapped IPv6 notation)
and unauthenticated TURN allocation. Results feed into the CVE findings block
in the HTML report.

### NAT Auto-Traversal

On startup (or when `--stun auto` is active), resolves the public reflexive IP
via STUN and patches all SIP `Via:` and `Contact:` headers. Attempts
UPnP/IGD port mapping to punch a pinhole for return traffic from the PBX.
Detects NAT type (direct, full-cone, restricted, symmetric) and warns when
symmetric NAT may break BYE routing. All NAT logic runs transparently; pass
`--no-upnp` to disable UPnP if your environment restricts it.

### Enterprise Reports

Every scan produces a timestamped directory under `reports/` containing:

- `report.html` — styled, printable HTML with findings, evidence, and
  per-finding remediation guidance
- `report.json` — machine-readable findings for SIEM/ticket ingestion
- `traffic.log` — every SIP packet sent and received, timestamped
- `sip_hashes.txt` — captured Digest challenges in hashcat format

## Installation

### Requirements

- Python 3.9 or later (3.12 recommended)
- No mandatory external dependencies — all core functionality runs on the
  Python standard library

Optional tools enhance specific capabilities when present on `$PATH`:

| Tool | Purpose |
|------|---------|
| `nmap` | Faster TCP port sweep during discovery |
| `socat` / `ncat` | Alternative SIP transport relay |
| `sngrep` | Interactive SIP packet capture (hint commands printed during scan) |
| `tcpdump` | Passive SIP capture (hint commands printed for cleartext findings) |
| `hashcat` | Fast offline SIP Digest hash cracking (GPU-accelerated) |
| `john` | Alternative offline hash cracking |
| `hydra` | Supplementary credential spray |

### Install Python Dependency

```bash
pip install -r requirements.txt
```

The only listed dependency is `cryptography>=41.0`, required for SRTP
offer/require mode (`--srtp offer` or `--srtp require`). All other
functionality works without it.

### Quick Start

```bash
# Verify the tool runs
python3 voip_scan.py --help

# Discovery only — safe, no intrusive probes
python3 voip_scan.py --target 192.168.1.100

# Full audit (prompts for interactive authorisation confirmation)
python3 voip_scan.py --target 192.168.1.100 --full

# One-command elite audit — bypasses interactive prompt
python3 voip_scan.py --target 192.168.1.100 --auto --i-have-authorization
```

## Usage Examples

### 1. Safe discovery scan — no authorisation required

Performs SIP OPTIONS sweep and HTTP port identification only. No enumeration,
no spray, no intrusive probes. Safe to run as a preliminary reconnaisance step.

```bash
python3 voip_scan.py --target 10.0.1.50
```

### 2. Full audit with scope file

The recommended workflow for client engagements. Logs the SHA-256 of the
signed scope document into the report as an authorisation audit trail. Runs
all checks including CVE scan, AMI attack, extension enumeration, and
credential spray.

```bash
python3 voip_scan.py \
    --target pbx.client.example.com \
    --scope-file ./signed-sow.pdf \
    --operator "Jane Smith" \
    --full \
    --i-have-authorization
```

### 3. One-command elite auto-mode with toll-fraud demonstration

`--auto` enables every check at stealth speed with STUN NAT traversal,
automatic dialplan prefix discovery, and a live call to a number you control.
Add this to the engagement only when explicitly authorised for full toll-fraud
PoC.

```bash
python3 voip_scan.py \
    --target 203.0.113.10 \
    --auto \
    --call-to +447700900123 \
    --scope-file signed-sow.pdf \
    --i-have-authorization
```

### 4. CIDR sweep — multiple targets from a network range

Sweeps an entire subnet. Useful when the client does not know the exact PBX IP
or has multiple systems in scope.

```bash
python3 voip_scan.py \
    --target 10.0.0.0/24 \
    --scope-file signed-sow.pdf \
    --full \
    --i-have-authorization \
    --report-dir reports/client-internal-audit
```

### 5. Stealth mode against a hardened target

Reduces probe rate to 5 requests per second with 4 workers and 150ms jitter.
Use when the target is known to run fail2ban or rate-limiting IDS rules.

```bash
python3 voip_scan.py \
    --target pbx.target.example.com \
    --scope-file signed-sow.pdf \
    --full \
    --mode stealth \
    --timeout 8 \
    --i-have-authorization
```

### 6. Extension enumeration with a specific range and credential spray

Enumerate only the 1000–1199 range (known to be provisioned from AMI dump),
then spray default credentials. The `--grandstream-creds` flag appends the
Grandstream-specific credential list for UCM targets.

```bash
python3 voip_scan.py \
    --target 10.1.2.50 \
    --scope-file signed-sow.pdf \
    --enum \
    --ext-range 1000-1199 \
    --spray \
    --grandstream-creds \
    --i-have-authorization
```

### 7. Dry-run toll-fraud call with identity spoofing

Places a call that stops at a provisional 18x response — demonstrates
dial-plan routing is reachable without completing a billable call. Spoofs
`P-Asserted-Identity` and `Diversion` headers to demonstrate caller-ID
manipulation risk.

```bash
python3 voip_scan.py \
    --target 203.0.113.10 \
    --scope-file signed-sow.pdf \
    --call-test \
    --call-to +447700900123 \
    --call-from 1001 \
    --call-dry-run \
    --pai "sip:+12025550199@pbx.target.example.com" \
    --diversion "<sip:+12025550100@pbx.target.example.com>;reason=unconditional" \
    --from-display "Spoofed Caller" \
    --i-have-authorization
```

### 8. Authenticated call with DTMF IVR traversal

Places a full call using a cracked extension credential, holds for 90 seconds,
sends DTMF `9` after answer (to exit the IVR), then `1p1000#` (digit 1, 1
second pause, digit hash). Demonstrates full automated toll-fraud capability
including IVR bypass.

```bash
python3 voip_scan.py \
    --target 203.0.113.10 \
    --scope-file signed-sow.pdf \
    --call-test \
    --call-to +447700900123 \
    --call-from 1005 \
    --call-duration 90 \
    --call-dtmf "9p2000 1p1000#" \
    --discover-prefix \
    --i-have-authorization
```

### 9. Behind NAT — multi-NIC host or VPN

When running from a host with multiple network interfaces, specify which
interface to use. STUN will resolve the public IP automatically and patch SIP
headers. Use `--list-networks` first to identify the correct interface index.

```bash
# List available interfaces
python3 voip_scan.py --list-networks

# Run on interface index 1 (e.g. the VPN NIC)
python3 voip_scan.py \
    --target 203.0.113.10 \
    --network 1 \
    --stun auto \
    --scope-file signed-sow.pdf \
    --full \
    --i-have-authorization
```

### 10. Non-standard SIP port with JSON output

When the PBX runs SIP on a non-standard port, pass `--port`. Machine-readable
findings are written to the specified JSON file for integration with ticketing
or SIEM systems.

```bash
python3 voip_scan.py \
    --target 10.10.5.20 \
    --port 5080 \
    --scope-file signed-sow.pdf \
    --full \
    --json-output findings.json \
    --i-have-authorization
```

## CLI Reference

### Target and Identity

| Flag | Description |
|------|-------------|
| `--target TARGET` | IP address, CIDR range, hostname, or `file:hosts.txt` |
| `--operator NAME` | Operator name logged in the report (defaults to `$USER`) |
| `--scope-file PATH` | Signed scope-of-work document; SHA-256 is logged |
| `--i-have-authorization` | Skip the interactive authorisation prompt |

### Scan Mode

| Flag | Description |
|------|-------------|
| `--auto` | One-command maximum-depth audit: enables `--full`, stealth mode, STUN, AMI, prefix discovery. Requires `--i-have-authorization`. |
| `--full` | Run all checks: enum + spray + AMI + HTTP probes + CVE scan. Alias for `--auto`. |

### Discovery and Enumeration

| Flag | Description |
|------|-------------|
| `--enum` | Enumerate extensions via REGISTER probe and INVITE acceptance check |
| `--ext-range RANGE` | Extension range: `1000-1099`, `100,200`, or `file:path` |
| `--ext-wordlist FILE` | Wordlist for extension enumeration (default: `wordlists/extensions.txt`) |
| `--spray` | Spray default credentials against auth-required extensions |
| `--cred-file FILE` | Credential wordlist (default: `wordlists/credentials.txt`) |
| `--grandstream-creds` | Append Grandstream-specific credential list |
| `--ami-attack` | Brute-force AMI (TCP/5038) and Asterisk HTTP rawman API |

### Toll-Fraud Call

| Flag | Description |
|------|-------------|
| `--call-test` | Place a proof-of-concept outbound call |
| `--call-to NUMBER` | Destination number — you must own or control this number |
| `--call-from EXT` | Source extension (defaults to first valid extension found) |
| `--call-dry-run` | Stop at provisional 18x response — no billable call placed |
| `--call-duration SECS` | Hold time before sending BYE (default: 60) |
| `--call-dtmf SEQUENCE` | DTMF digits after answer (`pN` = N ms pause, e.g. `1p500#`) |
| `--discover-prefix` | Auto-discover dialplan prefix (9, 0, +) before placing the call |
| `--call-to-auto` | Use AMI-discovered first extension as the calling party |
| `--check-refer` | Run REFER blind-transfer and SUBSCRIBE eavesdrop probes |
| `--refer-to NUMBER` | Destination for REFER PoC (defaults to `--call-to`) |

### Identity Header Spoofing

| Flag | Description |
|------|-------------|
| `--from-display NAME` | Display name on the `From:` header |
| `--pai URI` | `P-Asserted-Identity` header value |
| `--diversion HEADER` | `Diversion` header (spoofed forward history) |
| `--privacy VALUE` | `Privacy` header: `id`, `header`, `session`, `user`, `none`, `critical` |
| `--remote-party-id HEADER` | `Remote-Party-ID` header (Cisco/legacy PAI equivalent) |
| `--srtp {off,offer,require}` | SRTP policy for the call (default: `off`) |

### Tuning

| Flag | Description |
|------|-------------|
| `--mode {fast,standard,stealth}` | Speed preset: `fast` (rate=100, 64 workers), `standard` (rate=50, 32 workers), `stealth` (rate=5, 4 workers) |
| `--rate N` | Maximum requests per second (overrides mode preset) |
| `--timeout SECS` | Socket timeout in seconds (overrides mode preset) |
| `--workers N` | Parallel workers for sweeps (overrides mode preset) |
| `--jitter SECS` | Random per-request sleep 0 to N seconds (stealth default: 0.15s) |
| `--max-failures-per-ext N` | Stop spraying an extension after N failures (default: 5) |
| `--port PORT` | SIP port (default: 5060) |
| `--ami-port PORT` | AMI port (default: 5038) |
| `--http-attack-port PORT` | Asterisk HTTP API port (default: 8088) |

### Network and NAT

| Flag | Description |
|------|-------------|
| `--source-ip IP` | Bind all sockets to this IP (multi-NIC hosts) |
| `--network INDEX_OR_NAME` | Select outbound interface by index or name (e.g. `0`, `eth0`) |
| `--stun [auto\|HOST[:PORT]]` | Resolve public IP via STUN and patch SIP headers; `auto` tries well-known servers |
| `--no-upnp` | Disable UPnP/IGD port mapping |
| `--source-port-range LOW-HIGH` | Bind source ports within this range (e.g. `5060-5099`) |
| `--list-networks` | Print available network interfaces and exit |

### Output

| Flag | Description |
|------|-------------|
| `--report-dir DIR` | Output directory (default: `reports/<timestamp>`) |
| `--json-output FILE` | Write machine-readable JSON findings to FILE |
| `--no-color` | Disable ANSI colour output |

## Output

All output is written to a timestamped directory under `reports/` (or the path
specified by `--report-dir`).

### report.html

Styled HTML report suitable for direct client delivery or printing to PDF.
Sections: executive summary, per-host findings table, CVE details with
evidence and remediation guidance, credential findings (passwords redacted in
client copy), call PoC outcome with SIP trace excerpt.

### report.json

Machine-readable findings array. Each entry contains: host IP, finding ID,
platform, severity, title, evidence string, remediation, affected version, and
raw SIP trace excerpt. Compatible with standard SIEM and ticketing ingestion
pipelines.

### traffic.log

Complete SIP packet log — every message sent and received during the scan,
timestamped to millisecond precision. Useful for post-engagement review,
dispute resolution, and correlation with IDS/firewall logs on the target side.

### sip_hashes.txt

SIP Digest authentication challenges captured during the credential spray
phase, written in hashcat-compatible format:

```
username*realm*nonce*uri*response
```

Pass directly to hashcat (`-m 11400`) or john (`--format=sip`) for offline
password recovery. The scanner automatically attempts to crack these with
available tools during Phase 6b and re-sprays any extensions whose passwords
are recovered.

## Scope-of-Work Template

A blank scope template is included at `scope-template.md`. Fill in all fields,
obtain the asset owner's signature, and pass the signed document to the
scanner:

```bash
python3 voip_scan.py --scope-file signed-sow.pdf --scope-file ...
```

The SHA-256 hash of the file is recorded in the report header.

## Project Layout

```
voip_scan.py                CLI entry point — the only file you run
scanner/
  sip.py                    SIP message construction, parsing, Digest auth
  discovery.py              Host sweep, port detection, PBX fingerprinting
  enumeration.py            Extension enumeration (REGISTER + INVITE probes)
  auth.py                   Credential spray with lockout guard and hash logging
  call.py                   Toll-fraud PoC: INVITE, ACK, BYE, DTMF, SRTP
  ami.py                    AMI brute-force, loot dump, Originate call
  cve.py                    17 CVE and configuration checks
  http_probes.py            FreePBX / Asterisk / Grandstream / 3CX web probes
  nat.py                    NAT type detection, UPnP/IGD port mapping
  stun.py                   STUN/TURN client (RFC 5389) + CVE-2026-27624 probe
  rtp.py                    SDP parsing (IPv4 + IPv6)
  srtp.py                   SDES SRTP (requires cryptography package)
  dtmf.py                   SIP-INFO DTMF tone injection
  crack.py                  Offline SIP Digest hash cracking integration
  report.py                 HTML + JSON report generation
  utils.py                  Colours, progress bar, traffic log, file hashing
wordlists/
  extensions.txt            Common extension numbers
  extensions_priority.txt   High-value extensions probed first
  credentials.txt           Default SIP credentials
  grandstream.txt           Grandstream UCM-specific credentials
tests/
  ...                       pytest test suite
scope-template.md           Blank scope-of-work template for client sign-off
```

## Legal and Responsible Use

goldagent is designed and maintained for use by professional penetration
testers, red teams, and security researchers operating under written
authorisation from the asset owner.

**You are responsible for:**

- Obtaining explicit written authorisation before running any intrusive check
- Ensuring the destination number supplied to `--call-to` is a number you own
  or have permission to receive calls on
- Complying with all applicable laws in your jurisdiction and the jurisdiction
  of the target system
- Preventing inadvertent exposure of credentials, call recordings, or SIP
  hashes captured during the engagement
- Destroying or securely archiving engagement artefacts in accordance with
  client agreements

The `--scope-file` mechanism and interactive authorisation prompt exist to
create an unambiguous audit trail. They are not a legal defence — proper
written authorisation from the asset owner is always required regardless of
tool-level prompts.

Emergency services numbers (911, 999, 112, and equivalents) must never be
supplied as `--call-to` destinations. The scanner performs basic format
validation but cannot prevent all misuse; the operator is solely responsible.

See [SECURITY.md](SECURITY.md) for responsible disclosure policy and guidance
on reporting vulnerabilities found using this tool during authorised
assessments.

## License

<!-- License placeholder — to be determined by project maintainers -->
