# VoIP Pentest Scanner

A VoIP network security assessment tool for authorized penetration testing.
Discovers SIP/VoIP systems on a network, enumerates extensions, tests for
weak/default credentials, probes for anonymous calling, and optionally places
a proof-of-concept outbound call to demonstrate exposure to the client.

## Authorization

**This tool may only be used on networks and systems you own or have explicit
written authorization to test.** Unauthorized scanning, credential testing,
or call placement is illegal in most jurisdictions (CFAA, Computer Misuse
Act, etc.). The tool prints an authorization prompt on launch and logs the
operator's acknowledgement into the report — use `--scope-file` to record the
signed scope of work for the engagement.

## What it checks

| Check | Purpose |
|---|---|
| Host/port discovery | Finds hosts listening on SIP (5060/5061 UDP+TCP), IAX2 (4569), H.323 (1720), Skinny (2000), MGCP (2427) |
| SIP OPTIONS probe | Identifies PBX software + version from `Server` / `User-Agent` headers |
| Extension enumeration | Uses REGISTER/INVITE response codes (401 vs 404) to list valid extensions |
| Anonymous INVITE | Checks whether the PBX accepts calls from unauthenticated peers |
| Credential spraying | Tests extensions against a default-credentials list (admin/admin, 1000/1000, etc.) |
| Open management ports | Detects exposed FreePBX/Asterisk Manager/web admin |
| Call proof-of-concept | With explicit `--call-test` flag, places a SIP INVITE to a number you control to prove outbound toll-fraud risk |
| Report | Generates HTML + JSON report with findings, severity, evidence, remediation |

## Install

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

No root required for SIP probing (uses unprivileged UDP sockets).
Host sweep uses TCP connect — also unprivileged.

## Usage

```
# Passive discovery only (safe, OPTIONS only, no auth attempts)
python3 voip_scan.py --target 192.168.1.0/24 --discover

# Full audit without call placement
python3 voip_scan.py --target 192.168.1.0/24 --full --scope-file scope.txt

# Full audit + proof-of-concept call to a number YOU control
python3 voip_scan.py --target 10.0.0.50 --full \
    --call-test --call-to 15551234567 --call-from 1000 \
    --scope-file scope.txt --report-dir reports/acme

# Enumerate extensions on a known PBX
python3 voip_scan.py --target 10.0.0.50 --enum-extensions \
    --ext-range 1000-2000
```

### Key flags

- `--target`  Single IP, CIDR, or hostname
- `--discover`  Host+port sweep only (safest)
- `--enum-extensions`  REGISTER/INVITE extension enumeration
- `--test-creds`  Try default credentials against discovered extensions
- `--call-test`  Attempt outbound call (requires `--call-to`, `--call-from`)
- `--full`  All checks EXCEPT call-test (must be opted-in explicitly)
- `--scope-file path`  Path to signed authorization/scope document; hash is recorded in report
- `--report-dir dir`  Where to write findings (default `./reports/<timestamp>/`)
- `--rate N`  Max packets per second (default 50; tune to avoid DoS-like impact)
- `--timeout N`  Socket timeout seconds (default 3)

## Safety

- Rate-limited by default
- Call test requires BOTH `--call-test` AND a `--call-to` number to avoid accidental dialing
- Call test ACKs and immediately sends BYE — no audio streamed, no ring-through
- Authorization prompt must be answered `yes` interactively unless `--i-have-authorization` is passed and a `--scope-file` is supplied
- Never tests credentials without `--test-creds`
- Writes ALL outbound SIP traffic to `traffic.log` inside the report dir for post-engagement review

## Scope-of-work template

See `scope.template.txt` for a minimal authorization-to-test template you
should have the client countersign before running anything beyond `--discover`.
