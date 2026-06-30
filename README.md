# voip_scan

Minimal VoIP penetration testing scanner, tuned for **FreePBX / Asterisk /
Grandstream** engagements on internet-facing targets.

One CLI. One HTML report. One job: prove the toll-fraud risk.

> **Use only on systems you own or are explicitly authorised to test.**
> A signed scope-of-work is required before any intrusive action.

## Install

```bash
pip install -r requirements.txt
```

`cryptography` is the only dependency, and only needed for SRTP testing —
plain RTP scans work without it.

## Quick start

```bash
# Discovery only (safe, default)
python3.12 voip_scan.py --target 1.2.3.4

# Full external pentest with toll-fraud PoC
python3.12 voip_scan.py --target 1.2.3.0/24 \
    --scope-file sow.pdf \
    --full \
    --call-test --call-to +447900900900 --call-dry-run
```

Outputs land in `reports/<timestamp>/`:
- `report.html` — open in a browser, print to PDF for clients
- `report.json` — same data, machine-readable
- `traffic.log` — every SIP packet sent and received

## What it tests

| Phase            | Detect                                                   |
|------------------|----------------------------------------------------------|
| Discovery        | Open SIP/HTTP/AMI ports, fingerprint PBX vendor          |
| HTTP probes      | Exposed FreePBX admin, UCP, Asterisk HTTP, Grandstream UI |
| AMI attack       | Default credentials on TCP/5038 (FreePBX/Asterisk/UCM)   |
| Extension enum   | REGISTER probe + INVITE acceptance check                  |
| Credential spray | Common defaults + Grandstream-specific list, with lockout guard |
| Call PoC         | Toll-fraud demonstration — INVITE → 200 OK → ACK → BYE   |

The call PoC supports SRTP offer (to detect downgrade), SIP-INFO DTMF (to
traverse IVRs), source-IP/port binding (for multi-NIC hosts), and identity
header spoofing (PAI / Diversion / Privacy / Remote-Party-ID / display name)
— all the primitives a strong toll-fraud demonstration needs.

## Authorisation

```
--scope-file sow.pdf          # SHA-256 of the file is logged in the report
--operator "Your Name"        # Logged in the report
--i-have-authorization        # Skip the interactive y/n prompt
```

Every intrusive flag (`--enum`, `--spray`, `--call-test`, `--ami-attack`,
`--full`) requires either a scope file or the interactive prompt.

## Layout

```
voip_scan.py            CLI entry point — the only thing you run
scanner/
  sip.py                SIP build/parse, digest auth, identity headers
  discovery.py          Host + port + SIP fingerprint
  enumeration.py        Extension enum
  auth.py               Credential spray with lockout guard
  call.py               Toll-fraud PoC + SRTP + SIP-INFO DTMF
  ami.py                Asterisk Manager Interface attacks
  http_probes.py        FreePBX / Asterisk / Grandstream web probes
  rtp.py                SDP parse (IPv4 + IPv6)
  srtp.py               SDES SRTP (optional, needs cryptography)
  dtmf.py               SIP-INFO DTMF
  report.py             HTML + JSON report
  utils.py              Helpers
wordlists/
  extensions.txt        Common extensions
  credentials.txt       Common defaults
  grandstream.txt       Grandstream-specific
tests/
  ...                   pytest test suite
```
