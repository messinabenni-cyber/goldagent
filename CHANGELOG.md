# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- NAT auto-traversal via UPnP/IGD port mapping (`scanner/nat.py`)
- SIP session keepalive: responds to PBX OPTIONS and re-INVITE requests during hold
- BYE routing to Contact URI from 200 OK per RFC 3261 §12.2
- SIP request parser: `parse_request()` and `build_response_to_request()` helpers
- Adaptive scan state machine: `ScanState` dataclass with inter-phase chaining
- AMI-dumped extensions injected into credential spray target lists
- `--json-output` flag for machine-readable findings export
- `--no-upnp` flag to disable UPnP port mapping

### Security
- CRLF injection guard for extra headers in `build_message()`
- Maximum packet size limit (131 KB) enforced in SIP parser
- SSRF protection in `nat.py` `_fetch_url()` and `_soap_action()`
- Phone number format validation for `--call-to` argument

### Fixed
- BYE 481 error: PBX-initiated BYE requests are now correctly acknowledged
- Symmetric NAT: TCP transport is now recommended automatically when detected
- In-dialog OPTIONS keepalive prevents Asterisk session timeout during active calls

## [3.0.0]

### Added
- 17-check CVE scanner covering FreePBX, Asterisk, Grandstream, 3CX, and Mitel
- STUN/TURN probe for CVE-2026-27624 (coturn SSRF)
- Digest authentication capture to `sip_hashes.txt` in hashcat mode 11400 format
- SRTP offer and detection support in toll-fraud call flows
- SIP-INFO DTMF signalling during active calls
- TCP transport fallback when UDP is unreliable or blocked
- Enterprise-grade HTML and JSON report output
