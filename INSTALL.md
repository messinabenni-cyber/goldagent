# Installation Guide

USE ONLY ON SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORISED TO TEST.
See [SECURITY.md](SECURITY.md).

## System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Python | 3.9 | 3.11+ |
| OS | Ubuntu 20.04 / Kali 2022 / macOS 12 | Kali 2024 / Ubuntu 24.04 |
| RAM | 256 MB | 1 GB |
| Network | Direct path to target | Same VLAN as PBX (avoids NAT BYE issues) |

## Core Installation

No mandatory external packages. Python stdlib covers all core functionality.

```bash
git clone https://github.com/messinabenni-cyber/goldagent
cd goldagent
```

For SRTP testing only (optional):

```bash
pip install cryptography
```

Verify installation:

```bash
python3 voip_scan.py --help
python3 -m pytest tests/ -q    # 281 tests, all should pass
```

## Optional System Tools

goldagent auto-detects these tools and uses them when available:

| Tool | Enables | Install (Debian/Ubuntu) |
|---|---|---|
| `nmap` | Accelerated port scan, OS detection | `apt install nmap` |
| `ncat` / `socat` | Manual NAT bypass suggestions | `apt install ncat socat` |
| `sngrep` | Live SIP packet capture display | `apt install sngrep` |
| `tcpdump` | Raw packet capture | `apt install tcpdump` |

### Kali Linux (all at once)

```bash
apt update && apt install -y nmap ncat socat sngrep tcpdump
```

### macOS (Homebrew)

```bash
brew install nmap socat netcat
```

## Hash Cracking Setup (Optional)

To crack captured SIP digest hashes offline:

```bash
# rockyou wordlist (required by crack.py auto-install)
apt install wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz

# hashcat (GPU-accelerated, optional)
apt install hashcat
# crack with: hashcat -m 11400 sip_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Running Tests

```bash
python3 -m pytest tests/ -v
```

All 281 tests use mocked sockets — no real network required.

## Common Issues

### `ModuleNotFoundError: No module named 'cryptography'`
SRTP testing requires the `cryptography` package. Install it or skip SRTP:
```bash
pip install cryptography
# or run without SRTP:
python3 voip_scan.py --target ... --srtp off
```

### STUN lookup fails behind corporate proxy
Use `--no-stun` or specify a STUN server on your network:
```bash
python3 voip_scan.py --target ... --stun your-stun-server:3478
```

### BYE not acknowledged (NAT suspected)
Run with `--stun auto` so the scanner advertises your public IP in Contact/Via:
```bash
python3 voip_scan.py --target ... --stun auto --call-test ...
```
If behind symmetric NAT, add TCP transport: `--tcp` on the call attempt.

### Permission denied on port 5060
The scanner uses ephemeral ports (5062, 5063) not port 5060. No root required.

### UPnP port mapping fails
Disable with `--no-upnp` if your network doesn't have a UPnP-enabled gateway.
