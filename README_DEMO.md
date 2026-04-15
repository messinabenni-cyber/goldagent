# VoIP Live-Call Demo — `voip_demo.py`

Real-call version of the scanner. Finds a weakness in the client's PBX and
**actually makes your mobile ring**, plays audio when you answer, hangs up.
Use this to show a client exactly what a compromised VoIP system looks like.

## TL;DR

```bash
# The happy path: one command, done.
python3 voip_demo.py \
    --target 10.0.0.0/24 \
    --ring +447700900123 \
    --scope-file scope.txt
```

The tool will:

1. Sweep the network for SIP systems
2. Enumerate extensions on each PBX
3. Test anonymous INVITE + default credentials
4. Pick the strongest attack path
5. Place a real call to `--ring` with RTP audio
6. Hang up after `--hold` seconds (default 30)
7. Write a client-ready report

## Dial-plan prefixes (outside line + international access)

Most PBXes sit behind a dial-plan transform. From an internal extension the
dial string for an external mobile is typically **not** the raw E.164 number.
Common layers:

| Layer | Examples | Typical PBX |
|---|---|---|
| Outside-line selector | `9`, `0` | Nearly all corporate PBXes |
| International access code | `00` (EU/world), `011` (North America) | Any PBX doing PSTN |
| Combined | `900...`, `9011...` | US/UK corporate calling abroad |
| Direct E.164 | `+447...` | Modern/mobile-first deployments |

**The tool handles this for you automatically.** Before the real call, it
probes candidate formats against the PBX (INVITE + read-once + CANCEL) and
picks the one that routes. The probes use CANCEL so the target phone does
NOT ring during discovery — only the final, confirmed-routable format
actually rings your mobile.

```bash
# Just supply your mobile number — tool auto-finds the right prefix
python3 voip_demo.py --target 10.0.0.50 --ring +447700900123 \
    --scope-file scope.txt

# Force a specific prefix (skip probing)
python3 voip_demo.py ... --ring 447700900123 --dial-prefix 9011

# Turn off probing entirely (use --ring as literal dial string)
python3 voip_demo.py ... --ring 9011447700900123 --no-dialplan-probe
```

Example probe output (from a real PBX that only routes `9011...`):
```
Candidate              Status     Code   RTT    Reason
──────────────────────────────────────────────────────────────
+447700900123          rejected   404      1ms  Not Found
447700900123           rejected   404      0ms  Not Found
9+447700900123         rejected   404      0ms  Not Found
00447700900123         rejected   404      1ms  Not Found
011447700900123        rejected   404      0ms  Not Found
900447700900123        rejected   404      0ms  Not Found
9011447700900123       routed     100      0ms  Trying  ← winner
```

## PBX compatibility

Built on standard SIP (RFC 3261) + standard RTP (RFC 3550) + G.711 μ-law
& A-law (both offered & negotiated). Works against everything that accepts
one of those codecs — which in practice is the entire industry.

| PBX / system | Discovery | Enum | Live call | AMI pwn |
|---|:-:|:-:|:-:|:-:|
| Asterisk (all versions) | ✓ | ✓ | ✓ | ✓ |
| FreePBX / Yeastar / Elastix / Issabel / PIAF | ✓ | ✓ | ✓ | ✓ |
| FreeSWITCH | ✓ | ✓ | ✓ | — (uses ESL, not AMI) |
| Kamailio / OpenSIPS | ✓ | ✓ | ✓ (proxied) | — |
| 3CX | ✓ | ✓ | ✓ | — |
| Cisco CUCM / CME | ✓ | ✓ | ✓ | — |
| Avaya IP Office / Aura SM | ✓ | ✓ | ✓ | — |
| Mitel MiVoice / MX-One | ✓ | ✓ | ✓ | — |
| Grandstream UCM | ✓ | ✓ | ✓ | — |
| Panasonic KX-NS/NSX | ✓ | ✓ | ✓ | — |

**Known limitations:**

- **TLS-only PBXes** (port 5061 only, no 5060): not yet supported. Most corporate PBXes accept 5060/UDP; some hardened deployments disable it.
- **G.722 / G.729 / Opus only**: we offer PCMU+PCMA which all modern PBXes accept as a fallback, but a hardened-codec deployment could refuse. Adding G.722 is a straightforward upgrade.
- **SIP over TCP**: UDP only today. Affects some Cisco deployments.
- **IPv6**: IPv4 only.

## Which test number should I use?

**Your own mobile.** Full stop. It is the only number that is:

- Guaranteed to route through any PSTN trunk the PBX has
- Visible to you (the caller ID shown will be the client's own company number — great demo moment)
- Audible to you (so you can confirm the audio stream worked)
- Legal and ethical — you're calling yourself

Public "test" numbers are unreliable: carriers disable them, regional echo
services require SIP accounts not PSTN, and 1-800 test lines often short-circuit
inside the carrier before the PBX sees any RTP.

**Format:** use E.164 (`+447700900123`, `+15551234567`). Most PBXes normalize
it. If the PBX strips the `+`, fall back to the exact format it expects
(e.g. `91555...` or `00447...`).

### If you need a SECOND ring destination for comparison

Grab a free Google Voice number (US) or a 30-day burner SIM. Do NOT hammer
public "SIP test echo" services — many are offline, rate-limited, or
redirect to advertising content.

## Which softphone should I download?

You don't need one for this tool — `voip_demo.py` places the call itself.
But if you want a softphone to verify findings manually (register as the
cracked extension, dial by hand, etc.), these are the good free options:

| Softphone   | Platforms                  | Notes                                    |
|-------------|----------------------------|------------------------------------------|
| **Linphone** | macOS / Win / Linux / iOS / Android | Open-source, most complete SIP stack. Best default. |
| **Zoiper (Free)** | same                     | Friendly UI, quick to configure.        |
| **MicroSIP** | Windows only              | Lightweight, portable.                   |
| **Telephone** | macOS only               | Native macOS look, minimal.              |
| **Groundwire** | iOS / Android           | Paid, but mobile-demo quality.           |

On macOS I'd install **Linphone** (free from linphone.org) and
configure it against the discovered extension using the cracked password
the tool prints — that's a second way to show the client the breach.

## DTMF — navigate the IVR live

Send DTMF digits after the call answers to push through IVRs in real time.
RFC 4733 telephone-event over RTP (PT=101). Digits 0-9, *, #, A-D, plus
`pN` pause tokens for N milliseconds.

```bash
# Press 0 to reach the operator
python3 voip_demo.py ... --dtmf 0

# Enter PIN 1234 then hash
python3 voip_demo.py ... --dtmf 1234#

# Wait 1s, then dial 9, then wait 500ms, then 1
python3 voip_demo.py ... --dtmf "p1000,9,p500,1"

# Digit duration (default 200ms — good for most IVRs)
python3 voip_demo.py ... --dtmf "0" --dtmf-digit-ms 150
```

DTMF plays BEFORE audio streaming starts, so the IVR hears clean signalling.
After DTMF completes, the audio payload (TTS or custom WAV) streams as usual.

## Call recording — attach audio to the client report

The tool records the far-end audio stream to a WAV file by default.
Perfect evidence for the client briefing — they hear the call was real.

```bash
# Default: record to <report-dir>/call_<ip>_<ext>.wav
python3 voip_demo.py ... --ring +447700900123

# Custom path
python3 voip_demo.py ... --ring +... --record-path demo.wav

# Disable recording
python3 voip_demo.py ... --ring +... --no-record
```

The recording captures what the remote side was sending (their IVR prompts,
the person you're calling, the tones you hear) — it's what the client will
hear if they pick up. Decoded from G.711 μ-law or A-law depending on what
the PBX negotiated.

## Vuln probes — CVE-targeted HTTP checks

After discovery, the tool probes management surfaces for known-bad
patterns: FreePBX admin panel, Asterisk ARI, Cisco CUCM AXL, 3CX
WebClient, Grandstream UCM, Polycom phones, Avaya WebLM. Findings come
through in the report.

```bash
# Default: probes run automatically
python3 voip_demo.py ... --ring +447700900123

# Disable probes
python3 voip_demo.py ... --no-probe-vulns
```

## Vendor-specific credential spraying

When the PBX fingerprints as Cisco / Polycom / Yealink / Grandstream /
Avaya / Mitel, the tool merges the vendor-specific default-credentials
list into the spray. Finds more weak accounts with zero extra setup.

## AMI post-exploitation

When AMI creds hit, the tool automatically pulls:

- **Voicemail user list** — mailbox numbers, names, emails, message counts
- **Active channels** — live call state right now (callerID, ext, duration)
- **SIP trunk registrations** — the upstream carrier(s) the PBX uses

All surfaced as dedicated findings in the HTML report.

## Audio

By default the tool generates a spoken message via macOS `say`
(or `espeak` on Linux) at 8 kHz mono 16-bit, μ-law encodes it, and streams
it over RTP.

Default message:
> *"This is an authorized penetration test. Your VoIP system accepted this
> call without proper authentication. Please contact your security team
> immediately."*

Override it:

```bash
# Custom spoken message
--audio-message "You just got pwned. Acme Security, April 2026."

# Pre-recorded WAV (must be 8 kHz mono 16-bit PCM)
--audio-file evidence/briefing.wav

# If no TTS engine is found, it falls back to a 440Hz tone.
```

For the client-briefing version, record a 10-second WAV with:

```bash
ffmpeg -f lavfi -i "sine=frequency=440:duration=2" \
       -af "apad=whole_dur=10" \
       -ar 8000 -ac 1 -sample_fmt s16 \
       briefing.wav
# Or speak into a mic:
sox -d -r 8000 -c 1 -b 16 briefing.wav trim 0 15
```

## What gets demonstrated

The client hears their own desk phone's caller ID on your mobile, answers
it, hears your scripted message, and watches you hang up — in 60 seconds.
Then you hand them the HTML report showing:

- Which PBX, which extension, which attack path
- Exact SIP trace of the call
- RTP packets sent and codec negotiated
- The call duration they'll see in their CDR
- Remediation steps, severity-ranked

## Guardrails

- `--scope-file` is mandatory (not optional like `voip_scan.py`)
- Authorization prompt runs interactively unless `--i-have-authorization`
- `--dry-ring` does the full recon but skips the actual call (good for rehearsal)
- Only ONE successful call by default (`--stop-at-first`, on); use `--all-paths` for audits
- `--hold` caps how long the call stays up
- Full SIP + RTP trace written to `report_dir/traffic.log`

## Future upgrades (ordered by impact)

Practical next steps if you want to broaden coverage or tighten demos.
Anything here is a straightforward addition to the existing modules.

| Priority | Upgrade | Why |
|---|---|---|
| ★★★ | **G.722 + G.729 codec support** | Some modern deployments insist on wideband. ~200 LOC; mirrors audio.py A-law pattern. |
| ★★★ | **SIP over TLS (port 5061)** | Required for hardened PBXes (and growing share of cloud PBX). Python's ssl module handles it. |
| ★★★ | **DTMF (RFC 2833) sending** | Lets the tool navigate IVRs live — e.g. dial 0 for operator, * to reach voicemail. Massive demo upgrade. |
| ★★ | **Call recording → WAV in report** | Capture the real call's audio (both sides), attach to report as MP3. Devastating for the client briefing. |
| ★★ | **Post-exploitation voicemail extraction** | After breaching an extension, pull its voicemails via AMI `VoicemailUserlist`. Shows data-exfil risk, not just toll-fraud. |
| ★★ | **CDR pulling via AMI** | `Action: CoreShowChannels` + CDR database dump reveals historical abuse — great forensic evidence. |
| ★★ | **CVE-targeted probes** | Known FreePBX / Asterisk / CUCM / 3CX RCE & disclosure CVEs (FreePBX `config.php`, CUCM AXL leaks, 3CX 2023 supply-chain, etc.). Version-aware. |
| ★★ | **Asymmetric NAT / rport handling** | The tool is LAN-oriented; working across NAT requires STUN or listening on the advertised Contact port. |
| ★ | **SIP over TCP** | Some PBXes reject fragmented UDP. |
| ★ | **IPv6** | Rarely the only path, but some greenfield deployments are v6-only. |
| ★ | **Concurrency across multiple PBXes** | Run the full chain against N hosts in parallel. |
| ★ | **Fingerprint-driven default credentials** | Expand `default_credentials.txt` to vendor-specific lists (Cisco/Avaya/Mitel). |
| ★ | **TFTP config-pull** | Phones boot-download plaintext creds from TFTP; often unauth. |
| ★ | **ARP-spoof + RTP MITM** | Active call interception. Requires scapy / raw sockets; out of scope for most pentests but devastating when in-scope. |

**Not in scope** (would drift into red-team territory without clear pentest value):
detection evasion, log-scrubbing, persistence mechanisms, C2 channels.

## Command reference

| Flag | Default | Meaning |
|---|---|---|
| `--target` | required | IP, CIDR, or hostname |
| `--ring` | required | PSTN number to ring (your mobile) |
| `--scope-file` | required | Signed authorization document |
| `--hold` | 30 | Seconds to stay connected after answer |
| `--audio-file` | — | WAV override (8 kHz mono 16-bit) |
| `--audio-message` | default demo script | TTS text |
| `--caller-id-name` | "Pentest Demo" | SIP From display name |
| `--ext-range` | — | `1000-1099`, `100,200`, or `file:path` |
| `--ext-wordlist` | wordlists/common_extensions.txt | default wordlist |
| `--cred-file` | wordlists/default_credentials.txt | user:pass list |
| `--skip-creds` | off | Only test anon paths (quieter) |
| `--all-paths` | off | Don't stop at first successful call |
| `--dry-ring` | off | Skip the actual call, simulate only |
| `--rate` | 50 | SIP packets/sec |
| `--timeout` | 3 | Socket timeout (s) |
| `--port` | 5060 | SIP port |
| `--report-dir` | `reports/demo-<ts>/` | Output directory |
