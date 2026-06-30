"""SDP parsing + RTP header building.

The scanner's call PoC doesn't stream audio (no media path needed to prove
toll fraud), so RTP support is minimal — just enough to negotiate SDP and
optionally test SRTP downgrade.

parse_sdp_answer handles:
  - \\r\\n, \\n, or \\r line endings
  - Case-insensitive c= / m= / a= keys
  - Folded continuation lines (leading whitespace)
  - IPv4 (c=IN IP4) AND IPv6 (c=IN IP6) — modern cloud PBXes use both
  - a=crypto SDES answers (extracted into srtp_crypto when present)
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass


@dataclass
class RemoteMedia:
    ip: str
    port: int
    payload_type: int
    codec: str
    srtp_crypto: tuple[int, bytes, bytes] | None = None


def build_sdp_offer(local_ip: str, rtp_port: int = 49170,
                    srtp_offer: str | None = None) -> str:
    """SDP offer for PCMU + PCMA + telephone-event.

    srtp_offer: when given, emits a=crypto and advertises RTP/SAVP.
    """
    proto = "RTP/SAVP" if srtp_offer else "RTP/AVP"
    lines = [
        "v=0",
        f"o=scanner {random.randint(1, 1 << 31)} "
        f"{random.randint(1, 1 << 31)} IN IP4 {local_ip}",
        "s=voip-scan",
        f"c=IN IP4 {local_ip}",
        "t=0 0",
        f"m=audio {rtp_port} {proto} 0 8 101",
        "a=rtpmap:0 PCMU/8000",
        "a=rtpmap:8 PCMA/8000",
        "a=rtpmap:101 telephone-event/8000",
        "a=fmtp:101 0-15",
        "a=sendrecv",
    ]
    if srtp_offer:
        lines.append(srtp_offer)
    return "\r\n".join(lines) + "\r\n"


def parse_sdp_answer(body: str) -> RemoteMedia | None:
    if not body:
        return None

    ip = None
    port = None
    chosen_pt: int | None = None
    rtpmap: dict[int, str] = {}
    srtp_answer: tuple[int, bytes, bytes] | None = None

    # Normalise line endings, then unfold continuation lines
    raw = body.replace("\r\n", "\n").replace("\r", "\n")
    unfolded: list[str] = []
    for line in raw.split("\n"):
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)

    for line in unfolded:
        line = line.strip()
        if not line:
            continue
        low = line.lower()

        # c-line — accept both IPv4 (IP4) and IPv6 (IP6)
        if low.startswith("c=") and ("ip4" in low or "ip6" in low):
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[-1].split("/", 1)[0]   # strip optional TTL/scope
        elif low.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    port = int(parts[1].split("/", 1)[0])
                except ValueError:
                    port = None
                try:
                    chosen_pt = int(parts[3])
                except ValueError:
                    chosen_pt = None
        elif low.startswith("a=rtpmap:"):
            m = re.match(r"a=rtpmap:\s*(\d+)\s+([^/]+)/", line, re.I)
            if m:
                rtpmap[int(m.group(1))] = m.group(2).upper()
        elif low.startswith("a=crypto:"):
            try:
                from . import srtp as _srtp
                parsed = _srtp.parse_sdes_attribute(line)
                if parsed is not None:
                    srtp_answer = parsed
            except ImportError:
                # cryptography lib not available — degrade to plain RTP
                pass

    if not ip or not port:
        return None

    for pt, codec in rtpmap.items():
        if codec == "PCMU":
            return RemoteMedia(ip, port, pt, "PCMU", srtp_answer)
    for pt, codec in rtpmap.items():
        if codec == "PCMA":
            return RemoteMedia(ip, port, pt, "PCMA", srtp_answer)
    if chosen_pt is None:
        chosen_pt = 0
    codec = rtpmap.get(chosen_pt, "PCMU" if chosen_pt == 0 else "PCMA")
    return RemoteMedia(ip, port, chosen_pt, codec, srtp_answer)
