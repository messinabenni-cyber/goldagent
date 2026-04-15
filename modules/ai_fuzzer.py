"""LLM-guided dial-plan inference and extension fuzzer.

The fuzzer works in iterative rounds:

  Round 1  — ~50 structured+random probes across [100, 9999] to build an
             initial response-code histogram.
  Inference — ask Claude (or the rule-based fallback) to suggest the
             most likely extension number ranges based on the histogram.
  Round 2-N — probe the inferred ranges with increasing density until
             ``max_probes`` is reached or 50 consecutive probes return
             no new extensions.

Events are emitted on the shared event bus so the GUI can follow
progress in real time.

SIP probing delegates to ``modules.enumeration.enumerate_extension`` so
all the existing protocol-level logic is reused without duplication.
"""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .enumeration import enumerate_extension
from .events import bus


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    """Summary of one fuzzing run."""

    extensions_found: list[str]
    """All extension numbers that responded as existing (any status)."""

    response_histogram: dict
    """Maps response category to count: {"anon": n, "auth": n, "404": n, "error": n}."""

    inferred_ranges: list[tuple[int, int]]
    """Extension number ranges inferred by the LLM or rule-based fallback."""

    ivr_structure: str
    """Human-readable description of the inferred IVR / dial-plan layout."""

    total_probed: int
    """Total number of extension probes sent across all rounds."""

    duration_s: float
    """Wall-clock duration of the entire fuzzing run in seconds."""


# ---------------------------------------------------------------------------
# Anthropic API constants (shared with ai_advisor, but kept local to avoid
# a circular import)
# ---------------------------------------------------------------------------

_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


# ---------------------------------------------------------------------------
# SIP probe batch
# ---------------------------------------------------------------------------

# Response categories returned by _probe_batch
_CAT_ANON  = "anon"    # 200 OK / 100/180/183 to INVITE without auth
_CAT_AUTH  = "auth"    # 401 / 407
_CAT_404   = "404"     # 404 / 403 / 603
_CAT_ERROR = "error"   # no response / parse error

# Seed extensions covering statistically common PBX extension blocks.
# Used by Round 1 to ensure the initial scatter hits likely ranges.
_COMMON_SEEDS: list[int] = [
    100, 101, 102, 199,
    200, 201, 299,
    1000, 1001, 1099, 1100,
    1200, 1500, 1999,
    2000, 2001, 2099, 2100,
    2500, 2999,
    3000, 3100, 3999,
    4000, 5000, 6000, 7000,
    8000, 9000, 9999,
]


def _probe_batch(
    host: str,
    extensions: list[str],
    port: int,
    timeout: float,
    rate: float,
) -> dict[str, str]:
    """Probe a batch of extensions via SIP REGISTER then INVITE.

    Returns a mapping ``{extension: category}`` where category is one of
    ``"anon"``, ``"auth"``, ``"404"``, or ``"error"``.

    Strategy:
      - Send REGISTER first (cheap, avoids ringing a phone).
      - If REGISTER returns 401/407 the extension exists and requires auth.
      - If REGISTER returns 200 without auth → open register.
      - If REGISTER returns 404/403/603 → also try INVITE in case the PBX
        handles the two methods differently (some PBXes reject REGISTER
        from unknown IPs but happily answer INVITEs).
      - Anything else → INVITE to cross-check.
    """
    results: dict[str, str] = {}
    min_interval = 1.0 / max(rate, 1.0)

    for ext in extensions:
        t0 = time.monotonic()

        reg = enumerate_extension(
            host, ext, port=port, method="REGISTER", timeout=timeout
        )

        if not reg.exists and "no response" in reg.evidence:
            # Network error — don't bother with INVITE
            results[ext] = _CAT_ERROR
        elif reg.auth_required:
            results[ext] = _CAT_AUTH
        elif reg.open_register:
            results[ext] = _CAT_ANON
        else:
            # REGISTER → 404/403 or ambiguous: cross-check with INVITE
            inv = enumerate_extension(
                host, ext, port=port, method="INVITE", timeout=timeout
            )
            if inv.anonymous_invite:
                results[ext] = _CAT_ANON
            elif inv.auth_required:
                results[ext] = _CAT_AUTH
            elif inv.exists:
                results[ext] = _CAT_AUTH  # exists but not clearly open
            else:
                results[ext] = _CAT_404

        elapsed = time.monotonic() - t0
        remaining = min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)

    return results


# ---------------------------------------------------------------------------
# LLM inference of extension ranges
# ---------------------------------------------------------------------------

def _llm_infer_ranges(
    histogram: dict[str, Any],
    api_key: str,
    model: str,
) -> list[tuple[int, int]]:
    """Ask Claude to infer likely extension ranges from the probe histogram.

    ``histogram`` is a dict like::

        {
            "sampled": {"1234": "auth", "5678": "404", ...},
            "counts": {"anon": 2, "auth": 5, "404": 3, "error": 0}
        }

    The LLM must respond with a JSON array of [lo, hi] pairs — nothing else.
    """
    prompt = (
        "You are an expert VoIP penetration tester analysing SIP extension probe results.\n"
        "Below is a response histogram from an initial scatter probe of a PBX.\n"
        "Each sampled extension maps to one of: anon (accepts calls without auth), "
        "auth (exists, requires credentials), 404 (not found), error (no response).\n\n"
        f"Histogram:\n{json.dumps(histogram, indent=2)}\n\n"
        "Based on the pattern of which extensions exist vs. do not exist, infer the "
        "most likely numeric extension ranges used by this PBX dial-plan.\n"
        "Consider that PBX dial plans commonly cluster extensions in contiguous blocks "
        "(e.g., 1000-1099 for a department, 2000-2099 for another).\n"
        "Respond ONLY with a JSON array of [lo, hi] integer pairs covering the ranges "
        "you believe are most likely to contain live extensions.  "
        "Do not include markdown fences or any prose — only the JSON array.\n"
        "Example: [[1000, 1099], [2000, 2050], [3100, 3199]]"
    )

    body = json.dumps({
        "model": model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        _ANTHROPIC_API_URL,
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20.0) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return []

    try:
        data = json.loads(raw)
        text = data["content"][0]["text"].strip()
        # Strip possible fences
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(l for l in lines if not l.startswith("```"))
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            return []
        ranges: list[tuple[int, int]] = []
        for item in parsed:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                lo, hi = int(item[0]), int(item[1])
                if lo <= hi and lo >= 0:
                    ranges.append((lo, hi))
        return ranges
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
        return []


# ---------------------------------------------------------------------------
# Rule-based range inference fallback
# ---------------------------------------------------------------------------

def _rule_based_infer_ranges(histogram: dict[str, Any]) -> list[tuple[int, int]]:
    """Cluster observed live extensions and expand each cluster by ±50.

    ``histogram["sampled"]`` is a dict mapping extension string to category.
    Only extensions that are not ``"404"`` or ``"error"`` are used as seeds.
    """
    sampled: dict[str, str] = histogram.get("sampled", {})
    live_nums: list[int] = []
    for ext, cat in sampled.items():
        if cat in (_CAT_ANON, _CAT_AUTH):
            try:
                live_nums.append(int(ext))
            except ValueError:
                pass

    if not live_nums:
        # No hits at all — fall back to the standard default ranges
        return [(100, 499), (1000, 1999), (2000, 2999)]

    live_nums.sort()

    # Simple 1-D clustering: if two numbers are within 100 of each other,
    # merge them into the same cluster.
    clusters: list[list[int]] = []
    current_cluster: list[int] = [live_nums[0]]
    for n in live_nums[1:]:
        if n - current_cluster[-1] <= 100:
            current_cluster.append(n)
        else:
            clusters.append(current_cluster)
            current_cluster = [n]
    clusters.append(current_cluster)

    ranges: list[tuple[int, int]] = []
    for cluster in clusters:
        lo = max(0, min(cluster) - 50)
        hi = max(cluster) + 50
        # Clamp to sane extension space
        lo = max(lo, 100)
        hi = min(hi, 9999)
        ranges.append((lo, hi))

    return ranges


# ---------------------------------------------------------------------------
# IVR structure inference
# ---------------------------------------------------------------------------

def _describe_ivr_structure(
    found: dict[str, str],
    ranges: list[tuple[int, int]],
) -> str:
    """Build a plain-text description of the inferred dial-plan layout."""
    if not found:
        return "No extensions confirmed. Dial-plan structure unknown."

    anon_exts  = sorted(e for e, c in found.items() if c == _CAT_ANON)
    auth_exts  = sorted(e for e, c in found.items() if c == _CAT_AUTH)

    lines: list[str] = []
    lines.append(
        f"Inferred dial-plan covers {len(ranges)} numeric range(s): "
        + ", ".join(f"{lo}-{hi}" for lo, hi in ranges) + "."
    )
    if auth_exts:
        lines.append(
            f"Extensions requiring authentication ({len(auth_exts)}): "
            + ", ".join(auth_exts[:20])
            + (" ..." if len(auth_exts) > 20 else "") + "."
        )
    if anon_exts:
        lines.append(
            f"Extensions accepting anonymous calls ({len(anon_exts)}): "
            + ", ".join(anon_exts[:20])
            + (" ..." if len(anon_exts) > 20 else "")
            + " — HIGH RISK: toll-fraud directly exploitable."
        )

    # Guess at structure from numeric ranges
    for lo, hi in ranges:
        span = hi - lo
        if span <= 99:
            lines.append(
                f"  Range {lo}-{hi}: small block (~{span+1} extensions), "
                "possibly a single department or feature-code group."
            )
        elif span <= 999:
            lines.append(
                f"  Range {lo}-{hi}: mid-size block (~{span+1} slots), "
                "likely a department or floor grouping."
            )
        else:
            lines.append(
                f"  Range {lo}-{hi}: large range (~{span+1} slots), "
                "typical of a default dial-plan sweep zone."
            )

    return "  ".join(lines)


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def run_ai_fuzzer(
    host: str,
    port: int = 5060,
    api_key: str | None = None,
    timeout: float = 3.0,
    rate: float = 50.0,
    max_probes: int = 500,
    model: str = "claude-3-5-haiku-20241022",
) -> FuzzResult:
    """Run the LLM-guided extension fuzzer against a SIP host.

    Parameters
    ----------
    host:       Target PBX hostname or IP address.
    port:       SIP UDP port (default 5060).
    api_key:    Anthropic API key.  ``None`` activates the rule-based fallback.
    timeout:    Per-probe SIP socket timeout in seconds.
    rate:       Maximum probe rate in probes per second.
    max_probes: Hard cap on total probes sent across all rounds.  Round 1
                uses ~50 structured+random probes before this cap applies.
    model:      Claude model to use for range inference.

    Returns
    -------
    FuzzResult
        Aggregated results from all fuzzing rounds.
    """
    t_start = time.monotonic()

    # Cumulative state
    all_results: dict[str, str] = {}   # ext → category for every probe
    found_exts:  dict[str, str] = {}   # ext → category for confirmed-live only
    total_probed = 0
    histogram_counts: dict[str, int] = {
        _CAT_ANON: 0, _CAT_AUTH: 0, _CAT_404: 0, _CAT_ERROR: 0
    }

    # -----------------------------------------------------------------------
    # Round 1 — structured seeds + random scatter across [100, 9999]
    # -----------------------------------------------------------------------
    round1_exts = [str(n) for n in _COMMON_SEEDS] + [
        str(random.randint(100, 9999)) for _ in range(20)
    ]
    # Deduplicate while preserving order
    seen: set[str] = set()
    round1_unique: list[str] = []
    for e in round1_exts:
        if e not in seen:
            seen.add(e)
            round1_unique.append(e)

    bus.emit("ai_fuzzer.round", {
        "host": host,
        "round": 1,
        "probing": round1_unique,
        "reason": "Structured seeds + random scatter across [100-9999]",
    })

    r1_results = _probe_batch(host, round1_unique, port, timeout, rate)
    all_results.update(r1_results)
    total_probed += len(round1_unique)

    for ext, cat in r1_results.items():
        histogram_counts[cat] = histogram_counts.get(cat, 0) + 1
        if cat in (_CAT_ANON, _CAT_AUTH):
            found_exts[ext] = cat
            bus.emit("ai_fuzzer.found", {
                "host": host, "extension": ext, "category": cat,
                "round": 1,
            })

    # Build histogram dict for inference
    histogram: dict[str, Any] = {
        "sampled": r1_results,
        "counts":  dict(histogram_counts),
    }

    # -----------------------------------------------------------------------
    # Infer extension ranges from Round 1 results
    # -----------------------------------------------------------------------
    if api_key:
        inferred_ranges = _llm_infer_ranges(histogram, api_key, model)
    else:
        inferred_ranges = []

    # Fall back to rule-based if LLM failed or is disabled
    if not inferred_ranges:
        inferred_ranges = _rule_based_infer_ranges(histogram)

    bus.emit("ai_fuzzer.round", {
        "host":    host,
        "round":   "inference",
        "ranges":  inferred_ranges,
        "method":  "llm" if api_key else "rule-based",
    })

    # -----------------------------------------------------------------------
    # Round 2-N — probe inferred ranges, increasing density
    # -----------------------------------------------------------------------
    round_num = 2
    no_new_streak = 0   # consecutive probes with no new extensions

    for lo, hi in inferred_ranges:
        if total_probed >= max_probes:
            break

        # Build an ordered probe list for this range, skip already-probed
        candidates = [
            str(n) for n in range(lo, hi + 1)
            if str(n) not in all_results
        ]

        if not candidates:
            continue

        # Batch into chunks of up to 50 so we can emit progress events
        chunk_size = 50
        for chunk_start in range(0, len(candidates), chunk_size):
            if total_probed >= max_probes or no_new_streak >= 50:
                break

            remaining_budget = max_probes - total_probed
            chunk = candidates[chunk_start: chunk_start + min(chunk_size, remaining_budget)]
            if not chunk:
                break

            bus.emit("ai_fuzzer.round", {
                "host":         host,
                "round":        round_num,
                "range":        [lo, hi],
                "probing_n":    len(chunk),
                "total_probed": total_probed,
                "budget_left":  max_probes - total_probed,
            })

            batch_results = _probe_batch(host, chunk, port, timeout, rate)
            all_results.update(batch_results)
            total_probed += len(chunk)
            round_num += 1

            new_in_batch = 0
            for ext, cat in batch_results.items():
                histogram_counts[cat] = histogram_counts.get(cat, 0) + 1
                if cat in (_CAT_ANON, _CAT_AUTH) and ext not in found_exts:
                    found_exts[ext] = cat
                    new_in_batch += 1
                    bus.emit("ai_fuzzer.found", {
                        "host":      host,
                        "extension": ext,
                        "category":  cat,
                        "round":     round_num,
                    })

            if new_in_batch == 0:
                no_new_streak += len(chunk)
            else:
                no_new_streak = 0   # Reset streak on any discovery

    duration = time.monotonic() - t_start

    ivr_structure = _describe_ivr_structure(found_exts, inferred_ranges)

    result = FuzzResult(
        extensions_found=sorted(found_exts.keys(), key=lambda e: (len(e), e)),
        response_histogram=dict(histogram_counts),
        inferred_ranges=inferred_ranges,
        ivr_structure=ivr_structure,
        total_probed=total_probed,
        duration_s=round(duration, 2),
    )

    bus.emit("ai_fuzzer.done", {
        "host":              host,
        "extensions_found":  len(result.extensions_found),
        "total_probed":      total_probed,
        "duration_s":        result.duration_s,
        "inferred_ranges":   inferred_ranges,
    })

    return result
