"""Deadline-compliance attestation: the signed, examiner-recorded timeliness verdict.

The provenance spine already proves a run was not tampered with: the run-log sha,
the per-entry hash chain, and the detached Ed25519 signature attest the exact
ordered, complete event stream. What it does NOT yet emit is the one line a buyer
pays for and an examiner writes down first: per regime, "filed at T+N, M of margin,
GREEN", with that verdict itself bound inside the signature.

This module derives that verdict, deterministically and with NO LLM, from the
clock output the run already produced. For each filed regime it computes
`{regime, trigger_event, statutory_deadline, filed_at, margin_seconds, margin_human,
met}` straight from the packet's clock rows (started, deadline, stopped). A clock
that stopped at or before its deadline MET the deadline; a stop after the deadline
MISSED it; a clock still running is not filed and carries no verdict yet.

The whole attestation is then canonicalized (sorted-keys, no-whitespace JSON, the
same recipe the run log and the bound signing payload use, with NO now() and no
RNG) and hashed once to `attestation_sha`. That digest is folded into the bound
Ed25519 payload alongside the run-log sha and chain head, so a tampered margin
breaks the signature. The attestation object renders in the packet as the
"deadline compliance attestation" table; the digest is the value the signature
binds.

DERIVED, never hashed into the run log. The attestation is computed read-only from
the packet's clock rows (which are themselves derived from the deterministic
ClockEngine). It is folded ONLY into the detached signature and rendered at packet
time; it never becomes a run-log event, so the run-log sha, the chain head, and
byte-identical replay are untouched.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def _parse_ts(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp to an aware UTC datetime, or None if absent or
    unparseable. The clock rows the attestation reads always carry full ISO-8601
    instants; None is returned defensively so a sparse row never raises."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _human_margin(seconds: int) -> str:
    """Render a signed second count as a compact, deterministic human margin.

    Positive is time to spare before the deadline; negative is overrun past it.
    The form is stable (no locale, no now()) so the rendered string is byte-stable
    across machines: e.g. 111600 -> "31h 0m", -3600 -> "-1h 0m"."""
    sign = "-" if seconds < 0 else ""
    s = abs(int(seconds))
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, _ = divmod(s, 60)
    if days:
        return f"{sign}{days}d {hours}h {minutes}m"
    return f"{sign}{hours}h {minutes}m"


def build_attestation(clock_rows: list[dict]) -> dict:
    """Build the deterministic per-regime deadline-compliance attestation from the
    packet's clock rows.

    Each clock row carries `name`, `correlation_id`, `trigger_event`, `started`,
    `deadline`, and `stopped` (empty string while running). A FILED regime is one
    whose clock stopped: for it the attestation records the statutory deadline, the
    filed-at instant, the signed margin (deadline minus filed-at, in seconds and a
    human string), and `met` (filed at or before the deadline). A running clock is
    recorded as not filed with `met` null and no margin, so the attestation is an
    honest snapshot, never a guess.

    The regimes are sorted by correlation_id so the object is order-stable
    regardless of the clock-row order, which keeps `attestation_sha` byte-stable.
    """
    regimes: list[dict] = []
    for c in sorted(clock_rows, key=lambda r: r.get("correlation_id", "")):
        deadline = _parse_ts(c.get("deadline", ""))
        stopped = _parse_ts(c.get("stopped", ""))
        entry = {
            "regime": c.get("name", ""),
            "correlation_id": c.get("correlation_id", ""),
            "trigger_event": c.get("trigger_event", ""),
            "statutory_deadline": c.get("deadline", ""),
        }
        if stopped is not None and deadline is not None:
            margin_seconds = int((deadline - stopped).total_seconds())
            entry["filed"] = True
            entry["filed_at"] = c.get("stopped", "")
            entry["margin_seconds"] = margin_seconds
            entry["margin_human"] = _human_margin(margin_seconds)
            entry["met"] = margin_seconds >= 0
        else:
            entry["filed"] = False
            entry["filed_at"] = None
            entry["margin_seconds"] = None
            entry["margin_human"] = None
            entry["met"] = None
        regimes.append(entry)

    filed = [r for r in regimes if r["filed"]]
    met = [r for r in filed if r["met"]]
    return {
        "regimes": regimes,
        "filed_count": len(filed),
        "met_count": len(met),
        "all_met": bool(filed) and len(met) == len(filed),
    }


def canonical_attestation_bytes(attestation: dict) -> bytes:
    """The attestation serialized to canonical JSON bytes.

    Uses the SAME canonicalization recipe as the run log and the bound signing
    payload (`json.dumps(..., sort_keys=True, separators=(",",":"))`), with no
    now() and no RNG, so the same run always yields the same attestation bytes and
    therefore the same `attestation_sha`."""
    return json.dumps(attestation, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def attestation_sha(attestation: dict) -> str:
    """The sha256 over the canonical attestation bytes. This is the digest folded
    into the bound Ed25519 payload, so a tampered margin or verdict moves it and
    breaks the signature."""
    return hashlib.sha256(canonical_attestation_bytes(attestation)).hexdigest()
