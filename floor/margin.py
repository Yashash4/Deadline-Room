"""Deadline-margin tiered signal (E7.2): a pure, deterministic classifier that
turns a statutory Clock and an instant `now` into an operational tier
(GREEN -> WARN -> CRITICAL -> BREACH).

The operator's headline number is the MARGIN: how much statutory time is left
before a deadline. A clock counts down through three thresholds, configured per
regime in floor/regimes.yaml (`warn_margin` / `critical_margin`, in seconds):

  GREEN     margin > warn_margin            plenty of time
  WARN      critical_margin < margin <= warn_margin
  CRITICAL  0 < margin <= critical_margin   the deadline is imminent
  BREACH    margin <= 0                      the deadline is past

This module is PURE and READ-ONLY. It reads a Clock's deterministic fields
(deadline, stopped_at) and a caller-supplied `now`; it makes no LLM call, writes
nothing to any run-log, and reuses warden.clocks math (`Clock.remaining`,
`Clock.breached`). The live board (floor/live_clock.py), the live escalation
beat (floor/run_floor.py --live), and the web margin board all read these tiers;
none of it is ever the sealed deterministic record. So a margin classification
can never move a sealed run-log sha or perturb byte-identical replay.

A clock that has STOPPED (filed) is classified against its stopped_at instant,
so a filed clock reports the tier it landed in (its filing margin), frozen, not a
tier that keeps sliding after the work is done. That mirrors Clock.remaining,
which references stopped_at when set.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from warden.clocks import Clock

# Tier labels, ordered from most to least margin. The order also drives the live
# escalation: a crossing INTO a tier with strictly higher severity than the last
# observed tier fires one escalation post.
TIER_GREEN = "GREEN"
TIER_WARN = "WARN"
TIER_CRITICAL = "CRITICAL"
TIER_BREACH = "BREACH"

# Severity rank, ascending. A higher rank is a more urgent tier; an escalation
# fires only on a crossing to a strictly higher rank (GREEN->WARN, WARN->CRITICAL,
# CRITICAL->BREACH, or any skip), never on a downgrade.
_TIER_RANK = {
    TIER_GREEN: 0,
    TIER_WARN: 1,
    TIER_CRITICAL: 2,
    TIER_BREACH: 3,
}


def tier_rank(tier: str) -> int:
    """The ascending severity rank of a tier label. Raises on an unknown label so
    a typo surfaces structurally rather than silently ranking as GREEN."""
    try:
        return _TIER_RANK[tier]
    except KeyError as e:
        raise ValueError(f"unknown margin tier: {tier!r}") from e


@dataclass(frozen=True)
class MarginThresholds:
    """The per-clock warn/critical margin thresholds, in SECONDS of remaining
    statutory time. A clock with margin above warn_seconds is GREEN; at or below
    warn_seconds (but above critical_seconds) is WARN; at or below critical_seconds
    (but above zero) is CRITICAL; at or below zero is BREACH.

    Both thresholds are required to be positive and ordered (warn > critical): a
    mis-ordered or non-positive pair is a config error surfaced structurally, never
    silently reordered."""
    warn_seconds: float
    critical_seconds: float

    def __post_init__(self) -> None:
        if self.warn_seconds <= 0 or self.critical_seconds <= 0:
            raise ValueError(
                f"margin thresholds must be positive seconds, got "
                f"warn={self.warn_seconds} critical={self.critical_seconds}")
        if self.warn_seconds <= self.critical_seconds:
            raise ValueError(
                f"warn_margin ({self.warn_seconds}s) must be strictly greater "
                f"than critical_margin ({self.critical_seconds}s): WARN is the "
                f"outer band, CRITICAL the inner one")


@dataclass(frozen=True)
class MarginClassification:
    """The tiered classification of one clock at one instant. `margin_seconds` is
    the signed remaining statutory time (negative once breached); `tier` is the
    GREEN/WARN/CRITICAL/BREACH band; the rest is render-and-escalation provenance.
    Pure derived data, never written to any hashed run-log."""
    regime: str
    correlation_id: str
    deadline: str
    remaining: str
    tier: str
    margin_seconds: float

    @property
    def rank(self) -> int:
        return tier_rank(self.tier)


def classify(clock: Clock, now: datetime,
             thresholds: MarginThresholds) -> MarginClassification:
    """Classify one statutory clock at instant `now` into a margin tier.

    The margin is the deterministic Clock math: `clock.remaining(now)` (which
    references the clock's stopped_at when it has filed, else `now`). BREACH is
    decided by `clock.breached(now)` so the breach edge agrees exactly with the
    Warden's own clock-breach call. Pure function: same inputs, same output; no
    now() is read inside, the caller supplies the instant."""
    remaining = clock.remaining(now)
    margin_seconds = remaining.total_seconds()
    if clock.breached(now) or margin_seconds <= 0:
        tier = TIER_BREACH
    elif margin_seconds <= thresholds.critical_seconds:
        tier = TIER_CRITICAL
    elif margin_seconds <= thresholds.warn_seconds:
        tier = TIER_WARN
    else:
        tier = TIER_GREEN
    return MarginClassification(
        regime=clock.name,
        correlation_id=clock.correlation_id,
        deadline=clock.deadline.isoformat(),
        remaining=_fmt_remaining(remaining.total_seconds()),
        tier=tier,
        margin_seconds=round(margin_seconds, 3),
    )


def _fmt_remaining(seconds: float) -> str:
    """A signed HH:MM:SS (or Nd HH:MM:SS) remaining string for the operator view.
    Negative seconds render with a leading '-' (a breach overrun)."""
    sign = "-" if seconds < 0 else ""
    s = int(abs(seconds))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    hms = f"{h:02d}:{m:02d}:{s:02d}"
    body = f"{d}d {hms}" if d > 0 else hms
    return f"{sign}{body}"
