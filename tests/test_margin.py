"""test_margin.py -- the pure deadline-margin tiered classifier (E7.2).

The classifier turns a statutory Clock and an instant `now` into an operational
tier (GREEN -> WARN -> CRITICAL -> BREACH) over per-regime thresholds. These tests
pin the tier boundaries exactly per regime over an injected `now` (no wall clock),
and confirm the classifier is pure and never touches a sealed sha or any log.
"""

from datetime import datetime, timedelta, timezone

import pytest

from floor import regimes
from floor.margin import (
    TIER_BREACH,
    TIER_CRITICAL,
    TIER_GREEN,
    TIER_WARN,
    MarginThresholds,
    classify,
    tier_rank,
)
from warden.clocks import ClockEngine

T0 = datetime(2026, 6, 16, 2, 14, 0, tzinfo=timezone.utc)


def _hours_clock(hours: int, warn_s: float, critical_s: float):
    eng = ClockEngine()
    c = eng.start_hours("test", "inc:test", T0.isoformat(), hours)
    return c, MarginThresholds(warn_seconds=warn_s, critical_seconds=critical_s)


def test_tier_rank_is_ascending_and_total():
    assert tier_rank(TIER_GREEN) < tier_rank(TIER_WARN)
    assert tier_rank(TIER_WARN) < tier_rank(TIER_CRITICAL)
    assert tier_rank(TIER_CRITICAL) < tier_rank(TIER_BREACH)


def test_unknown_tier_rank_raises():
    with pytest.raises(ValueError):
        tier_rank("PURPLE")


def test_green_when_margin_above_warn():
    # 24h clock, warn at 6h, critical at 1h. At T0+10h, 14h remain -> GREEN.
    c, th = _hours_clock(24, 6 * 3600, 1 * 3600)
    cls = classify(c, T0 + timedelta(hours=10), th)
    assert cls.tier == TIER_GREEN
    assert cls.margin_seconds == pytest.approx(14 * 3600)


def test_warn_band_boundaries():
    c, th = _hours_clock(24, 6 * 3600, 1 * 3600)
    # Exactly at the warn margin (6h left) is WARN (at-or-below warn).
    assert classify(c, T0 + timedelta(hours=18), th).tier == TIER_WARN
    # Just inside the warn band (5h left) is WARN.
    assert classify(c, T0 + timedelta(hours=19), th).tier == TIER_WARN
    # Just above the warn margin (6h+1s left) is GREEN.
    just_above = T0 + timedelta(hours=18) - timedelta(seconds=1)
    assert classify(c, just_above, th).tier == TIER_GREEN


def test_critical_band_boundaries():
    c, th = _hours_clock(24, 6 * 3600, 1 * 3600)
    # Exactly at the critical margin (1h left) is CRITICAL.
    assert classify(c, T0 + timedelta(hours=23), th).tier == TIER_CRITICAL
    # Inside the critical band (30m left) is CRITICAL.
    assert classify(c, T0 + timedelta(hours=23, minutes=30), th).tier == TIER_CRITICAL
    # Just above the critical margin (1h+1s) is WARN.
    just_above = T0 + timedelta(hours=23) - timedelta(seconds=1)
    assert classify(c, just_above, th).tier == TIER_WARN


def test_breach_at_and_past_deadline():
    c, th = _hours_clock(24, 6 * 3600, 1 * 3600)
    # Exactly at the deadline (0 margin) is BREACH (margin <= 0).
    assert classify(c, T0 + timedelta(hours=24), th).tier == TIER_BREACH
    # Past the deadline is BREACH with a negative margin.
    past = classify(c, T0 + timedelta(hours=25), th)
    assert past.tier == TIER_BREACH
    assert past.margin_seconds == pytest.approx(-3600)


def test_breach_edge_agrees_with_clock_breached():
    # The classifier's BREACH edge must agree with Clock.breached exactly.
    c, th = _hours_clock(72, 12 * 3600, 3 * 3600)
    now = c.deadline + timedelta(seconds=1)
    assert c.breached(now) is True
    assert classify(c, now, th).tier == TIER_BREACH
    before = c.deadline - timedelta(seconds=1)
    assert c.breached(before) is False
    assert classify(c, before, th).tier != TIER_BREACH


def test_stopped_clock_classified_at_filing_margin():
    # A filed clock is classified against its stopped_at instant, so its tier is
    # frozen at the margin it landed with, not a tier that keeps sliding.
    eng = ClockEngine()
    c = eng.start_hours("test", "inc:test", T0.isoformat(), 24)
    # Filed 20h in: 4h of margin remained -> WARN under 6h/1h thresholds.
    eng.stop("inc:test", (T0 + timedelta(hours=20)).isoformat())
    th = MarginThresholds(warn_seconds=6 * 3600, critical_seconds=1 * 3600)
    # Even evaluated far past the deadline, the filed clock holds its filing tier.
    cls = classify(c, T0 + timedelta(hours=48), th)
    assert cls.tier == TIER_WARN
    assert cls.margin_seconds == pytest.approx(4 * 3600)


def test_classify_is_pure_same_inputs_same_output():
    c, th = _hours_clock(24, 6 * 3600, 1 * 3600)
    now = T0 + timedelta(hours=20)
    a = classify(c, now, th)
    b = classify(c, now, th)
    assert a == b


def test_thresholds_must_be_ordered_and_positive():
    with pytest.raises(ValueError):
        MarginThresholds(warn_seconds=3600, critical_seconds=3600)  # not strictly >
    with pytest.raises(ValueError):
        MarginThresholds(warn_seconds=3600, critical_seconds=7200)  # inverted
    with pytest.raises(ValueError):
        MarginThresholds(warn_seconds=0, critical_seconds=-1)


def test_catalog_startup_regimes_declare_ordered_thresholds():
    # Every startup regime that drives the live board carries a valid, ordered
    # warn/critical pair, parsed from the catalog. This is the data the live board
    # and escalation read.
    specs = regimes.load_catalog()
    startup = regimes.startup_regimes(specs)
    assert {s.key for s in startup} == {"nis2_early", "nis2_full", "dora", "sec"}
    for s in startup:
        w = s.clock.warn_margin_seconds
        cr = s.clock.critical_margin_seconds
        assert w is not None and cr is not None
        assert w > cr > 0
