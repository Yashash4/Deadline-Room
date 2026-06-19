"""test_router.py -- the deterministic complexity-tier router (E5.7 part 2).

floor.router scores a filing's complexity from declared signals (regime weight,
regulator factor count, record magnitude, grounding) and bands it into a
cheap | mid | premium tier, returning the tier's (provider, model) and a RELATIVE
cost weight. Pure and deterministic; it never calls a model and gates nothing.
"""

import pytest

from floor import roster
from floor.router import RouteSignals, cost_ledger, route, signals_for


def test_low_complexity_routes_cheap():
    """A light filing (generic regime, no factors, small breach, ungrounded) bands
    to the cheap tier with the low complexity label."""
    d = route(RouteSignals(regime="", records_affected=10, factor_count=0))
    assert d.tier == roster.TIER_CHEAP
    assert d.complexity_label == "low"
    assert d.provider == roster.FEATHERLESS
    assert d.cost_weight == roster.tier_spec(roster.TIER_CHEAP).cost_weight


def test_high_complexity_routes_premium():
    """A heavy filing (SEC, many factors, mass breach, grounded) bands premium."""
    d = route(RouteSignals(regime="SEC", records_affected=2_100_000,
                           factor_count=5, grounded=True))
    assert d.tier == roster.TIER_PREMIUM
    assert d.complexity_label == "high"
    assert d.model == roster.tier_spec(roster.TIER_PREMIUM).model


def test_mid_band():
    """A standard NIS2 filing with a couple of factors lands in the mid tier."""
    d = route(RouteSignals(regime="NIS2", records_affected=500, factor_count=1))
    assert d.tier == roster.TIER_MID


def test_routing_is_deterministic():
    sig = RouteSignals(regime="DORA", records_affected=48211, factor_count=3,
                       grounded=True)
    a, b = route(sig), route(sig)
    assert a.score == b.score and a.tier == b.tier and a.model == b.model


def test_mass_breach_pushes_complexity_up():
    light = route(RouteSignals(regime="NIS2", records_affected=10, factor_count=0))
    heavy = route(RouteSignals(regime="NIS2", records_affected=200_000,
                               factor_count=0))
    assert heavy.score > light.score


def test_signals_for_reads_floor_data():
    class _Expert:
        factors = ["scope", "duration", "sensitivity"]

    fact_record = {"records_affected": 48211}
    sig = signals_for("SEC", fact_record, expert_profile=_Expert(),
                      grounding_chunks=[1, 2])
    assert sig.regime == "SEC"
    assert sig.records_affected == 48211
    assert sig.factor_count == 3
    assert sig.grounded is True


def test_signals_for_handles_missing_fields():
    sig = signals_for("NIS2", {}, expert_profile=None, grounding_chunks=None)
    assert sig.records_affected == 0
    assert sig.factor_count == 0
    assert sig.grounded is False


def test_unknown_tier_raises():
    with pytest.raises(ValueError):
        roster.tier_spec("platinum")


def test_cost_ledger_is_relative_not_currency():
    """The cost ledger sums RELATIVE weights and reports a relative saving against
    all-premium; there is no currency amount and no fabricated invoice."""
    decisions = [
        route(RouteSignals(regime="", records_affected=1, factor_count=0)),   # cheap
        route(RouteSignals(regime="NIS2", records_affected=1, factor_count=1)),  # mid
        route(RouteSignals(regime="SEC", records_affected=2_000_000,
                           factor_count=5, grounded=True)),                    # premium
    ]
    ledger = cost_ledger(decisions)
    premium_w = roster.tier_spec(roster.TIER_PREMIUM).cost_weight
    assert ledger["all_premium_relative_cost"] == premium_w * 3
    assert ledger["relative_cost_total"] < ledger["all_premium_relative_cost"]
    assert 0.0 <= ledger["relative_saving_fraction"] <= 1.0
    # the ledger advertises that the unit is relative, never a currency
    assert "currency" in ledger["unit"]


def test_empty_ledger_is_empty():
    assert cost_ledger([]) == {}


def test_decision_as_dict_is_out_of_log_shape():
    d = route(RouteSignals(regime="SEC", records_affected=48211, factor_count=2))
    rec = d.as_dict()
    assert rec["tier"] in roster.TIERS
    assert rec["complexity"] in ("low", "high")
    # purely descriptive, carries no gate / claims field
    assert "claims" not in rec and "gate" not in rec
