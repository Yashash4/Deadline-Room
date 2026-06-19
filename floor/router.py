"""Deterministic complexity-based model router (E5.7 part 2).

A production multi-model gateway routes each filing to a model whose cost matches
its complexity: a short, low-factor notice goes to a cheap fast model; a long,
many-factor, high-stakes filing goes to a premium reasoning model. This module
makes that routing decision DETERMINISTICALLY from declared, checkable signals,
the same no-LLM way the Warden decides everything that gates.

The complexity score is a pure function of inputs already on the floor:

  - the regime's statutory weight (SEC Item 1.05 materiality and DORA's incident
    skeleton are heavier than a single NIS2 early-warning),
  - the number of named regulator factors the expert profile carries (more
    factors to address = a harder filing),
  - the record-count magnitude (a mass breach is higher stakes),
  - whether the filing carries grounding chunks (a grounded filing must reason
    against real statutory text).

It scores, bands the score into cheap | mid | premium against fixed thresholds,
and returns the routing DECISION plus the (provider, model) and the RELATIVE-cost
weight from roster.TIER_TABLE. It never calls a model and never reads the network.

DEFAULT OFF: run_floor consults the router only under --route. The default
drafting path ignores it entirely, so the offline suite and replay stay
byte-identical. The decision is OUT-OF-LOG: it rides the trace like
recovered_retries and never enters the hashed [CLAIMS].
"""

from __future__ import annotations

from dataclasses import dataclass

from floor import roster

# Per-regime statutory weight: a small integer reflecting how heavy the filing is
# to draft. SEC (materiality judgment) and DORA (long field skeleton) are the
# heaviest; a bare NIS2 early warning is the lightest. Deterministic config.
_REGIME_WEIGHT: dict[str, int] = {
    "SEC": 3,
    "DORA": 3,
    "NIS2": 2,
    "UK ICO": 2,
    "NYDFS 23 NYCRR 500": 2,
}
_DEFAULT_REGIME_WEIGHT = 1

# A record count at or above this is a mass breach: high stakes, push complexity.
_MASS_BREACH_RECORDS = 100_000

# Score bands. A score below CHEAP_MAX routes cheap; below MID_MAX routes mid;
# at or above MID_MAX routes premium. Fixed thresholds so the banding is
# reproducible and explainable.
_CHEAP_MAX = 3
_MID_MAX = 6


@dataclass(frozen=True)
class RouteSignals:
    """The declared, checkable inputs the complexity score reads. All derived from
    data already on the floor (the regime, the fact-record, the expert profile,
    the grounding chunks), never from an LLM."""
    regime: str = ""
    records_affected: int = 0
    factor_count: int = 0       # named regulator factors the expert profile carries
    grounded: bool = False      # the filing carries grounding chunks


@dataclass(frozen=True)
class RouteDecision:
    """One routing decision: the complexity score, the tier it banded into, the
    (provider, model) that tier serves, the relative-cost weight, and a short
    deterministic explanation. complexity_label is the coarse low|high the drafter
    is allowed to emit in its sanitized [ROUTE] block."""
    score: int
    tier: str
    provider: str
    model: str
    cost_weight: float
    rationale: str
    signals: RouteSignals

    @property
    def complexity_label(self) -> str:
        """The coarse low|high label, derived from the tier. cheap -> low, mid and
        premium -> high. This is the only complexity token the drafter emits in its
        out-of-log [ROUTE] block."""
        return "low" if self.tier == roster.TIER_CHEAP else "high"

    def as_dict(self) -> dict:
        """The out-of-log routing record for the packet ledger. Read at packet
        time, never written into the hashed run-log JSONL."""
        return {
            "regime": self.signals.regime,
            "score": self.score,
            "tier": self.tier,
            "complexity": self.complexity_label,
            "provider": self.provider,
            "model": self.model,
            "cost_weight": self.cost_weight,
            "rationale": self.rationale,
            "signals": {
                "regime": self.signals.regime,
                "records_affected": self.signals.records_affected,
                "factor_count": self.signals.factor_count,
                "grounded": self.signals.grounded,
            },
        }


def _score(signals: RouteSignals) -> int:
    """The deterministic complexity score. Pure integer arithmetic over the
    declared signals; same signals always yield the same score."""
    score = _REGIME_WEIGHT.get(signals.regime, _DEFAULT_REGIME_WEIGHT)
    # Each named regulator factor adds weight, capped so a factor-rich regime does
    # not dominate the band entirely.
    score += min(signals.factor_count, 4)
    if signals.records_affected >= _MASS_BREACH_RECORDS:
        score += 2
    if signals.grounded:
        score += 1
    return score


def _band(score: int) -> str:
    """Band a complexity score into a tier name against the fixed thresholds."""
    if score < _CHEAP_MAX:
        return roster.TIER_CHEAP
    if score < _MID_MAX:
        return roster.TIER_MID
    return roster.TIER_PREMIUM


def route(signals: RouteSignals) -> RouteDecision:
    """Route one filing to a tier from its declared complexity signals.

    Pure and deterministic: no LLM, no network, no clock, no randomness. The same
    RouteSignals always yields the same RouteDecision, so the routing ledger is a
    re-runnable receipt. The decision GATES NOTHING (it only selects which model
    drafts the content) and is OUT-OF-LOG."""
    score = _score(signals)
    tier = _band(score)
    spec = roster.tier_spec(tier)
    rationale = (
        f"complexity score {score} bands to the {tier} tier "
        f"(regime {signals.regime or 'generic'} weight, "
        f"{signals.factor_count} regulator factor(s), "
        f"{'mass-breach record count, ' if signals.records_affected >= _MASS_BREACH_RECORDS else ''}"
        f"{'grounded' if signals.grounded else 'ungrounded'}). {spec.rationale}"
    )
    return RouteDecision(
        score=score, tier=tier, provider=spec.provider, model=spec.model,
        cost_weight=spec.cost_weight, rationale=rationale, signals=signals)


def signals_for(regime: str, fact_record: dict, *, expert_profile=None,
                grounding_chunks=None) -> RouteSignals:
    """Build RouteSignals from the floor's own data: the regime, the canonical
    fact-record's records_affected, the count of named factors the expert profile
    carries (E5.6), and whether grounding chunks are present (E5.9). Pure read."""
    records = fact_record.get("records_affected", 0)
    records = records if isinstance(records, int) else 0
    factor_count = (
        len(expert_profile.factors)
        if expert_profile is not None and getattr(expert_profile, "factors", None)
        else 0
    )
    return RouteSignals(
        regime=regime,
        records_affected=records,
        factor_count=factor_count,
        grounded=bool(grounding_chunks),
    )


def cost_ledger(decisions: list[RouteDecision]) -> dict:
    """Aggregate a run's routing decisions into a RELATIVE-cost ledger for the
    packet. Sums the relative cost weights (never a currency amount) and shows, as
    a comparison, the relative cost had every filing gone to the premium tier
    instead. The savings figure is a RELATIVE ratio, never a dollar figure, so the
    ledger states relative cost, never a fabricated invoice. Pure aggregation."""
    if not decisions:
        return {}
    routed_cost = sum(d.cost_weight for d in decisions)
    premium_weight = roster.tier_spec(roster.TIER_PREMIUM).cost_weight
    all_premium_cost = premium_weight * len(decisions)
    saved_fraction = (
        (all_premium_cost - routed_cost) / all_premium_cost
        if all_premium_cost else 0.0
    )
    return {
        "rows": [d.as_dict() for d in decisions],
        "relative_cost_total": round(routed_cost, 4),
        "all_premium_relative_cost": round(all_premium_cost, 4),
        "relative_saving_fraction": round(saved_fraction, 4),
        "unit": "relative weight (unitless), not a currency amount",
    }
