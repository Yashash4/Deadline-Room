"""Deterministic adjudication of Challenger objections (pure, no LLM).

This is the receipt that makes the adversarial review rigorous rather than
theater: the Challenger (an LLM) raises natural-language objections; THIS module
(pure Python) decides which of those objections are real, by cross-checking each
against the existing deterministic grounding scorer (floor/grounding.py).

The shape mirrors warden/second_opinion.py::reconcile: an LLM produces evidence,
and a pure function collapses it into a verdict. Here the verdict per objection
is CONFIRMED (the grounding oracle independently agrees the challenged span is
ungrounded) or OVERTURNED (the grounding oracle does not flag it, so the
Challenger's objection is not supported by the deterministic check).

Three hard properties, all required because the result is a printed receipt and
replay must stay byte-identical:

  1. Pure function of (challenge, filing_text, fact_record). No network, no
     clock, no randomness, no global state. Same inputs, same result, always.
  2. It NEVER gates. Nothing here blocks a filing, moves a transition, stops a
     clock, or releases. It reads already-produced text and labels objections.
  3. The deterministic grounding scorer is the sole oracle. An objection is
     CONFIRMED only when score_filing independently flags an ungrounded span of
     the matching dimension. The LLM does not get to mark its own homework.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from floor.challenger import (
    Challenge, Objection, TARGET_ATTACKER, TARGET_INCIDENT_START, TARGET_RECORDS)
from floor.grounding import UngroundedSpan, score_filing

# Each objection target is mapped to the grounding-scorer span KIND that would
# independently corroborate it. An objection whose target maps to no kind cannot
# be confirmed by the deterministic oracle (the oracle has no checkable surface
# for it), so it is OVERTURNED, which is the honest "not deterministically
# provable / the Challenger was wrong" outcome.
_TARGET_TO_KIND = {
    TARGET_RECORDS: "number",
    TARGET_INCIDENT_START: "date",
    TARGET_ATTACKER: "named_entity",
}

# Free-form target words a Challenger may use for the same dimensions, normalized
# so a loosely phrased objection still maps to the right oracle dimension.
_TARGET_ALIASES = {
    "records": TARGET_RECORDS,
    "record_count": TARGET_RECORDS,
    "records_affected": TARGET_RECORDS,
    "affected_records": TARGET_RECORDS,
    "count": TARGET_RECORDS,
    "number": TARGET_RECORDS,
    "incident_start": TARGET_INCIDENT_START,
    "incident_start_utc": TARGET_INCIDENT_START,
    "start_time": TARGET_INCIDENT_START,
    "date": TARGET_INCIDENT_START,
    "time": TARGET_INCIDENT_START,
    "attacker": TARGET_ATTACKER,
    "actor": TARGET_ATTACKER,
    "threat_actor": TARGET_ATTACKER,
    "breach_actor": TARGET_ATTACKER,
}

CONFIRMED = "confirmed"
OVERTURNED = "overturned"


@dataclass(frozen=True)
class AdjudicatedObjection:
    """One Challenger objection paired with the deterministic grounding verdict.

    `verdict` is CONFIRMED iff the grounding scorer independently flagged an
    ungrounded span of the dimension this objection targets; OVERTURNED
    otherwise. `evidence` carries the matching ungrounded span (when confirmed)
    or the reason it could not be confirmed."""
    target: str
    claim: str
    reason: str
    verdict: str
    evidence: str

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "claim": self.claim,
            "reason": self.reason,
            "verdict": self.verdict,
            "evidence": self.evidence,
        }


@dataclass
class AdjudicationResult:
    """The full adversarial-review adjudication for one filing."""
    branch: str
    source: str
    memo: str = ""
    objections: list[AdjudicatedObjection] = field(default_factory=list)

    @property
    def raised(self) -> int:
        return len(self.objections)

    @property
    def confirmed(self) -> int:
        return sum(1 for o in self.objections if o.verdict == CONFIRMED)

    @property
    def overturned(self) -> int:
        return sum(1 for o in self.objections if o.verdict == OVERTURNED)

    def as_dict(self) -> dict:
        return {
            "branch": self.branch,
            "source": self.source,
            "memo": self.memo,
            "raised": self.raised,
            "confirmed": self.confirmed,
            "overturned": self.overturned,
            "objections": [o.as_dict() for o in self.objections],
        }


def _normalize_target(target: str) -> str:
    """Map a Challenger target string to a canonical fact dimension, or '' if it
    does not name a deterministically checkable dimension."""
    key = (target or "").strip().lower().replace(" ", "_")
    if key in _TARGET_TO_KIND:
        return key
    return _TARGET_ALIASES.get(key, "")


def _spans_by_kind(spans: list[UngroundedSpan]) -> dict[str, list[UngroundedSpan]]:
    out: dict[str, list[UngroundedSpan]] = {}
    for s in spans:
        out.setdefault(s.kind, []).append(s)
    return out


def adjudicate(challenge: Challenge, filing_text: str,
               fact_record: dict) -> AdjudicationResult:
    """Adjudicate every objection in a Challenge against the deterministic
    grounding scorer. Pure and deterministic: same inputs, identical result.

    For each objection, the grounding scorer is run over the SAME filing prose
    and fact-record. The objection is CONFIRMED iff the scorer independently
    flagged an ungrounded span of the kind the objection's target maps to;
    OVERTURNED otherwise. The scorer is the oracle; the Challenger's text is
    never trusted to confirm itself."""
    grounding = score_filing(filing_text, fact_record, branch=challenge.branch)
    by_kind = _spans_by_kind(grounding.ungrounded)
    adjudicated: list[AdjudicatedObjection] = []
    for obj in challenge.objections:
        adjudicated.append(_adjudicate_one(obj, by_kind))
    return AdjudicationResult(
        branch=challenge.branch, source=challenge.source, memo=challenge.memo,
        objections=adjudicated)


def _adjudicate_one(obj: Objection,
                    by_kind: dict[str, list[UngroundedSpan]]) -> AdjudicatedObjection:
    dimension = _normalize_target(obj.target)
    kind = _TARGET_TO_KIND.get(dimension, "")
    if not kind:
        return AdjudicatedObjection(
            target=obj.target, claim=obj.claim, reason=obj.reason,
            verdict=OVERTURNED,
            evidence=("the deterministic grounding oracle has no checkable "
                      "surface for this objection's target, so it cannot be "
                      "confirmed"))
    spans = by_kind.get(kind, [])
    if spans:
        ev = spans[0]
        return AdjudicatedObjection(
            target=obj.target, claim=obj.claim, reason=obj.reason,
            verdict=CONFIRMED,
            evidence=(f"grounding oracle independently flagged an ungrounded "
                      f"{ev.kind}: '{ev.span}' ({ev.reason})"))
    return AdjudicatedObjection(
        target=obj.target, claim=obj.claim, reason=obj.reason,
        verdict=OVERTURNED,
        evidence=("the deterministic grounding oracle finds the challenged "
                  f"{kind} grounded in the fact-record; objection not supported"))
