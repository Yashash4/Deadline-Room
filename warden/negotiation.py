"""A1: the amendment-negotiation protocol (spec v2 section 2.11).

The ONLY place one drafter reads and responds to another drafter. The
Warden's guard is purely structural and deterministic: it checks that a
reconciliation happened and converged before the amendment diff is
allowed to pass. It never judges the legal characterization itself
(that stays the drafters' job), so the Warden stays no-LLM.

Guard conditions enforced:
  1. amend_round is bounded to MAX_ROUNDS (3).
  2. counter/concur envelopes must hash-link to what they answer.
  3. The SEC branch cannot advance amending -> draft_submitted until a
     CONCUR envelope exists for the current amendment round.
  4. The amendment diff cannot pass until the concurred proposed_value
     matches across both branches after canonicalization.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum

from .clocks import parse_ts

MAX_ROUNDS = 3


class Verdict(str, Enum):
    PROPOSE = "propose"
    CONCUR = "concur"
    COUNTER = "counter"


@dataclass(frozen=True)
class NegotiationEnvelope:
    """Spec section 2.11 schema. Validated structurally by the Warden."""
    correlation_id: str          # e.g. "inc-8842:sec"
    amend_round: int             # 1-based, bounded to MAX_ROUNDS
    from_agent: str
    to_agent: str                # the @mentioned counterparty
    fact_key: str                # e.g. "records_affected"
    proposed_value: object       # canonical value (e.g. 2100000)
    characterization: str        # the legal framing of that value
    data_category_bounds: tuple[str, ...]
    containment_framing: str
    verdict: Verdict
    ts_utc: str                  # UTC-canonical timestamp (A4)
    prior_envelope_hash: str | None = None

    def canonical(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "amend_round": self.amend_round,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "fact_key": self.fact_key,
            "proposed_value": self.proposed_value,
            "characterization": self.characterization,
            "data_category_bounds": list(self.data_category_bounds),
            "containment_framing": self.containment_framing,
            "verdict": self.verdict.value,
            "ts_utc": parse_ts(self.ts_utc).isoformat(),
            "prior_envelope_hash": self.prior_envelope_hash,
        }

    def sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str = ""


class NegotiationGuard:
    """Deterministic Warden-side guard over the amendment negotiation.

    Tracks envelopes per (incident, amend_round). Composed by the Warden
    OUTSIDE the pure transition table: the state machine stays a dict;
    this guard is the extra gate on the amendment path.
    """

    def __init__(self) -> None:
        self._envelopes: dict[int, list[NegotiationEnvelope]] = {}

    # --- posting ---------------------------------------------------------
    def post(self, env: NegotiationEnvelope) -> GuardDecision:
        if env.amend_round < 1 or env.amend_round > MAX_ROUNDS:
            return GuardDecision(False, f"amend_round {env.amend_round} outside 1..{MAX_ROUNDS}")
        chain = self._envelopes.setdefault(env.amend_round, [])
        if env.verdict is Verdict.PROPOSE:
            if env.prior_envelope_hash is not None and not self._hash_known(env.prior_envelope_hash):
                return GuardDecision(False, "propose links to unknown prior envelope")
        else:  # CONCUR / COUNTER must answer something
            if env.prior_envelope_hash is None:
                return GuardDecision(False, f"{env.verdict.value} must carry prior_envelope_hash")
            if not self._hash_known(env.prior_envelope_hash):
                return GuardDecision(False, f"{env.verdict.value} links to unknown prior envelope")
        chain.append(env)
        return GuardDecision(True)

    def _hash_known(self, h: str) -> bool:
        return any(e.sha256() == h for chain in self._envelopes.values() for e in chain)

    # --- the gates the Warden consults ------------------------------------
    def concur_envelope(self, amend_round: int) -> NegotiationEnvelope | None:
        for e in self._envelopes.get(amend_round, []):
            if e.verdict is Verdict.CONCUR:
                return e
        return None

    def can_submit_amendment(self, branch_correlation_id: str, amend_round: int) -> GuardDecision:
        """Gate on amending -> draft_submitted (spec 2.11 step 5)."""
        if self.concur_envelope(amend_round) is None:
            return GuardDecision(
                False,
                f"no concur envelope for amend round {amend_round}: "
                f"{branch_correlation_id} may not submit its amendment yet",
            )
        return GuardDecision(True)

    def can_pass_diff(self, amend_round: int, branch_values: dict[str, object]) -> GuardDecision:
        """Gate on the amendment's contradiction check: the concurred value
        must match across both branches' submitted claims."""
        concur = self.concur_envelope(amend_round)
        if concur is None:
            return GuardDecision(False, f"no concur envelope for amend round {amend_round}")
        mismatched = {b: v for b, v in branch_values.items() if v != concur.proposed_value}
        if mismatched:
            return GuardDecision(
                False,
                f"branch values diverge from concurred value {concur.proposed_value}: {mismatched}",
            )
        return GuardDecision(True)

    def history(self) -> list[NegotiationEnvelope]:
        return [e for r in sorted(self._envelopes) for e in self._envelopes[r]]
