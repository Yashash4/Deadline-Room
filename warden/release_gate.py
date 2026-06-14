"""Two-key release gate: segregation of duties on the human release.

A filing reaching AWAITING_HUMAN_SIGNOFF cannot release on one signature. Two
DISTINCT human roles must both sign before the Warden admits HUMAN_RELEASED:
Lena (Head of Investor Relations) AND the General Counsel. One key alone never
turns the lock; two of the SAME key (Lena signing twice) never turns it either.

This is pure Python, composed OUTSIDE the state-machine transition table. The
table holds the single AWAITING_HUMAN_SIGNOFF -> RELEASED edge; this gate decides
WHEN that edge is allowed to fire by requiring both keys first. The Warden owns
the gate; no LLM is involved. The signatures and the verdict are deterministic
and replay-verifiable.

Convention: each branch (correlation id) has its own lock. A sign-off is a
(role, actor) pair. REQUIRED_ROLES is the set that must all be present.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The two distinct human roles that must both sign to release a filing.
REQUIRED_ROLES: frozenset[str] = frozenset({"head_of_ir", "general_counsel"})


@dataclass(frozen=True)
class Signoff:
    """One human sign-off on one branch."""
    correlation_id: str
    role: str
    actor: str
    ts: str


@dataclass
class GateDecision:
    """The result of asking the gate whether a branch may release."""
    correlation_id: str
    released: bool
    have_roles: frozenset[str]
    missing_roles: frozenset[str]
    reason: str


@dataclass
class TwoKeyReleaseGate:
    """Per-branch two-key lock. The Warden records each human sign-off and asks
    the gate whether both required keys are present before it admits the
    HUMAN_RELEASED transition. Recording the same role twice does not count as
    two keys (a second distinct role is required)."""

    _signoffs: dict[str, dict[str, Signoff]] = field(default_factory=dict)

    def sign(self, correlation_id: str, role: str, actor: str, ts: str) -> GateDecision:
        """Record one human sign-off and return the current gate decision.

        Raises ValueError if the role is not one of the two required keys, so a
        stray actor cannot be quietly accepted. Recording a role that has already
        signed overwrites the prior actor for that role (idempotent on the role,
        never a second key)."""
        if role not in REQUIRED_ROLES:
            raise ValueError(
                f"unknown release role {role!r}; expected one of "
                f"{sorted(REQUIRED_ROLES)}")
        self._signoffs.setdefault(correlation_id, {})[role] = Signoff(
            correlation_id, role, actor, ts)
        return self.decision(correlation_id)

    def decision(self, correlation_id: str) -> GateDecision:
        have = frozenset(self._signoffs.get(correlation_id, {}).keys())
        missing = REQUIRED_ROLES - have
        if missing:
            reason = (
                "release withheld: awaiting " + ", ".join(sorted(missing))
                + " (have " + (", ".join(sorted(have)) if have else "none") + ")")
            return GateDecision(correlation_id, False, have, missing, reason)
        return GateDecision(
            correlation_id, True, have, frozenset(),
            "two keys present: " + ", ".join(sorted(have)) + "; release admitted")

    def can_release(self, correlation_id: str) -> bool:
        return self.decision(correlation_id).released

    def signoffs(self, correlation_id: str) -> list[Signoff]:
        return list(self._signoffs.get(correlation_id, {}).values())

    def reset(self, correlation_id: str) -> None:
        """Clear a branch's lock so a subsequent release (e.g. an amendment
        re-release after the facts changed) must collect BOTH distinct keys
        again from scratch. Without this, keys recorded on the initial release
        would carry over and let an amendment re-release on a single fresh key.
        Every release, initial and amendment, demands two distinct keys."""
        self._signoffs.pop(correlation_id, None)
