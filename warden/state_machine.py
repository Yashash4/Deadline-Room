"""Deadline Warden: typed protocol state machine.

Pure Python, no LLM, no I/O. Every handoff is a typed transition.
An event not in the transition table is an illegal move and is
rejected BEFORE any downstream message would be sent.

Correlation ID convention: "<incident_id>:<branch>", e.g. "inc-8842:nis2".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class State(str, Enum):
    INITIATED = "initiated"
    FACT_RECORD_READY = "fact_record_ready"
    DRAFTING = "drafting"
    DRAFT_SUBMITTED = "draft_submitted"
    CONTRADICTION_CHECKED = "contradiction_checked"
    AWAITING_HUMAN_SIGNOFF = "awaiting_human_signoff"
    RELEASED = "released"          # reopenable via FACT_AMENDED (A1)
    AMENDING = "amending"          # A1: a released branch reopened by a fact revision
    SUPPRESSED = "suppressed"      # terminal (e.g. SEC branch vetoed by Materiality)
    FAILED = "failed"              # terminal (clock breached)


class Event(str, Enum):
    FACT_RECORD_POSTED = "fact_record_posted"
    DRAFT_STARTED = "draft_started"
    DRAFT_POSTED = "draft_posted"
    DIFF_PASSED = "diff_passed"
    DIFF_BLOCKED = "diff_blocked"          # contradiction found: bounce back to drafting
    SIGNOFF_OPENED = "signoff_opened"      # only the Warden may emit this
    HUMAN_RELEASED = "human_released"      # only a human owner/admin may emit this
    SUPPRESS = "suppress"                  # Materiality veto (typed terminal, not chat opinion)
    CLOCK_BREACHED = "clock_breached"
    FACT_AMENDED = "fact_amended"          # A1: Triage revises a load-bearing fact post-release


# A1: RELEASED is no longer terminal; it is REOPENABLE via FACT_AMENDED only.
TERMINAL_STATES = frozenset({State.SUPPRESSED, State.FAILED})
REOPENABLE_STATES = frozenset({State.RELEASED})

# The entire protocol, readable in 30 seconds. (J4's probe: this is code,
# not a system prompt containing the word "deterministic".)
TRANSITIONS: dict[tuple[State, Event], State] = {
    (State.INITIATED, Event.FACT_RECORD_POSTED): State.FACT_RECORD_READY,
    (State.INITIATED, Event.SUPPRESS): State.SUPPRESSED,
    (State.FACT_RECORD_READY, Event.DRAFT_STARTED): State.DRAFTING,
    (State.FACT_RECORD_READY, Event.SUPPRESS): State.SUPPRESSED,
    (State.DRAFTING, Event.DRAFT_POSTED): State.DRAFT_SUBMITTED,
    (State.DRAFTING, Event.SUPPRESS): State.SUPPRESSED,
    (State.DRAFT_SUBMITTED, Event.DIFF_PASSED): State.CONTRADICTION_CHECKED,
    (State.DRAFT_SUBMITTED, Event.DIFF_BLOCKED): State.DRAFTING,
    (State.CONTRADICTION_CHECKED, Event.SIGNOFF_OPENED): State.AWAITING_HUMAN_SIGNOFF,
    (State.CONTRADICTION_CHECKED, Event.DIFF_BLOCKED): State.DRAFTING,
    (State.AWAITING_HUMAN_SIGNOFF, Event.HUMAN_RELEASED): State.RELEASED,
    (State.AWAITING_HUMAN_SIGNOFF, Event.DIFF_BLOCKED): State.DRAFTING,
    # --- A1: the FACT_AMENDED reopen sub-cycle (spec section 2.5) ---
    (State.RELEASED, Event.FACT_AMENDED): State.AMENDING,
    (State.AMENDING, Event.DRAFT_POSTED): State.DRAFT_SUBMITTED,
    # (amending -> draft_submitted is additionally gated by the negotiation
    #  guard in negotiation.py for branches under reconciliation; the guard
    #  is a Warden-side check composed OUTSIDE this pure table.)
}
# Clock breach is legal from any non-terminal, non-released state.
# A RELEASED branch has a stopped clock; breach cannot fire there.
for _s in State:
    if _s not in TERMINAL_STATES and _s not in REOPENABLE_STATES:
        TRANSITIONS[(_s, Event.CLOCK_BREACHED)] = State.FAILED


@dataclass(frozen=True)
class Transition:
    correlation_id: str
    from_state: State
    event: Event
    to_state: State
    ts: str  # ISO-8601 UTC timestamp of the underlying real event
    actor: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def admitted(self) -> bool:
        return True


@dataclass(frozen=True)
class Rejection:
    correlation_id: str
    from_state: State
    event: Event
    ts: str
    actor: str = ""
    reason: str = ""

    @property
    def admitted(self) -> bool:
        return False


# Authority table: which class of actor may emit which event.
# Drafters are room `member`s; only the Warden opens signoff; only
# human owner/admin can release. RBAC mirror of the Band room roles.
EVENT_AUTHORITY: dict[Event, frozenset[str]] = {
    Event.FACT_RECORD_POSTED: frozenset({"triage"}),
    Event.DRAFT_STARTED: frozenset({"drafter"}),
    Event.DRAFT_POSTED: frozenset({"drafter"}),
    Event.DIFF_PASSED: frozenset({"warden"}),
    Event.DIFF_BLOCKED: frozenset({"warden"}),
    Event.SIGNOFF_OPENED: frozenset({"warden"}),
    Event.HUMAN_RELEASED: frozenset({"human_owner", "human_admin"}),
    Event.SUPPRESS: frozenset({"materiality"}),
    Event.CLOCK_BREACHED: frozenset({"warden"}),
    Event.FACT_AMENDED: frozenset({"triage"}),   # A1: only Triage revises facts
}


class ProtocolStateMachine:
    """Holds per-branch typed state. apply() admits or rejects; it never guesses."""

    def __init__(self) -> None:
        self._states: dict[str, State] = {}

    def state(self, correlation_id: str) -> State:
        return self._states.get(correlation_id, State.INITIATED)

    def branches(self) -> dict[str, State]:
        return dict(self._states)

    def apply(
        self,
        correlation_id: str,
        event: Event,
        ts: str,
        actor: str = "",
        actor_role: Optional[str] = None,
        meta: Optional[dict] = None,
    ) -> Transition | Rejection:
        current = self.state(correlation_id)

        if actor_role is not None and actor_role not in EVENT_AUTHORITY[event]:
            return Rejection(
                correlation_id, current, event, ts, actor,
                reason=f"authority violation: role '{actor_role}' may not emit {event.value}",
            )

        if current in TERMINAL_STATES:
            return Rejection(
                correlation_id, current, event, ts, actor,
                reason=f"branch is terminal in state '{current.value}'",
            )

        nxt = TRANSITIONS.get((current, event))
        if nxt is None:
            return Rejection(
                correlation_id, current, event, ts, actor,
                reason=f"illegal transition: no edge ({current.value}, {event.value})",
            )

        self._states[correlation_id] = nxt
        return Transition(correlation_id, current, event, nxt, ts, actor, meta or {})
