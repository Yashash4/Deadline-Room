"""Public conformance check: an EXTERNAL prover for exactly-once that an LLM
cannot self-certify.

The premise (Ofer's thesis, "your coding agent can't review its own work"): a
Band agent author who claims their agent is exactly-once should not be trusted to
mark their own homework. `verify_exactly_once` is the independent grader. You
hand it an `agent_factory` that builds a FRESH agent over a shared
`IdempotencyLedger`, and it drives a large, SEEDED space of kill + duplicate
delivery schedules through that agent, asserting the exactly-once invariant on
every one:

  * every unit of work is ACCEPTED exactly once (no double-post), and
  * no unit of work is lost (every delivered key ends up accepted).

If any schedule violates the invariant, the result names the FIRST violating
schedule (its seed and a human-readable reason), mirroring
`chain.first_broken_index` (the exact link where it broke) and `logcheck`'s typed
`ValidationResult` shape. A clean agent passes; a buggy agent (one that, say,
records work BEFORE checking the ledger, or skips the ledger entirely) fails with
the first schedule that exposes it.

The agent contract is intentionally tiny and framework-agnostic. An agent is a
callable:

    agent(ledger, dedup_key, attempt, ts) -> Disposition

It MUST consult `ledger` to decide whether this delivery is the first sight of
`dedup_key` (ACCEPTED) or a redelivery (DUPLICATE_DROPPED), and return the
ledger's verdict. The canonical correct implementation is one line:
`return ledger.record(dedup_key, attempt, ts).disposition`. `clean_echo_agent`
below is exactly that, so `verify_exactly_once(clean_echo_agent)` passes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Optional

from band_once.ledger import Disposition, IdempotencyLedger

# An Agent consults the shared ledger and returns the ledger's disposition for
# this delivery. The factory takes no arguments and returns a fresh agent.
Agent = Callable[[IdempotencyLedger, str, int, str], Disposition]
AgentFactory = Callable[[], Agent]

DEFAULT_SCHEDULES = 500
DEFAULT_SEED = 20260616
_KEYS = [f"work:k{k}:job-1:round-1" for k in range(6)]
_DELIVERIES_PER_SCHEDULE = 400
_TS = "2026-06-16T03:10:00+00:00"


@dataclass(frozen=True)
class ConformanceResult:
    """A structured verdict, the same shape `logcheck.ValidationResult` uses.

    ok=True means exactly-once held across every schedule checked. On a failure
    ok=False, first_violating_seed is the seed of the FIRST schedule that broke
    the invariant (the analogue of `chain.first_broken_index`), and reason names
    the defect in one human-readable clause. schedules_checked records how many
    schedules ran (the whole sweep on a pass, up to and including the violator on
    a failure)."""

    ok: bool
    schedules_checked: int = 0
    first_violating_seed: Optional[int] = None
    reason: str = ""

    def __bool__(self) -> bool:  # so `if verify_exactly_once(...):` reads naturally
        return self.ok


def clean_echo_agent() -> Agent:
    """The reference correct agent: consult the ledger, return its verdict. One
    delivery of a key is ACCEPTED; every later delivery of the same key is
    DUPLICATE_DROPPED. This is the exactly-once contract, discharged in one line."""

    def agent(ledger: IdempotencyLedger, dedup_key: str, attempt: int, ts: str) -> Disposition:
        return ledger.record(dedup_key, attempt, ts).disposition

    return agent


def _delivery_schedule(rng: random.Random) -> list[tuple[str, int]]:
    """A randomized kill + duplicate delivery schedule: many interleaved
    deliveries of a handful of keys, with random attempt numbers standing in for
    crash-retry redelivery (position A/B and lost-ack all reduce to 'the same key
    is delivered again with some attempt number'). Every key appears at least
    once so a lost-key bug is detectable."""
    deliveries = [(rng.choice(_KEYS), rng.randint(1, 9))
                  for _ in range(_DELIVERIES_PER_SCHEDULE)]
    # Guarantee every key is delivered at least once this schedule.
    for k in _KEYS:
        deliveries.append((k, rng.randint(1, 9)))
    rng.shuffle(deliveries)
    return deliveries


def _check_one_schedule(agent: Agent, deliveries: list[tuple[str, int]]) -> Optional[str]:
    """Drive one schedule through a fresh ledger + the agent. Returns None if
    exactly-once held, else a human-readable reason for the first defect."""
    ledger = IdempotencyLedger()
    delivered_keys: set[str] = set()
    accept_counts: dict[str, int] = {}
    for dedup_key, attempt in deliveries:
        delivered_keys.add(dedup_key)
        disposition = agent(ledger, dedup_key, attempt, _TS)
        if disposition is Disposition.ACCEPTED:
            accept_counts[dedup_key] = accept_counts.get(dedup_key, 0) + 1

    # Double-post: a key accepted more than once.
    for key, n in accept_counts.items():
        if n > 1:
            return (f"key '{key}' was ACCEPTED {n} times "
                    f"(exactly-once requires exactly 1): a double-post")
    # Lost work: a delivered key never accepted at all.
    lost = delivered_keys - set(accept_counts)
    if lost:
        sample = sorted(lost)[0]
        return (f"key '{sample}' was delivered but never ACCEPTED: a lost message "
                f"({len(lost)} key(s) lost)")
    # The ledger's own accepted set must match the keys it accepted.
    if ledger.accepted_keys() != set(accept_counts):
        return ("the agent's accepted set disagrees with the ledger's accepted set: "
                "the agent is not driving exactly-once through the ledger")
    return None


def verify_exactly_once(
    agent_factory: AgentFactory,
    *,
    schedules: int = DEFAULT_SCHEDULES,
    seed: int = DEFAULT_SEED,
) -> ConformanceResult:
    """Independently verify that agents built by `agent_factory` are exactly-once.

    Drives `schedules` seeded kill + duplicate delivery schedules through a FRESH
    agent each time and asserts exactly-once on every one. Returns a typed
    ConformanceResult: a clean pass with the schedule count, or a failure naming
    the FIRST violating schedule's seed and the defect. Deterministic: the same
    (schedules, seed) always gives the same verdict, so the result is a receipt,
    not a vibe.

    The grader never trusts the agent's claim about itself: it re-derives the
    exactly-once invariant from the deliveries and the agent's own dispositions.
    An agent that records before checking, or ignores the ledger, fails here."""
    for i in range(schedules):
        schedule_seed = seed + i
        rng = random.Random(schedule_seed)
        deliveries = _delivery_schedule(rng)
        agent = agent_factory()
        reason = _check_one_schedule(agent, deliveries)
        if reason is not None:
            return ConformanceResult(
                ok=False,
                schedules_checked=i + 1,
                first_violating_seed=schedule_seed,
                reason=reason,
            )
    return ConformanceResult(ok=True, schedules_checked=schedules)
