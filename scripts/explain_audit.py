"""Explainability coverage audit (E9.2): every reachable gate has a rationale.

A non-engineer's trust in this system rests on every Warden decision carrying a
plain-English explanation. That promise is only real if it is MECHANICALLY
enforced: a new gate must not be able to ship without a rationale, a determinism
chip, and a provenance binding. This audit is that enforcement.

It reads the protocol state machine (warden.state_machine.TRANSITIONS) and the
rationale catalog (floor.rationale) and proves, for every decision type the
Warden can reach:

  1. the Event has a governing rule        (EVENT_RULE),
  2. that rule has a plain-English template (RULES),
  3. the rule declares HOW it was decided   (DECIDED_BY, the determinism chip),
  4. the rule declares its evidence events   (EVIDENCE_EVENTS, the provenance).

A "decision type" is a protocol Event that appears in the transition table, so a
new edge that introduces a new narrated event without a rationale is caught here.
It is keyless and read-only (it imports the tables, computes nothing into the
run-log), prints "N decision types, N explained, 0 unexplained", and exits 0 when
every reachable gate is fully covered and nonzero (naming the offenders) when one
is not. CI runs it so a new uncovered gate FAILS the build.

Run it:  py scripts/explain_audit.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.rationale import (  # noqa: E402
    DECIDED_BY,
    DECIDED_BY_LABEL,
    EVENT_RULE,
    EVIDENCE_EVENTS,
    RULES,
)
from warden.state_machine import TRANSITIONS, Event  # noqa: E402


def _reachable_events() -> list[str]:
    """The distinct protocol Events the Warden can reach in the transition table,
    sorted for a stable report. These are the decision types that must each carry
    a rationale."""
    return sorted({event.value for (_state, event) in TRANSITIONS})


def audit() -> tuple[int, int, list[str]]:
    """Return (decision_type_count, explained_count, unexplained_reasons).

    A decision type is EXPLAINED when its Event maps to a governing rule, that
    rule has a non-empty template, and the rule declares both a determinism class
    (a valid DECIDED_BY entry with a label) and an evidence-events binding. Any
    gap is reported as a precise, human-readable reason."""
    events = _reachable_events()
    unexplained: list[str] = []
    explained = 0

    for event in events:
        ev = Event(event)
        kind = EVENT_RULE.get(ev)
        if kind is None:
            unexplained.append(
                f"{event}: no governing rule (add it to rationale.EVENT_RULE)")
            continue
        rule = RULES.get(kind)
        if rule is None or not rule.template or not rule.rule_id:
            unexplained.append(
                f"{event} -> {kind}: no plain-English template in rationale.RULES")
            continue
        decided_by = DECIDED_BY.get(kind)
        if not decided_by or decided_by not in DECIDED_BY_LABEL:
            unexplained.append(
                f"{event} -> {kind}: no determinism class in rationale.DECIDED_BY")
            continue
        if kind not in EVIDENCE_EVENTS:
            unexplained.append(
                f"{event} -> {kind}: no provenance binding in "
                "rationale.EVIDENCE_EVENTS")
            continue
        explained += 1

    return len(events), explained, unexplained


def main() -> int:
    total, explained, unexplained = audit()
    unexplained_count = len(unexplained)
    print(f"{total} decision types, {explained} explained, "
          f"{unexplained_count} unexplained")
    if unexplained:
        print()
        print("Uncovered gates (a new gate cannot ship without a rationale):")
        for reason in unexplained:
            print(f"  - {reason}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
