"""Materiality gate: the deterministic Warden side of the SEC suppression branch.

The SEC 8-K (Item 1.05) clock is only triggered when a cybersecurity incident is
MATERIAL under the SEC "substantial likelihood that a reasonable investor would
consider it important" standard. An immaterial incident does not start the
four-business-day clock and produces no SEC filing.

The materiality JUDGMENT is an LLM decision (floor/materiality.py); it is the
kind of qualitative call a securities lawyer makes, so it is delegated to a
model. THIS module is the deterministic part the Warden owns: it takes the LLM's
typed verdict (material yes/no plus its memo) and decides, by a pure rule, which
protocol edge fires:

  material      -> the SEC branch proceeds (the clock is already running; drafting
                   continues normally).
  not material  -> the Warden emits Event.SUPPRESS on the SEC branch, which the
                   state machine moves to the terminal SUPPRESSED state. No SEC
                   filing is drafted, and the SEC clock is stopped.

No LLM call happens here. The verdict crosses the boundary as data; the gating is
a deterministic, replay-verifiable rule.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MaterialityVerdict:
    """The typed result of the materiality assessment for one branch.

    `material` is the load-bearing boolean the Warden gates on. `memo` is the
    LLM's short rationale (shown in the Examiner Packet, never gated on). `source`
    records who produced the verdict (the materiality role's model id, or a
    deterministic fixture tag) for the audit trail."""
    branch: str
    material: bool
    memo: str
    source: str = ""

    def disposition(self) -> str:
        return "proceed" if self.material else "suppress"


def gate(verdict: MaterialityVerdict) -> bool:
    """Pure rule: does the branch proceed (True) or get suppressed (False)?

    This is the entire deterministic decision. The Warden calls it with the LLM's
    verdict and acts on the boolean: True keeps the branch on the filing path,
    False drives it to the terminal SUPPRESSED state via Event.SUPPRESS."""
    return bool(verdict.material)
