"""Second-opinion reconciliation: collapse TWO independent open-model materiality
verdicts into ONE typed MaterialityVerdict for the existing deterministic gate.

This is deterministic Warden-side glue, NOT a gate. The SEC Item 1.05 materiality
call is the single most load-bearing LLM judgment in the product: it decides
whether an entire statutory branch is even drafted. Rather than trust one model
with it, the floor can run it on two different open Featherless families
(DeepSeek-V3.2 and MiniMax-M2.7) and pass both typed verdicts here.

The reconciliation rule is pure Python, makes NO LLM call, and is fully
replayable given the two logged booleans:

  agree    (both material, or both not material) -> return that boolean. The
           record states two independent open models concurred, which strengthens
           the audit trail.
  disagree (one material, one not) -> the conservative, safe-by-construction
           direction for a breach filing: treat as MATERIAL (proceed, do NOT
           suppress), because suppressing a branch that a qualified model judged
           reportable is the unsafe direction. The disagreement is surfaced
           loudly: escalated=True and both original memos preserved, so a human
           reviews it. No third model adjudicates; the human does.

The output is exactly ONE MaterialityVerdict, so the contract with
warden/materiality.py::gate is identical: gate still consumes one verdict's
`material` boolean. This module never imports or alters that gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from warden.materiality import MaterialityVerdict


@dataclass(frozen=True)
class SecondOpinionResult:
    """The full reconciliation outcome, for the Examiner Packet and the run log.

    `verdict` is the single reconciled MaterialityVerdict the existing gate then
    consumes. The remaining fields are the visible evidence: who said what, whether
    they agreed, and whether the disagreement was escalated to a human."""
    verdict: MaterialityVerdict
    primary: MaterialityVerdict
    second: MaterialityVerdict
    agreement: str       # "agree" | "disagree"
    escalated: bool      # True iff they disagreed (human review required)


def reconcile(primary: MaterialityVerdict, second: MaterialityVerdict) -> SecondOpinionResult:
    """Collapse two independent materiality verdicts into one, by the conservative
    rule. Pure and deterministic: same two verdicts in, identical result out, no
    network. The branch is carried through from the primary verdict."""
    if not isinstance(primary, MaterialityVerdict) or not isinstance(second, MaterialityVerdict):
        raise TypeError("reconcile requires two MaterialityVerdict inputs")
    branch = primary.branch
    both_sources = f"{primary.source} + {second.source}"

    if primary.material == second.material:
        agreed = primary.material
        memo = (
            "Two independent open models concurred. "
            f"Primary ({primary.source}): {primary.memo} "
            f"Second opinion ({second.source}): {second.memo}"
        )
        verdict = MaterialityVerdict(branch=branch, material=agreed, memo=memo,
                                     source=both_sources)
        return SecondOpinionResult(verdict=verdict, primary=primary, second=second,
                                   agreement="agree", escalated=False)

    # Disagreement: conservative proceed (treat as material) plus human escalation.
    memo = (
        "Models disagreed; escalated to human; branch not suppressed pending "
        "review. "
        f"Primary ({primary.source}, material={primary.material}): {primary.memo} "
        f"Second opinion ({second.source}, material={second.material}): {second.memo}"
    )
    verdict = MaterialityVerdict(branch=branch, material=True, memo=memo,
                                 source=both_sources)
    return SecondOpinionResult(verdict=verdict, primary=primary, second=second,
                               agreement="disagree", escalated=True)
