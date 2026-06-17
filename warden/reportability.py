"""Reportability gate: the deterministic Warden side of the per-regime
duty-to-notify suppression branch.

Every breach-notification regime turns on a reportability THRESHOLD: the duty to
file does not attach automatically, it attaches only when the incident crosses
that regime's statutory trigger standard. NIS2 Art 23 "significant impact", DORA
"major incident" per the RTS classification criteria, GDPR / UK ICO Art 33 "risk
to the rights and freedoms of natural persons", NYDFS 23 NYCRR 500.17 "material"
harm, and SEC Item 1.05 "material" each name a different standard, and an
incident below a regime's standard should produce NO filing for that regime.

This generalizes the SEC-only materiality seam (warden/materiality.py) to every
regime. The reportability JUDGMENT is an LLM decision (floor/reportability.py);
it is the kind of qualitative call an incident commander or breach lawyer makes
per jurisdiction, so it is delegated to a model. THIS module is the deterministic
part the Warden owns: it takes the LLM's typed verdict (reportable yes/no plus
its rationale) and decides, by a pure rule, which protocol edge fires:

  reportable        -> the regime's branch proceeds (the clock runs, drafting
                       continues normally).
  not reportable    -> the Warden emits Event.SUPPRESS on the branch, which the
                       state machine moves to the terminal SUPPRESSED state. No
                       filing is drafted, and the branch's clock is stopped, with
                       the named statutory rule recorded.

No LLM call happens here. The verdict crosses the boundary as data; the gating is
a deterministic, replay-verifiable rule. The Warden stays no-LLM: it acts only on
the typed boolean, exactly as it does for SEC materiality.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReportabilityVerdict:
    """The typed result of the reportability assessment for one regime.

    `reportable` is the load-bearing boolean the Warden gates on. `rationale` is
    the LLM's short basis (shown in the Examiner Packet, never gated on). `regime`
    names the regime the verdict is for; `standard` is the statutory trigger
    standard applied; `rule` is the short human rule label rendered when the
    regime is suppressed. `source` records who produced the verdict (the
    reportability role's model id, or a deterministic fixture tag) for the audit
    trail."""
    branch: str
    regime: str
    reportable: bool
    rationale: str
    standard: str = ""
    rule: str = ""
    source: str = ""

    def disposition(self) -> str:
        return "file" if self.reportable else "suppress"


def gate(verdict: ReportabilityVerdict) -> bool:
    """Pure rule: does the regime's branch proceed and FILE (True) or get
    SUPPRESSED below its threshold (False)?

    This is the entire deterministic decision. The Warden calls it with the LLM's
    verdict and acts on the boolean: True keeps the branch on the filing path,
    False drives it to the terminal SUPPRESSED state via Event.SUPPRESS with the
    named statutory rule recorded. No gate or release surface is exposed beyond
    this single boolean rule."""
    return bool(verdict.reportable)
