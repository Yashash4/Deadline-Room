"""High-risk gate: the deterministic Warden side of the affected-party (data
subject) notification trigger.

The regulator-notification duty (GDPR / UK ICO Article 33, the reportability beat
in warden/reportability.py) attaches whenever a personal-data breach is not
unlikely to risk the rights and freedoms of natural persons. The duty owed to the
affected INDIVIDUALS is a DIFFERENT, HIGHER bar: GDPR Article 34 requires
communication of a personal-data breach to the data subject only when the breach
is "likely to result in a HIGH RISK to the rights and freedoms of natural
persons". So a breach can be reportable to the supervisory authority yet not owe a
communication to the data subjects, and the affected-party obligation must be
decided on its own standard, not inferred from the regulator filing.

The high-risk JUDGMENT is an LLM decision (floor/high_risk.py); it is the kind of
qualitative call a DPO or breach lawyer makes under the Art 34 standard, so it is
delegated to a model. THIS module is the deterministic part the Warden owns: it
takes the LLM's typed verdict (high_risk yes/no plus its rationale) and decides,
by a pure rule, whether an affected-party communication obligation is REQUIRED:

  high_risk        -> the affected-party communication to data subjects is
                      REQUIRED. The Warden recruits the affected-party branch
                      (gated on the regulator release), starts its own
                      "without undue delay" clock anchored at the release moment,
                      and the Art 34 notice is drafted and flows through the same
                      typed handoff and the same two-key release gate.
  not high_risk    -> NO communication to data subjects is required. The
                      obligation is RECORDED as not-required with the Art 34 rule,
                      so the determination is documented (a real Art 34 decision is
                      "we assessed high risk and concluded it does not attach"),
                      never silently absent.

No LLM call happens here. The verdict crosses the boundary as data; the gating is
a deterministic, replay-verifiable rule. The Warden stays no-LLM: it acts only on
the typed boolean, exactly as it does for SEC materiality and per-regime
reportability. This module exposes ONLY the typed verdict and the single pure
boolean gate: no release surface, no clock surface, no LLM surface.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HighRiskVerdict:
    """The typed result of the GDPR Art 34 high-risk assessment.

    `high_risk` is the load-bearing boolean the Warden gates on: True when the
    breach is likely to result in a HIGH RISK to the rights and freedoms of natural
    persons (the Art 34 communication-to-data-subject trigger), False otherwise.
    `rationale` is the LLM's short basis (shown in the Examiner Packet, never gated
    on). `standard` is the Art 34 standard applied; `rule` is the short human rule
    label rendered when no communication is required. `source` records who produced
    the verdict (the high-risk role's model id, or a deterministic fixture tag) for
    the audit trail."""
    high_risk: bool
    rationale: str
    standard: str = ""
    rule: str = ""
    source: str = ""

    def disposition(self) -> str:
        return "notify_data_subjects" if self.high_risk else "no_communication_required"


def gate(verdict: HighRiskVerdict) -> bool:
    """Pure rule: is an affected-party communication to data subjects REQUIRED
    (True) or not required (False)?

    This is the entire deterministic decision. The Warden calls it with the LLM's
    verdict and acts on the boolean: True recruits the affected-party branch (its
    Art 34 notice gated on the regulator release, on its own without-undue-delay
    clock), False records the obligation as not-required with the named Art 34
    rule. No gate-state, no release, and no clock surface is exposed beyond this
    single boolean rule."""
    return bool(verdict.high_risk)
