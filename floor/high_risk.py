"""High-risk drafter role: the LLM judgment that decides whether a personal-data
breach is "likely to result in a HIGH RISK to the rights and freedoms of natural
persons" and therefore owes a communication to the affected DATA SUBJECTS under
GDPR Article 34.

This is a true LLM judgment role, not a narrator, and it is DISTINCT from the
per-regime reportability judgment (floor/reportability.py). Reportability decides
the duty owed to the supervisory AUTHORITY under the Art 33 "risk to rights and
freedoms" standard. This role decides the duty owed to the affected INDIVIDUALS
under the Art 34 "HIGH RISK" standard, which is a strictly higher bar: a breach
can be reportable to the regulator yet not owe a communication to the data
subjects. The model applies the Art 34 standard to the canonical fact-record and
returns a typed verdict (high_risk yes / no plus a one-paragraph rationale). On
the dev provider set it runs on Featherless. It reuses the same fenced-verdict
pattern as the materiality and reportability assessors, so the load-bearing value
the Warden gates on is a deterministic parse, not an LLM essay the Warden has to
interpret.

The Warden never calls this. The verdict it returns crosses into the deterministic
warden/high_risk.py gate as data; the Warden only acts on the boolean. So the
qualitative CALL is the model's, and whether the affected-party communication
obligation attaches (and the branch is recruited) is deterministic and
replay-verifiable.
"""

from __future__ import annotations

import json
import re

from warden.high_risk import HighRiskVerdict

from floor.drafter import DrafterError, llm_complete
from floor import roster

_VERDICT = re.compile(r"\[HIGH_RISK\](.*?)\[/HIGH_RISK\]", re.DOTALL)

_SYSTEM = (
    "You are a data-protection breach assessor for a regulated entity's incident "
    "response team. You decide ONE question: is this personal-data breach LIKELY "
    "TO RESULT IN A HIGH RISK to the rights and freedoms of natural persons, the "
    "GDPR Article 34 standard that triggers a COMMUNICATION OF THE BREACH TO THE "
    "AFFECTED DATA SUBJECTS (the individuals), not the regulator. This is a HIGHER "
    "bar than the Article 33 duty to notify the supervisory authority: a breach "
    "can be reportable to the authority yet NOT owe a communication to data "
    "subjects. High risk is indicated by the sensitivity and volume of the data, "
    "the ease of identifying individuals, the severity of consequences (identity "
    "theft, financial loss, fraud on exposed account numbers), and whether "
    "protective measures (encryption, prompt containment) reduce the realistic "
    "risk to individuals. You decide honestly against the Article 34 standard. End "
    "your reply with a fenced verdict block on its own lines, exactly:\n"
    "[HIGH_RISK]\nhigh_risk=yes|no\n[/HIGH_RISK]"
)


def _parse_verdict_bool(text: str) -> bool:
    m = _VERDICT.search(text or "")
    if not m:
        raise DrafterError("high-risk reply missing [HIGH_RISK] verdict block")
    for raw in m.group(1).strip().splitlines():
        key, _, value = raw.strip().partition("=")
        if key.strip() == "high_risk":
            v = value.strip().lower()
            if v in ("yes", "true", "high_risk", "high"):
                return True
            if v in ("no", "false", "not_high_risk", "low"):
                return False
    raise DrafterError("high-risk verdict block has no parsable high_risk= line")


def assess_high_risk(fact_record: dict, *, standard: str, rule: str,
                     model: str, provider: str = roster.FEATHERLESS,
                     api_key: str | None = None,
                     max_tokens: int = 500, timeout: int = 90,
                     max_attempts: int = 1) -> HighRiskVerdict:
    """Run the LLM GDPR Art 34 high-risk assessment on the named provider and
    return a typed verdict. The boolean is parsed off the fenced block; the
    rationale is the prose above it. Raises DrafterError on transport or unparsable
    verdict.

    `standard` is the Art 34 high-risk standard (from the catalog); it is injected
    into the prompt so the model judges against the real rule. `rule` is the short
    human rule label carried through onto the verdict for the packet. max_attempts
    threads straight through to llm_complete: default 1 (no retry, unchanged
    offline behavior); the live runner raises it so a transient 429/5xx on the
    high-risk call is retried with backoff."""
    user = (
        "Assess whether this personal-data breach is LIKELY TO RESULT IN A HIGH "
        "RISK to the rights and freedoms of natural persons, the GDPR Article 34 "
        f"trigger to communicate the breach to the affected data subjects. Apply "
        f"ONLY this standard:\n\n{standard}\n\n"
        "Use ONLY these facts. Write a short rationale (under 150 words) explaining "
        "whether the breach crosses the HIGH-RISK threshold, then the fenced "
        f"verdict block.\n\nFACT RECORD (canonical):\n{json.dumps(fact_record, indent=2)}"
    )
    text = llm_complete(
        provider, model,
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.1, timeout=timeout,
        max_attempts=max_attempts)
    high_risk = _parse_verdict_bool(text)
    rationale = _VERDICT.sub("", text).strip()
    return HighRiskVerdict(
        high_risk=high_risk, rationale=rationale,
        standard=standard, rule=rule, source=f"{provider}:{model}")
