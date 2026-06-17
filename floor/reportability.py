"""Reportability drafter role: the LLM judgment that decides, per regime, whether
the incident even crosses that regulator's reporting threshold (the duty to
notify).

This is a true LLM judgment role, not a narrator. For a given regime it applies
that regime's statutory trigger standard (NIS2 Art 23 significant impact, DORA
major incident per the RTS classification, GDPR / UK ICO Art 33 risk to the
rights and freedoms of natural persons, NYDFS 23 NYCRR 500.17 material harm, SEC
Item 1.05 materiality) to the canonical fact-record and returns a typed verdict
(reportable yes / no plus a one-paragraph rationale). On the dev provider set it
runs on Featherless. It reuses the same pattern as the SEC materiality assessor
(floor/materiality.py): a fenced verdict block the role is instructed to emit, so
the load-bearing value the Warden gates on is a deterministic parse, not an LLM
essay the Warden has to interpret.

The Warden never calls this. The verdict it returns crosses into the
deterministic warden/reportability.py gate as data; the Warden only acts on the
boolean. So the qualitative CALL is the model's, and the gating of the regime's
branch is deterministic and replay-verifiable.
"""

from __future__ import annotations

import json
import re

from warden.reportability import ReportabilityVerdict

from floor.drafter import DrafterError, llm_complete
from floor import roster

_VERDICT = re.compile(r"\[REPORTABILITY\](.*?)\[/REPORTABILITY\]", re.DOTALL)

_SYSTEM = (
    "You are a regulatory reportability assessor for a regulated entity's "
    "incident response team. You decide, for ONE named regime, whether a "
    "cybersecurity / data-breach incident crosses that regime's statutory "
    "reporting THRESHOLD (the duty to notify), applying ONLY the standard you "
    "are given. The duty does NOT attach automatically: a small, contained, "
    "non-sensitive incident that does not meet the standard is NOT reportable, "
    "and over-notifying creates needless liability. You decide honestly against "
    "the named standard. End your reply with a fenced verdict block on its own "
    "lines, exactly:\n"
    "[REPORTABILITY]\nreportable=yes|no\n[/REPORTABILITY]"
)


def _parse_verdict_bool(text: str) -> bool:
    m = _VERDICT.search(text or "")
    if not m:
        raise DrafterError("reportability reply missing [REPORTABILITY] verdict block")
    for raw in m.group(1).strip().splitlines():
        key, _, value = raw.strip().partition("=")
        if key.strip() == "reportable":
            v = value.strip().lower()
            if v in ("yes", "true", "reportable"):
                return True
            if v in ("no", "false", "not_reportable", "unreportable"):
                return False
    raise DrafterError("reportability verdict block has no parsable reportable= line")


def assess_reportability(fact_record: dict, *, regime: str, branch: str,
                         standard: str, rule: str,
                         model: str, provider: str = roster.FEATHERLESS,
                         api_key: str | None = None,
                         max_tokens: int = 500, timeout: int = 90,
                         max_attempts: int = 1) -> ReportabilityVerdict:
    """Run the LLM reportability assessment for one regime on the named provider
    and return a typed verdict. The boolean is parsed off the fenced block; the
    rationale is the prose above it. Raises DrafterError on transport or
    unparsable verdict.

    `standard` is the regime's statutory trigger standard (from the catalog); it
    is injected into the prompt so the model judges against the real rule. `rule`
    is the short human rule label carried through onto the verdict for the
    packet. max_attempts threads straight through to llm_complete: default 1 (no
    retry, unchanged offline behavior); the live runner raises it so a transient
    429/5xx on the reportability call is retried with backoff."""
    user = (
        f"Assess whether this incident is REPORTABLE under the {regime} regime. "
        f"Apply ONLY this standard:\n\n{standard}\n\n"
        "Use ONLY these facts. Write a short rationale (under 150 words) "
        "explaining whether the incident crosses the threshold, then the fenced "
        f"verdict block.\n\nFACT RECORD (canonical):\n{json.dumps(fact_record, indent=2)}"
    )
    text = llm_complete(
        provider, model,
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.1, timeout=timeout,
        max_attempts=max_attempts)
    reportable = _parse_verdict_bool(text)
    rationale = _VERDICT.sub("", text).strip()
    return ReportabilityVerdict(
        branch=branch, regime=regime, reportable=reportable, rationale=rationale,
        standard=standard, rule=rule, source=f"{provider}:{model}")
