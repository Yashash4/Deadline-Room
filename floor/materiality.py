"""Materiality drafter role: the LLM judgment that decides whether the SEC clock
is even triggered.

This is a true LLM judgment role, not a narrator. It applies the SEC "substantial
likelihood that a reasonable investor would consider it important" materiality
standard to the canonical fact-record and returns a typed verdict (material yes /
no plus a one-paragraph memo). On the dev provider set it runs on Featherless.

The Warden never calls this. The verdict it returns crosses into the
deterministic warden/materiality.py gate as data; the Warden only acts on the
boolean. So the qualitative CALL is the model's, and the gating of the SEC branch
is deterministic and replay-verifiable.

The memo prose is the model's; the boolean is parsed off a fenced verdict block
the role is instructed to emit, so the load-bearing value the Warden gates on is
a deterministic parse, not an LLM essay the Warden has to interpret.
"""

from __future__ import annotations

import json
import re

from warden.materiality import MaterialityVerdict

from floor.drafter import DrafterError, llm_complete
from floor import roster

_VERDICT = re.compile(r"\[MATERIALITY\](.*?)\[/MATERIALITY\]", re.DOTALL)

_SYSTEM = (
    "You are a securities-law materiality assessor for a public bank's incident "
    "response team. You apply the SEC Item 1.05 cybersecurity-incident standard: "
    "an incident is MATERIAL if there is a substantial likelihood that a "
    "reasonable investor would consider it important, weighing both quantitative "
    "scale (records, systems, financial exposure) and qualitative factors "
    "(reputational harm, regulated data, operational disruption). You decide "
    "honestly: small, contained, non-sensitive incidents are NOT material. End "
    "your reply with a fenced verdict block on its own lines, exactly:\n"
    "[MATERIALITY]\nmaterial=yes|no\n[/MATERIALITY]"
)


def _parse_verdict_bool(text: str) -> bool:
    m = _VERDICT.search(text or "")
    if not m:
        raise DrafterError("materiality reply missing [MATERIALITY] verdict block")
    for raw in m.group(1).strip().splitlines():
        key, _, value = raw.strip().partition("=")
        if key.strip() == "material":
            v = value.strip().lower()
            if v in ("yes", "true", "material"):
                return True
            if v in ("no", "false", "immaterial", "not_material"):
                return False
    raise DrafterError("materiality verdict block has no parsable material= line")


def assess_materiality(fact_record: dict, *, model: str, provider: str = roster.FEATHERLESS,
                       api_key: str | None = None, branch: str = "sec",
                       max_tokens: int = 500, timeout: int = 90) -> MaterialityVerdict:
    """Run the LLM materiality assessment on the named provider and return a typed
    verdict. The boolean is parsed off the fenced block; the memo is the prose
    above it. Raises DrafterError on transport or unparsable verdict."""
    user = (
        "Assess the materiality of this cybersecurity incident for an SEC Item "
        "1.05 8-K determination. Use ONLY these facts. Write a short memo (under "
        "150 words) explaining your reasoning, then the fenced verdict block.\n\n"
        f"FACT RECORD (canonical):\n{json.dumps(fact_record, indent=2)}"
    )
    text = llm_complete(
        provider, model,
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.1, timeout=timeout)
    material = _parse_verdict_bool(text)
    memo = _VERDICT.sub("", text).strip()
    return MaterialityVerdict(branch=branch, material=material, memo=memo,
                              source=f"{provider}:{model}")


def assess_materiality_two_opinions(fact_record: dict, *,
                                    primary: tuple[str, str],
                                    second: tuple[str, str],
                                    branch: str = "sec",
                                    api_key: str | None = None,
                                    primary_max_tokens: int = 500,
                                    second_max_tokens: int = 2000,
                                    timeout: int = 90
                                    ) -> tuple[MaterialityVerdict, MaterialityVerdict, str]:
    """Run the materiality judgment on TWO different open models SEQUENTIALLY and
    return both typed verdicts plus an agreement string ("agree" | "disagree").

    `primary` and `second` are (provider, model) pairs from the verified roster
    (DeepSeek-V3.2 then MiniMax-M2.7). The two calls run one after another, never
    concurrently: Featherless permits only one big model at a time, so this adds
    one sequential big-model call before the drafter loop, not a parallel one. The
    pinned two-model set stays well under the 4-switches-per-minute cap, and each
    call carries the same small fact-record payload (no 32K context pressure).

    The two roles get DIFFERENT token budgets on purpose. The primary (DeepSeek, an
    instruct model) emits the memo plus verdict in a lean budget. The second model
    is the latest MiniMax, a reasoning model that spends a few hundred tokens on an
    internal preamble before any visible content, so a small budget can return
    empty; it gets the same larger budget the UK drafter already uses for this
    model. Featherless is flat-rate, so the extra tokens cost nothing on dev.

    The reconciliation into a single verdict is NOT done here; that is pure-Python
    Warden-side logic in warden/second_opinion.py. This function only gathers the
    two data points."""
    p_provider, p_model = primary
    s_provider, s_model = second
    v_primary = assess_materiality(
        fact_record, model=p_model, provider=p_provider, branch=branch,
        api_key=api_key, max_tokens=primary_max_tokens, timeout=timeout)
    v_second = assess_materiality(
        fact_record, model=s_model, provider=s_provider, branch=branch,
        api_key=api_key, max_tokens=second_max_tokens, timeout=timeout)
    agreement = "agree" if v_primary.material == v_second.material else "disagree"
    return v_primary, v_second, agreement
