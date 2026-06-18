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

# OPTIONAL confidence add (E5.3). This single sentence is appended to the system
# prompt ONLY when assess_materiality is called with emit_confidence=True. The
# DEFAULT path never appends it, so _SYSTEM and the whole request are
# byte-identical to today and replay is unaffected. The instruction asks for a
# SEPARATE confidence line that lives OUTSIDE the fenced [MATERIALITY] block, so
# the verdict block the Warden gate consumes is unchanged whether confidence is
# on or off. The confidence is calibration metadata for the eval receipt only;
# the Warden never reads it.
_CONFIDENCE_SUFFIX = (
    " On the line immediately before the [MATERIALITY] block, also emit your "
    "confidence in this verdict as a single line exactly: confidence=0.NN (a "
    "number from 0 to 1, where 1 is fully certain). The verdict block itself "
    "stays exactly as specified above."
)

# Parses the optional confidence line. Deliberately anchored to its own
# 'confidence=' key so it never collides with the 'material=' line inside the
# fenced block. Returns None when absent (the default, no-confidence path).
_CONFIDENCE = re.compile(r"(?im)^\s*confidence\s*=\s*([+-]?[0-9]*\.?[0-9]+)\s*$")


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


def _parse_confidence(text: str) -> float | None:
    """Deterministically parse the optional confidence line from a reply, or None.

    Looks ONLY at confidence lines OUTSIDE the fenced [MATERIALITY] block (the
    block is stripped first), so the gate's verdict block is never read for this.
    A value outside [0, 1] is clamped into range. Returns None when the model
    emitted no parsable confidence line, which is the default path. Pure function
    of the reply text."""
    outside = _VERDICT.sub("", text or "")
    m = _CONFIDENCE.search(outside)
    if not m:
        return None
    value = float(m.group(1))
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _grounding_context_block(grounding_chunks) -> str:
    """Render the SEC Item 1.05 materiality-standard passages as a GROUNDING CONTEXT
    block injected ahead of the fact-record (E5.9), or "" when none are supplied.

    Putting the REAL materiality standard (the Item 1.05 determination anchor and
    the CorpFin C&DIs) in front of the assessor makes it apply the actual SEC test,
    not the model's memory of it. Pure string work; it carries no Warden control
    fence and states no incident facts, so the [MATERIALITY] verdict block the gate
    consumes is unchanged whether grounding is on or off."""
    if not grounding_chunks:
        return ""
    lines = [
        "GROUNDING CONTEXT (authoritative SEC materiality standard, apply this "
        "standard):",
    ]
    for c in grounding_chunks:
        lines.append("")
        lines.append(f"[id: {c.id}] {c.citation} ({c.title})")
        lines.append(c.text)
    return "\n".join(lines) + "\n\n"


def assess_materiality(fact_record: dict, *, model: str, provider: str = roster.FEATHERLESS,
                       api_key: str | None = None, branch: str = "sec",
                       max_tokens: int = 500, timeout: int = 90,
                       max_attempts: int = 1,
                       emit_confidence: bool = False,
                       grounding_chunks=None):
    """Run the LLM materiality assessment on the named provider and return a typed
    verdict. The boolean is parsed off the fenced block; the memo is the prose
    above it. Raises DrafterError on transport or unparsable verdict.

    max_attempts threads straight through to llm_complete: default 1 (no retry,
    unchanged offline behavior); the live runner raises it so a transient 429/5xx
    on the materiality call is retried with backoff.

    emit_confidence DEFAULTS OFF (False). With it off, the system prompt, the user
    prompt, the request to llm_complete, and the returned MaterialityVerdict are
    byte-identical to the historical behavior: this function returns a bare
    MaterialityVerdict exactly as before, the fenced [MATERIALITY] gate block is
    parsed exactly as before, and replay is unaffected. With it ON, a single
    sentence is appended to the system prompt asking the model for a separate
    confidence line OUTSIDE the verdict block, and the function returns a
    (MaterialityVerdict, confidence_or_None) tuple instead. The confidence is
    eval/calibration metadata only; the Warden never reads it, and the verdict
    block it gates on is unchanged either way. The return-type switch is
    deliberate so the default path's return value is byte-identical to today.

    grounding_chunks, when supplied (E5.9), is the list of floor.rag.RetrievedChunk
    SEC Item 1.05 materiality-standard passages a pure deterministic retriever
    fetched from the regulation corpus. They are injected as a GROUNDING CONTEXT
    block ahead of the fact-record so the assessor applies the REAL standard rather
    than its memory of it. Like emit_confidence it changes only the prose half: the
    fenced [MATERIALITY] verdict block the Warden gate consumes is unchanged, the
    retrieval is out-of-log, and grounding_chunks DEFAULTS None so the default path
    is byte-identical to before."""
    system = _SYSTEM + _CONFIDENCE_SUFFIX if emit_confidence else _SYSTEM
    user = (
        _grounding_context_block(grounding_chunks)
        + "Assess the materiality of this cybersecurity incident for an SEC Item "
        "1.05 8-K determination. Use ONLY these facts. Write a short memo (under "
        "150 words) explaining your reasoning, then the fenced verdict block.\n\n"
        f"FACT RECORD (canonical):\n{json.dumps(fact_record, indent=2)}"
    )
    text = llm_complete(
        provider, model,
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.1, timeout=timeout,
        max_attempts=max_attempts)
    material = _parse_verdict_bool(text)
    memo = _VERDICT.sub("", text).strip()
    verdict = MaterialityVerdict(branch=branch, material=material, memo=memo,
                                 source=f"{provider}:{model}")
    if emit_confidence:
        return verdict, _parse_confidence(text)
    return verdict


def assess_materiality_two_opinions(fact_record: dict, *,
                                    primary: tuple[str, str],
                                    second: tuple[str, str],
                                    branch: str = "sec",
                                    api_key: str | None = None,
                                    primary_max_tokens: int = 500,
                                    second_max_tokens: int = 2000,
                                    timeout: int = 90,
                                    max_attempts: int = 1
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
        api_key=api_key, max_tokens=primary_max_tokens, timeout=timeout,
        max_attempts=max_attempts)
    v_second = assess_materiality(
        fact_record, model=s_model, provider=s_provider, branch=branch,
        api_key=api_key, max_tokens=second_max_tokens, timeout=timeout,
        max_attempts=max_attempts)
    agreement = "agree" if v_primary.material == v_second.material else "disagree"
    return v_primary, v_second, agreement
