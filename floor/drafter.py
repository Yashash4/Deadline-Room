"""LLM drafting for the filing agents.

Two providers, both OpenAI-compatible:

  featherless: the DEV provider (flat-rate). One big model at a time on the plan,
      so drafters run SEQUENTIALLY, never concurrently, and a small pinned roster
      avoids the "switch models 4x/minute" cap.
  aimlapi: the AI/ML API gateway (Authorization: Bearer, base api.aimlapi.com/v1),
      used by the PROD split for the parallel racing drafters. Concurrency is
      independent of Featherless.

A single router, `llm_complete(provider, model, messages, ...)`, picks the base
URL + API key for the named provider and makes one chat completion. Both
`draft_filing` and `draft_characterization` go through it, so a role's provider
is just a parameter and dev stays all-Featherless unless prod is requested.

The Warden NEVER calls this. Only drafter processes draft filing text here.
"""

from __future__ import annotations

import json
import os

import requests

from floor import roster
from floor.claims import emit_claims

FEATHERLESS_BASE = "https://api.featherless.ai/v1"
AIMLAPI_BASE = "https://api.aimlapi.com/v1"
DEFAULT_MODEL = "deepseek-ai/DeepSeek-V3.2"  # fast, clean content, the hero open model
DEFAULT_PROVIDER = roster.FEATHERLESS

# Per-provider transport config: (base URL, env var holding the API key).
_PROVIDERS = {
    roster.FEATHERLESS: (FEATHERLESS_BASE, "FEATHERLESS_API_KEY"),
    roster.AIMLAPI: (AIMLAPI_BASE, "AIML_API_KEY"),
}


class DrafterError(RuntimeError):
    pass


def provider_config(provider: str) -> tuple[str, str]:
    """Return (base_url, key_env) for a provider, raising on an unknown one."""
    try:
        return _PROVIDERS[provider]
    except KeyError as e:
        raise DrafterError(f"unknown LLM provider: {provider!r}") from e


def llm_complete(provider: str, model: str, messages: list[dict], *,
                 api_key: str | None = None, max_tokens: int = 700,
                 temperature: float = 0.2, timeout: int = 90) -> str:
    """Route one chat completion to the named provider and return the content.

    Both providers are OpenAI-compatible (Authorization: Bearer, /chat/completions),
    so the only per-provider difference is the base URL and which env var holds the
    key. Raises DrafterError on a missing key, transport error, non-200, malformed
    body, or empty content (the caller decides any fallback)."""
    base, key_env = provider_config(provider)
    key = api_key or os.environ.get(key_env, "")
    if not key:
        raise DrafterError(f"{key_env} not set (provider {provider})")
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    try:
        r = requests.post(
            base + "/chat/completions",
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=timeout,
        )
    except requests.RequestException as e:
        raise DrafterError(f"{provider} transport error: {e}") from e
    if r.status_code != 200:
        raise DrafterError(f"{provider} HTTP {r.status_code}: {r.text[:300]}")
    body = r.json()
    try:
        content = body["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError, TypeError) as e:
        raise DrafterError(f"{provider} malformed response: {body}") from e
    if not content:
        raise DrafterError(f"{provider} returned empty content")
    return sanitize_llm_text(content)


# Models sometimes emit em/en dashes, unicode hyphens, smart quotes, and ellipses.
# This artifact (the Examiner Packet) must stay free of em/en dashes and reads
# cleanest in plain ASCII punctuation, so normalize every LLM output at the one
# chokepoint before it can reach a filing or the packet.
_PUNCT_MAP = {
    "—": ", ",   # em dash
    "–": "-",     # en dash
    "‒": "-",     # figure dash
    "―": "-",     # horizontal bar
    "‑": "-",     # non-breaking hyphen
    "‐": "-",     # hyphen
    "‘": "'", "’": "'",          # single smart quotes
    "“": '"', "”": '"',          # double smart quotes
    "…": "...",   # ellipsis
    " ": " ",     # non-breaking space
}


def sanitize_llm_text(text: str) -> str:
    """Normalize model output to clean ASCII punctuation (no em/en dashes)."""
    for bad, good in _PUNCT_MAP.items():
        text = text.replace(bad, good)
    return text.replace(",  ", ", ")


def build_draft_body(prose: str, branch: str, claim_facts: dict) -> str:
    """Assemble the message a drafter posts back: the LLM prose followed by the
    deterministic structured-claims block the Warden diffs.

    claim_facts is the fact dict this drafter is asserting (normally the shared
    fact-record; in the contradiction demo one drafter's copy is perturbed). The
    LLM never formats the claims; the drafter process attaches them, so the
    load-bearing facts are deterministic and the Warden's diff is checkable."""
    return prose.rstrip() + "\n\n" + emit_claims(branch, claim_facts)


def draft_filing(fact_record: dict, *, model: str = DEFAULT_MODEL,
                 provider: str = DEFAULT_PROVIDER, api_key: str | None = None,
                 regime: str = "NIS2", format_profile=None, max_tokens: int = 700,
                 timeout: int = 90) -> str:
    """Draft the regulatory notification body for one regime from the canonical
    fact-record on the named provider. Returns the model's text. Raises
    DrafterError on transport or empty-content failure (the caller decides
    fallback).

    format_profile, when supplied, is a floor.formats.FormatProfile carrying the
    REAL per-regime field skeleton (e.g. SEC 8-K Item 1.05's four mandated
    elements). The model then writes prose INTO those labelled slots instead of a
    generic structure, so the filing reads examiner-authored. The structured
    [CLAIMS] block is attached separately and is never affected by this."""
    if format_profile is not None:
        from floor.formats import prompt_for
        structure = prompt_for(format_profile)
        system = (
            "You are a regulatory breach-notification drafter for a bank's "
            "incident response team. You write tight, examiner-ready filings. You "
            "state only what the supplied fact-record supports, never invent "
            "facts, and you fill the exact mandated fields the form requires. No "
            "markdown headers; plain prose under each field label."
        )
        user = (
            f"Draft the {regime} mandatory incident notification from this "
            f"canonical fact-record. Use ONLY these facts. Keep it under 300 "
            f"words total.\n\n{structure}\n\n"
            f"FACT RECORD (canonical, authoritative):\n"
            f"{json.dumps(fact_record, indent=2)}"
        )
        return llm_complete(
            provider, model,
            [{"role": "system", "content": system},
             {"role": "user", "content": user}],
            api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout)
    system = (
        "You are a regulatory breach-notification drafter for a bank's incident "
        "response team. You write tight, examiner-ready filings. You state only "
        "what the supplied fact-record supports, never invent facts, and you keep "
        "the structure a regulator expects. No markdown headers, plain prose with "
        "short labelled sections."
    )
    user = (
        f"Draft the {regime} mandatory incident notification (the 72-hour "
        f"notification where applicable) from this canonical fact-record. "
        f"Use ONLY these facts. Keep it under 300 words.\n\n"
        f"FACT RECORD (canonical, authoritative):\n{json.dumps(fact_record, indent=2)}"
    )
    return llm_complete(
        provider, model,
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout)


def draft_characterization(*, regime: str, old_records: int, new_records: int,
                           role: str, counterpart_text: str = "",
                           model: str = DEFAULT_MODEL,
                           provider: str = DEFAULT_PROVIDER,
                           api_key: str | None = None,
                           max_tokens: int = 160, timeout: int = 90) -> str:
    """Draft ONE short reconciliation sentence: how this drafter proposes to
    characterize the revised record count for its regulator, so the two filings
    share one phrasing of the same number.

    This is the only LLM step in the amendment beat. It writes prose only; the
    structured figure and verdict are attached by the drafter process, not the
    model, so the value the Warden gates on stays deterministic. Returns a single
    plain sentence (no markdown, no quotes). Raises DrafterError on failure.
    """
    system = (
        "You are a regulatory breach-notification drafter reconciling a revised "
        "figure with a counterpart drafter so both filings characterize the same "
        "number identically. Reply with ONE plain sentence, under 30 words, no "
        "markdown, no quotation marks, no preamble. State only how to phrase the "
        "revised affected-record count for the regulator."
    )
    if role == "propose":
        user = (
            f"You draft the {regime} filing. Forensics revised affected records "
            f"from {old_records:,} to {new_records:,}. Propose to the counterpart "
            f"drafter one shared way to characterize {new_records:,} affected "
            f"records in both filings."
        )
    else:
        user = (
            f"You draft the {regime} filing. The counterpart proposed this "
            f"characterization of {new_records:,} affected records: "
            f"\"{counterpart_text}\". Reply concurring with a single shared "
            f"sentence that both filings will use."
        )
    content = llm_complete(
        provider, model,
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout)
    # One clean sentence: collapse whitespace, drop wrapping quotes.
    content = " ".join(content.split())
    if len(content) >= 2 and content[0] in "\"'" and content[-1] in "\"'":
        content = content[1:-1].strip()
    return content
