"""LLM drafting for the filing agents.

Featherless is the dev provider (flat-rate, OpenAI-compatible). One big model
at a time on the plan, so drafters must run SEQUENTIALLY, never concurrently,
and the small pinned roster avoids the "switch models 4x/minute" cap.

The Warden NEVER calls this. Only drafter processes draft filing text here.
"""

from __future__ import annotations

import json
import os

import requests

from floor.claims import emit_claims

FEATHERLESS_BASE = "https://api.featherless.ai/v1"
DEFAULT_MODEL = "deepseek-ai/DeepSeek-V3.2"  # fast, clean content, the hero open model


class DrafterError(RuntimeError):
    pass


def build_draft_body(prose: str, branch: str, claim_facts: dict) -> str:
    """Assemble the message a drafter posts back: the LLM prose followed by the
    deterministic structured-claims block the Warden diffs.

    claim_facts is the fact dict this drafter is asserting (normally the shared
    fact-record; in the contradiction demo one drafter's copy is perturbed). The
    LLM never formats the claims; the drafter process attaches them, so the
    load-bearing facts are deterministic and the Warden's diff is checkable."""
    return prose.rstrip() + "\n\n" + emit_claims(branch, claim_facts)


def draft_filing(fact_record: dict, *, model: str = DEFAULT_MODEL,
                 api_key: str | None = None, regime: str = "NIS2",
                 max_tokens: int = 700, timeout: int = 90) -> str:
    """Draft the regulatory notification body for one regime from the canonical
    fact-record. Returns the model's text. Raises DrafterError on transport or
    empty-content failure (the caller decides fallback)."""
    key = api_key or os.environ.get("FEATHERLESS_API_KEY", "")
    if not key:
        raise DrafterError("FEATHERLESS_API_KEY not set")

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
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    try:
        r = requests.post(
            FEATHERLESS_BASE + "/chat/completions",
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=timeout,
        )
    except requests.RequestException as e:
        raise DrafterError(f"featherless transport error: {e}") from e
    if r.status_code != 200:
        raise DrafterError(f"featherless HTTP {r.status_code}: {r.text[:300]}")
    body = r.json()
    try:
        content = body["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError) as e:
        raise DrafterError(f"featherless malformed response: {body}") from e
    if not content:
        raise DrafterError("featherless returned empty content")
    return content


def draft_characterization(*, regime: str, old_records: int, new_records: int,
                           role: str, counterpart_text: str = "",
                           model: str = DEFAULT_MODEL, api_key: str | None = None,
                           max_tokens: int = 160, timeout: int = 90) -> str:
    """Draft ONE short reconciliation sentence: how this drafter proposes to
    characterize the revised record count for its regulator, so the two filings
    share one phrasing of the same number.

    This is the only LLM step in the amendment beat. It writes prose only; the
    structured figure and verdict are attached by the drafter process, not the
    model, so the value the Warden gates on stays deterministic. Returns a single
    plain sentence (no markdown, no quotes). Raises DrafterError on failure.
    """
    key = api_key or os.environ.get("FEATHERLESS_API_KEY", "")
    if not key:
        raise DrafterError("FEATHERLESS_API_KEY not set")

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
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    try:
        r = requests.post(
            FEATHERLESS_BASE + "/chat/completions",
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=timeout,
        )
    except requests.RequestException as e:
        raise DrafterError(f"featherless transport error: {e}") from e
    if r.status_code != 200:
        raise DrafterError(f"featherless HTTP {r.status_code}: {r.text[:300]}")
    body = r.json()
    try:
        content = body["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError) as e:
        raise DrafterError(f"featherless malformed response: {body}") from e
    if not content:
        raise DrafterError("featherless returned empty characterization")
    # One clean sentence: collapse whitespace, drop wrapping quotes.
    content = " ".join(content.split())
    if len(content) >= 2 and content[0] in "\"'" and content[-1] in "\"'":
        content = content[1:-1].strip()
    return content
