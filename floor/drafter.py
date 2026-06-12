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

FEATHERLESS_BASE = "https://api.featherless.ai/v1"
DEFAULT_MODEL = "deepseek-ai/DeepSeek-V3.2"  # fast, clean content, the hero open model


class DrafterError(RuntimeError):
    pass


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
