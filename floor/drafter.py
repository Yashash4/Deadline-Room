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
import time

import requests

from floor import roster
from floor.claims import emit_claims
from floor.retry import call_with_retry, is_transient_status, log as net_log

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


class _TransientDrafterError(DrafterError):
    """A DrafterError whose cause is transient (transport error or 429/5xx), so
    the retry wrapper may try again. It is still a DrafterError, so if attempts
    run out it surfaces to the caller exactly like the non-retry path did: a
    transient that never clears is reported as the same typed error, never
    swallowed."""


def _is_transient_drafter_error(e: BaseException) -> bool:
    return isinstance(e, _TransientDrafterError)


def llm_complete(provider: str, model: str, messages: list[dict], *,
                 api_key: str | None = None, max_tokens: int = 700,
                 temperature: float = 0.2, timeout: int = 90,
                 max_attempts: int = 1) -> str:
    """Route one chat completion to the named provider and return the content.

    Both providers are OpenAI-compatible (Authorization: Bearer, /chat/completions),
    so the only per-provider difference is the base URL and which env var holds the
    key. Raises DrafterError on a missing key, transport error, non-200, malformed
    body, or empty content (the caller decides any fallback).

    max_attempts is the total number of network attempts (including the first).
    The DEFAULT is 1, so the offline FakeBand-backed tests and byte-identical
    replay are unchanged: with one attempt there is no retry path and no backoff.
    The live runner passes a small value (e.g. 3); then a transient transport
    error or an HTTP 429/5xx is retried with bounded jittered exponential backoff,
    while a 4xx (bad request, bad key, forbidden) fails fast on the first try.
    Each attempt emits one structured log line (provider, model, status,
    latency_ms, attempt, token usage when the body returns it) on the quiet
    deadline_room.net logger."""
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
    endpoint = base + "/chat/completions"
    attempt_box = {"n": 0}

    def attempt() -> str:
        attempt_box["n"] += 1
        n = attempt_box["n"]
        started = time.monotonic()
        try:
            r = requests.post(
                endpoint,
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json=payload, timeout=timeout,
            )
        except requests.RequestException as e:
            # Transport errors (connection reset, read timeout) are transient.
            latency_ms = int((time.monotonic() - started) * 1000)
            net_log.info(
                "llm call provider=%s model=%s status=transport_error "
                "latency_ms=%d attempt=%d error=%s",
                provider, model, latency_ms, n, e)
            raise _TransientDrafterError(f"{provider} transport error: {e}") from e
        latency_ms = int((time.monotonic() - started) * 1000)
        usage = ""
        if r.status_code == 200:
            try:
                usage = str((r.json() or {}).get("usage", ""))
            except ValueError:
                usage = ""
        net_log.info(
            "llm call provider=%s model=%s status=%d latency_ms=%d attempt=%d "
            "usage=%s", provider, model, r.status_code, latency_ms, n, usage)
        if r.status_code != 200:
            msg = f"{provider} HTTP {r.status_code}: {r.text[:300]}"
            # 429 and 5xx are transient and may be retried; every other status
            # (400/401/403/404 ...) is terminal and fails fast.
            if is_transient_status(r.status_code):
                raise _TransientDrafterError(msg)
            raise DrafterError(msg)
        body = r.json()
        try:
            content = body["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, AttributeError, TypeError) as e:
            raise DrafterError(f"{provider} malformed response: {body}") from e
        if not content:
            raise DrafterError(f"{provider} returned empty content")
        return sanitize_llm_text(content)

    return call_with_retry(
        attempt, classify=_is_transient_drafter_error, max_attempts=max_attempts)


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


# Control fences the deterministic half of the system parses out of posted
# messages: the load-bearing [CLAIMS] envelope the Warden diffs, the [RECONCILE]
# amendment envelope, the [CHALLENGE] objection block, and the [MATERIALITY]
# verdict block. The drafter PROCESS appends the one legitimate authoritative
# block AFTER this sanitizer runs (see build_draft_body / draft_filing), so any
# such fence appearing in MODEL output is never legitimate: it can only be a
# prompt-injection trying to plant attacker-chosen values that a first-match
# parser would gate on. We DEFANG every model-emitted fence into an inert,
# visible escaped form so it can never be parsed as a real control envelope, then
# the authoritative block the drafter attaches afterwards is the only one a parser
# ever sees. This is the chokepoint half of a defense in depth; the parsers
# (parse_claims and friends) assert exactly one block as the matching belt.
_CONTROL_FENCES = (
    "[CLAIMS]", "[/CLAIMS]",
    "[RECONCILE]", "[/RECONCILE]",
    "[CHALLENGE]", "[/CHALLENGE]",
    "[MATERIALITY]", "[/MATERIALITY]",
)


def defang_control_fences(text: str) -> str:
    """Neutralize any control-envelope fence emitted in MODEL text so it can never
    be parsed as a real block. Replaces the square brackets with parentheses
    (e.g. [CLAIMS] -> (CLAIMS)), which is inert to the [TOKEN] parsers, stays
    human-readable so an injection attempt is visible in the prose, and contains
    no em/en dashes. Pure string work; a clean draft (no fences) is untouched, so
    this is a no-op on every legitimate filing and replay stays byte-identical."""
    for fence in _CONTROL_FENCES:
        if fence in text:
            text = text.replace(fence, "(" + fence[1:-1] + ")")
    return text


def sanitize_llm_text(text: str) -> str:
    """Normalize model output to clean ASCII punctuation (no em/en dashes) and
    defang any control-envelope fence the model emitted, so a prompt injection can
    never plant a parsable [CLAIMS]/[RECONCILE]/[CHALLENGE]/[MATERIALITY] block in
    the prose. The drafter process appends the authoritative block AFTER this
    runs, so the only legitimate block survives intact."""
    for bad, good in _PUNCT_MAP.items():
        text = text.replace(bad, good)
    text = text.replace(",  ", ", ")
    return defang_control_fences(text)


# Each factual sentence in the filing cites the fact-record FIELD it relies on,
# as a trailing tag using the EXACT field name from the record, so the filing is
# self-evidencing and a deterministic validator can confirm every cited field
# exists. The model emits only the tags; the load-bearing [CLAIMS] block the
# Warden diffs is attached separately by the drafter process and is never
# affected by this instruction. The tag form is "[field: <name>]".
_CITATION_INSTRUCTION = (
    "After each sentence that states a fact drawn from the record, add a trailing "
    "citation tag naming the exact fact-record field it relies on, in the form "
    "[field: <field_name>] (for example [field: records_affected]). Use only "
    "field names that appear verbatim in the supplied fact-record. Do not cite a "
    "field that is not in the record. Keep the tags inline in the prose."
)


def _citation_fields_hint(fact_record: dict) -> str:
    """A one-line reminder listing the exact citeable field names, so the model
    cites real keys. Deterministic from the record; affects only the prose tags,
    never the [CLAIMS] block."""
    fields = ", ".join(fact_record.keys())
    return f"Citeable fact-record fields (cite by these exact names): {fields}."


# The fence the regime-expert rationale is wrapped in (E5.6). It is NOT a Warden
# control envelope: it carries no gated value, it is prose, and it is extracted by
# the packet renderer for the human-readable reasoning section only. It is
# deliberately NOT in _CONTROL_FENCES, so the sanitizer leaves it intact (the
# drafter WANTS to keep this block), while a model-emitted [CLAIMS] / [RECONCILE] /
# [CHALLENGE] / [MATERIALITY] fence is still defanged exactly as before. The
# rationale never enters the hashed run-log (the run-log holds only the structured
# protocol events; the filing prose is packet data, not log data), so a fresh run
# reproduces the sealed sha and replay stays byte-identical.
RATIONALE_OPEN = "[REGIME_RATIONALE]"
RATIONALE_CLOSE = "[/REGIME_RATIONALE]"


def _expert_system_prompt(expert_profile) -> str:
    """The regime-expert fragment threaded into the drafter SYSTEM prompt, built
    from a regimes.ExpertProfileSpec exactly the way prompt_for builds the
    format-skeleton fragment. It states the statutory standard the filing must
    meet, the named factors the regulator weighs, and the common failure modes to
    avoid, then instructs the model to emit an OPTIONAL fenced rationale block
    reasoning in regime-specific terms. Deterministic text; the model fills the
    reasoning. Changes only the prose, never the [CLAIMS] block."""
    lines = [
        "You are a domain EXPERT in this specific regulation, not a generic "
        "drafter. Reason about what THIS regulator requires.",
        f"Statutory standard the filing must satisfy: {expert_profile.statutory_standard}",
    ]
    if expert_profile.factors:
        lines.append("Named factors this regulator weighs (address the ones the "
                     "fact-record supports):")
        for f in expert_profile.factors:
            lines.append(f"  - {f}")
    if expert_profile.failure_modes:
        lines.append("Common failure modes for this regime (write to avoid these):")
        for fm in expert_profile.failure_modes:
            lines.append(f"  - {fm}")
    lines.append(
        "After the filing body, you MAY add one OPTIONAL short reasoning block, "
        f"wrapped exactly as {RATIONALE_OPEN} on its own line, then two to four "
        "sentences reasoning in REGIME-SPECIFIC terms (why this filing meets the "
        "statutory standard, which named factors the fact-record drove, and which "
        "failure mode you avoided), then "
        f"{RATIONALE_CLOSE} on its own line. The rationale is explanatory prose "
        "only: it states no new facts and repeats no figures the body did not "
        "already carry.")
    return "\n".join(lines)


def extract_rationale(text: str) -> str:
    """Extract the regime-expert rationale wrapped in the [REGIME_RATIONALE] fence
    from a filing body, or "" if none is present. Pure string work used by the
    packet renderer to show the per-regime reasoning in its own section; it never
    feeds a gate, a clock, the diff, or the hashed run-log. Returns the inner text
    with surrounding whitespace stripped; tolerant of no block, an unclosed block
    (returns ""), or the close appearing before the open (returns "")."""
    start = text.find(RATIONALE_OPEN)
    if start == -1:
        return ""
    inner_start = start + len(RATIONALE_OPEN)
    end = text.find(RATIONALE_CLOSE, inner_start)
    if end == -1:
        return ""
    return text[inner_start:end].strip()


def strip_rationale(text: str) -> str:
    """Return the filing body with the [REGIME_RATIONALE] block removed, so the
    human-readable filing prose and the per-regime reasoning section can be
    rendered separately. A body with no block is returned unchanged. Pure string
    work; never touches the [CLAIMS] block (the rationale always sits in the prose
    half, the claims block is appended after sanitization)."""
    start = text.find(RATIONALE_OPEN)
    if start == -1:
        return text
    end = text.find(RATIONALE_CLOSE, start + len(RATIONALE_OPEN))
    if end == -1:
        return text
    end += len(RATIONALE_CLOSE)
    return (text[:start].rstrip() + "\n" + text[end:].lstrip()).strip()


def build_draft_body(prose: str, branch: str, claim_facts: dict) -> str:
    """Assemble the message a drafter posts back: the LLM prose followed by the
    deterministic structured-claims block the Warden diffs.

    claim_facts is the fact dict this drafter is asserting (normally the shared
    fact-record; in the contradiction demo one drafter's copy is perturbed). The
    LLM never formats the claims; the drafter process attaches them, so the
    load-bearing facts are deterministic and the Warden's diff is checkable.

    The prose is sanitized here before the authoritative block is appended, so any
    control-envelope fence the model emitted (a prompt injection) is defanged and
    cannot be parsed as a rival [CLAIMS] block. On the live path the prose already
    passed through sanitize_llm_text inside llm_complete, so this is idempotent and
    a no-op for a clean filing; replay stays byte-identical."""
    return sanitize_llm_text(prose).rstrip() + "\n\n" + emit_claims(branch, claim_facts)


def draft_filing(fact_record: dict, *, model: str = DEFAULT_MODEL,
                 provider: str = DEFAULT_PROVIDER, api_key: str | None = None,
                 regime: str = "NIS2", format_profile=None, expert_profile=None,
                 max_tokens: int = 700, timeout: int = 90,
                 max_attempts: int = 1) -> str:
    """Draft the regulatory notification body for one regime from the canonical
    fact-record on the named provider. Returns the model's text. Raises
    DrafterError on transport or empty-content failure (the caller decides
    fallback).

    format_profile, when supplied, is a floor.formats.FormatProfile carrying the
    REAL per-regime field skeleton (e.g. SEC 8-K Item 1.05's four mandated
    elements). The model then writes prose INTO those labelled slots instead of a
    generic structure, so the filing reads examiner-authored. The structured
    [CLAIMS] block is attached separately and is never affected by this.

    expert_profile, when supplied, is a floor.regimes.ExpertProfileSpec carrying the
    statutory standard the filing must meet, the named factors the regulator weighs,
    and the common failure modes for this regime (E5.6). It is threaded into the
    SYSTEM prompt exactly the way format_profile is, turning the drafter from a
    slot-filler into a regime EXPERT that reasons about the specific regulation and
    emits an OPTIONAL fenced [REGIME_RATIONALE] block of regime-specific reasoning.
    Like format_profile, it changes ONLY the human-readable prose: the [CLAIMS]
    block is attached after sanitization and is never affected, and the rationale is
    out-of-log (the run-log holds structured events, not filing prose), so a fresh
    run reproduces the sealed sha and replay stays byte-identical. Both params
    default to None, so a caller that passes neither is byte-identical to before."""
    expert = (
        "\n\n" + _expert_system_prompt(expert_profile)
        if expert_profile is not None else ""
    )
    if format_profile is not None:
        from floor.formats import prompt_for
        structure = prompt_for(format_profile)
        system = (
            "You are a regulatory breach-notification drafter for a bank's "
            "incident response team. You write tight, examiner-ready filings. You "
            "state only what the supplied fact-record supports, never invent "
            "facts, and you fill the exact mandated fields the form requires. No "
            "markdown headers; plain prose under each field label. "
            + _CITATION_INSTRUCTION + expert
        )
        user = (
            f"Draft the {regime} mandatory incident notification from this "
            f"canonical fact-record. Use ONLY these facts. Keep it under 300 "
            f"words total.\n\n{structure}\n\n"
            f"FACT RECORD (canonical, authoritative):\n"
            f"{json.dumps(fact_record, indent=2)}\n\n"
            f"{_citation_fields_hint(fact_record)}"
        )
        return llm_complete(
            provider, model,
            [{"role": "system", "content": system},
             {"role": "user", "content": user}],
            api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout,
            max_attempts=max_attempts)
    system = (
        "You are a regulatory breach-notification drafter for a bank's incident "
        "response team. You write tight, examiner-ready filings. You state only "
        "what the supplied fact-record supports, never invent facts, and you keep "
        "the structure a regulator expects. No markdown headers, plain prose with "
        "short labelled sections. "
        + _CITATION_INSTRUCTION + expert
    )
    user = (
        f"Draft the {regime} mandatory incident notification (the 72-hour "
        f"notification where applicable) from this canonical fact-record. "
        f"Use ONLY these facts. Keep it under 300 words.\n\n"
        f"FACT RECORD (canonical, authoritative):\n{json.dumps(fact_record, indent=2)}\n\n"
        f"{_citation_fields_hint(fact_record)}"
    )
    return llm_complete(
        provider, model,
        [{"role": "system", "content": system},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout,
        max_attempts=max_attempts)


def draft_characterization(*, regime: str, old_records: int, new_records: int,
                           role: str, counterpart_text: str = "",
                           model: str = DEFAULT_MODEL,
                           provider: str = DEFAULT_PROVIDER,
                           api_key: str | None = None,
                           max_tokens: int = 160, timeout: int = 90,
                           max_attempts: int = 1) -> str:
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
        api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout,
        max_attempts=max_attempts)
    # One clean sentence: collapse whitespace, drop wrapping quotes.
    content = " ".join(content.split())
    if len(content) >= 2 and content[0] in "\"'" and content[-1] in "\"'":
        content = content[1:-1].strip()
    return content
