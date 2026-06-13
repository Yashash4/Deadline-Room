"""Serialize and parse the NegotiationEnvelope across a live Band message.

The amendment beat is the one place a drafter reads and answers another drafter.
The reconciliation envelope (warden/negotiation.py) is carried inside the Band
message body as a fenced block, exactly like the [CLAIMS] block: fenced so it
survives Band's @mention markers and any prose around it. The Warden parses the
block (pure string work, no LLM) and feeds it to the deterministic
NegotiationGuard, so the gate stays no-LLM and replayable.

The drafter's LLM writes only the characterization prose (how to phrase the
revised number for the regulator). The structured envelope (figure, verdict,
bounds, hash link) is attached by the drafter process, never formatted by the
model, so the value the Warden gates on is deterministic.

Block shape:

    [RECONCILE]
    correlation_id=inc-8842:sec
    amend_round=1
    from_agent=sec_drafter
    to_agent=nis2_drafter
    fact_key=records_affected
    proposed_value=2100000
    characterization=approximately 2.1 million records
    data_category_bounds=name|address|account_number
    containment_framing=contained as of 2026-06-16T07:00:00+00:00
    verdict=propose
    ts_utc=2026-06-16T08:14:00+00:00
    prior_envelope_hash=
    [/RECONCILE]
"""

from __future__ import annotations

import re

from warden.negotiation import NegotiationEnvelope, Verdict

_BLOCK = re.compile(r"\[RECONCILE\](.*?)\[/RECONCILE\]", re.DOTALL)
_LIST_SEP = "|"


def emit_envelope(env: NegotiationEnvelope) -> str:
    """Render the fenced reconciliation block from a NegotiationEnvelope."""
    bounds = _LIST_SEP.join(env.data_category_bounds)
    prior = env.prior_envelope_hash or ""
    lines = [
        "[RECONCILE]",
        f"correlation_id={env.correlation_id}",
        f"amend_round={env.amend_round}",
        f"from_agent={env.from_agent}",
        f"to_agent={env.to_agent}",
        f"fact_key={env.fact_key}",
        f"proposed_value={env.proposed_value}",
        f"characterization={env.characterization}",
        f"data_category_bounds={bounds}",
        f"containment_framing={env.containment_framing}",
        f"verdict={env.verdict.value}",
        f"ts_utc={env.ts_utc}",
        f"prior_envelope_hash={prior}",
        "[/RECONCILE]",
    ]
    return "\n".join(lines)


def parse_envelope(text: str) -> NegotiationEnvelope:
    """Parse a fenced [RECONCILE] block out of a posted message.

    Raises ValueError if the block is missing or malformed. The Warden owns this
    parse: deterministic string work, zero LLM. proposed_value is parsed as an
    int (records_affected is an integer fact); extend here if other fact keys
    ever carry non-integer values.
    """
    m = _BLOCK.search(text or "")
    if not m:
        raise ValueError("no [RECONCILE] block in message")
    fields: dict[str, str] = {}
    for raw in m.group(1).strip().splitlines():
        raw = raw.strip()
        if not raw or "=" not in raw:
            continue
        key, _, value = raw.partition("=")
        fields[key.strip()] = value.strip()

    required = ("correlation_id", "amend_round", "from_agent", "to_agent",
                "fact_key", "proposed_value", "characterization",
                "containment_framing", "verdict", "ts_utc")
    for r in required:
        if r not in fields:
            raise ValueError(f"reconcile block missing {r}")

    try:
        amend_round = int(fields["amend_round"])
    except ValueError as e:
        raise ValueError(f"reconcile block bad amend_round: {fields['amend_round']}") from e
    try:
        proposed_value: object = int(fields["proposed_value"])
    except ValueError as e:
        raise ValueError(f"reconcile block bad proposed_value: {fields['proposed_value']}") from e
    try:
        verdict = Verdict(fields["verdict"])
    except ValueError as e:
        raise ValueError(f"reconcile block bad verdict: {fields['verdict']}") from e

    bounds_raw = fields.get("data_category_bounds", "")
    bounds = tuple(b for b in bounds_raw.split(_LIST_SEP) if b) if bounds_raw else ()
    prior = fields.get("prior_envelope_hash", "") or None

    return NegotiationEnvelope(
        correlation_id=fields["correlation_id"],
        amend_round=amend_round,
        from_agent=fields["from_agent"],
        to_agent=fields["to_agent"],
        fact_key=fields["fact_key"],
        proposed_value=proposed_value,
        characterization=fields["characterization"],
        data_category_bounds=bounds,
        containment_framing=fields["containment_framing"],
        verdict=verdict,
        ts_utc=fields["ts_utc"],
        prior_envelope_hash=prior,
    )
