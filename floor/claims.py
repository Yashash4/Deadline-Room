"""Structured fact-claims envelope carried alongside a drafter's prose.

Every drafter posts its regulatory filing as human prose PLUS a machine-parsable
claims block. The Warden parses the block (pure string work, no LLM) and feeds
the values into warden/diff.py so the cross-filing contradiction diff is a
checkable deterministic condition, not an LLM reading two essays.

The block is fenced so it survives Band's @mention markers and arbitrary prose
around it:

    [CLAIMS]
    branch=sec
    incident_start_utc=2026-06-16T02:14:00+00:00
    records_affected=48211
    attacker=LockBit 3.0
    containment=partially_contained
    [/CLAIMS]

The drafter process draws these values from the canonical fact-record it was
handed (optionally perturbed in --inject-contradiction demo mode), so the claims
are load-bearing facts, not LLM mood. The LLM writes only the prose body.
"""

from __future__ import annotations

import re

from warden.diff import Containment, FactClaims

_BLOCK = re.compile(r"\[CLAIMS\](.*?)\[/CLAIMS\]", re.DOTALL)

# The load-bearing fact fields a filing must agree on. Keep in lockstep with
# warden/diff.py FactClaims.
CLAIM_FIELDS = ("incident_start_utc", "records_affected", "attacker", "containment")


def emit_claims(branch: str, facts: dict) -> str:
    """Render the fenced claims block from a fact dict. The drafter appends this
    to its prose so the Warden can diff it deterministically."""
    lines = [
        "[CLAIMS]",
        f"branch={branch}",
        f"incident_start_utc={facts['incident_start_utc']}",
        f"records_affected={facts['records_affected']}",
        f"attacker={facts['attacker']}",
        f"containment={facts['containment']}",
        "[/CLAIMS]",
    ]
    return "\n".join(lines)


def parse_claims(text: str) -> FactClaims:
    """Parse a fenced claims block out of a posted message into a FactClaims.

    Raises ValueError if the block is missing or malformed. The Warden owns this
    parse; it is deterministic string work with zero LLM involvement.
    """
    m = _BLOCK.search(text or "")
    if not m:
        raise ValueError("no [CLAIMS] block in message")
    fields: dict[str, str] = {}
    for raw in m.group(1).strip().splitlines():
        raw = raw.strip()
        if not raw or "=" not in raw:
            continue
        key, _, value = raw.partition("=")
        fields[key.strip()] = value.strip()

    branch = fields.get("branch", "")
    if not branch:
        raise ValueError("claims block missing branch")
    try:
        containment = Containment(fields["containment"])
    except (KeyError, ValueError) as e:
        raise ValueError(f"claims block bad containment: {fields.get('containment')}") from e
    try:
        records = int(fields["records_affected"])
    except (KeyError, ValueError) as e:
        raise ValueError(f"claims block bad records_affected: {fields.get('records_affected')}") from e
    if "incident_start_utc" not in fields:
        raise ValueError("claims block missing incident_start_utc")
    if "attacker" not in fields:
        raise ValueError("claims block missing attacker")

    return FactClaims(
        branch=branch,
        incident_start_ts=fields["incident_start_utc"],
        records_affected=records,
        attacker=fields["attacker"],
        containment=containment,
    )
