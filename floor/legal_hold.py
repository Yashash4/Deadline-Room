"""Build the legal-hold / preservation obligation record at incident detection.

When the room convenes (an incident is detected at INCIDENT_T0), a
litigation-hold / preservation duty attaches by rule: preserve the relevant
evidence, suspend routine deletion over the affected systems and data. This
module builds the typed LegalHold record whose preservation SCOPE is bound to the
EXACT canonical fact-record fields that name what was affected (the systems and
the data categories), exactly like the determination record binds each factor to
the field it rests on (floor/determination.py).

The scope BINDING and the record SHAPE are deterministic Python: the preservation
scope a breach hold covers is fixed (the affected systems, the affected data
categories), and each scope item reads its value straight off the canonical
fact-record field it cites. No LLM is involved at any point: the hold attaches by
rule at incident detection, and it is released only by an explicit human signoff
(warden/legal_hold.py::LegalHold.released_hold), never by a model and never by a
rule. So the obligation is raised deterministically, scoped from real facts, and
the structured, validatable record is the Warden's, hash-chained and signed like
every other event.

Nothing here gates. The hold is a PARALLEL preservation obligation; it never gates
a filing, stops a statutory clock, or moves a state-machine transition.
"""

from __future__ import annotations

from warden.legal_hold import (
    PRESERVATION_BASIS, LegalHold, PreservationScopeItem)

# The preservation scope a breach legal hold covers, each item bound to the EXACT
# canonical fact-record field it rests on. This is the deterministic spine: a
# (category, fact_field) pair per scope item. A breach hold preserves the affected
# SYSTEMS (where the breach happened) and the affected DATA categories (what was
# exposed); those two fields ARE the preservation scope, read off the canonical
# record. The order is fixed so the record is byte-stable across runs.
_SCOPE_SPINE: tuple[tuple[str, str], ...] = (
    ("Affected systems (preserve in place, suspend routine deletion)", "systems"),
    ("Affected data categories (preserve, suspend routine deletion)",
     "data_categories"),
)


def _render_value(value: object) -> str:
    """Render a fact-record value as a stable string for the scope item. A list is
    joined on ', ' so a systems / data-categories scope reads cleanly; everything
    else is str()'d. Deterministic: same value, same rendering, always."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def build_legal_hold(*, incident_id: str, attached_at: str, fact_record: dict,
                     trigger_event: str = "incident detection") -> LegalHold:
    """Build the typed legal-hold record that attaches at incident detection.

    `attached_at` is the incident-detection timestamp the hold anchors on
    (INCIDENT_T0): the hold runs from detection. `fact_record` is the canonical
    fact-record; each scope item reads its value off the affected-systems /
    affected-data-categories field it binds to. A scope item whose field is ABSENT
    from the record is still emitted with its binding intact (value rendered
    empty), so the pure validator flags it as a missing item rather than the
    binding being silently dropped: the record must always show what it claims to
    preserve.

    The returned hold is ACTIVE (no release record): it stays active until a human
    explicitly releases it via LegalHold.released_hold. Pure and deterministic:
    same inputs, same record."""
    scope: list[PreservationScopeItem] = []
    for category, fact_field in _SCOPE_SPINE:
        present = fact_field in fact_record
        value = _render_value(fact_record.get(fact_field, "")) if present else ""
        scope.append(PreservationScopeItem(
            category=category, value=value, fact_field=fact_field))
    return LegalHold(
        incident_id=incident_id,
        trigger_event=trigger_event,
        attached_at=attached_at,
        scope=tuple(scope),
        basis=PRESERVATION_BASIS,
    )
