"""Build the reasonable-basis determination record for a file/suppress call.

The materiality role (floor/materiality.py) and the per-regime reportability role
(floor/reportability.py) each return a typed boolean verdict. That boolean is the
load-bearing decision the Warden gates on; it is NOT changed here. This module
builds the contemporaneous, structured record that documents WHY the verdict was
reached: the named legal standard, and a factor table where each factor the
standard weighs is bound to the EXACT canonical fact-record field it rests on.

The factor->fact BINDING and the record SHAPE are deterministic Python: the
factor set a standard weighs (records affected, systems, regulated data
categories, containment, attacker) is fixed, and each factor reads its value
straight off the fact-record field it cites. The LLM may supply the per-factor
RATIONALE prose (passed in as `rationale_by_field`), but the binding never depends
on the model: a factor is grounded because its `fact_field` is a real key in the
record, checked by the pure warden/determination.py validator, not because a model
said so. So the qualitative judgment (material / reportable) stays the LLM's, the
basis prose may be the LLM's, and the structured, validatable record is the
Warden's, hash-chained and signed like every other event.

Nothing here gates. The disposition is copied verbatim from the verdict the
deterministic gate already consumed.
"""

from __future__ import annotations

from warden.determination import DeterminationFactor, DeterminationRecord

# The factor table a breach-reportability / materiality standard weighs, each
# factor bound to the EXACT canonical fact-record field it rests on. This is the
# deterministic spine: a (factor name, fact_field, qualitative) triple per factor.
# Every standard in the catalog weighs quantitative scale (records, systems) and
# qualitative factors (regulated data categories, containment, the named threat
# actor); the standard string differs per regime, the weighed factors do not, so
# one table grounds every determination in the same load-bearing inputs. The order
# is fixed so the record is byte-stable across runs.
_FACTOR_SPINE: tuple[tuple[str, str, bool], ...] = (
    ("Quantitative scale: records affected", "records_affected", False),
    ("Quantitative scale: systems involved", "systems", False),
    ("Qualitative factor: regulated data categories", "data_categories", True),
    ("Qualitative factor: containment status", "containment", True),
    ("Qualitative factor: named threat actor", "attacker", True),
)


def _render_value(value: object) -> str:
    """Render a fact-record value as a stable string for the record. A list is
    joined on ', ' so a systems / data-categories factor reads cleanly; everything
    else is str()'d. Deterministic: same value, same rendering, always."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def build_determination_record(*, branch: str, regime: str, standard: str,
                               disposition: str, fact_record: dict,
                               source: str = "",
                               rationale_by_field: dict[str, str] | None = None
                               ) -> DeterminationRecord:
    """Build the typed determination record from a verdict's standard +
    disposition and the fact-record the verdict was reached against.

    `standard` is the named legal standard (from the regime catalog, e.g. the SEC
    Item 1.05 materiality standard or the NIS2 Art 23 significant-impact standard).
    `disposition` is the typed outcome the deterministic gate already produced
    ("file" or "suppress"); it is copied verbatim, never recomputed here.
    `fact_record` is the canonical fact-record; each factor reads its value off the
    field it binds to. A factor whose field is ABSENT from the record is still
    emitted with its binding intact (value rendered empty), so the pure validator
    flags it as a missing factor rather than the binding being silently dropped:
    the record must always show what it claims to weigh.

    `rationale_by_field` optionally carries the LLM's per-factor basis prose keyed
    by the bound fact_field; it is attached to the factor for the packet and is
    never validated or gated on. Pure and deterministic: same inputs, same
    record."""
    rationale_by_field = rationale_by_field or {}
    factors: list[DeterminationFactor] = []
    for name, fact_field, qualitative in _FACTOR_SPINE:
        present = fact_field in fact_record
        value = _render_value(fact_record.get(fact_field, "")) if present else ""
        factors.append(DeterminationFactor(
            name=name,
            value=value,
            fact_field=fact_field,
            rationale=rationale_by_field.get(fact_field, ""),
            qualitative=qualitative,
        ))
    return DeterminationRecord(
        branch=branch,
        regime=regime,
        standard=standard,
        disposition=disposition,
        factors=tuple(factors),
        source=source,
    )
