"""Reasonable-basis determination record: the typed, validatable artifact that
documents WHY a file/suppress determination was made.

Every breach-notification regime turns on a JUDGMENT made under time pressure:
SEC Item 1.05 materiality, NIS2 Article 23 significant impact, DORA major-incident
classification, GDPR / UK ICO Article 33 risk to the rights and freedoms of
natural persons, NYDFS 23 NYCRR 500.17 material harm. When a regulator or a
plaintiff later challenges a non-filing (or a late filing), the dispositive
question is whether the entity had a documented, contemporaneous, REASONABLE
BASIS at the moment it decided. The boolean verdict is worthless in litigation;
the DEFENSIBILITY of how it was reached is everything. "We asked a model" is not a
reasonable basis. "Here is the factor table the determination weighed, each factor
tied to a fact-record field, frozen and signed at determination time" is.

This module is the deterministic Warden side. It owns:

  * the typed record shape: a named legal `standard`, the `disposition`
    (file / suppress), and a list of weighed `DeterminationFactor`s, each naming
    the factor, its value, and the EXACT canonical fact-record FIELD it rests on
    (so no factor is free-text; every factor is grounded in a load-bearing input);
  * a PURE validator (`validate_determination`) that checks every cited field
    EXISTS in the fact-record, exactly like the grounding citation validator
    (floor/grounding.py::validate_citations). It is a SCORER / RECORDER, never a
    gate: nothing here blocks a filing, moves a transition, stops a clock, or
    releases. The file/suppress decision stays the typed boolean from the
    materiality / reportability verdict; this record documents and validates the
    basis for that decision, it does not make it.

No LLM call happens here. The per-factor RATIONALE prose may be supplied by the
drafting model upstream (floor/determination.py), but the factor->fact binding,
the record shape, and this validation are deterministic Python, so the record is
hash-chained, replayed, and signed byte-identically like every other run-log
event.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeterminationFactor:
    """One factor the legal standard weighs, bound to a load-bearing fact.

    `name` is the factor the standard names (e.g. "Quantitative scale: records
    affected"). `value` is the factor's value rendered as a string for the record
    (e.g. "48211"). `fact_field` is the EXACT canonical fact-record key the factor
    rests on (e.g. "records_affected"): the binding that makes the factor grounded
    rather than free-text. `rationale` is the optional per-factor basis prose; the
    drafting model may supply it, but it is never gated on and never validated as a
    fact. `qualitative` flags a qualitative factor (containment, regulated data,
    reputational exposure) versus a quantitative one (records, systems count)."""
    name: str
    value: str
    fact_field: str
    rationale: str = ""
    qualitative: bool = False

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "fact_field": self.fact_field,
            "rationale": self.rationale,
            "qualitative": self.qualitative,
        }


@dataclass(frozen=True)
class DeterminationRecord:
    """The contemporaneous reasonable-basis record for one file/suppress call.

    `branch` / `regime` identify the determination. `standard` is the named legal
    standard applied (SEC Item 1.05 materiality, NIS2 Art 23 significant impact,
    etc.). `disposition` is the typed outcome ("file" or "suppress"), carried over
    verbatim from the materiality / reportability verdict that DECIDED it: this
    record documents the basis, it does not re-decide. `factors` is the ordered
    factor table, each factor bound to a canonical fact-record field. `source`
    records who produced the verdict (the LLM model id or a fixture tag) for the
    audit trail."""
    branch: str
    regime: str
    standard: str
    disposition: str
    factors: tuple[DeterminationFactor, ...]
    source: str = ""

    def cited_fields(self) -> list[str]:
        """The canonical fact-record fields every factor binds to, in order."""
        return [f.fact_field for f in self.factors]

    def as_dict(self) -> dict:
        return {
            "branch": self.branch,
            "regime": self.regime,
            "standard": self.standard,
            "disposition": self.disposition,
            "source": self.source,
            "factors": [f.as_dict() for f in self.factors],
        }


@dataclass(frozen=True)
class ReasonableBasis:
    """The validation verdict over a determination record.

    `complete` is True iff every factor binds to a field the fact-record actually
    carries (no fabricated factor). `missing_factors` lists, in order, the
    (factor name, cited field) pairs whose cited field does not exist in the
    fact-record. This is a RECORDER's verdict, never a gate: a record with a
    missing field is flagged in the packet, it does not block or release
    anything."""
    branch: str
    complete: bool
    cited_fields: tuple[str, ...]
    missing_factors: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict:
        return {
            "branch": self.branch,
            "complete": self.complete,
            "cited_fields": list(self.cited_fields),
            "missing_factors": [
                {"factor": name, "fact_field": fieldname}
                for name, fieldname in self.missing_factors
            ],
        }


def validate_determination(record: DeterminationRecord,
                           fact_record: dict) -> ReasonableBasis:
    """Pure validator: does every factor in the record cite a field the
    fact-record actually carries?

    Deterministic and side-effect free, exactly like
    floor/grounding.validate_citations: same (record, fact_record) always yields
    the same ReasonableBasis. It is a SCORER / RECORDER only. Nothing here gates,
    blocks a filing, moves a transition, stops a clock, or releases: it reads a
    record that was already produced and reports whether each factor is grounded
    in a real input. A factor whose cited fact_field is absent from the
    fact-record is a fabricated factor and is reported in `missing_factors`; it is
    never silently dropped and it never changes the file/suppress decision."""
    keys = set(fact_record.keys())
    cited: list[str] = []
    missing: list[tuple[str, str]] = []
    for factor in record.factors:
        cited.append(factor.fact_field)
        if factor.fact_field not in keys:
            missing.append((factor.name, factor.fact_field))
    return ReasonableBasis(
        branch=record.branch,
        complete=not missing,
        cited_fields=tuple(cited),
        missing_factors=tuple(missing),
    )
