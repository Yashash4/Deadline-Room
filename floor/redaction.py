"""PII redaction for the PUBLISHED Examiner Packet (E9.5).

The packet is published twice over: to a shared Band room and to a hosted web
URL. The canonical fact-record it carries holds PII-class detail (the categories
of personal data that leaked, the internal systems that were touched) that a
breach victim should not have to also publish to the open web to prove the room
worked. This module masks those PII-class field values in the PUBLISHED packet
while keeping every load-bearing statutory fact verbatim, so a regulator still
reads the real numbers and a casual web reader never sees the personal-data
categories.

Two hard properties:

  1. RENDER / PUBLISH layer ONLY. This is a pure function over a packet dict. It
     is applied at packet-render time and at capture-write time, NEVER folded
     into the hashed run-log. The run-log sha, the chain head, and byte-identical
     replay are untouched. The [CLAIMS] block the Warden actually gated on lives
     inside the filing prose, which this pass never edits, so the gated facts and
     the statutory facts stay byte-for-byte verbatim.

  2. STATUTORY FACTS STAY VERBATIM. Only the fields in PII_FACT_FIELDS are
     masked. The load-bearing facts a regulator needs (incident_start_utc,
     records_affected, attacker, containment, incident_id) and the filing
     identity (regulated_entity, competent_authority) are kept exactly. A
     redaction receipt records how many fields were masked, so the masking is
     auditable rather than silent.

The pass is deterministic (no now(), no randomness): the same packet always
redacts to the same bytes, so the published packet stays replay-stable.
"""

from __future__ import annotations

import copy

# The PII-class fact-record fields whose VALUES are masked in the published
# packet. These name the categories of personal data that leaked and the
# internal systems touched: detail a regulator receives in the filing itself but
# that does not belong in a packet published to the open web. Everything NOT in
# this set (the statutory facts and the filing identity) is kept verbatim.
PII_FACT_FIELDS = frozenset(
    {
        "data_categories",
        "systems",
    }
)

# The placeholder a masked scalar field carries in the published packet. Chosen
# to read as an explicit redaction, never as a missing or empty value.
REDACTION_MASK = "[REDACTED FOR PUBLICATION]"


def _mask_value(value):
    """Mask one PII field value, preserving its SHAPE so the published packet
    still reads as structured data.

    A list keeps its length (the count of leaked data categories or touched
    systems is not itself PII and is load-bearing for an examiner), with each
    element masked. A scalar becomes the single mask string. The shape is
    preserved so a reader sees "three data categories, each redacted", not a
    bare string where a list was."""
    if isinstance(value, list):
        return [REDACTION_MASK for _ in value]
    if isinstance(value, dict):
        return {k: REDACTION_MASK for k in value}
    return REDACTION_MASK


def redact_fact_record(fact_record: dict) -> tuple[dict, list[str]]:
    """Return a deep-copied fact-record with PII-class field VALUES masked, plus
    the sorted list of field names that were actually masked.

    Pure: the input dict is never mutated. A field listed in PII_FACT_FIELDS is
    masked only if it is actually present, so the redacted-field list reflects
    what THIS record carried, not the catalogue. Every other field, including the
    statutory facts and the filing identity, is copied through verbatim."""
    redacted = copy.deepcopy(fact_record)
    masked: list[str] = []
    for field in fact_record:
        if field in PII_FACT_FIELDS:
            redacted[field] = _mask_value(fact_record[field])
            masked.append(field)
    return redacted, sorted(masked)


def redaction_receipt(masked_fields: list[str]) -> dict:
    """Build the publication-redaction receipt for the published packet.

    The receipt states how many fact-record fields were masked, names them, and
    affirms that the load-bearing statutory facts were kept verbatim. It is the
    auditable record that the masking happened and exactly which fields it
    touched: a reader of the published packet sees "N fields redacted for
    publication" and the named fields, never a silent edit."""
    count = len(masked_fields)
    return {
        "redacted_field_count": count,
        "redacted_fields": list(masked_fields),
        "mask": REDACTION_MASK,
        "summary": f"{count} fields redacted for publication",
        "note": (
            "PII-class fact-record field values were masked for publication. The "
            "statutory facts (incident_start_utc, records_affected, attacker, "
            "containment) and the [CLAIMS] block the Warden gated on are kept "
            "verbatim. Redaction is applied at publish time only and is never part "
            "of the hashed run-log, so the run-log sha and byte-identical replay "
            "are unchanged."
        ),
    }


def redact_packet_for_publication(packet: dict) -> dict:
    """Return a deep-copied packet whose published view masks PII-class
    fact-record field values and carries a redaction receipt.

    The ONLY mutation versus the input packet is on packet["incident"]
    ["fact_record"] (PII values masked) plus an additive packet["redaction"]
    receipt. The filings (and the [CLAIMS] block inside them), the diff, the
    clocks, the replay hash, and every other section are copied through verbatim.

    Pure and additive: the input packet is never mutated, the replay hash is
    never touched, and nothing here ever reaches the hashed run-log. A packet with
    no incident.fact_record is returned with an empty (zero-field) receipt so the
    receipt is always present and honest."""
    published = copy.deepcopy(packet)
    incident = published.get("incident")
    fact_record = incident.get("fact_record") if isinstance(incident, dict) else None
    if isinstance(fact_record, dict):
        redacted, masked_fields = redact_fact_record(fact_record)
        incident["fact_record"] = redacted
    else:
        masked_fields = []
    published["redaction"] = redaction_receipt(masked_fields)
    return published
