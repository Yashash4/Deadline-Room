"""Fact-record input provenance: hash and bind the INPUT the run was driven from.

The chain of custody starts at the canonical fact-record (`CANONICAL_FACTS`): the
load-bearing input every drafter, the materiality assessor, and the Challenger
reason from. Yet the signature historically attested only the OUTPUT (the run-log
bytes). Nothing bound the INPUT, so a poisoned field could flow into the prompts
and out into a signed artifact with no part of the seal pointing back at what the
run was actually fed.

This module closes the LEFT half of the provenance spine: a pure, no-LLM digest
over the canonical fact-record, folded into the bound Ed25519 payload alongside the
run-log sha, the chain head, and the deadline-compliance attestation. With it, a
valid signature attests "this exact ordered, complete run, driven from THIS exact
fact-record, met THESE deadlines", which is the full custody statement.

DERIVED, never hashed into the run log. The fact-record hash is computed read-only
from the input dict and folded ONLY into the detached signature; it never becomes a
run-log event, so the run-log sha, the chain head, and byte-identical replay are
untouched.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime

# The typed schema the canonical fact-record must satisfy before it is allowed to
# reach the first prompt. The chain of custody starts at the fact-record, so a
# poisoned or malformed field caught HERE never flows into the drafting prompts and
# never out into a signed artifact. This is the input integrity gate: pure, no LLM,
# deterministic. It rejects rather than repairs, so a bad input fails loud.
#
# Bounds are deliberately generous (a real incident can be small or enormous) but
# finite, so a nonsensical or attacker-chosen value (a negative count, an absurd
# count, a control-envelope token smuggled into a string) is refused.
MAX_RECORDS_AFFECTED = 10_000_000_000  # 10B: larger than any real population.
MAX_STRING_LEN = 512                   # a fact-record field is a label, not prose.
MAX_LIST_LEN = 64                      # systems / data_categories are short lists.

# The required typed fields and the field-level rules they must satisfy. A SIEM
# finding mapped to a fact-record, or a hand-authored one, must carry every
# required field with a well-formed value before any prompt sees it.
REQUIRED_STRING_FIELDS = (
    "incident_id",
    "attacker",
    "containment",
    "regulated_entity",
)

# Control-envelope tokens that must never appear inside a fact-record string: these
# are the claims/protocol fence markers the drafting and protocol layers parse. A
# value carrying one is a prompt-injection attempt (the poisoned-feed attack the
# --inject-claims mode models), so it is quarantined at the door.
_FORBIDDEN_TOKENS = ("[CLAIMS]", "[/CLAIMS]", "[MATERIALITY]", "[TRIGGER]")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class FactRecordError(ValueError):
    """The fact-record is not well-formed: a required field is missing, a value is
    out of its typed range, or a string carries a control-envelope token. Raised so
    a poisoned or malformed input is QUARANTINED before the first prompt rather than
    flowing into a signed artifact. The message names the offending field."""


def _check_plain_string(field: str, value: object) -> str:
    if not isinstance(value, str):
        raise FactRecordError(
            f"fact-record field {field!r} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise FactRecordError(f"fact-record field {field!r} must not be empty")
    if len(value) > MAX_STRING_LEN:
        raise FactRecordError(
            f"fact-record field {field!r} exceeds {MAX_STRING_LEN} chars "
            f"({len(value)})")
    if _CONTROL_CHARS.search(value):
        raise FactRecordError(
            f"fact-record field {field!r} carries a control character")
    upper = value.upper()
    for token in _FORBIDDEN_TOKENS:
        if token in upper:
            raise FactRecordError(
                f"fact-record field {field!r} carries control-envelope token "
                f"{token!r}; quarantined as a possible injection")
    return value


def _check_string_list(field: str, value: object) -> list[str]:
    if not isinstance(value, list):
        raise FactRecordError(
            f"fact-record field {field!r} must be a list of strings, got "
            f"{type(value).__name__}")
    if len(value) > MAX_LIST_LEN:
        raise FactRecordError(
            f"fact-record field {field!r} exceeds {MAX_LIST_LEN} entries "
            f"({len(value)})")
    for i, item in enumerate(value):
        _check_plain_string(f"{field}[{i}]", item)
    return list(value)


def validate_fact_record(fact_record: object) -> dict:
    """Validate a canonical fact-record against the typed schema and return it
    unchanged, or raise FactRecordError naming the first offending field.

    Pure, no LLM, deterministic: the same input always yields the same verdict.
    This is the integrity gate the chain of custody starts at, so a SIEM finding
    mapped to a fact-record (floor/ingest_ocsf.py) and any hand-authored record
    flow through it BEFORE the first drafting prompt. It rejects, never repairs, so
    a malformed or poisoned input fails loud instead of producing signed garbage.

    The validator is additive and does NOT touch the canonical bytes or the
    fact-record hash: a record that passes hashes exactly as it did before this
    gate existed, so the sealed run-log shas and byte-identical replay are
    untouched."""
    if not isinstance(fact_record, dict):
        raise FactRecordError(
            f"fact-record must be a dict, got {type(fact_record).__name__}")

    for field in REQUIRED_STRING_FIELDS:
        if field not in fact_record:
            raise FactRecordError(f"fact-record missing required field {field!r}")
        _check_plain_string(field, fact_record[field])

    if "incident_start_utc" not in fact_record:
        raise FactRecordError("fact-record missing required field 'incident_start_utc'")
    start = fact_record["incident_start_utc"]
    if not isinstance(start, str):
        raise FactRecordError(
            "fact-record field 'incident_start_utc' must be an ISO-8601 string")
    try:
        datetime.fromisoformat(start)
    except ValueError as exc:
        raise FactRecordError(
            f"fact-record field 'incident_start_utc' is not ISO-8601: {start!r}"
        ) from exc

    if "records_affected" not in fact_record:
        raise FactRecordError("fact-record missing required field 'records_affected'")
    records = fact_record["records_affected"]
    # bool is an int subclass; a True/False here is a type error, not a count.
    if isinstance(records, bool) or not isinstance(records, int):
        raise FactRecordError(
            "fact-record field 'records_affected' must be an int, got "
            f"{type(records).__name__}")
    if records < 0:
        raise FactRecordError(
            f"fact-record field 'records_affected' must be non-negative, got {records}")
    if records > MAX_RECORDS_AFFECTED:
        raise FactRecordError(
            f"fact-record field 'records_affected' {records} exceeds the sane "
            f"upper bound {MAX_RECORDS_AFFECTED}")

    # Optional list fields, validated only when present (the canonical record
    # carries them; a minimal mapped finding may not).
    for field in ("systems", "data_categories"):
        if field in fact_record:
            _check_string_list(field, fact_record[field])

    return fact_record


def canonical_fact_record_bytes(fact_record: dict) -> bytes:
    """The fact-record serialized to canonical JSON bytes.

    Uses the SAME canonicalization recipe as the run log and the bound signing
    payload (`json.dumps(..., sort_keys=True, separators=(",",":"))`), so the same
    input always produces the same bytes and the same hash. Sorted keys make the
    digest independent of the dict's insertion order, so the hash attests the
    CONTENT of the fact-record, not the order it happened to be built in."""
    return json.dumps(fact_record, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def fact_record_hash(fact_record: dict) -> str:
    """The sha256 over the canonical fact-record bytes. This is the input digest
    folded into the bound Ed25519 payload, so a changed input field moves it and
    breaks the signature: the seal now attests the INPUT, not just the output."""
    return hashlib.sha256(canonical_fact_record_bytes(fact_record)).hexdigest()
