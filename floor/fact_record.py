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
