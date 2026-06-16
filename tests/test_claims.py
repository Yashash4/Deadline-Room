"""test_claims.py -- the structured fact-claims envelope the drafters emit and the
Warden parses. This is the seam that makes the contradiction diff deterministic:
the Warden reads a fenced block, not an LLM essay. These tests pin the parse,
including malformed input, so a garbled draft fails loudly rather than silently
agreeing."""

import pytest

from floor.claims import ClaimsInjectionError, emit_claims, parse_claims
from warden.diff import Containment, diff_claims


CANON = {
    "incident_start_utc": "2026-06-16T02:14:00+00:00",
    "records_affected": 48211,
    "attacker": "LockBit 3.0",
    "containment": "partially_contained",
}


def test_emit_then_parse_round_trips():
    block = emit_claims("nis2", CANON)
    claims = parse_claims("some prose\n\n" + block + "\n\ntrailing")
    assert claims.branch == "nis2"
    assert claims.records_affected == 48211
    assert claims.attacker == "LockBit 3.0"
    assert claims.containment is Containment.PARTIALLY_CONTAINED
    assert claims.canonical()["incident_start_utc"] == "2026-06-16T02:14:00+00:00"


def test_parse_survives_band_mention_markers_around_block():
    block = emit_claims("sec", CANON)
    wrapped = f"@[[2a495c04-bc1e-429d-8a73-a75f827e55b6]] {block}"
    claims = parse_claims(wrapped)
    assert claims.branch == "sec"


def test_missing_block_raises():
    with pytest.raises(ValueError):
        parse_claims("just prose, no claims block at all")


def test_bad_records_raises():
    bad = ("[CLAIMS]\nbranch=nis2\nincident_start_utc=2026-06-16T02:14:00+00:00\n"
           "records_affected=not_a_number\nattacker=LockBit\n"
           "containment=partially_contained\n[/CLAIMS]")
    with pytest.raises(ValueError):
        parse_claims(bad)


def test_bad_containment_raises():
    bad = ("[CLAIMS]\nbranch=nis2\nincident_start_utc=2026-06-16T02:14:00+00:00\n"
           "records_affected=10\nattacker=LockBit\ncontainment=fully_gone\n[/CLAIMS]")
    with pytest.raises(ValueError):
        parse_claims(bad)


def test_two_blocks_raise_injection_error():
    # The historic gate-bypass: a model-emitted [CLAIMS] block AHEAD of the
    # drafter's authoritative one. A first-match parser would gate on the
    # attacker's values. parse_claims now refuses to guess: two blocks is an
    # injection signature, not an ambiguity.
    attacker = emit_claims("sec", dict(CANON, records_affected=1, attacker="none"))
    authoritative = emit_claims("sec", CANON)
    poisoned = "prose\n\n" + attacker + "\n\nmore prose\n\n" + authoritative
    with pytest.raises(ClaimsInjectionError):
        parse_claims(poisoned)


def test_injection_error_is_a_value_error():
    # Subclassing ValueError keeps existing callers that catch ValueError working.
    assert issubclass(ClaimsInjectionError, ValueError)
    two = emit_claims("nis2", CANON) + "\n" + emit_claims("nis2", CANON)
    with pytest.raises(ValueError):
        parse_claims(two)


def test_single_block_still_parses_after_guard():
    # The guard must not regress the normal one-block path.
    claims = parse_claims("prose\n\n" + emit_claims("dora", CANON))
    assert claims.branch == "dora"
    assert claims.records_affected == 48211


def test_two_agreeing_claims_diff_green():
    a = parse_claims(emit_claims("nis2", CANON))
    b = parse_claims(emit_claims("sec", CANON))
    assert diff_claims([a, b]) == []


def test_two_disagreeing_claims_diff_red():
    perturbed = dict(CANON, incident_start_utc="2026-06-16T02:41:00+00:00")
    a = parse_claims(emit_claims("nis2", CANON))
    b = parse_claims(emit_claims("sec", perturbed))
    conflicts = diff_claims([a, b])
    assert len(conflicts) == 1
    assert conflicts[0].field == "incident_start_utc"
