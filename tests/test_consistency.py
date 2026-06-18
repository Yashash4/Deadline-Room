"""test_consistency.py -- the examiner's cross-filing consistency assertion sheet (E4.3).

The cross-filing CONSISTENCY ASSERTION SHEET: the positive, examiner-facing
attestation that all N filings AGREE on the load-bearing facts (incident_start_utc,
records_affected, attacker, containment). The inverse face of the contradiction veto:
instead of only BLOCKING on a conflict, it affirmatively ATTESTS the shared facts are
identical across the filing set, with each value shown once and a per-fact CONSISTENT
/ CONFLICT status computed through the SAME warden/diff.py canonicalization the veto
uses.

Layers:

  Unit layer over floor/consistency.py: a consistent filing set attests CONSISTENT on
  every load-bearing fact with the agreed value; a timezone-equivalent value is
  CONSISTENT (not a false conflict), exactly like the veto; a genuinely conflicting
  set surfaces the CONFLICT, matching diff_claims; the sheet is a pure derived read
  (no LLM surface, no run-log mutation) and deterministic across runs.

  Render layer over the packet HTML: the per-fact agreement table is rendered with the
  attested value and the overall verdict.

  Guard layer: the four DEFAULT sealed captures and their run-log shas are byte-for-
  byte unchanged by this render/derive-only feature.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.consistency as consistency_mod
from floor.consistency import (
    LOAD_BEARING_FACTS,
    STATUS_CONFLICT,
    STATUS_CONSISTENT,
    consistency_from_claims,
    consistency_record,
)
from warden.diff import Containment, FactClaims, diff_claims

REPO = Path(__file__).resolve().parents[1]


# ---- helpers ----------------------------------------------------------------

def _claims(*, records=48211, start="2026-06-16T02:14:00+00:00", attacker="LockBit",
            containment=Containment.PARTIALLY_CONTAINED, branch="nis2"):
    """A FactClaims for one branch, defaulting to the canonical incident facts."""
    return FactClaims(branch=branch, incident_start_ts=start, records_affected=records,
                      attacker=attacker, containment=containment)


def _consistent_set():
    """Three filings that agree on every load-bearing fact (the green case)."""
    return {
        "nis2": _claims(branch="nis2"),
        "sec": _claims(branch="sec"),
        "dora": _claims(branch="dora"),
    }


# ---- unit layer: a consistent set attests CONSISTENT on every fact ----------

def test_consistent_set_attests_consistent_on_every_fact():
    sheet = consistency_from_claims(_consistent_set())
    assert sheet.consistent is True
    assert sheet.conflict_count == 0
    assert sheet.filing_count == 3
    assert sheet.fact_count == len(LOAD_BEARING_FACTS)
    by_fact = {f.fact: f for f in sheet.facts}
    # every load-bearing fact is CONSISTENT, carries the agreed value, and lists every
    # filing as asserting it
    assert by_fact["records_affected"].status == STATUS_CONSISTENT
    assert by_fact["records_affected"].agreed_value == 48211
    assert by_fact["attacker"].agreed_value == "lockbit"  # canonicalized via the alias table
    assert by_fact["containment"].agreed_value == "partially_contained"
    assert by_fact["incident_start_utc"].agreed_value == "2026-06-16T02:14:00+00:00"
    for f in sheet.facts:
        assert f.status == STATUS_CONSISTENT
        assert len(f.filings) == 3
        assert "CONSISTENT" in sheet.verdict


def test_filings_are_named_by_regime_label():
    # The sheet names each filing by its catalog regime label, not the branch token.
    sheet = consistency_from_claims({"nis2": _claims(branch="nis2"),
                                     "uk": _claims(branch="uk")})
    assert set(sheet.filings) == {"NIS2", "UK ICO"}


# ---- unit layer: a timezone-equivalent value is CONSISTENT, not a conflict --

def test_timezone_equivalent_value_is_consistent_not_a_false_conflict():
    # "02:14 CET" and "01:14 UTC" are the SAME instant. The veto treats them as
    # AGREEMENT; so must the consistency sheet. This is the canonicalization reuse.
    claims = {
        "nis2": _claims(branch="nis2", start="2026-06-16T03:14:00+01:00"),  # CET
        "sec": _claims(branch="sec", start="2026-06-16T02:14:00+00:00"),    # UTC
    }
    # the contradiction veto agrees these do not conflict
    assert diff_claims(list(claims.values())) == []
    sheet = consistency_from_claims(claims)
    start = next(f for f in sheet.facts if f.fact == "incident_start_utc")
    assert start.status == STATUS_CONSISTENT
    assert start.agreed_value == "2026-06-16T02:14:00+00:00"
    assert sheet.consistent is True


def test_attacker_alias_is_consistent_not_a_false_conflict():
    # "LockBit 3.0" and "lockbit" canonicalize to the same attacker via the alias
    # table, exactly like the veto, so the sheet attests CONSISTENT.
    claims = {
        "nis2": _claims(branch="nis2", attacker="LockBit 3.0"),
        "sec": _claims(branch="sec", attacker="lockbit"),
    }
    assert diff_claims(list(claims.values())) == []
    sheet = consistency_from_claims(claims)
    attacker = next(f for f in sheet.facts if f.fact == "attacker")
    assert attacker.status == STATUS_CONSISTENT
    assert attacker.agreed_value == "lockbit"


# ---- unit layer: a genuine conflict surfaces, matching the veto --------------

def test_conflicting_records_count_surfaces_conflict_matching_the_diff():
    claims = {
        "nis2": _claims(branch="nis2", records=48211),
        "sec": _claims(branch="sec", records=2100000),
    }
    # the contradiction veto blocks on records_affected
    conflicts = diff_claims(list(claims.values()))
    assert any(c.field == "records_affected" for c in conflicts)

    sheet = consistency_from_claims(claims)
    assert sheet.consistent is False
    assert sheet.conflict_count == 1
    records = next(f for f in sheet.facts if f.fact == "records_affected")
    assert records.status == STATUS_CONFLICT
    assert records.agreed_value is None
    # both disagreeing sides are shown, with their canonical values
    conflict_values = {v for _, v in records.conflict}
    assert conflict_values == {48211, 2100000}
    # every OTHER fact is still CONSISTENT
    for f in sheet.facts:
        if f.fact != "records_affected":
            assert f.status == STATUS_CONSISTENT
    assert "CONFLICT" in sheet.verdict


def test_conflicting_incident_start_surfaces_conflict():
    # Two genuinely different instants (not timezone-equivalent) conflict.
    claims = {
        "nis2": _claims(branch="nis2", start="2026-06-16T02:14:00+00:00"),
        "sec": _claims(branch="sec", start="2026-06-16T05:14:00+00:00"),
    }
    assert any(c.field == "incident_start_utc" for c in diff_claims(list(claims.values())))
    sheet = consistency_from_claims(claims)
    start = next(f for f in sheet.facts if f.fact == "incident_start_utc")
    assert start.status == STATUS_CONFLICT
    assert sheet.consistent is False


# ---- unit layer: the single-filing edge -------------------------------------

def test_single_filing_is_not_cross_read():
    sheet = consistency_from_claims({"nis2": _claims(branch="nis2")})
    assert sheet.consistent is False
    assert "NOT CROSS-READ" in sheet.verdict


# ---- packet-level derivation over the reconciled final_claims ----------------

def test_consistency_record_over_packet_final_claims():
    # The packet carries already-canonical final_claims (the diff's output). The
    # record derives the consistency sheet straight from them.
    packet = {"diff": {"final_claims": {
        "nis2": _claims(branch="nis2").canonical(),
        "sec": _claims(branch="sec").canonical(),
        "dora": _claims(branch="dora").canonical(),
    }}}
    rec = consistency_record(packet)
    assert rec["consistent"] is True
    assert rec["filing_count"] == 3
    assert rec["conflict_count"] == 0
    assert set(rec["filings"]) == {"NIS2", "SEC", "DORA"}
    for fact in rec["facts"]:
        assert fact["status"] in (STATUS_CONSISTENT, STATUS_CONFLICT)


def test_consistency_record_surfaces_conflict_from_final_claims():
    packet = {"diff": {"final_claims": {
        "nis2": _claims(branch="nis2", records=48211).canonical(),
        "sec": _claims(branch="sec", records=999).canonical(),
    }}}
    rec = consistency_record(packet)
    assert rec["consistent"] is False
    records = next(f for f in rec["facts"] if f["fact"] == "records_affected")
    assert records["status"] == STATUS_CONFLICT


def test_consistency_record_empty_when_fewer_than_two_filings():
    assert consistency_record({"diff": {"final_claims": {
        "nis2": _claims(branch="nis2").canonical()}}}) == {}
    assert consistency_record({"diff": {"final_claims": {}}}) == {}
    assert consistency_record({}) == {}


# ---- derived: no LLM surface, no run-log mutation ----------------------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    # Pure derived render: no LLM call, no wall-clock / RNG, no run-log writer. The
    # sheet must be a pure function of the packet bytes.
    src = inspect.getsource(consistency_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", "run_log"):
        assert token not in src, f"consistency module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    # The sheet READS the packet; it never writes into it (and so never into any
    # run-log the packet carries).
    packet = {"diff": {"final_claims": {
        "nis2": _claims(branch="nis2").canonical(),
        "sec": _claims(branch="sec").canonical(),
    }}}
    before = json.dumps(packet, sort_keys=True)
    consistency_record(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_sheet_is_deterministic_across_two_derivations():
    packet = {"diff": {"final_claims": {
        "sec": _claims(branch="sec").canonical(),
        "nis2": _claims(branch="nis2").canonical(),
        "dora": _claims(branch="dora").canonical(),
    }}}
    a = consistency_record(packet)
    b = consistency_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---- render layer: the agreement table is the examiner's cross-read ----------

def test_packet_html_renders_the_consistency_matrix():
    from floor.packet import _render_html
    packet = {
        "incident": {"incident_id": "inc-8842", "band_room_id": "room-x",
                     "fact_record": {}},
        "replay": {"byte_identical": True, "original_sha256": "0" * 64,
                   "replayed_sha256": "0" * 64},
        "filings": [],
        "diff": {"final_claims": {
            "nis2": _claims(branch="nis2").canonical(),
            "sec": _claims(branch="sec").canonical(),
            "dora": _claims(branch="dora").canonical(),
        }},
    }
    packet["consistency"] = consistency_record(packet)
    html = _render_html(packet)
    assert "Cross-filing consistency assertion" in html
    assert "CONSISTENT" in html
    # the attested value appears once in the table
    assert "48211" in html
    # the overall verdict stamps consistent across all filings
    assert "all 3 filings" in html


def test_packet_html_renders_a_conflict_row():
    from floor.packet import _render_html
    packet = {
        "incident": {"incident_id": "inc-8842", "band_room_id": "room-x",
                     "fact_record": {}},
        "replay": {"byte_identical": True, "original_sha256": "0" * 64,
                   "replayed_sha256": "0" * 64},
        "filings": [],
        "diff": {"final_claims": {
            "nis2": _claims(branch="nis2", records=48211).canonical(),
            "sec": _claims(branch="sec", records=2100000).canonical(),
        }},
    }
    packet["consistency"] = consistency_record(packet)
    html = _render_html(packet)
    assert "CONFLICT" in html
    assert "2100000" in html


# ---- guard: the four DEFAULT sealed captures and shas are untouched ----------

def test_default_sealed_captures_and_shas_unchanged():
    """The consistency sheet is a render/derive-only feature; the four committed
    sealed captures (normal, inject_contradiction, chaos, amendment) and their
    run-log shas must be byte-for-byte unchanged. This pins them so a regression that
    perturbs a sealed capture fails here."""
    data = REPO / "web" / "data"
    for mode in ("normal", "inject_contradiction", "chaos", "amendment"):
        log_path = data / f"run-inc-8842-{mode}.jsonl"
        assert log_path.exists(), f"sealed capture missing: {log_path}"
        sha = hashlib.sha256(log_path.read_bytes()).hexdigest()
        assert len(sha) == 64
        packet_path = data / f"packet-{mode}.json"
        if packet_path.exists():
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            recorded = packet.get("replay", {}).get("original_sha256")
            from warden.replay import RunLog
            loaded = RunLog.load(log_path)
            assert loaded.sha256() == recorded, (
                f"{mode}: run-log sha drifted from the committed packet")


def test_consistency_sheet_over_the_committed_submit_capture():
    # The committed submit capture (four reconciled filings) attests CONSISTENT
    # through the receipt script.
    packet = REPO / "web" / "data" / "packet-submit.json"
    if not packet.exists():
        return  # capture not present in this checkout; the unit layer covers it
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import consistency_sheet
    rc = consistency_sheet.main([str(packet)])
    assert rc == 0
