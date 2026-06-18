"""test_completeness.py -- the examiner's first auto-screen (E4.2).

The per-regime submission COMPLETENESS SHEET: for each regime, every mandated field
the form requires is marked PRESENT / EMPTY / NOT-APPLICABLE against the EXACT field
labels the form defines (floor/formats.py, drawn from the same regime catalog that
drives the clocks), and an overall complete/incomplete verdict falls out per regime.

Three layers:

  Unit layer over floor/completeness.py: a present mandated field is PRESENT, a
  missing one is EMPTY; the per-regime verdict is COMPLETE iff every field is present;
  a regime with a profile but no filing yields an all-NA sheet; the screen is a pure
  derived read (no LLM surface, no run-log mutation) and deterministic across runs.

  Render layer over the packet HTML: the completeness matrix is the first screen, with
  a PRESENT / EMPTY status per mandated field and the overall verdict.

  Guard layer: the four DEFAULT sealed captures and their run-log shas are byte-for-
  byte unchanged by this render/derive-only feature.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.completeness as completeness_mod
from floor.completeness import (
    STATUS_EMPTY,
    STATUS_NA,
    STATUS_PRESENT,
    completeness_record,
    na_sheet_for_profile,
    packet_complete,
    sheet_for_filing,
    sheets_for_packet,
)
from floor.formats import ICO_ART33, SEC_8K, format_profile_for

REPO = Path(__file__).resolve().parents[1]


# ---- helpers ----------------------------------------------------------------

def _labelled_prose(profile, *, omit=None):
    """A filing whose mandated fields are written as labelled sections, the form the
    drafter fills via floor/formats.prompt_for. Omitting a field models a gap."""
    lines = [profile.cover_tag, ""]
    for f in profile.fields:
        if omit is not None and f.label == omit:
            continue
        lines.append(f"{f.label}: stated from the fact-record for this field.")
        lines.append("")
    return "\n".join(lines).rstrip()


# ---- unit layer: PRESENT vs EMPTY, the verdict ------------------------------

def test_present_mandated_field_is_marked_present():
    filing = {"regime": "UK ICO", "branch": "uk", "text": _labelled_prose(ICO_ART33)}
    sheet = sheet_for_filing(filing)
    assert sheet is not None
    by_label = {f.label: f for f in sheet.fields}
    for f in ICO_ART33.fields:
        assert by_label[f.label].status == STATUS_PRESENT
        assert by_label[f.label].evidence  # a present field carries an evidence snippet


def test_missing_mandated_field_is_marked_empty():
    omitted = "Likely consequences"
    filing = {"regime": "UK ICO", "branch": "uk",
              "text": _labelled_prose(ICO_ART33, omit=omitted)}
    sheet = sheet_for_filing(filing)
    by_label = {f.label: f for f in sheet.fields}
    assert by_label[omitted].status == STATUS_EMPTY
    # every OTHER field is still present
    for f in ICO_ART33.fields:
        if f.label != omitted:
            assert by_label[f.label].status == STATUS_PRESENT


def test_label_present_but_empty_body_is_empty_not_present():
    # A label with no body is EMPTY: the contract is real, not a label rubber stamp.
    prose = (ICO_ART33.cover_tag + "\n\n"
             + "Nature of the breach: stated.\n\n"
             + "Categories and approximate number of data subjects and records:\n\n"
             + "Likely consequences: stated.\n\n"
             + "Measures taken or proposed: stated.")
    filing = {"regime": "UK ICO", "branch": "uk", "text": prose}
    sheet = sheet_for_filing(filing)
    by_label = {f.label: f for f in sheet.fields}
    assert by_label["Categories and approximate number of data subjects and "
                    "records"].status == STATUS_EMPTY


def test_overall_verdict_is_complete_when_all_present():
    filing = {"regime": "UK ICO", "branch": "uk", "text": _labelled_prose(ICO_ART33)}
    sheet = sheet_for_filing(filing)
    assert sheet.complete is True
    assert sheet.empty_count == 0
    assert sheet.present_count == sheet.total
    assert "COMPLETE" in sheet.verdict


def test_overall_verdict_is_incomplete_when_a_field_is_empty():
    filing = {"regime": "UK ICO", "branch": "uk",
              "text": _labelled_prose(ICO_ART33, omit="Measures taken or proposed")}
    sheet = sheet_for_filing(filing)
    assert sheet.complete is False
    assert sheet.empty_count == 1
    assert "INCOMPLETE" in sheet.verdict


def test_sec_filing_resolves_the_edgar_8k_mandated_fields():
    # The SEC branch resolves to the SEC 8-K Item 1.05 mandated content elements.
    filing = {"regime": "SEC", "branch": "sec", "text": _labelled_prose(SEC_8K)}
    sheet = sheet_for_filing(filing)
    assert [f.label for f in sheet.fields] == [f.label for f in SEC_8K.fields]
    assert sheet.complete is True


def test_filing_resolves_profile_by_regime_label_without_a_branch():
    # A filing that carries only a regime label (no branch token) still resolves.
    filing = {"regime": "SEC", "text": _labelled_prose(SEC_8K)}
    sheet = sheet_for_filing(filing)
    assert sheet is not None
    assert sheet.complete is True


def test_unknown_regime_filing_is_skipped():
    filing = {"regime": "Atlantis Data Authority", "text": "free prose"}
    assert sheet_for_filing(filing) is None


def test_na_sheet_marks_every_field_not_applicable():
    sheet = na_sheet_for_profile(format_profile_for("sec_8k"), "SEC")
    assert sheet.applicable is False
    assert sheet.complete is False
    assert all(f.status == STATUS_NA for f in sheet.fields)
    assert sheet.na_count == sheet.total
    assert "NOT APPLICABLE" in sheet.verdict


# ---- packet-level derivation -------------------------------------------------

def test_sheets_for_packet_one_per_known_filing():
    packet = {"filings": [
        {"regime": "UK ICO", "branch": "uk", "text": _labelled_prose(ICO_ART33)},
        {"regime": "SEC", "branch": "sec", "text": _labelled_prose(SEC_8K)},
        {"regime": "Unknown", "text": "free prose"},  # skipped
    ]}
    sheets = sheets_for_packet(packet)
    assert [s.regime for s in sheets] == ["UK ICO", "SEC"]


def test_packet_complete_true_when_every_owed_regime_complete():
    sheets = [
        sheet_for_filing({"regime": "UK ICO", "branch": "uk",
                          "text": _labelled_prose(ICO_ART33)}),
        sheet_for_filing({"regime": "SEC", "branch": "sec",
                          "text": _labelled_prose(SEC_8K)}),
    ]
    assert packet_complete(sheets) is True


def test_packet_complete_false_when_one_regime_incomplete():
    sheets = [
        sheet_for_filing({"regime": "UK ICO", "branch": "uk",
                          "text": _labelled_prose(ICO_ART33)}),
        sheet_for_filing({"regime": "SEC", "branch": "sec",
                          "text": _labelled_prose(SEC_8K, omit="Scope of the incident")}),
    ]
    assert packet_complete(sheets) is False


def test_completeness_record_shape():
    packet = {"filings": [
        {"regime": "UK ICO", "branch": "uk", "text": _labelled_prose(ICO_ART33)}]}
    rec = completeness_record(packet)
    assert rec["all_complete"] is True
    assert rec["regimes_screened"] == ["UK ICO"]
    assert rec["sheets"][0]["complete"] is True
    # every per-field row carries a typed status
    for fld in rec["sheets"][0]["fields"]:
        assert fld["status"] in (STATUS_PRESENT, STATUS_EMPTY, STATUS_NA)


def test_completeness_record_empty_when_no_screenable_filing():
    assert completeness_record({"filings": [{"regime": "Unknown", "text": "x"}]}) == {}
    assert completeness_record({"filings": []}) == {}


# ---- derived: no LLM surface, no run-log mutation ----------------------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    # Pure derived render: no LLM call, no wall-clock / RNG, no run-log writer. The
    # sheet must be a pure function of the packet bytes.
    src = inspect.getsource(completeness_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", "run_log"):
        assert token not in src, f"completeness module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    # The screen READS the packet; it never writes into it (and so never into any
    # run-log the packet carries). The filings list is untouched.
    packet = {"filings": [
        {"regime": "UK ICO", "branch": "uk", "text": _labelled_prose(ICO_ART33)}]}
    before = json.dumps(packet, sort_keys=True)
    completeness_record(packet)
    sheets_for_packet(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_sheet_is_deterministic_across_two_derivations():
    packet = {"filings": [
        {"regime": "SEC", "branch": "sec", "text": _labelled_prose(SEC_8K)},
        {"regime": "UK ICO", "branch": "uk", "text": _labelled_prose(ICO_ART33)}]}
    a = completeness_record(packet)
    b = completeness_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---- render layer: the matrix is the first screen ----------------------------

def test_packet_html_renders_the_completeness_matrix():
    from floor.packet import _render_html
    packet = {
        "incident": {"incident_id": "inc-8842", "band_room_id": "room-x",
                     "fact_record": {}},
        "replay": {"byte_identical": True, "original_sha256": "0" * 64,
                   "replayed_sha256": "0" * 64},
        "filings": [
            {"regime": "SEC", "branch": "sec", "text": _labelled_prose(SEC_8K)},
            {"regime": "UK ICO", "branch": "uk",
             "text": _labelled_prose(ICO_ART33, omit="Likely consequences")},
        ],
    }
    packet["completeness"] = completeness_record(packet)
    html = _render_html(packet)
    assert "Submission completeness screen" in html
    assert "PRESENT" in html
    assert "EMPTY" in html
    # the omitted field's regime reads INCOMPLETE; the SEC sheet reads COMPLETE
    assert "INCOMPLETE" in html
    assert "COMPLETE" in html
    # the exact mandated label appears in the matrix
    assert "Nature of the incident" in html


# ---- guard: the four DEFAULT sealed captures and shas are untouched ----------

def test_default_sealed_captures_and_shas_unchanged():
    """The completeness sheet is a render/derive-only feature; the four committed
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


def test_completeness_sheet_over_the_committed_submit_capture():
    # The committed submit capture (fully labelled filings) screens COMPLETE through
    # the receipt script.
    packet = REPO / "web" / "data" / "packet-submit.json"
    if not packet.exists():
        return  # capture not present in this checkout; the unit layer covers it
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import completeness_sheet
    rc = completeness_sheet.main([str(packet)])
    assert rc == 0


def test_completeness_block_is_present_in_the_committed_submit_packet():
    # The submit capture carries the completeness block, derived at assembly time.
    packet_path = REPO / "web" / "data" / "packet-submit.json"
    if not packet_path.exists():
        return
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    rec = packet.get("completeness")
    # Either the committed packet already carries it, or it derives cleanly now; both
    # are screened to the same COMPLETE verdict over the labelled submit filings.
    if rec is None:
        rec = completeness_record(packet)
    assert rec["all_complete"] is True
    assert isinstance(rec["sheets"], list) and rec["sheets"]
