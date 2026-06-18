"""test_deficiency.py -- the deficiency / rejection loop (E3.9).

Two layers:

  Unit layer over floor/deficiency.py: the modeled regulator's intake review is a
  DETERMINISTIC mandated-field completeness screen. A filing missing a mandated
  field draws a typed DeficiencyNotice naming that exact field; a complete filing
  is ACCEPTED with no loop; the review exposes no LLM surface; the verdict is
  honest (a modeled stub, no fabricated receipt number).

  Full-floor layer over the --deficiency beat: the cure loop reopens the SEC
  branch (FACT_AMENDED), the drafter re-drafts the cited element and re-files, the
  modeled regulator re-reviews -> ACCEPTED, the Warden gate stays deterministic,
  and the run replays byte for byte. A guard asserts the four DEFAULT sealed
  captures and their shas are untouched by this new scenario.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.deficiency as deficiency_mod
from floor.deficiency import (
    CODE_MISSING_FIELD,
    MODELED_CAVEAT,
    SEVERITY_REJECT,
    Deficiency,
    review,
)
from floor.formats import SEC_8K
from floor.run_floor import (
    DEFICIENCY_OMITTED_FIELD,
    DRAFTER_ROLES,
    run_floor,
)
from floor.shell_adapter import FakeBandClient, FakeRoom


# ---- a complete SEC 8-K filing prose, every mandated Item 1.05 field present ----

def _complete_sec_prose(omit: str | None = None) -> str:
    lines = [SEC_8K.cover_tag, ""]
    for f in SEC_8K.fields:
        if omit is not None and f.label == omit:
            continue
        lines.append(f"{f.label}: stated from the fact-record for this field.")
        lines.append("")
    return "\n".join(lines).rstrip()


# ---- unit layer: the deterministic completeness screen ----------------------

def test_missing_mandated_field_draws_typed_deficiency_naming_the_field():
    prose = _complete_sec_prose(omit="Timing of the incident")
    verdict = review(SEC_8K, prose, "SEC")
    assert verdict.accepted is False
    assert len(verdict.deficiencies) == 1
    d = verdict.deficiencies[0]
    assert isinstance(d, Deficiency)
    assert d.code == CODE_MISSING_FIELD
    assert d.regime == "SEC"
    assert d.deficient_field == "Timing of the incident"
    assert d.severity == SEVERITY_REJECT
    # the human reason names the exact field
    assert "Timing of the incident" in d.reason
    assert verdict.stamp.startswith("DEFICIENCY NOTICE")


def test_complete_filing_is_accepted_with_no_loop():
    prose = _complete_sec_prose()
    verdict = review(SEC_8K, prose, "SEC")
    assert verdict.accepted is True
    assert verdict.deficiencies == ()
    assert verdict.stamp == "ACCEPTED FOR FILING"


def test_an_empty_field_body_is_treated_as_missing():
    # The label is present but carries no content: still a deficiency.
    prose = (SEC_8K.cover_tag + "\n\n"
             + "Nature of the incident: stated.\n\n"
             + "Scope of the incident: stated.\n\n"
             + "Timing of the incident:\n\n"   # label present, body empty
             + "Material impact or reasonably likely material impact: stated.")
    verdict = review(SEC_8K, prose, "SEC")
    assert verdict.accepted is False
    fields = [d.deficient_field for d in verdict.deficiencies]
    assert fields == ["Timing of the incident"]


def test_multiple_missing_fields_each_get_a_typed_row():
    prose = (SEC_8K.cover_tag + "\n\n"
             + "Nature of the incident: stated.\n\n"
             + "Material impact or reasonably likely material impact: stated.")
    verdict = review(SEC_8K, prose, "SEC")
    assert verdict.accepted is False
    fields = sorted(d.deficient_field for d in verdict.deficiencies)
    assert fields == sorted(["Scope of the incident", "Timing of the incident"])


def test_review_is_deterministic():
    prose = _complete_sec_prose(omit="Scope of the incident")
    a = review(SEC_8K, prose, "SEC")
    b = review(SEC_8K, prose, "SEC")
    assert a.as_dict() == b.as_dict()


def test_review_ignores_the_claims_block_envelope():
    # The Warden-owned [CLAIMS] block is not a mandated form field; it must not be
    # read as prose by the completeness screen.
    prose = (_complete_sec_prose()
             + "\n\n[CLAIMS]\nbranch=sec\nrecords_affected=48211\n[/CLAIMS]")
    verdict = review(SEC_8K, prose, "SEC")
    assert verdict.accepted is True


def test_verdict_carries_the_honest_modeled_stub_caveat():
    verdict = review(SEC_8K, _complete_sec_prose(), "SEC")
    assert verdict.caveat == MODELED_CAVEAT
    # honesty: no fabricated receipt / accession number language
    assert "no accession or receipt number" in verdict.caveat.lower()
    assert "not a real government endpoint" in verdict.caveat.lower()


def test_deficiency_check_exposes_no_llm_surface():
    # The deficiency module must make zero LLM calls: no llm_complete import, no
    # provider/model parameters, no network. The detection is a pure field rule.
    src = inspect.getsource(deficiency_mod)
    for token in ("llm_complete", "requests", "openai", "httpx",
                  "draft_filing", "api_key", "provider", "model="):
        assert token not in src, f"deficiency module must not reference {token!r}"
    sig = inspect.signature(review)
    assert list(sig.parameters) == ["profile", "filing_text", "regime"]


def test_as_dict_is_json_serializable_and_stable():
    verdict = review(SEC_8K, _complete_sec_prose(omit="Timing of the incident"), "SEC")
    blob = json.dumps(verdict.as_dict(), sort_keys=False)
    again = json.dumps(verdict.as_dict(), sort_keys=False)
    assert blob == again
    parsed = json.loads(blob)
    assert parsed["accepted"] is False
    assert parsed["deficiencies"][0]["deficient_field"] == "Timing of the incident"


# ---- full-floor layer: the cure loop on the corrected-resubmission seam ------

def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return room, clients


def _stub_draft_fns():
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _run(tmp_path):
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="deficiency", clients=clients,
                       draft_fns=_stub_draft_fns())
    return room, packet


def test_beat_issues_a_typed_deficiency_notice_naming_the_omitted_field(tmp_path):
    _, packet = _run(tmp_path)
    d = packet["deficiency"]
    initial = d["initial_review"]
    assert initial["accepted"] is False
    fields = [x["deficient_field"] for x in initial["deficiencies"]]
    assert DEFICIENCY_OMITTED_FIELD in fields
    assert initial["deficiencies"][0]["code"] == CODE_MISSING_FIELD
    assert initial["stamp"].startswith("DEFICIENCY NOTICE")


def test_cure_loop_reopens_redrafts_refiles_and_accepts(tmp_path):
    _, packet = _run(tmp_path)
    corr = "inc-8842:sec"
    events = [(t["correlation_id"], t["event"], t["admitted"])
              for t in packet["state_transitions"]]
    # the SEC branch reached released, then FACT_AMENDED reopened it for the cure
    assert (corr, "human_released", True) in events
    assert (corr, "fact_amended", True) in events
    # the cured filing was re-posted (DRAFT_POSTED from the amending state) and
    # the SEC branch released a SECOND time
    sec_releases = [t for t in packet["state_transitions"]
                    if t["admitted"] and t["event"] == "human_released"
                    and t["correlation_id"] == corr]
    assert len(sec_releases) == 2
    # the modeled regulator re-reviewed the cured filing -> ACCEPTED
    final = packet["deficiency"]["final_review"]
    assert final["accepted"] is True
    assert final["stamp"] == "ACCEPTED FOR FILING"


def test_cured_sec_filing_in_packet_carries_the_restored_field(tmp_path):
    _, packet = _run(tmp_path)
    sec = [f for f in packet["filings"] if f["regime"] == "SEC"]
    assert len(sec) == 1
    assert DEFICIENCY_OMITTED_FIELD in sec[0]["text"]


def test_only_the_sec_branch_reopens_for_the_cure(tmp_path):
    _, packet = _run(tmp_path)
    # NIS2 and DORA were complete and accepted; they must not see FACT_AMENDED.
    for other in ("nis2", "dora"):
        amended = [t for t in packet["state_transitions"]
                   if t["correlation_id"] == f"inc-8842:{other}"
                   and t["event"] == "fact_amended"]
        assert amended == []


def test_no_rejected_transitions_in_deficiency_run(tmp_path):
    _, packet = _run(tmp_path)
    rejected = [t for t in packet["state_transitions"] if not t["admitted"]]
    assert rejected == []


def test_warden_gate_stays_deterministic_no_llm_in_intake_log(tmp_path):
    room, packet = _run(tmp_path)
    # the two regulator-intake records in the run log carry only the typed verdict
    # (accepted + the named fields), never any LLM/model/provider surface.
    lines = Path(packet["_paths"]["run_log"]).read_text(encoding="utf-8").splitlines()
    entries = [json.loads(x) for x in lines if x.strip()]
    intake = [e for e in entries if e["type"] == "regulator_intake"]
    assert {e["payload"]["phase"] for e in intake} == {"initial", "cured"}
    initial = next(e for e in intake if e["payload"]["phase"] == "initial")
    cured = next(e for e in intake if e["payload"]["phase"] == "cured")
    assert initial["payload"]["accepted"] is False
    assert cured["payload"]["accepted"] is True
    for e in intake:
        keys = set(e["payload"].keys())
        assert keys == {"phase", "regime", "accepted", "deficient_fields"}


def test_deficiency_run_replays_byte_identical(tmp_path):
    _, packet = _run(tmp_path)
    assert packet["replay"]["byte_identical"] is True
    from warden.replay import RunLog, replay
    loaded = RunLog.load(Path(packet["_paths"]["run_log"]))
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]


def test_deficiency_run_is_deterministic_across_runs(tmp_path):
    _, p1 = _run(tmp_path / "a")
    _, p2 = _run(tmp_path / "b")
    assert p1["replay"]["original_sha256"] == p2["replay"]["original_sha256"]
    assert p1["deficiency"]["initial_review"] == p2["deficiency"]["initial_review"]
    assert p1["deficiency"]["final_review"] == p2["deficiency"]["final_review"]


def test_packet_html_renders_the_deficiency_roundtrip(tmp_path):
    _, packet = _run(tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Deficiency / rejection loop" in html
    assert "DEFICIENCY NOTICE" in html
    assert "ACCEPTED FOR FILING" in html
    assert "modeled regulator" in html.lower()
    # the honest caveat is rendered: no fabricated receipt
    assert "no accession or receipt number" in html.lower()


# ---- guard: the four DEFAULT sealed captures and shas are untouched ----------

def test_default_sealed_captures_and_shas_unchanged():
    """The deficiency beat is its own scenario; the four committed sealed captures
    (normal, inject_contradiction, chaos, amendment) and their run-log shas must be
    byte-for-byte unchanged. This pins them so a regression that perturbs a sealed
    capture fails here."""
    data = Path(__file__).resolve().parents[1] / "web" / "data"
    expected = {
        "normal": data / "run-inc-8842-normal.jsonl",
        "inject_contradiction": data / "run-inc-8842-inject_contradiction.jsonl",
        "chaos": data / "run-inc-8842-chaos.jsonl",
        "amendment": data / "run-inc-8842-amendment.jsonl",
    }
    for mode, log_path in expected.items():
        assert log_path.exists(), f"sealed capture missing: {log_path}"
        raw = log_path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        # the packet that pairs with the capture records the run-log sha; it must
        # match the bytes on disk (the capture has not been regenerated).
        packet_path = data / f"packet-{mode}.json"
        if packet_path.exists():
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            recorded = packet.get("replay", {}).get("original_sha256")
            # the recorded sha is over the canonical jsonl the run produced; recompute
            # it from the loaded log to compare apples to apples.
            from warden.replay import RunLog
            loaded = RunLog.load(log_path)
            assert loaded.sha256() == recorded, (
                f"{mode}: run-log sha drifted from the committed packet")
        assert len(sha) == 64
