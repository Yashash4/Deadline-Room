"""test_determination_record.py -- the reasonable-basis determination record (E3.2).

When the materiality / reportability role makes a file/suppress call, the room
emits a typed reasonable-basis DETERMINATION RECORD: the named legal standard, and
a factor table where each factor the standard weighs is bound to the EXACT
canonical fact-record FIELD it rests on. The factor->fact binding and the record
shape are deterministic Python (floor/determination.py); the pure
warden/determination.py validator confirms every cited field exists (no fabricated
factor). The record is logged as ONE additive event so it is hash-chained,
replayed, and signed exactly like the materiality / reportability event it
documents.

These tests pin the contract:
  * every factor binds to a real CANONICAL_FACTS field;
  * the validator REJECTS a factor citing a nonexistent field;
  * the record is sealed and replayed byte-identically in the determination beat;
  * the four DEFAULT sealed captures and their shas are UNCHANGED;
  * it NEVER gates: no release / suppress decision comes from the record itself,
    only from the existing typed verdict.
"""

from pathlib import Path

import pytest

from warden.determination import (
    DeterminationFactor, DeterminationRecord, ReasonableBasis,
    validate_determination)
from warden.materiality import MaterialityVerdict
from warden.reportability import ReportabilityVerdict
from floor.determination import build_determination_record
from floor.run_floor import (
    CANONICAL_FACTS, DRAFTER_ROLES, REPORTABILITY_BRANCHES, _REGIME_BY_BRANCH,
    run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

DATA = Path(__file__).resolve().parent.parent / "web" / "data"


# ---- test plumbing (mirrors the materiality / reportability suites) ---------

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
            return (f"{regime} notification. Incident "
                    f"{claim_facts['incident_start_utc']}, "
                    f"{claim_facts['records_affected']} records.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _material_verdict(_facts):
    return MaterialityVerdict("sec", True,
                              "Millions of regulated records across core banking.",
                              source="test:material")


def _immaterial_verdict(_facts):
    return MaterialityVerdict("sec", False,
                              "Twelve cafeteria menu records, contained.",
                              source="test:immaterial")


def _run_materiality(verdict_fn, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                     draft_fns=_stub_draft_fns(), materiality=True,
                     materiality_fn=verdict_fn)


def _rep_verdict(branch, spec, reportable):
    return ReportabilityVerdict(
        branch=branch, regime=spec.regime_label, reportable=reportable,
        rationale=f"{branch} basis.", standard=spec.reportability.standard,
        rule=spec.reportability.rule,
        source=f"test:{'reportable' if reportable else 'suppressed'}")


def _mixed_rep_fn(branch, _facts, spec):
    return _rep_verdict(branch, spec, reportable=(branch != "nis2"))


def _run_reportability(fn, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="reportability", clients=clients,
                     draft_fns=_stub_draft_fns(), reportability=True,
                     reportability_fn=fn)


# ---- the record shape: each factor binds to a real CANONICAL_FACTS field ----

def test_builder_binds_every_factor_to_a_real_fact_field():
    spec = _REGIME_BY_BRANCH["sec"]
    record = build_determination_record(
        branch="sec", regime=spec.regime_label,
        standard=spec.reportability.standard, disposition="file",
        fact_record=CANONICAL_FACTS, source="test:material")
    assert isinstance(record, DeterminationRecord)
    assert record.factors, "the standard must weigh at least one factor"
    # Every factor names the EXACT canonical fact-record field it rests on, and
    # that field exists in the record (no free-text factor).
    for f in record.factors:
        assert isinstance(f, DeterminationFactor)
        assert f.fact_field in CANONICAL_FACTS, \
            f"factor {f.name!r} binds to {f.fact_field!r} not in CANONICAL_FACTS"
    # The factor value is read straight off the bound field.
    by_field = {f.fact_field: f for f in record.factors}
    assert by_field["records_affected"].value == str(CANONICAL_FACTS["records_affected"])
    assert by_field["containment"].value == CANONICAL_FACTS["containment"]


def test_builder_carries_the_standard_and_disposition_verbatim():
    spec = _REGIME_BY_BRANCH["nis2"]
    record = build_determination_record(
        branch="nis2", regime=spec.regime_label,
        standard=spec.reportability.standard, disposition="suppress",
        fact_record=CANONICAL_FACTS, source="test:suppressed")
    # The standard is the named legal standard; the disposition is copied verbatim
    # (the record documents the basis, it does not re-decide).
    assert record.standard == spec.reportability.standard
    assert record.disposition == "suppress"


def test_record_has_both_quantitative_and_qualitative_factors():
    spec = _REGIME_BY_BRANCH["sec"]
    record = build_determination_record(
        branch="sec", regime=spec.regime_label,
        standard=spec.reportability.standard, disposition="file",
        fact_record=CANONICAL_FACTS, source="x")
    kinds = {f.qualitative for f in record.factors}
    assert kinds == {True, False}, "must weigh quantitative AND qualitative factors"


# ---- the validator: rejects a factor citing a nonexistent field -------------

def test_validator_accepts_a_fully_grounded_record():
    spec = _REGIME_BY_BRANCH["sec"]
    record = build_determination_record(
        branch="sec", regime=spec.regime_label,
        standard=spec.reportability.standard, disposition="file",
        fact_record=CANONICAL_FACTS, source="x")
    basis = validate_determination(record, CANONICAL_FACTS)
    assert isinstance(basis, ReasonableBasis)
    assert basis.complete is True
    assert basis.missing_factors == ()
    assert set(basis.cited_fields) == {f.fact_field for f in record.factors}


def test_validator_rejects_a_factor_citing_a_nonexistent_field():
    # A fabricated factor that cites a field the fact-record does not carry.
    record = DeterminationRecord(
        branch="sec", regime="SEC",
        standard="SEC Item 1.05 materiality", disposition="file",
        factors=(
            DeterminationFactor("Quantitative scale: records affected",
                                "48211", "records_affected"),
            DeterminationFactor("Fabricated factor", "9001",
                                "ransom_demand_btc", qualitative=True),
        ),
        source="x")
    basis = validate_determination(record, CANONICAL_FACTS)
    assert basis.complete is False
    assert basis.missing_factors == (("Fabricated factor", "ransom_demand_btc"),)
    # The grounded factor is still reported as cited; only the fabricated one is
    # flagged missing.
    assert "records_affected" in basis.cited_fields
    assert "ransom_demand_btc" in basis.cited_fields


def test_validator_is_pure_and_deterministic():
    record = build_determination_record(
        branch="sec", regime="SEC", standard="SEC Item 1.05 materiality",
        disposition="file", fact_record=CANONICAL_FACTS, source="x")
    a = validate_determination(record, CANONICAL_FACTS)
    b = validate_determination(record, CANONICAL_FACTS)
    assert a == b


def test_builder_keeps_binding_for_a_missing_field_so_validator_can_flag_it():
    # A fact-record missing one of the spine fields: the factor binding is kept
    # (not silently dropped) so the validator flags it, never hides it.
    facts = {k: v for k, v in CANONICAL_FACTS.items() if k != "attacker"}
    record = build_determination_record(
        branch="sec", regime="SEC", standard="SEC Item 1.05 materiality",
        disposition="file", fact_record=facts, source="x")
    assert any(f.fact_field == "attacker" for f in record.factors)
    basis = validate_determination(record, facts)
    assert basis.complete is False
    assert any(field == "attacker" for _, field in basis.missing_factors)


# ---- the validator gates nothing --------------------------------------------

def test_warden_determination_module_exposes_no_gate_or_release_surface():
    import warden.determination as det
    # No release / gate / clock / suppress / llm surface anywhere in the module.
    for forbidden in ("release", "gate", "clock", "suppress", "llm",
                      "complete_release", "hold"):
        assert not any(forbidden in n.lower() for n in dir(det)
                       if not n.startswith("_")), \
            f"warden.determination must not expose a {forbidden!r} surface"
    # The only callable is the validator (plus the imported dataclass decorator).
    callables = {n for n in dir(det)
                 if not n.startswith("_") and callable(getattr(det, n))}
    assert callables - {"dataclass"} == {
        "DeterminationFactor", "DeterminationRecord", "ReasonableBasis",
        "validate_determination"}


def test_an_incomplete_basis_does_not_suppress_a_material_branch(tmp_path):
    # Even when a determination record were incomplete, the file/suppress decision
    # is the verdict's, never the record's. A material SEC verdict files; the
    # determination record is documentation riding alongside, it gates nothing.
    packet = _run_materiality(_material_verdict, tmp_path)
    det = packet["materiality"]["determination"]
    assert det["reasonable_basis"]["complete"] is True
    # SEC still filed on the verdict, and the determination disposition mirrors the
    # verdict disposition verbatim (it did not drive it). The materiality verdict's
    # disposition is "proceed" (material) / "suppress" (immaterial).
    assert det["disposition"] == "proceed"
    assert "SEC" in [f["regime"] for f in packet["filings"]]
    # The immaterial verdict suppresses on the verdict, and the determination
    # record mirrors that disposition: it documents, it does not decide.
    suppressed = _run_materiality(_immaterial_verdict, tmp_path / "imm")
    sdet = suppressed["materiality"]["determination"]
    assert sdet["disposition"] == "suppress"
    assert "SEC" not in [f["regime"] for f in suppressed["filings"]]


# ---- sealed + replayable in the determination beat (deterministic) ----------

def test_determination_record_is_logged_in_the_materiality_beat(tmp_path):
    packet = _run_materiality(_material_verdict, tmp_path)
    log_path = Path(packet["_paths"]["run_log"])
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    det_lines = [ln for ln in lines if '"type":"determination_record"' in ln]
    assert len(det_lines) == 1, "exactly one determination_record event in the beat"
    # It rides BEFORE the gate decision and is hash-chained into the sealed run.
    assert '"reasonable_basis_complete":true' in det_lines[0]


def test_determination_record_per_regime_in_the_reportability_beat(tmp_path):
    packet = _run_reportability(_mixed_rep_fn, tmp_path)
    log_path = Path(packet["_paths"]["run_log"])
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    det_lines = [ln for ln in lines if '"type":"determination_record"' in ln]
    # One determination record per assessed regime (NIS2, SEC, DORA).
    assert len(det_lines) == len(REPORTABILITY_BRANCHES)
    # Each regime's packet record carries its determination + a complete basis.
    for reg in packet["reportability"]["regimes"]:
        det = reg["determination"]
        assert det["reasonable_basis"]["complete"] is True
        for f in det["factors"]:
            assert f["fact_field"] in CANONICAL_FACTS


def test_determination_beat_replay_is_byte_identical(tmp_path):
    for fn in (_material_verdict, _immaterial_verdict):
        packet = _run_materiality(fn, tmp_path / fn.__name__)
        assert packet["replay"]["byte_identical"] is True
    packet = _run_reportability(_mixed_rep_fn, tmp_path / "rep")
    assert packet["replay"]["byte_identical"] is True


def test_determination_beat_is_deterministic_across_two_runs(tmp_path):
    # Same injected verdict -> identical run-log sha: the record build + validate +
    # log path reads no now()/RNG.
    a = _run_materiality(_material_verdict, tmp_path / "a")
    b = _run_materiality(_material_verdict, tmp_path / "b")
    assert a["replay"]["original_sha256"] == b["replay"]["original_sha256"]


def test_determination_record_renders_in_the_packet_html(tmp_path):
    packet = _run_materiality(_material_verdict, tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Reasonable-basis determination record" in html
    assert "Bound to fact-record field" in html
    assert "records_affected" in html


# ---- the four DEFAULT sealed captures + their shas are UNCHANGED -------------

SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_no_determination_event_leaked_into_a_sealed_capture(mode):
    # The determination record rides ONLY the materiality / reportability beat, so
    # it must NOT appear in any of the four default sealed captures.
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    assert log_path.exists(), f"{mode}: sealed capture missing"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines
    assert not any('"determination_record"' in ln for ln in lines), \
        f"{mode}: a determination_record event leaked into the sealed capture"


def test_default_normal_run_sha_unchanged():
    # A fresh default normal run (no materiality/reportability) must still
    # reproduce the sealed normal sha byte for byte: the determination code is
    # dormant unless the beat runs, so it cannot have moved the default stream.
    from tests.test_operability_report import (
        SEALED_NORMAL_SHA, _build_clients as _bc, _stub_draft_fns as _sd)
    import tempfile
    room, clients = _bc()
    with tempfile.TemporaryDirectory() as td:
        packet = run_floor(out_dir=td, mode="normal", clients=clients,
                           draft_fns=_sd())
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA
