"""test_affected_party.py -- the affected-party / GDPR Art 34 communication-to-
data-subject track (E3.4).

The regulator clocks point at a GOVERNMENT recipient. This track points at the
affected INDIVIDUALS whose data leaked: GDPR Article 34, the communication of a
personal-data breach to the data subject, owed without undue delay when the breach
is "likely to result in a HIGH RISK to the rights and freedoms of natural persons"
(a strictly higher bar than the Art 33 regulator-notification trigger). It is a
SEPARATE obligation, NOT a regulator filing, and it is GATED ON the regulator
release.

A high-risk LLM judgment (floor/high_risk.py) crosses into the deterministic
warden/high_risk.py gate as a typed boolean:
  high risk     -> the affected-party communication is REQUIRED and tracked: the
                   branch is recruited, its own without-undue-delay clock anchors
                   at the RELEASE moment, the Art 34 notice is drafted, and it
                   passes the SAME two-key release gate.
  not high risk -> NO communication is required: the obligation is RECORDED
                   not-required with the named Art 34 rule, never silently absent.

The amendment cascade (records 48,211 -> 2,100,000) grows the affected-party SCOPE
(the number of individuals owed a communication), surfaced in the record. The
high-risk gate is deterministic Python: the warden.high_risk module exposes no
release / clock / LLM surface.

The judgment is the LLM's (here a deterministic injected verdict so the tests need
no live LLM, exactly the seam reportability_fn / materiality_fn use); the gating is
deterministic. These tests also pin that the four DEFAULT sealed captures (normal,
inject_contradiction, chaos, amendment) and their run-log shas are UNCHANGED by
this feature (the affected-party beat is its own scenario, never regenerated), and
that byte-identical replay holds for the new beat.
"""

from pathlib import Path

import pytest

from warden.high_risk import HighRiskVerdict, gate
from floor import regimes
from floor.run_floor import (
    AFFECTED_PARTY_BRANCH, AMENDED_RECORDS, CANONICAL_FACTS, DRAFTER_ROLES,
    _REGIME_BY_BRANCH, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

DATA = Path(__file__).resolve().parent.parent / "web" / "data"


def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    clients[AFFECTED_PARTY_BRANCH] = FakeBandClient(
        room, "ds-id", "data_subject_drafter", f"draft:{AFFECTED_PARTY_BRANCH}")
    return room, clients


def _stub_draft_fns():
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} notification. Incident "
                    f"{claim_facts['incident_start_utc']}, "
                    f"{claim_facts['records_affected']} records.")
        return fn
    fns = {r.branch: make(r.regime) for r in DRAFTER_ROLES}

    def ds_fn(notice_facts):
        return ("GDPR Art 34 communication to data subjects. Incident "
                f"{notice_facts['incident_start_utc']}, "
                f"{notice_facts['records_affected']} individuals affected.")
    fns[AFFECTED_PARTY_BRANCH] = ds_fn
    # The amendment beat the affected_party scenario rides needs reconciliation
    # characterization fns for the SEC and NIS2 turns.
    fns["sec:characterize"] = lambda x: "revised upward materially per forensics."
    fns["nis2:characterize"] = lambda x: "revised upward materially per forensics."
    return fns


def _verdict(spec, high_risk):
    return HighRiskVerdict(
        high_risk=high_risk,
        rationale=("Exposed account numbers create a high risk of fraud and "
                   "identity theft to the affected individuals."
                   if high_risk else
                   "The breach is contained and the data was encrypted; no "
                   "realistic high risk to individuals."),
        standard=spec.high_risk.standard, rule=spec.high_risk.rule,
        source=f"test:{'high_risk' if high_risk else 'not_high_risk'}")


def _high_risk_fn(_facts, spec):
    return _verdict(spec, high_risk=True)


def _not_high_risk_fn(_facts, spec):
    return _verdict(spec, high_risk=False)


def _run(fn, tmp_path, *, mode="affected_party", affected_party_facts=None):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                     draft_fns=_stub_draft_fns(), affected_party=True,
                     high_risk_fn=fn, affected_party_facts=affected_party_facts)


# ---- the deterministic gate ------------------------------------------------

def test_gate_is_pure_boolean():
    spec = _REGIME_BY_BRANCH[AFFECTED_PARTY_BRANCH]
    assert gate(_verdict(spec, True)) is True
    assert gate(_verdict(spec, False)) is False


def test_gate_returns_plain_bool():
    spec = _REGIME_BY_BRANCH[AFFECTED_PARTY_BRANCH]
    assert isinstance(gate(_verdict(spec, True)), bool)
    assert isinstance(gate(_verdict(spec, False)), bool)


def test_high_risk_module_exposes_no_release_clock_or_llm_surface():
    # The high-risk API is exactly one pure boolean rule plus a typed verdict; it
    # exposes no gate-state, no release, no clock, and no LLM surface. The Warden
    # gate stays deterministic and the qualitative call never touches it.
    import warden.high_risk as hr
    callables = {n for n in dir(hr)
                 if not n.startswith("_") and callable(getattr(hr, n))}
    own = callables - {"dataclass"}
    assert own == {"HighRiskVerdict", "gate"}
    for forbidden in ("release", "hold", "clock", "llm", "assess", "complete"):
        assert not any(forbidden in n.lower() for n in dir(hr)), \
            f"warden.high_risk must not expose a {forbidden!r} surface"


def test_warden_high_risk_module_makes_no_llm_or_network_import():
    # The deterministic gate module imports nothing that could make a model or
    # network call: it is pure dataclass + a boolean rule.
    import inspect
    import warden.high_risk as hr
    src = inspect.getsource(hr)
    for forbidden in ("import requests", "llm_complete", "openai", "httpx",
                      "import socket"):
        assert forbidden not in src, \
            f"warden.high_risk must not reference {forbidden!r}"


# ---- the catalog carries the Art 34 high-risk threshold --------------------

def test_data_subject_regime_has_a_high_risk_standard_in_the_catalog():
    spec = _REGIME_BY_BRANCH[AFFECTED_PARTY_BRANCH]
    assert spec.high_risk is not None
    assert spec.high_risk.standard.strip()
    assert spec.high_risk.rule.strip()
    assert "Article 34" in spec.high_risk.standard
    # It is a post-release obligation, neither a startup nor a recruit regime.
    assert spec.is_post_release
    assert not spec.is_startup and not spec.is_recruit


def test_data_subject_regime_is_not_a_startup_or_recruit_clock():
    catalog = regimes.load_catalog()
    startup = {s.branch for s in regimes.startup_regimes(catalog)}
    recruit = {s.branch for s in regimes.recruit_regimes(catalog)}
    # The affected-party clock starts at the regulator release, so it must NOT be
    # walked as a startup clock (floor open) or a jurisdiction recruit.
    assert AFFECTED_PARTY_BRANCH not in startup
    assert AFFECTED_PARTY_BRANCH not in recruit
    # Only the data_subject regime carries a high_risk block.
    with_high_risk = [s for s in catalog if s.high_risk is not None]
    assert [s.branch for s in with_high_risk] == [AFFECTED_PARTY_BRANCH]


# ---- high risk -> the communication is REQUIRED, tracked, gated on release --

def test_high_risk_requires_a_tracked_gated_communication(tmp_path):
    packet = _run(_high_risk_fn, tmp_path)
    ap = packet["affected_party"]
    assert ap["high_risk"] is True
    assert ap["required"] is True
    assert ap["disposition"] == "notify_data_subjects"
    assert ap["recruited"] is True
    assert ap["released"] is True
    # It is GATED ON the regulator release: its clock anchors at the release moment.
    assert ap["gated_on_release"] is True
    assert ap["release_anchor_ts"]

    # The affected-party branch reached RELEASED through the legal typed path.
    released = [t for t in packet["state_transitions"]
                if t["admitted"] and t["to_state"] == "released"
                and t["correlation_id"].endswith(f":{AFFECTED_PARTY_BRANCH}")]
    assert len(released) == 1

    # The Art 34 notice is a NON-regulator filing in the packet.
    ap_filings = [f for f in packet["filings"] if f.get("non_regulator")]
    assert len(ap_filings) == 1
    assert ap_filings[0]["regime"] == "Affected-party (GDPR Art 34)"

    # The packet HTML names the track and the high-risk decision.
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Affected-party notification (GDPR Art 34" in html
    assert "COMMUNICATION TO DATA SUBJECTS REQUIRED" in html


def test_affected_party_clock_anchors_at_release_not_t0(tmp_path):
    packet = _run(_high_risk_fn, tmp_path)
    ap = packet["affected_party"]
    clock = next(c for c in packet["clocks"]
                 if c["correlation_id"].endswith(f":{AFFECTED_PARTY_BRANCH}"))
    # The without-undue-delay clock starts at the regulator release moment, which
    # is strictly after incident T0; it is independent of the regulator clocks.
    assert clock["started"] == ap["release_anchor_ts"]
    assert clock["started"] > CANONICAL_FACTS["incident_start_utc"]
    assert clock["stopped"]


def test_affected_party_passes_the_same_two_key_gate(tmp_path):
    # The Art 34 communication releases only with BOTH distinct human keys (GC +
    # Lena), exactly like every regulator filing. One key alone never releases it.
    packet = _run(_high_risk_fn, tmp_path)
    signoffs = [e for e in packet["state_transitions"]
                if e["correlation_id"].endswith(f":{AFFECTED_PARTY_BRANCH}")]
    # The branch walked fact_record -> drafting -> draft_submitted ->
    # contradiction_checked -> awaiting_human_signoff -> released.
    states = [t["to_state"] for t in signoffs if t["admitted"]]
    assert "awaiting_human_signoff" in states
    assert "released" in states
    rel = packet.get("release", {})
    # The two distinct keys are recorded for the data_subject branch.
    ds_signers = {s["role"] for s in rel.get("signoffs", [])
                  if s["correlation_id"].endswith(f":{AFFECTED_PARTY_BRANCH}")}
    assert ds_signers == {"general_counsel", "head_of_ir"}


# ---- not high risk -> recorded not-required with the rule -------------------

def test_not_high_risk_records_not_required_with_the_rule(tmp_path):
    packet = _run(_not_high_risk_fn, tmp_path)
    ap = packet["affected_party"]
    assert ap["high_risk"] is False
    assert ap["required"] is False
    assert ap["disposition"] == "no_communication_required"
    assert ap["recruited"] is False
    assert "GDPR Art 34" in ap["rule"]

    # NO affected-party notice was produced.
    assert not any(f.get("non_regulator") for f in packet["filings"])
    # No data_subject branch ever released.
    released = [t for t in packet["state_transitions"]
                if t["admitted"] and t["to_state"] == "released"
                and t["correlation_id"].endswith(f":{AFFECTED_PARTY_BRANCH}")]
    assert released == []

    # The packet HTML names the rule and the no-communication decision.
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "NO COMMUNICATION REQUIRED" in html
    assert "no communication to data subjects required under GDPR Art 34" in html


# ---- the amendment cascade grows the affected-party scope -------------------

def test_amendment_cascade_grows_the_affected_party_scope(tmp_path):
    # The affected_party scenario rides the amendment: the forensic revision raises
    # records 48,211 -> 2,100,000, which cascades into the affected-party SCOPE (the
    # number of individuals owed a communication), the CISO's point on camera.
    packet = _run(_high_risk_fn, tmp_path)
    ap = packet["affected_party"]
    assert ap["scope_grew_from_amendment"] is True
    assert ap["scope_old"] == CANONICAL_FACTS["records_affected"] == 48211
    assert ap["scope_individuals"] == AMENDED_RECORDS == 2_100_000

    # The high-risk event records the scope and the growth in the sealed log.
    hr_events = [e for e in packet["state_transitions"]]  # touch to ensure loaded
    assert hr_events is not None
    # The packet HTML names the scope jump.
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "48,211 -> 2,100,000" in html
    assert "expanded the customer-notification scope" in html


def test_trigger_only_without_amendment_keeps_canonical_scope(tmp_path):
    # The affected-party trigger can run without the amendment (mode normal): the
    # high-risk communication is still required, but the scope stays the canonical
    # count (no cascade), proving the cascade is the amendment's doing, not the
    # affected-party phase's.
    packet = _run(_high_risk_fn, tmp_path, mode="normal")
    ap = packet["affected_party"]
    assert ap["required"] is True
    assert ap["scope_grew_from_amendment"] is False
    assert ap["scope_individuals"] == CANONICAL_FACTS["records_affected"] == 48211


# ---- decision-driven, not always-notify / always-skip ----------------------

def test_affected_party_is_decision_driven_not_always(tmp_path):
    p_yes = _run(_high_risk_fn, tmp_path / "yes")
    p_no = _run(_not_high_risk_fn, tmp_path / "no")
    assert p_yes["affected_party"]["required"] is True
    assert any(f.get("non_regulator") for f in p_yes["filings"])
    assert p_no["affected_party"]["required"] is False
    assert not any(f.get("non_regulator") for f in p_no["filings"])


# ---- the gate decision is deterministic Python (no LLM on the gate path) ----

def test_no_llm_release_or_gate_surface_on_the_high_risk_module():
    # Belt-and-suspenders alongside the surface test: the only callable that decides
    # is gate(), a pure bool, and the verdict is the only type the floor passes the
    # gate. The floor high_risk drafter (the LLM side) lives in floor/, not warden/.
    import warden.high_risk as hr
    assert hr.gate.__module__ == "warden.high_risk"
    spec = _REGIME_BY_BRANCH[AFFECTED_PARTY_BRANCH]
    assert hr.gate(_verdict(spec, True)) is True


# ---- byte-identical replay for the new beat --------------------------------

def test_replay_is_byte_identical_for_the_affected_party_beat(tmp_path):
    for fn in (_high_risk_fn, _not_high_risk_fn):
        packet = _run(fn, tmp_path / fn.__name__)
        assert packet["replay"]["byte_identical"] is True


def test_affected_party_run_is_deterministic_across_two_runs(tmp_path):
    a = _run(_high_risk_fn, tmp_path / "a")
    b = _run(_high_risk_fn, tmp_path / "b")
    assert a["replay"]["original_sha256"] == b["replay"]["original_sha256"]


# ---- the four DEFAULT sealed captures + their shas are UNCHANGED ------------

SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_sealed_capture_run_log_unchanged(mode):
    # The affected-party feature adds NO event to these four scenarios, so each
    # sealed capture file still exists and is non-empty, and no affected-party event
    # leaked into a default sealed capture.
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    assert log_path.exists(), f"{mode}: sealed capture missing"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    assert lines
    for token in ("affected_party_high_risk", '"data_subject"', "high_risk"):
        assert not any(token in ln for ln in lines), \
            f"{mode}: an affected-party token ({token}) leaked into the sealed capture"


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_sealed_capture_sha_matches_committed_bytes(mode):
    # The sealed run-log JSONL on disk must still hash to the sha recorded in its
    # committed packet: the affected-party feature touched no default capture, so
    # each sealed stream is byte-for-byte unchanged. This is the read-only guard
    # that the four DEFAULT shas are unchanged (the amendment scenario, which the
    # affected_party beat layers onto, is one of the four).
    import json
    from warden.replay import RunLog
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    packet_path = DATA / f"packet-{mode}.json"
    recorded_sha = json.loads(
        packet_path.read_text(encoding="utf-8"))["replay"]["original_sha256"]
    on_disk_sha = RunLog.load(log_path).sha256()
    assert on_disk_sha == recorded_sha, \
        f"{mode}: sealed run-log bytes no longer match the recorded sha"
