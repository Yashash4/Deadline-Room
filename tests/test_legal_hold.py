"""test_legal_hold.py -- the legal-hold / preservation obligation (E3.10).

The instant a breach is reasonably anticipated to lead to litigation or a
regulatory inquiry (which is when this war room convenes), the duty to PRESERVE
evidence attaches: preserve the affected systems and data, suspend routine
deletion. Failure to issue the hold is independent spoliation liability under
FRCP 37(e), separate from the breach. The room raises the hold AS a tracked
obligation:

  * it ATTACHES at incident detection (anchored at INCIDENT_T0), scoped
    deterministically from the affected-systems / affected-data-categories fields
    of the canonical fact-record (each scope item bound to the EXACT field);
  * it is a STANDING obligation: it stays ACTIVE until counsel explicitly RELEASES
    it (a human signoff), never auto-released by a clock, a filing, or any rule;
  * the scope->fact binding and the record shape are deterministic Python
    (floor/legal_hold.py); the pure warden/legal_hold.py validator confirms every
    cited field exists (no fabricated scope item);
  * it GATES NOTHING: no filing is held, suppressed, or released by it; it is a
    parallel preservation duty alongside the breach-notification track.

These tests pin the contract:
  * the hold attaches at incident detection with the scope bound to the real
    affected systems + data_categories fields;
  * it stays active until an explicit human release (no auto-release);
  * the scope validator REJECTS a hold citing a nonexistent fact field;
  * it NEVER gates a filing (no release / suppress decision flows from the hold);
  * the four DEFAULT sealed captures and their shas are UNCHANGED;
  * byte-identical replay for the legal-hold beat.
"""

from pathlib import Path

import pytest

from warden.legal_hold import (
    LegalHold, LegalHoldAlreadyReleased, LegalHoldRelease, PRESERVATION_BASIS,
    PreservationScopeCheck, PreservationScopeItem, STATE_ACTIVE, STATE_RELEASED,
    validate_legal_hold)
from floor.legal_hold import build_legal_hold
from floor.run_floor import (
    CANONICAL_FACTS, DRAFTER_ROLES, INCIDENT_ID, INCIDENT_T0,
    LEGAL_HOLD_RELEASE_ACTOR, LEGAL_HOLD_RELEASE_ROLE, TS_LEGAL_HOLD_RELEASE,
    run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

DATA = Path(__file__).resolve().parent.parent / "web" / "data"


# ---- test plumbing (mirrors the determination / materiality suites) ---------

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


def _run_legal_hold(tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="legal_hold", clients=clients,
                     draft_fns=_stub_draft_fns())


# ---- the record shape: scope bound to the real affected fields --------------

def test_builder_binds_scope_to_the_real_affected_systems_and_data_fields():
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0,
        fact_record=CANONICAL_FACTS)
    assert isinstance(hold, LegalHold)
    assert hold.scope, "the hold must carry a preservation scope"
    # Every scope item names the EXACT canonical fact-record field it rests on, and
    # that field exists in the record (no free-text scope item).
    for item in hold.scope:
        assert isinstance(item, PreservationScopeItem)
        assert item.fact_field in CANONICAL_FACTS, \
            f"scope item {item.category!r} binds to {item.fact_field!r} not in CANONICAL_FACTS"
    # The affected systems and data categories ARE the preservation scope, read
    # straight off the canonical record.
    by_field = {item.fact_field: item for item in hold.scope}
    assert "systems" in by_field
    assert "data_categories" in by_field
    assert by_field["systems"].value == ", ".join(CANONICAL_FACTS["systems"])
    assert by_field["data_categories"].value == ", ".join(CANONICAL_FACTS["data_categories"])


def test_hold_attaches_at_incident_detection_active_with_the_preservation_basis():
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0,
        fact_record=CANONICAL_FACTS)
    # It attaches at incident detection (anchored at INCIDENT_T0) and is ACTIVE.
    assert hold.attached_at == INCIDENT_T0
    assert hold.trigger_event == "incident detection"
    assert hold.state == STATE_ACTIVE
    assert hold.active is True
    assert hold.release is None
    # The basis is the FRCP 37(e) spoliation / preservation duty.
    assert hold.basis == PRESERVATION_BASIS
    assert "FRCP 37(e)" in hold.basis


# ---- it stays active until an explicit human release (no auto-release) -------

def test_hold_stays_active_until_an_explicit_human_release():
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0,
        fact_record=CANONICAL_FACTS)
    assert hold.state == STATE_ACTIVE
    # A human (counsel) explicitly releases it; only then does it leave the active
    # state. The state is derived from the release record, never set independently.
    released = hold.released_hold(
        released_by="general_counsel", actor="gc",
        ts=TS_LEGAL_HOLD_RELEASE, reason="matter resolved")
    assert released.state == STATE_RELEASED
    assert released.active is False
    assert isinstance(released.release, LegalHoldRelease)
    assert released.release.released_by == "general_counsel"
    assert released.release.actor == "gc"
    # The original hold is unchanged (frozen dataclass: release is a pure
    # transition to a new value, never a mutation).
    assert hold.state == STATE_ACTIVE


def test_hold_is_never_released_twice():
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0,
        fact_record=CANONICAL_FACTS)
    released = hold.released_hold(
        released_by="general_counsel", actor="gc",
        ts=TS_LEGAL_HOLD_RELEASE, reason="matter resolved")
    # A second release is structural, never a silent overwrite of the original
    # human release record.
    with pytest.raises(LegalHoldAlreadyReleased):
        released.released_hold(
            released_by="general_counsel", actor="someone_else",
            ts="2026-06-17T00:00:00+00:00", reason="again")


def test_state_field_is_derived_from_the_release_record_not_set_independently():
    # The state cannot be "released" without a release record, and cannot be
    # "active" with one: the state is a pure derivation, so no caller can fake a
    # release by flipping a flag.
    active = LegalHold(
        incident_id=INCIDENT_ID, trigger_event="incident detection",
        attached_at=INCIDENT_T0,
        scope=(PreservationScopeItem("Affected systems", "x", "systems"),))
    assert active.state == STATE_ACTIVE and active.release is None
    released = LegalHold(
        incident_id=INCIDENT_ID, trigger_event="incident detection",
        attached_at=INCIDENT_T0,
        scope=(PreservationScopeItem("Affected systems", "x", "systems"),),
        release=LegalHoldRelease("general_counsel", "gc",
                                 TS_LEGAL_HOLD_RELEASE, "done"))
    assert released.state == STATE_RELEASED and released.release is not None


# ---- the validator: rejects a scope item citing a nonexistent field ---------

def test_validator_accepts_a_fully_grounded_hold():
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0,
        fact_record=CANONICAL_FACTS)
    check = validate_legal_hold(hold, CANONICAL_FACTS)
    assert isinstance(check, PreservationScopeCheck)
    assert check.complete is True
    assert check.missing_items == ()
    assert set(check.cited_fields) == {item.fact_field for item in hold.scope}


def test_validator_rejects_a_scope_item_citing_a_nonexistent_field():
    # A fabricated scope item that cites a field the fact-record does not carry.
    hold = LegalHold(
        incident_id=INCIDENT_ID, trigger_event="incident detection",
        attached_at=INCIDENT_T0,
        scope=(
            PreservationScopeItem("Affected systems",
                                  "core banking ledger", "systems"),
            PreservationScopeItem("Fabricated scope", "ghost",
                                  "nonexistent_field"),
        ))
    check = validate_legal_hold(hold, CANONICAL_FACTS)
    assert check.complete is False
    assert check.missing_items == (("Fabricated scope", "nonexistent_field"),)
    # The grounded item is still reported as cited; only the fabricated one is
    # flagged missing.
    assert "systems" in check.cited_fields
    assert "nonexistent_field" in check.cited_fields


def test_builder_keeps_binding_for_a_missing_field_so_validator_can_flag_it():
    # A fact-record missing one of the scope fields: the item binding is kept (not
    # silently dropped) so the validator flags it, never hides it.
    facts = {k: v for k, v in CANONICAL_FACTS.items() if k != "data_categories"}
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0, fact_record=facts)
    assert any(item.fact_field == "data_categories" for item in hold.scope)
    check = validate_legal_hold(hold, facts)
    assert check.complete is False
    assert any(field == "data_categories" for _, field in check.missing_items)


def test_validator_is_pure_and_deterministic():
    hold = build_legal_hold(
        incident_id=INCIDENT_ID, attached_at=INCIDENT_T0,
        fact_record=CANONICAL_FACTS)
    a = validate_legal_hold(hold, CANONICAL_FACTS)
    b = validate_legal_hold(hold, CANONICAL_FACTS)
    assert a == b


# ---- the hold gates nothing (no release / suppress flows from it) -----------

def test_warden_legal_hold_module_exposes_no_gate_or_suppress_surface():
    import warden.legal_hold as lh
    # No gate / suppress / clock-stop / llm surface in the public API. (The hold
    # carries "active" / "release" lifecycle members, but never a verb that gates,
    # suppresses, stops a statutory clock, or invokes a model.)
    for forbidden in ("gate", "suppress", "stop_clock", "llm", "block_filing"):
        assert not any(forbidden in n.lower() for n in dir(lh)
                       if not n.startswith("_")), \
            f"warden.legal_hold must not expose a {forbidden!r} surface"


def test_legal_hold_does_not_gate_or_suppress_any_filing(tmp_path):
    # The legal-hold beat rides the clean release path: all three regulator
    # branches file and release exactly as a normal run. The hold gates nothing,
    # so no branch is held, suppressed, or released because of it.
    packet = _run_legal_hold(tmp_path)
    regimes = {f["regime"] for f in packet["filings"]}
    assert {"NIS2", "SEC", "DORA"} <= regimes, \
        "every regulator branch must still file; the hold suppresses none"
    # The released branches are exactly the regulator branches; the hold added no
    # branch and removed none.
    assert set(packet["release"]["released_branches"]) == {"nis2", "sec", "dora"}
    # The hold record itself never carries a file/suppress disposition: it is a
    # preservation obligation, not a gate verdict.
    lh = packet["legal_hold"]
    assert "disposition" not in lh
    assert "suppressed" not in lh


def test_legal_hold_record_does_not_appear_in_any_clock_stop(tmp_path):
    # The hold's own attach / release events are NOT clock_started / clock_stopped
    # events, so they never enter the statutory-clock audit predicate and never
    # stop a statutory clock. Only the four statutory clocks are stopped.
    packet = _run_legal_hold(tmp_path)
    log_path = Path(packet["_paths"]["run_log"])
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    stops = [ln for ln in lines if '"type":"clock_stopped"' in ln]
    # The legal hold issued no clock_stopped (it stops no statutory clock); the
    # only clock stops are the regulator branches' own releases.
    assert all("legal_hold" not in ln for ln in stops)


# ---- the beat: attaches at detection, releases by human, sealed + replayed ---

def test_beat_attaches_the_hold_at_incident_detection(tmp_path):
    packet = _run_legal_hold(tmp_path)
    lh = packet["legal_hold"]
    assert lh["trigger_event"] == "incident detection"
    assert lh["attached_at"] == INCIDENT_T0
    # The scope is bound to the real affected fields, both present and complete.
    fields = {item["fact_field"] for item in lh["scope"]}
    assert fields == {"systems", "data_categories"}
    assert lh["preservation_scope"]["complete"] is True


def test_beat_releases_only_by_an_explicit_human_signoff(tmp_path):
    packet = _run_legal_hold(tmp_path)
    lh = packet["legal_hold"]
    # After the regulator branches release, counsel explicitly lifts the hold.
    assert lh["state"] == "released"
    rel = lh["release"]
    assert rel is not None
    assert rel["released_by"] == LEGAL_HOLD_RELEASE_ROLE
    assert rel["actor"] == LEGAL_HOLD_RELEASE_ACTOR
    assert rel["ts"] == TS_LEGAL_HOLD_RELEASE
    # The recorded basis makes plain a human, not a rule or a model, lifted it.
    assert "human signoff" in rel["reason"]


def test_beat_logs_attach_and_release_as_additive_events(tmp_path):
    packet = _run_legal_hold(tmp_path)
    log_path = Path(packet["_paths"]["run_log"])
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    attached = [ln for ln in lines if '"type":"legal_hold_attached"' in ln]
    released = [ln for ln in lines if '"type":"legal_hold_released"' in ln]
    assert len(attached) == 1, "exactly one legal_hold_attached event in the beat"
    assert len(released) == 1, "exactly one legal_hold_released event in the beat"
    # The attach is sealed with a complete preservation scope.
    assert '"preservation_scope_complete":true' in attached[0]


def test_beat_replay_is_byte_identical(tmp_path):
    packet = _run_legal_hold(tmp_path)
    assert packet["replay"]["byte_identical"] is True


def test_beat_is_deterministic_across_two_runs(tmp_path):
    # Same beat -> identical run-log sha: the hold build + validate + log path
    # reads no now()/RNG.
    a = _run_legal_hold(tmp_path / "a")
    b = _run_legal_hold(tmp_path / "b")
    assert a["replay"]["original_sha256"] == b["replay"]["original_sha256"]


def test_beat_renders_in_the_packet_html(tmp_path):
    packet = _run_legal_hold(tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Legal hold / preservation obligation" in html
    assert "FRCP 37(e)" in html
    assert "Bound to fact-record field" in html
    # The affected systems and data categories render as the scope.
    assert "core banking ledger" in html


# ---- the four DEFAULT sealed captures + their shas are UNCHANGED -------------

SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_no_legal_hold_event_leaked_into_a_sealed_capture(mode):
    # The legal-hold events ride ONLY the legal_hold beat, so they must NOT appear
    # in any of the four default sealed captures.
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    assert log_path.exists(), f"{mode}: sealed capture missing"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines
    assert not any('"legal_hold_attached"' in ln or '"legal_hold_released"' in ln
                   for ln in lines), \
        f"{mode}: a legal_hold event leaked into the sealed capture"


def test_default_normal_run_sha_unchanged():
    # A fresh default normal run (no legal-hold beat) must still reproduce the
    # sealed normal sha byte for byte: the legal-hold code is dormant unless the
    # beat runs, so it cannot have moved the default stream.
    from tests.test_operability_report import (
        SEALED_NORMAL_SHA, _build_clients as _bc, _stub_draft_fns as _sd)
    import tempfile
    room, clients = _bc()
    with tempfile.TemporaryDirectory() as td:
        packet = run_floor(out_dir=td, mode="normal", clients=clients,
                           draft_fns=_sd())
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA
