"""test_two_key_release.py -- segregation of duties on the human release.

A filing releases only when BOTH distinct human keys sign: Lena (Head of IR) AND
the General Counsel. One key alone never turns the lock; the same key twice never
turns it either. Covers the deterministic gate in isolation and end to end on the
full floor (the floor always drives two-key release, so every released branch
carries two distinct sign-offs).
"""

from pathlib import Path

import pytest

from warden.release_gate import REQUIRED_ROLES, TwoKeyReleaseGate
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom


T = "2026-06-16T05:00:00+00:00"


# ---- the gate in isolation -------------------------------------------------

def test_one_key_does_not_release():
    gate = TwoKeyReleaseGate()
    d = gate.sign("inc-1:sec", "general_counsel", "gc", T)
    assert d.released is False
    assert "head_of_ir" in d.missing_roles
    assert gate.can_release("inc-1:sec") is False


def test_two_distinct_keys_release():
    gate = TwoKeyReleaseGate()
    gate.sign("inc-1:sec", "general_counsel", "gc", T)
    d = gate.sign("inc-1:sec", "head_of_ir", "lena", T)
    assert d.released is True
    assert d.missing_roles == frozenset()
    assert gate.can_release("inc-1:sec") is True


def test_same_key_twice_is_not_two_keys():
    gate = TwoKeyReleaseGate()
    gate.sign("inc-1:sec", "head_of_ir", "lena", T)
    d = gate.sign("inc-1:sec", "head_of_ir", "lena", T)  # same role again
    assert d.released is False
    assert "general_counsel" in d.missing_roles


def test_unknown_role_is_rejected():
    gate = TwoKeyReleaseGate()
    with pytest.raises(ValueError):
        gate.sign("inc-1:sec", "intern", "someone", T)


def test_gate_is_per_branch():
    gate = TwoKeyReleaseGate()
    gate.sign("inc-1:sec", "general_counsel", "gc", T)
    gate.sign("inc-1:sec", "head_of_ir", "lena", T)
    # a different branch has its own lock and is still closed
    assert gate.can_release("inc-1:sec") is True
    assert gate.can_release("inc-1:nis2") is False


def test_required_roles_are_the_two_humans():
    assert REQUIRED_ROLES == frozenset({"head_of_ir", "general_counsel"})


# ---- end to end on the full floor -----------------------------------------

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
                    f"{claim_facts['records_affected']} records, "
                    f"{claim_facts['attacker']}, {claim_facts['containment']}.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def test_floor_release_records_two_distinct_human_signoffs(tmp_path):
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns())
    rel = packet["release"]
    assert sorted(rel["required_roles"]) == ["general_counsel", "head_of_ir"]
    # every released branch carries exactly the two distinct human roles
    for b in rel["released_branches"]:
        roles = sorted(s["role"] for s in rel["signoffs"]
                       if s["correlation_id"].endswith(f":{b}"))
        assert roles == ["general_counsel", "head_of_ir"]


def test_floor_release_log_shows_first_key_withheld(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
              draft_fns=_stub_draft_fns())
    run_log = Path(tmp_path) / "run-inc-8842-normal.jsonl"
    text = run_log.read_text(encoding="utf-8")
    # the GC signs first and the release is WITHHELD (released:false), then Lena
    # signs and it releases (released:true). Both appear in the replayable log.
    assert '"released": false' in text or '"released":false' in text
    assert '"role": "general_counsel"' in text or '"role":"general_counsel"' in text
    assert '"role": "head_of_ir"' in text or '"role":"head_of_ir"' in text


def test_floor_html_shows_two_key_section(tmp_path):
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns())
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Two-key release" in html
    assert "general_counsel" in html
    assert "head_of_ir" in html
