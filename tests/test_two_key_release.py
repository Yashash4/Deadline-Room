"""test_two_key_release.py -- segregation of duties on the human release.

A filing releases only when BOTH distinct human keys sign: Lena (Head of IR) AND
the General Counsel. One key alone never turns the lock; the same key twice never
turns it either. Covers the deterministic gate in isolation and end to end on the
full floor (the floor always drives two-key release, so every released branch
carries two distinct sign-offs).
"""

import json
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


# ---- the segregation-of-duties INVARIANT (initial AND amendment) -----------
# This is the regression guard for the amendment two-key bug: the amendment
# re-release once fired HUMAN_RELEASED directly on a single key ("lena"), no GC,
# because the state-machine authority table checks the role CLASS, not the
# two-key collection. The largest material change (records 48,211 -> 2,100,000)
# got the fewest approvals. The invariant below scans the replayable run log and
# asserts EVERY admitted release (initial AND amendment, every branch) was backed
# by a gate decision carrying BOTH distinct keys. If the amendment ever bypasses
# the two-key gate again, this fails.

def _load_log(path):
    return [json.loads(line) for line in
            Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _every_release_required_two_distinct_keys(entries):
    """Walk the run log in order. For every admitted human_released protocol
    event, the immediately preceding release_signoff for that branch must be the
    decision that flipped to released:true while carrying BOTH distinct required
    roles. Also asserts that decision was preceded by a withheld single-key step,
    so a release can never come from one key. Returns the number of releases
    checked so the caller can assert it is non-zero."""
    # Per-branch running view of the most recent gate decision sequence.
    pending = {}          # corr -> list of (role, released) since last release
    releases_checked = 0
    for e in entries:
        typ = e.get("type")
        payload = e.get("payload", {})
        if typ == "release_signoff":
            corr = payload["correlation_id"]
            pending.setdefault(corr, []).append(
                (payload["role"], payload["released"], frozenset(payload["have_roles"])))
        elif typ == "protocol_event" and payload.get("event") == "human_released" \
                and payload.get("admitted"):
            corr = payload["correlation_id"]
            seq = pending.get(corr, [])
            assert seq, f"human_released for {corr} with no release_signoff trail"
            # the LAST recorded decision before this release must be released:true
            last_role, last_released, last_have = seq[-1]
            assert last_released is True, (
                f"{corr} released without a released:true gate decision")
            assert last_have == frozenset({"general_counsel", "head_of_ir"}), (
                f"{corr} released without both distinct keys; had {sorted(last_have)}")
            # at least two DISTINCT signing roles appear in this release block
            roles_in_block = {r for (r, _rel, _have) in seq}
            assert roles_in_block == {"general_counsel", "head_of_ir"}, (
                f"{corr} release block did not collect two distinct keys; "
                f"saw {sorted(roles_in_block)}")
            # the block must contain a withheld single-key step (no one-key release)
            assert any(rel is False for (_r, rel, _h) in seq), (
                f"{corr} released with no prior single-key-withheld step")
            releases_checked += 1
            pending[corr] = []   # reset for any subsequent (amendment) release
    return releases_checked


def test_invariant_every_initial_release_required_two_keys(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
              draft_fns=_stub_draft_fns())
    entries = _load_log(Path(tmp_path) / "run-inc-8842-normal.jsonl")
    n = _every_release_required_two_distinct_keys(entries)
    assert n >= 1, "no releases were found to verify in the normal run"


def test_invariant_amendment_re_release_also_required_two_keys(tmp_path):
    # The regression guard for the fixed bug. The amendment branches (SEC, NIS2)
    # release TWICE each: once initially, once after the fact amendment. Every one
    # of those releases must carry both distinct keys, including the amendment.
    from tests.test_amendment_floor import (_build_clients as _amend_clients,
                                            _stub_draft_fns as _amend_draft_fns)
    room, clients = _amend_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="amendment", clients=clients,
                       draft_fns=_amend_draft_fns())
    entries = _load_log(Path(tmp_path) / "run-inc-8842-amendment.jsonl")
    n = _every_release_required_two_distinct_keys(entries)
    # 3 initial releases (sec, nis2, dora) + 2 amendment re-releases (sec, nis2)
    assert n == 5, f"expected 5 two-key releases in the amendment run, saw {n}"
    # and the run still replays byte for byte with the corrected release path
    assert packet["replay"]["byte_identical"] is True
