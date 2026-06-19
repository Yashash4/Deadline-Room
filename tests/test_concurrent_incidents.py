"""test_concurrent_incidents.py -- E6.1: two breaches, ONE Warden.

The Warden holds nothing per-incident: its state machine is dict[correlation_id ->
State], its ledger is dict[dedup_key -> entry], its clocks key on correlation id,
its chain folds an opaque stream. So running two incidents at once is a NAMESPACING
change, and these tests pin the headline guarantee ACROSS both keyspaces:

  - each incident reaches 'released' independently;
  - a drafter kill in incident B is dropped EXACTLY ONCE by the SHARED ledger while
    incident A is untouched;
  - the interleaved concurrent log replays byte-identically and is deterministic;
  - the Incident namespace default reproduces the single-incident correlation ids,
    dedup keys, and clock ids exactly (so the four sealed captures are untouched).
"""

from floor.run_floor import (
    CANONICAL_FACTS, DRAFTER_ROLES, INCIDENT_ID, INCIDENT_T0, Incident,
    run_concurrent)


# ---- the Incident namespace default is byte-identical to the constants --------

def test_canonical_incident_is_the_module_constants():
    inc = Incident.canonical()
    assert inc.id == INCIDENT_ID
    assert inc.t0 == INCIDENT_T0
    assert inc.facts == CANONICAL_FACTS
    assert inc.branches == tuple(r.branch for r in DRAFTER_ROLES)


def test_canonical_incident_correlation_and_dedup_keys_match_floor_shapes():
    inc = Incident.canonical()
    # branch_corr in the floor is f"{INCIDENT_ID}:{branch}".
    assert inc.correlation_id("nis2") == f"{INCIDENT_ID}:nis2"
    assert inc.correlation_id("sec") == f"{INCIDENT_ID}:sec"
    # the floor's fact-record and draft dedup-key shapes.
    assert inc.factrecord_key() == f"factrecord:{INCIDENT_ID}"
    assert inc.draft_key("sec") == f"draft:sec:{INCIDENT_ID}:round-1"
    assert inc.draft_key("nis2", "round-2-corrected") == \
        f"draft:nis2:{INCIDENT_ID}:round-2-corrected"


def test_two_incidents_never_share_a_namespace():
    a = Incident.canonical()
    b = Incident(id="inc-9001", t0="2026-06-16T05:40:00+00:00",
                 facts=dict(CANONICAL_FACTS), branches=("nis2", "sec", "dora"))
    for branch in a.branches:
        assert a.correlation_id(branch) != b.correlation_id(branch)
        assert a.draft_key(branch) != b.draft_key(branch)
    assert a.factrecord_key() != b.factrecord_key()


# ---- each incident reaches released independently -----------------------------

def test_both_incidents_reach_released(tmp_path):
    result = run_concurrent(out_dir=str(tmp_path))
    assert result["all_released"] is True
    assert len(result["incidents"]) == 2
    for inc_id in result["incidents"]:
        states = result["incident_states"][inc_id]
        assert states, f"{inc_id} produced no branch states"
        assert all(s == "released" for s in states.values()), \
            f"{inc_id} did not fully release: {states}"


def test_each_incident_has_its_own_three_branches(tmp_path):
    result = run_concurrent(out_dir=str(tmp_path))
    for inc_id in result["incidents"]:
        assert set(result["incident_states"][inc_id]) == {"nis2", "sec", "dora"}


# ---- the B-kill is dropped exactly once; A is untouched -----------------------

def test_kill_in_b_dropped_exactly_once_by_shared_ledger(tmp_path):
    result = run_concurrent(out_dir=str(tmp_path), kill_branch="sec", kill_incident=1)
    # Exactly one duplicate dropped across the WHOLE shared ledger.
    assert result["duplicates_dropped"] == 1
    kill_inc = result["kill_incident"]
    # The single dropped key belongs to the killed branch of the killed incident.
    dropped = [e for e in result["ledger"]
               if e["disposition"] == "duplicate_dropped"]
    assert len(dropped) == 1
    assert dropped[0]["key"] == f"draft:sec:{kill_inc}:round-1"
    assert dropped[0]["attempt"] == 2


def test_kill_in_b_leaves_incident_a_untouched(tmp_path):
    result = run_concurrent(out_dir=str(tmp_path), kill_branch="sec", kill_incident=1)
    a_id = result["incidents"][0]
    # No A-namespaced key was ever dropped; A still releases every branch.
    a_dropped = [e for e in result["ledger"]
                 if e["disposition"] == "duplicate_dropped" and a_id in e["key"]]
    assert a_dropped == []
    a_states = result["incident_states"][a_id]
    assert all(s == "released" for s in a_states.values())
    # And A's three draft keys were each accepted exactly once.
    for branch in ("nis2", "sec", "dora"):
        accepted = [e for e in result["ledger"]
                    if e["key"] == f"draft:{branch}:{a_id}:round-1"
                    and e["disposition"] == "accepted"]
        assert len(accepted) == 1


def test_kill_branch_still_releases_after_dropping_the_duplicate(tmp_path):
    # Exactly-once means the duplicate is dropped, NOT that the branch fails: the
    # killed branch still files once and reaches released.
    result = run_concurrent(out_dir=str(tmp_path), kill_branch="sec", kill_incident=1)
    kill_inc = result["kill_incident"]
    assert result["incident_states"][kill_inc]["sec"] == "released"


# ---- the interleaved log replays byte-identically and is deterministic --------

def test_interleaved_log_replays_byte_identical(tmp_path):
    result = run_concurrent(out_dir=str(tmp_path))
    assert result["replay_byte_identical"] is True


def test_concurrent_run_is_deterministic(tmp_path):
    a = run_concurrent(out_dir=str(tmp_path / "a"))
    b = run_concurrent(out_dir=str(tmp_path / "b"))
    # Same interleave schedule, same fixed timestamps: identical chain head and
    # identical run-log sha across independent runs.
    assert a["chain_head"] == b["chain_head"]
    assert a["run_log_sha256"] == b["run_log_sha256"]
    assert a["incident_states"] == b["incident_states"]
    assert a["ledger"] == b["ledger"]


def test_a_clean_concurrent_run_drops_nothing(tmp_path):
    # With no kill, every draft key across both incidents is accepted once; the
    # shared ledger drops zero duplicates.
    result = run_concurrent(out_dir=str(tmp_path), kill_branch="sec",
                            kill_incident=99)  # kill_incident out of range -> no kill
    assert result["duplicates_dropped"] == 0
    assert all(e["disposition"] == "accepted" for e in result["ledger"])
    assert result["all_released"] is True


# ---- a custom interleave keeps the cross-incident guarantee -------------------

def test_custom_interleave_still_releases_both_and_replays(tmp_path):
    def front_loaded(stream_list):
        # Drain incident A fully, then incident B fully (a different deterministic
        # schedule). The shared Warden must still release both and replay identically.
        for stream in stream_list:
            for _label, step in stream:
                yield step

    result = run_concurrent(out_dir=str(tmp_path), interleave=front_loaded)
    assert result["all_released"] is True
    assert result["replay_byte_identical"] is True
    assert result["duplicates_dropped"] == 1
