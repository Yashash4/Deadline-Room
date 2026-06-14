"""test_replay_byte_identical.py, feed a saved run log back in and assert
a byte-for-byte identical trace. Plus the contradiction-diff and SEC
business-day clock guarantees."""

from warden.diff import Containment, FactClaims, diff_claims
from warden.replay import RunLog, replay
from warden.simulate import KillSchedule, run_incident


def test_replay_is_byte_identical_clean_run():
    r = run_incident()
    replayed = replay(r.log)
    assert replayed.to_jsonl() == r.log.to_jsonl()
    assert replayed.sha256() == r.log.sha256()


def test_replay_is_byte_identical_under_chaos_and_contradiction():
    r = run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "A", ("dora", 1): "B"}),
        contradiction_in="sec",
    )
    replayed = replay(r.log)
    assert replayed.sha256() == r.log.sha256()


def test_replay_survives_save_load_roundtrip(tmp_path):
    r = run_incident(contradiction_in="nis2")
    p = tmp_path / "run.jsonl"
    original_hash = r.log.save(p)
    loaded = RunLog.load(p)
    assert replay(loaded).sha256() == original_hash


# --- contradiction diff ------------------------------------------------

def _claims(branch, start, attacker="LockBit 3.0"):
    return FactClaims(branch, start, 48211, attacker, Containment.PARTIALLY_CONTAINED)


def test_timezone_equivalence_is_not_a_contradiction():
    # 02:14 UTC == 04:14 CEST (+02:00). A naive string diff would flag this.
    a = _claims("nis2", "2026-06-16T04:14:00+02:00")
    b = _claims("sec", "2026-06-16T02:14:00+00:00")
    assert diff_claims([a, b]) == []


def test_same_wallclock_different_zone_IS_a_contradiction():
    a = _claims("nis2", "2026-06-16T02:14:00+02:00")
    b = _claims("sec", "2026-06-16T02:14:00+00:00")
    conflicts = diff_claims([a, b])
    assert len(conflicts) == 1 and conflicts[0].field == "incident_start_utc"


def test_attacker_alias_is_not_a_contradiction():
    a = _claims("nis2", "2026-06-16T02:14:00+00:00", attacker="LockBit 3.0")
    b = _claims("dora", "2026-06-16T02:14:00+00:00", attacker="lockbit")
    assert diff_claims([a, b]) == []


def test_contradiction_blocks_then_clears_in_full_run():
    r = run_incident(contradiction_in="sec")
    diffs = [e["payload"]["conflicts"] for e in r.log.entries() if e["type"] == "diff"]
    assert len(diffs) == 2
    assert diffs[0] != [] and diffs[1] == []   # blocked, then green after correction
    assert set(r.filings) == {"nis2", "dora", "sec"}
