"""test_exactly_once.py — run the incident N times with randomized kill
points (both crash positions) and assert the filing set is invariant and
never double-counted. Direct fix for the postmortem's 'ship tests' lesson."""

import random

from warden.simulate import BRANCHES, KillSchedule, run_incident

N_RUNS = 50


def random_schedule(rng: random.Random) -> KillSchedule:
    kills = {}
    for b in BRANCHES:
        n_kills = rng.choice([0, 0, 1, 1, 2])  # bias toward some chaos
        for attempt in range(1, n_kills + 1):
            kills[(b, attempt)] = rng.choice(["A", "B"])
    return KillSchedule(kills)


def test_baseline_no_chaos():
    r = run_incident()
    assert set(r.filings) == set(BRANCHES)
    assert r.duplicates_dropped == 0
    assert r.breached_clocks == []


def test_filing_set_invariant_under_randomized_kills():
    baseline = run_incident().filings
    rng = random.Random(8842)
    for i in range(N_RUNS):
        schedule = random_schedule(rng)
        r = run_incident(kill_schedule=schedule)
        assert r.filings == baseline, f"run {i}: filings diverged under {schedule.kills}"
        assert r.breached_clocks == []


def test_position_b_duplicate_is_dropped_not_double_counted():
    r = run_incident(kill_schedule=KillSchedule({("nis2", 1): "B"}))
    assert r.duplicates_dropped >= 1
    assert set(r.filings) == set(BRANCHES)
    # exactly one accepted nis2 round-1 draft, ever:
    ledger_entries = [e for e in r.log.entries() if e["type"] == "ledger"
                      and e["payload"]["key"] == "draft:nis2:inc-8842:round-1"]
    accepted = [e for e in ledger_entries if e["payload"]["disposition"] == "accepted"]
    assert len(accepted) == 1
