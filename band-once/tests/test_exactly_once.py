"""Exactly-once fuzz for the band-once ledger and conformance check.

A retargeted slice of the production exactly-once fuzz: a large, SEEDED duplicate
storm straight through the IdempotencyLedger (the component whose whole job is to
admit a key exactly once under a flood of re-deliveries), plus the public
verify_exactly_once prover over the reference correct agent and a deliberately
buggy one. A fixed master seed keeps it deterministic and fast.
"""

import random

from band_once.ledger import Disposition, IdempotencyLedger
from band_once.verify import (
    ConformanceResult,
    clean_echo_agent,
    verify_exactly_once,
)

MASTER_SEED = 20260616


def test_n_duplicate_storm_admits_exactly_one_per_key():
    # The ledger's core job, hit directly with a flood: thousands of deliveries
    # of a handful of keys, interleaved in random order with random attempt
    # numbers. Exactly one ACCEPTED per key, every later delivery dropped.
    rng = random.Random(424242)
    ledger = IdempotencyLedger()
    keys = [f"work:k{k}:job-1:round-1" for k in range(6)]
    deliveries = [(rng.choice(keys), rng.randint(1, 9)) for _ in range(5000)]
    rng.shuffle(deliveries)
    for key, attempt in deliveries:
        ledger.record(key, attempt, "2026-06-16T03:10:00+00:00")
    accepted = [e for e in ledger.history() if e.disposition is Disposition.ACCEPTED]
    assert len(accepted) == len(keys)                # exactly one accept per key
    assert {e.dedup_key for e in accepted} == set(keys)
    assert ledger.duplicates_dropped() == len(deliveries) - len(keys)
    assert len(ledger.history()) == len(deliveries)  # nothing lost, nothing invented


def test_duplicate_storm_is_order_independent_across_seeds():
    # The exactly-once count must not depend on the interleaving order: across
    # many seeds the accepted set is always the distinct keys, never more.
    keys = [f"work:k{k}:job-1:round-1" for k in range(6)]
    for seed in range(50):
        rng = random.Random(seed)
        ledger = IdempotencyLedger()
        deliveries = [(rng.choice(keys), rng.randint(1, 9)) for _ in range(1200)]
        rng.shuffle(deliveries)
        for key, attempt in deliveries:
            ledger.record(key, attempt, "2026-06-16T03:10:00+00:00")
        assert ledger.accepted_keys() == set(keys)
        accepted = [e for e in ledger.history()
                    if e.disposition is Disposition.ACCEPTED]
        assert len(accepted) == len(keys)


def test_verify_passes_the_reference_clean_agent():
    result = verify_exactly_once(clean_echo_agent, schedules=200, seed=MASTER_SEED)
    assert isinstance(result, ConformanceResult)
    assert result.ok is True
    assert bool(result) is True
    assert result.schedules_checked == 200
    assert result.first_violating_seed is None
    assert result.reason == ""


def test_verify_names_first_violating_schedule_on_a_double_posting_agent():
    # A buggy agent that records the work and returns ACCEPTED on EVERY delivery,
    # ignoring the ledger's verdict, so a redelivery double-posts.
    def buggy_factory():
        def agent(ledger, dedup_key, attempt, ts):
            ledger.record(dedup_key, attempt, ts)
            return Disposition.ACCEPTED
        return agent

    result = verify_exactly_once(buggy_factory, schedules=200, seed=MASTER_SEED)
    assert result.ok is False
    assert bool(result) is False
    # The grader names the FIRST violating schedule (the first seed it tries).
    assert result.first_violating_seed == MASTER_SEED
    assert result.schedules_checked == 1
    assert "ACCEPTED" in result.reason and "double-post" in result.reason


def test_verify_names_lost_message_on_an_agent_that_drops_work():
    # A buggy agent that ALWAYS drops, so every delivered key is lost.
    def dropping_factory():
        def agent(ledger, dedup_key, attempt, ts):
            return Disposition.DUPLICATE_DROPPED
        return agent

    result = verify_exactly_once(dropping_factory, schedules=50, seed=MASTER_SEED)
    assert result.ok is False
    assert result.first_violating_seed == MASTER_SEED
    assert "lost message" in result.reason


def test_verify_is_deterministic():
    a = verify_exactly_once(clean_echo_agent, schedules=120, seed=777)
    b = verify_exactly_once(clean_echo_agent, schedules=120, seed=777)
    assert a == b
