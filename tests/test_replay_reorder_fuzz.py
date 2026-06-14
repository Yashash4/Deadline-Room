"""Replay determinism + adversarial-reorder hardening.

test_replay_byte_identical.py proves a clean replay reproduces the sealed hash on
~3 happy schedules; test_chain.py proves ONE reorder/omission breaks the chain.
This file widens both to the full input space a depth-prober pokes:

  * replay is a PURE, DETERMINISTIC function of its log: replaying the same log
    a hundred times yields the same hash, and replay(replay(log)) is stable
    (idempotent), and
  * EVERY non-trivial reorder of the sealed log moves the chain head and is
    point-at-able (first_broken_index names a real index), across hundreds of
    random permutations, not a single swap.

Pure test additions. The replay path and chain module are unchanged, so the
byte-identical guarantee and the 282 core tests are untouched.
"""

import copy
import random

from warden.chain import chain_head, chain_over, first_broken_index
from warden.replay import RunLog, replay
from warden.simulate import KillSchedule, run_incident


def _sealed_log() -> RunLog:
    return run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "A", ("dora", 1): "B"}),
        contradiction_in="sec",
    ).log


# --- replay is a pure, deterministic function --------------------------

def test_replay_is_deterministic_across_many_runs():
    r = run_incident(kill_schedule=KillSchedule({("nis2", 1): "B"}),
                     contradiction_in="sec")
    h = replay(r.log).sha256()
    for _ in range(100):
        assert replay(r.log).sha256() == h


def test_replay_is_idempotent_replay_of_replay_is_stable():
    r = run_incident(kill_schedule=KillSchedule({("dora", 1): "A"}),
                     contradiction_in="nis2")
    once = replay(r.log)
    twice = replay(once)
    assert twice.to_jsonl() == once.to_jsonl()
    assert twice.sha256() == once.sha256()
    # and equal to the original log's bytes: replay is a fixed point of the log.
    assert once.to_jsonl() == r.log.to_jsonl()


def test_replay_does_not_mutate_its_input_log():
    log = _sealed_log()
    before_jsonl = log.to_jsonl()
    before_sha = log.sha256()
    replay(log)
    replay(log)
    assert log.to_jsonl() == before_jsonl
    assert log.sha256() == before_sha


# --- every non-trivial reorder is detected -----------------------------

def test_every_random_reorder_moves_the_chain_head_and_is_point_at_able():
    base = _sealed_log().entries()
    base_head = chain_head(base)
    base_chain = chain_over(base)
    rng = random.Random(7)
    nontrivial = 0
    for _ in range(500):
        perm = copy.deepcopy(base)
        rng.shuffle(perm)
        if perm == base:
            continue  # the identity permutation must NOT be flagged
        nontrivial += 1
        assert chain_head(perm) != base_head
        assert first_broken_index(perm, base_chain) is not None
    assert nontrivial > 400  # the sweep really did exercise reorderings


def test_identity_permutation_is_never_a_false_positive():
    base = _sealed_log().entries()
    base_chain = chain_over(base)
    # shuffling with a permutation that happens to be identity reports no break.
    assert first_broken_index(copy.deepcopy(base), base_chain) is None


def test_every_adjacent_swap_moves_the_head():
    # The single-swap case generalized: swapping ANY adjacent pair of entries
    # (not just the first two protocol events) moves the head.
    base = _sealed_log().entries()
    base_head = chain_head(base)
    base_chain = chain_over(base)
    for i in range(len(base) - 1):
        swapped = copy.deepcopy(base)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        if swapped == base:
            continue  # two identical adjacent entries (none expected, but safe)
        assert chain_head(swapped) != base_head
        assert first_broken_index(swapped, base_chain) == i


def test_reordered_log_replays_to_a_different_hash_than_the_clean_log():
    # A reordered log is still structurally replayable, but it is a DIFFERENT run:
    # its replay hash diverges from the clean log's. Replay does not silently
    # normalize the order back.
    clean = _sealed_log()
    clean_hash = replay(clean).sha256()
    reordered = RunLog()
    entries = copy.deepcopy(clean.entries())
    # move the last entry to the front: a real reorder
    entries.insert(0, entries.pop())
    reordered._entries = entries  # noqa: SLF001
    reordered._seq = entries[-1]["seq"] + 1  # noqa: SLF001
    assert replay(reordered).sha256() != clean_hash
