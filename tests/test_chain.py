"""The per-entry hash chain (warden/chain.py) is a derived, append-only
sidecar over the run log. These tests pin its real guarantees:

  * deterministic: same log -> same chain head, across recomputations.
  * a field edit breaks the chain at exactly that entry.
  * a reorder of two entries is detected and the first broken index named.
  * an omission is detected and the first broken index named.
  * critically: computing the chain does NOT change the run log or the
    replay sha. Byte-identical replay still holds with the chain present.
"""

import copy

from warden.chain import (
    GENESIS,
    chain_for_log,
    chain_head,
    chain_over,
    first_broken_index,
    head_for_log,
    verify_chain,
)
from warden.replay import RunLog, replay
from warden.simulate import KillSchedule, run_incident


def _fresh_log() -> RunLog:
    return run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "A", ("dora", 1): "B"}),
        contradiction_in="sec",
    ).log


# --- determinism -------------------------------------------------------

def test_chain_head_is_deterministic_same_log_same_head():
    log = _fresh_log()
    entries = log.entries()
    assert chain_head(entries) == chain_head(entries)
    # an independently built log of the same incident yields the same head.
    other = _fresh_log()
    assert chain_head(other.entries()) == chain_head(entries)


def test_empty_log_head_is_genesis():
    assert chain_head([]) == GENESIS
    assert head_for_log(RunLog()) == GENESIS


def test_chain_has_one_hash_per_entry_and_links_forward():
    log = _fresh_log()
    entries = log.entries()
    chain = chain_over(entries)
    assert len(chain) == len(entries)
    # each hash is a 64-char hex sha256 and the head is the last one.
    assert all(len(h) == 64 and int(h, 16) >= 0 for h in chain)
    assert chain[-1] == chain_head(entries)


def test_verify_chain_accepts_the_honest_head_and_rejects_a_wrong_one():
    log = _fresh_log()
    entries = log.entries()
    head = chain_head(entries)
    assert verify_chain(entries, head) is True
    assert verify_chain(entries, GENESIS) is False


def test_chain_for_log_pairs_seq_with_entry_hash():
    log = _fresh_log()
    sidecar = chain_for_log(log)
    entries = log.entries()
    chain = chain_over(entries)
    assert [r["seq"] for r in sidecar] == [e["seq"] for e in entries]
    assert [r["entry_hash"] for r in sidecar] == chain


# --- field edit detected at the exact entry ----------------------------

def test_field_edit_breaks_the_chain_at_exactly_that_entry():
    log = _fresh_log()
    sealed_entries = log.entries()
    sealed_chain = chain_over(sealed_entries)

    tampered = copy.deepcopy(sealed_entries)
    # pick the first admitted protocol_event and flip it, like a forger.
    target = next(
        k for k, e in enumerate(tampered)
        if e["type"] == "protocol_event" and e["payload"].get("admitted") is True
    )
    tampered[target]["payload"]["admitted"] = False
    tampered[target]["payload"]["to_state"] = None

    assert chain_head(tampered) != chain_head(sealed_entries)
    # the FIRST broken link is exactly the entry we edited.
    assert first_broken_index(tampered, sealed_chain) == target


# --- reorder detected, first broken index named ------------------------

def test_reorder_of_two_entries_is_detected_with_first_broken_index():
    log = _fresh_log()
    sealed_entries = log.entries()
    sealed_chain = chain_over(sealed_entries)

    reordered = copy.deepcopy(sealed_entries)
    proto_idxs = [k for k, e in enumerate(reordered) if e["type"] == "protocol_event"]
    a, b = proto_idxs[0], proto_idxs[1]
    reordered[a], reordered[b] = reordered[b], reordered[a]

    assert chain_head(reordered) != chain_head(sealed_entries)
    # the divergence starts at the earlier of the two swapped positions.
    assert first_broken_index(reordered, sealed_chain) == a


def test_a_reorder_that_changes_nothing_is_not_a_false_positive():
    log = _fresh_log()
    entries = log.entries()
    sealed_chain = chain_over(entries)
    # an identical copy (no reorder) reports no break.
    assert first_broken_index(copy.deepcopy(entries), sealed_chain) is None


# --- omission detected, first broken index named -----------------------

def test_omission_of_one_entry_is_detected_with_first_broken_index():
    log = _fresh_log()
    sealed_entries = log.entries()
    sealed_chain = chain_over(sealed_entries)

    omitted = copy.deepcopy(sealed_entries)
    drop_at = next(
        k for k, e in enumerate(omitted) if e["type"] == "protocol_event"
    )
    del omitted[drop_at]

    assert chain_head(omitted) != chain_head(sealed_entries)
    # the chain matches up to the dropped position, then diverges there.
    assert first_broken_index(omitted, sealed_chain) == drop_at


def test_truncating_the_tail_is_detected_by_length():
    log = _fresh_log()
    sealed_entries = log.entries()
    sealed_chain = chain_over(sealed_entries)

    truncated = copy.deepcopy(sealed_entries)[:-1]
    assert chain_head(truncated) != chain_head(sealed_entries)
    # every shared prefix matches, so the break is reported at the boundary.
    assert first_broken_index(truncated, sealed_chain) == len(truncated)


# --- the load-bearing guard: chain is derived, replay untouched --------

def test_computing_the_chain_does_not_mutate_the_log_or_its_sha():
    log = _fresh_log()
    before_jsonl = log.to_jsonl()
    before_sha = log.sha256()

    # compute the chain in every way the module offers.
    chain_over(log.entries())
    chain_head(log.entries())
    chain_for_log(log)
    head_for_log(log)

    # the run log bytes and its sha are byte-identical afterwards.
    assert log.to_jsonl() == before_jsonl
    assert log.sha256() == before_sha


def test_byte_identical_replay_still_holds_with_chain_present():
    log = _fresh_log()
    original_sha = log.sha256()

    # exercise the chain feature, then assert replay is still byte-identical.
    head = head_for_log(log)
    assert isinstance(head, str) and len(head) == 64

    replayed = replay(log)
    assert replayed.to_jsonl() == log.to_jsonl()
    assert replayed.sha256() == original_sha
    # and the chain over the replayed log matches the original chain: replay
    # reproduces the exact bytes the chain is derived from.
    assert chain_head(replayed.entries()) == chain_head(log.entries())
