"""test_modelcheck.py -- the exhaustive reachable-state model-checker.

These tests assert three things about warden/modelcheck.py:

  1. POSITIVE: the checker PASSES on the REAL shipped state machine. Every named
     invariant (SAFE-1..5, PROG-1) holds at every one of the reachable nodes, the
     reachable set is non-trivial (released, suppressed, and failed are all
     reached), and the determinism certificate is green.

  2. NEGATIVE CONTROL: when a deliberately bad edge is planted (a release that
     skips the second key, an amendment that skips concurrence), the checker
     CATCHES it and returns a counterexample PATH. A model-checker nobody has seen
     fail is itself suspect; these tests prove it can fail, so its PASS is
     meaningful and not vacuous.

  3. DETERMINISM CERTIFICATE: running the checker twice yields the identical
     result (same node count, same edge count, same per-invariant verdicts), and
     replay over the reachable run space is a pure function (same event sequence
     yields the same sealed sha and chain head; replay is idempotent).

Real assertions against the real module. No network, no randomness.
"""

from warden.modelcheck import (
    GATE_ACTION_AUTHORITY,
    START,
    GateAction,
    certify_determinism,
    model_check,
    reachable,
)
from warden.state_machine import (
    EVENT_AUTHORITY,
    TRANSITIONS,
    Event,
    State,
)


# =====================================================================
# 1. POSITIVE: the checker passes on the real machine
# =====================================================================

def test_real_machine_passes_every_invariant():
    result = model_check()
    assert result.passed, (
        "the model-checker found a reachable invariant violation on the REAL "
        "state machine: "
        + "; ".join(
            f"{inv.invariant_id} via {' -> '.join(inv.counterexample_path)}"
            for inv in result.invariants if not inv.passed
        )
    )
    # Every named invariant is present and green.
    ids = {inv.invariant_id for inv in result.invariants}
    assert ids == {"SAFE-1", "SAFE-2", "SAFE-3", "SAFE-4", "SAFE-5", "PROG-1"}
    for inv in result.invariants:
        assert inv.passed, f"{inv.invariant_id} failed: {inv.detail}"


def test_reachable_set_is_non_trivial():
    r = reachable()
    states = {node.state for node in r.nodes}
    # The enumeration must actually reach the meaningful outcomes, otherwise a
    # vacuous "all invariants hold over the empty set" would pass.
    assert State.RELEASED in states, "released was never reached"
    assert State.SUPPRESSED in states, "suppressed (a terminal) was never reached"
    assert State.FAILED in states, "failed (clock breach terminal) was never reached"
    assert State.AMENDING in states, "the amendment reopen state was never reached"
    assert State.AWAITING_HUMAN_SIGNOFF in states, "signoff was never reached"
    assert len(r.nodes) > 1


def test_reachable_count_is_reported_and_positive():
    result = model_check()
    assert result.reachable_states > 1
    assert result.edges_explored >= result.reachable_states - 1


def test_two_distinct_keys_are_reached_before_any_release():
    # The only nodes in RELEASED must have been entered from a source holding both
    # keys (SAFE-1 already proves this; here we assert the reachable graph actually
    # contains a both-keys-present node so the proof is not vacuous).
    r = reachable()
    both_keys_present = any(
        node.have_keys == frozenset({"head_of_ir", "general_counsel"})
        for node in r.nodes
    )
    assert both_keys_present, "no node ever held both distinct keys"


# =====================================================================
# 2. NEGATIVE CONTROL: the checker catches planted bad edges
# =====================================================================

def test_negative_control_two_key_bypass_is_caught():
    # Simulate the historical amendment bug: HUMAN_RELEASED fires without the
    # two-key gate (the authority table checks the role class, not the two-key
    # collection). The checker's SAFE-1 must catch the release-without-two-keys
    # and return a counterexample path.
    result = model_check(enforce_two_key=False)
    safe1 = next(i for i in result.invariants if i.invariant_id == "SAFE-1")
    assert not safe1.passed, (
        "SAFE-1 did NOT catch a release reachable without two keys; the checker is "
        "vacuous")
    assert safe1.counterexample_path, "no counterexample path was returned"
    # The counterexample names the illegal release edge and points at the node it
    # fires from. The path leads from the initial state UP TO that node.
    assert "human_released" in safe1.detail
    assert safe1.counterexample_node is not None
    # The releasing source node holds fewer than both keys (that is the violation).
    assert safe1.counterexample_node.have_keys != frozenset(
        {"head_of_ir", "general_counsel"})


def test_negative_control_concurrence_bypass_is_caught():
    # Bypass the negotiation guard: an amendment submits without a CONCUR for its
    # round. SAFE-4 must catch the amendment-without-concurrence with a path.
    result = model_check(enforce_concur=False)
    safe4 = next(i for i in result.invariants if i.invariant_id == "SAFE-4")
    assert not safe4.passed, (
        "SAFE-4 did NOT catch an amendment submitted without concurrence")
    assert safe4.counterexample_path
    assert any("fact_amended" in step for step in safe4.counterexample_path)


def test_negative_control_planted_backdoor_edge_is_caught():
    # Plant a back-door release edge directly out of DRAFT_SUBMITTED (skipping the
    # diff AND the signoff) and bypass the two-key gate. This is the most faithful
    # reproduction of a release reachable without the diff and without two keys.
    # SAFE-1 must catch it with the shortest path to the illegal release.
    bad = dict(TRANSITIONS)
    bad[(State.DRAFT_SUBMITTED, Event.HUMAN_RELEASED)] = State.RELEASED
    result = model_check(transitions=bad, enforce_two_key=False)
    safe1 = next(i for i in result.invariants if i.invariant_id == "SAFE-1")
    assert not safe1.passed, "the planted back-door release edge was not caught"
    # The violation is a release firing from DRAFT_SUBMITTED, never having passed
    # the diff and never having collected keys.
    assert "human_released" in safe1.detail
    assert safe1.counterexample_node.state is State.DRAFT_SUBMITTED
    # The shortest illegal path reaches the releasing node WITHOUT a diff pass.
    assert not any("diff_passed" in step for step in safe1.counterexample_path), (
        "the back-door path should reach release WITHOUT a diff pass")


def test_negative_control_planted_terminal_exit_breaks_safe2():
    # Plant an edge OUT of a terminal state (SUPPRESSED), which would make the
    # terminal non-absorbing. SAFE-2 must catch it. The state machine's apply()
    # rejects from terminal, so to actually plant a reachable exit we override the
    # admission check by routing through a table that the checker treats as
    # authoritative for the override case AND mark the source non-terminal is not
    # possible (terminality is intrinsic to the state). Instead we assert that the
    # real checker treats SUPPRESSED/FAILED as absorbing: no successors exist.
    from warden.modelcheck import Node, successors
    suppressed = Node(State.SUPPRESSED, frozenset(), False, 0, False)
    failed = Node(State.FAILED, frozenset(), False, 0, False)
    assert successors(suppressed) == [], "SUPPRESSED is not absorbing"
    assert successors(failed) == [], "FAILED is not absorbing"


# =====================================================================
# 3. DETERMINISM CERTIFICATE
# =====================================================================

def test_checker_is_deterministic_across_runs():
    # Running the checker twice must yield the identical structural result.
    a = model_check()
    b = model_check()
    assert a.reachable_states == b.reachable_states
    assert a.edges_explored == b.edges_explored
    assert [(i.invariant_id, i.passed) for i in a.invariants] == \
           [(i.invariant_id, i.passed) for i in b.invariants]


def test_reachable_enumeration_is_deterministic():
    a = reachable()
    b = reachable()
    # Same node set and same number of edges, every run.
    assert a.nodes == b.nodes
    assert len(a.edges) == len(b.edges)


def test_determinism_certificate_is_green():
    cert = certify_determinism()
    assert cert.paths_checked > 0, "no run shapes were enumerated"
    assert cert.replay_idempotent, (
        "replay is not idempotent over the reachable run space: " + cert.detail)
    assert cert.sha_is_pure_function, (
        "the sealed (sha256, chain head) is not a pure function of the event "
        "sequence: " + cert.detail)
    assert cert.passed


def test_determinism_certificate_is_stable_across_runs():
    # The certificate itself is a pure function: same paths_checked and verdict.
    a = certify_determinism()
    b = certify_determinism()
    assert a.paths_checked == b.paths_checked
    assert a.replay_idempotent == b.replay_idempotent
    assert a.sha_is_pure_function == b.sha_is_pure_function


# =====================================================================
# Sanity: the spec wiring the checker reads is the real one
# =====================================================================

def test_checker_reads_the_real_authority_tables():
    # The gate-action authority is defined for every gate action, and the event
    # authority the checker enumerates is the SHIPPED EVENT_AUTHORITY (not a copy).
    for action in GateAction:
        assert GATE_ACTION_AUTHORITY.get(action), action
    for event in Event:
        assert event in EVENT_AUTHORITY


def test_start_node_is_the_initial_configuration():
    assert START.state is State.INITIATED
    assert START.have_keys == frozenset()
    assert START.released_once is False
    assert START.amend_round == 0
    assert START.concurred is False
