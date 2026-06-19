"""test_whatif.py -- the What-If Console (E9.3): deterministic counterfactual replay.

The same deterministic substrate that makes the PAST byte-identically replayable
makes the COUNTERFACTUAL computable. These tests prove the three shipped what-ifs
(floor/whatif.py) compute deterministically over the sealed captures, each carries
a signed mini-receipt under a DISTINCT counterfactual namespace label, each
re-verifies, and (the load-bearing fence) the engine NEVER moves a sealed real-run
sha and NEVER writes a canonical run log.
"""

import json
from pathlib import Path

import pytest

from warden.chain import chain_head
from warden.counterfactual_signing import (
    COUNTERFACTUAL_SIGNED_PAYLOAD,
    sign_counterfactual,
    verify_counterfactual,
)
from warden.replay import RunLog, replay
from warden.signing import (
    bound_payload_bytes as per_run_payload,
)
from warden.portfolio_signing import (
    PORTFOLIO_SIGNED_PAYLOAD,
    portfolio_payload_bytes,
)

from floor.whatif import (
    DATA,
    all_counterfactuals,
    amended_count_unchanged,
    contradiction_not_caught,
    sec_materiality_later,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# The four canonical sealed run-log shas (LF-canonical), which must stay FROZEN
# with whatif.py present. The What-If engine is a pure CONSUMER of these bytes; it
# is a hard error if computing a counterfactual moved any of them.
FROZEN_SHAS = {
    "run-inc-8842-normal.jsonl":
        "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3",
    "run-inc-8842-inject_contradiction.jsonl": "f1f2223a",
    "run-inc-8842-chaos.jsonl": "303c4371",
    "run-inc-8842-amendment.jsonl": "0ca07fb0",
}


def _sha_of(name: str) -> str:
    return RunLog.load(DATA / name).sha256()


# --- The fence: the real-run shas are unchanged with whatif.py present ---------

def test_sealed_real_run_shas_unchanged_with_whatif_present():
    for name, prefix in FROZEN_SHAS.items():
        sha = _sha_of(name)
        assert sha.startswith(prefix), (
            f"{name}: sealed sha {sha[:16]} no longer starts with {prefix}; the "
            "What-If engine must never move a real-run sha")


def test_running_all_counterfactuals_does_not_move_a_sealed_sha():
    before = {name: _sha_of(name) for name in FROZEN_SHAS}
    # Compute every counterfactual (the contradiction one builds a hypothetical
    # RunLog and replays it); none of this may touch a sealed capture on disk.
    all_counterfactuals()
    after = {name: _sha_of(name) for name in FROZEN_SHAS}
    assert before == after


def test_sealed_runs_still_replay_byte_identical():
    for name in FROZEN_SHAS:
        log = RunLog.load(DATA / name)
        replayed = replay(log)
        assert replayed.to_jsonl() == log.to_jsonl()
        assert replayed.sha256() == log.sha256()


# --- Determinism ---------------------------------------------------------------

def test_counterfactuals_are_deterministic():
    a = [cf.as_dict() for cf in all_counterfactuals()]
    b = [cf.as_dict() for cf in all_counterfactuals()]
    assert a == b


def test_exactly_three_counterfactuals():
    cfs = all_counterfactuals()
    names = [cf.name for cf in cfs]
    assert names == [
        "sec_materiality_6h_later",
        "contradiction_not_caught",
        "amended_count_unchanged",
    ]


# --- Each what-if signs and re-verifies under the DISTINCT namespace -----------

def test_each_counterfactual_signs_and_reverifies():
    for cf in all_counterfactuals():
        sig = sign_counterfactual(cf.name, cf.actual_chain_head, cf.outcome())
        assert sig["namespace"] == "counterfactual"
        assert sig["signed_payload"] == COUNTERFACTUAL_SIGNED_PAYLOAD
        assert verify_counterfactual(
            cf.name, cf.actual_chain_head, cf.outcome(), sig)


def test_counterfactual_label_is_distinct_from_per_run_and_portfolio():
    # The three signing namespaces must never collide: a per-run, a portfolio, and
    # a counterfactual receipt carry three different signed_payload labels, so a
    # verifier reading the label always knows which kind of receipt it holds.
    assert COUNTERFACTUAL_SIGNED_PAYLOAD != PORTFOLIO_SIGNED_PAYLOAD
    assert COUNTERFACTUAL_SIGNED_PAYLOAD != (
        "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}")
    # And the BYTES differ for the same inputs, so a signature can never be replayed
    # across namespaces.
    cf = all_counterfactuals()[0]
    from warden.counterfactual_signing import counterfactual_payload_bytes
    cf_bytes = counterfactual_payload_bytes(
        cf.name, cf.actual_chain_head, "deadbeef")
    assert cf_bytes != per_run_payload("a", "b", "c", "d")
    assert cf_bytes != portfolio_payload_bytes("root", 4)


def test_tampered_outcome_breaks_the_counterfactual_signature():
    cf = all_counterfactuals()[0]
    sig = sign_counterfactual(cf.name, cf.actual_chain_head, cf.outcome())
    tampered = cf.outcome()
    tampered["divergence"] = tampered["divergence"] + " (forged)"
    assert not verify_counterfactual(
        cf.name, cf.actual_chain_head, tampered, sig)


def test_tampered_actual_chain_head_breaks_the_signature():
    cf = all_counterfactuals()[0]
    sig = sign_counterfactual(cf.name, cf.actual_chain_head, cf.outcome())
    forged_head = "0" * 64
    assert not verify_counterfactual(
        cf.name, forged_head, cf.outcome(), sig)


# --- CF1: SEC materiality determined later (holiday-aware clock load-bearing) --

def test_cf1_holiday_aware_deadline_is_load_bearing():
    cf = sec_materiality_later(hours=6)
    # The actual and counterfactual both land on 2026-06-23 because Juneteenth
    # (2026-06-19) is skipped; a weekends-only count lands a day earlier.
    assert cf.counterfactual["sec_deadline_utc"].startswith("2026-06-23")
    assert cf.counterfactual["weekends_only_deadline_utc"].startswith("2026-06-22")
    assert cf.counterfactual["holiday_added_days"] == 1
    assert "Juneteenth" in cf.counterfactual["holiday_skipped"]


def test_cf1_reanchor_uses_the_real_clock_engine():
    # A larger shift that pushes the determination into the next day MUST move the
    # deadline, proving the re-anchor runs through the real business-day engine and
    # is not a constant.
    later = sec_materiality_later(hours=30)
    assert later.counterfactual["sec_deadline_utc"].startswith("2026-06-24")


# --- CF2: the contradiction had NOT been caught (different chain head) ---------

def test_cf2_no_block_yields_a_different_chain_head():
    cf = contradiction_not_caught()
    actual_head = cf.actual["chain_head"]
    cf_head = cf.counterfactual["chain_head"]
    assert actual_head != cf_head, (
        "removing the diff block must change the ordered run's chain head")
    # The actual head matches the recomputed head of the sealed capture.
    sealed = chain_head([
        json.loads(line)
        for line in (DATA / "run-inc-8842-inject_contradiction.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()])
    assert actual_head == sealed


def test_cf2_divergent_filing_recomputes_a_real_conflict():
    cf = contradiction_not_caught()
    # The conflict set is RECOMPUTED with warden/diff over the divergent claims,
    # not just transcribed: it names the SEC 02:41 vs NIS2/DORA 02:14 mismatch.
    conflicts = cf.counterfactual["recomputed_conflicts"]
    assert conflicts, "the divergent filing must still contradict"
    assert any("02:41:00" in c for c in conflicts)
    assert cf.counterfactual["diff_blocked"] is False


# --- CF3: the amended count stayed 48K (no fact delta, no re-file) -------------

def test_cf3_no_fact_delta_means_no_refile():
    cf = amended_count_unchanged()
    assert cf.actual["sec_refiled"] is True
    assert cf.actual["fact_delta"] is True
    assert cf.counterfactual["sec_refiled"] is False
    assert cf.counterfactual["fact_delta"] is False


def test_cf3_grounding_shows_the_amended_claim_is_unsupported_on_old_record():
    cf = amended_count_unchanged()
    # An amended 8-K asserting 2,100,000 is grounded against the amended record but
    # ungrounded against the unchanged 48,211 record (the 2.1M span is flagged).
    assert cf.actual["amended_filing_grounded_vs_amended_record"] == "1.0000"
    assert float(cf.actual["amended_filing_grounded_vs_unchanged_record"]) < 1.0
    assert "2,100,000" in cf.actual["ungrounded_spans_if_refiled_on_old_record"]


# --- The committed web/data artifacts match the engine and re-verify -----------

def _artifact(name: str) -> dict:
    return json.loads(
        (DATA / f"whatif-{name}.json").read_text(encoding="utf-8"))


def test_committed_artifacts_match_engine_and_reverify():
    for cf in all_counterfactuals():
        path = DATA / f"whatif-{cf.name}.json"
        assert path.exists(), f"committed artifact missing: {path}"
        committed = json.loads(path.read_text(encoding="utf-8"))
        # The outcome the engine computes must equal what was committed.
        committed_outcome = {k: committed[k] for k in cf.outcome()}
        assert committed_outcome == cf.outcome()
        assert committed["actual_chain_head"] == cf.actual_chain_head
        sig = committed["signature"]
        assert sig["signed_payload"] == COUNTERFACTUAL_SIGNED_PAYLOAD
        assert verify_counterfactual(
            cf.name, cf.actual_chain_head, cf.outcome(), sig)


def test_committed_artifacts_tamper_breaks_verification():
    committed = _artifact("contradiction_not_caught")
    sig = committed["signature"]
    cf = contradiction_not_caught()
    # Flip the divergence text in the recomputed outcome: the committed signature
    # must no longer verify over it.
    forged = cf.outcome()
    forged["counterfactual"] = dict(forged["counterfactual"])
    forged["counterfactual"]["chain_head"] = "0" * 64
    assert not verify_counterfactual(
        cf.name, cf.actual_chain_head, forged, sig)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
