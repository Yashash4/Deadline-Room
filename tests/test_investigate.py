"""test_investigate.py -- sub-agent INVESTIGATION + smarter NEGOTIATION (E9.7).

Two features, both with a load-bearing DETERMINISTIC half:

  INVESTIGATION. An LLM derivation sub-agent proposes candidate facts from the
  record (a NIS2 full-notification deadline, a GDPR Art 34 trigger). A PURE
  verify_derivation recomputes EACH candidate against the SAME frozen Warden core
  the rest of the system gates on (warden.clocks for a deadline, a threshold
  predicate for a trigger) and ADMITS only the candidates the recompute confirms,
  REJECTING any the recompute disagrees with. The admitted facts feed the drafting
  PROMPT only, never the [CLAIMS] gate envelope. The whole step is additive and
  default-off in the runner.

  NEGOTIATION. The amendment characterization becomes a bounded multi-turn
  deliberation, and a DETERMINISTIC figure-equality check (reusing
  floor/grounding.py) arbitrates that both amended filings state the SAME
  reconciled number. The figure check is the load-bearing deterministic half.

These tests also pin the hard E9.7 constraint: with both features OFF (the
default), the four sealed captures' run-log shas and byte-identical replay are
UNCHANGED, the verify_derivation recompute is read-only over the frozen clocks,
and the admitted facts never reach the gated [CLAIMS] envelope.
"""

from pathlib import Path

import pytest

from warden.clocks import ClockEngine
from floor import investigate as inv
from floor.drafter import (
    CharacterizationExchange, negotiate_characterization)
from floor.grounding import check_figure_equality
from floor.run_floor import (
    AMENDED_RECORDS, CANONICAL_FACTS, DRAFTER_ROLES, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

DATA = Path(__file__).resolve().parent.parent / "web" / "data"

# The four sealed captures and their byte-frozen run-log shas. E9.7 is additive
# and default-off, so these must be UNCHANGED.
SEALED = {
    "normal": "89dae145",
    "inject_contradiction": "f1f2223a",
    "chaos": "303c4371",
    "amendment": "0ca07fb0",
}


# ---------------------------------------------------------------------------
# verify_derivation: a derived DEADLINE is admitted only when the deterministic
# clock recompute confirms it, and rejected when the recompute disagrees.
# ---------------------------------------------------------------------------
def _correct_deadline(anchor_ts: str, hours: int) -> str:
    """The deadline a fresh ClockEngine computes for `hours` from `anchor_ts`, the
    exact frozen-core value verify_derivation recomputes against."""
    engine = ClockEngine()
    clock = engine.start_hours("x", "x", anchor_ts, hours)
    return clock.deadline.isoformat()


def test_deadline_admitted_when_recompute_confirms():
    anchor = CANONICAL_FACTS["incident_start_utc"]
    correct = _correct_deadline(anchor, 72)
    candidate = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2",
        field="nis2_full_notification_deadline_utc", value=correct,
        anchor_ts=anchor, window_hours=72,
        basis="NIS2 Art 23 full notification, 72h from becoming aware")
    verdict = inv.verify_derivation(candidate, CANONICAL_FACTS)
    assert verdict.confirmed is True
    assert verdict.admitted is True
    assert verdict.recomputed_value == correct


def test_deadline_rejected_when_recompute_disagrees():
    anchor = CANONICAL_FACTS["incident_start_utc"]
    correct = _correct_deadline(anchor, 72)
    # The model miscounts the window as 96 hours; it claims a WRONG deadline.
    wrong = _correct_deadline(anchor, 96)
    assert wrong != correct
    candidate = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2",
        field="nis2_full_notification_deadline_utc", value=wrong,
        anchor_ts=anchor, window_hours=72,
        basis="miscounted window")
    verdict = inv.verify_derivation(candidate, CANONICAL_FACTS)
    assert verdict.confirmed is False
    assert verdict.admitted is False
    # The recompute records the TRUE value, naming what the derivation got wrong.
    assert verdict.recomputed_value == correct


def test_deadline_rejected_without_recomputable_inputs():
    candidate = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2", field="d", value="2026-06-19",
        anchor_ts="", window_hours=0)
    verdict = inv.verify_derivation(candidate, CANONICAL_FACTS)
    assert verdict.confirmed is False


# ---------------------------------------------------------------------------
# verify_derivation: a derived TRIGGER is admitted only when the deterministic
# threshold predicate over the fact-record confirms it.
# ---------------------------------------------------------------------------
def test_trigger_admitted_when_predicate_confirms():
    # CANONICAL_FACTS has 48,211 records and the sensitive "account_number"
    # category, so the Art 34 high-risk trigger fires deterministically.
    candidate = inv.CandidateFact(
        kind=inv.KIND_TRIGGER, regime="GDPR Art 34",
        field="gdpr_art34_communication_required", value="yes",
        basis="large breach of financial data")
    verdict = inv.verify_derivation(candidate, CANONICAL_FACTS)
    assert verdict.confirmed is True
    assert verdict.recomputed_value == "yes"


def test_trigger_rejected_when_model_overreads():
    # A small, non-sensitive breach does NOT clear the high-risk bar; a model that
    # claims the trigger fires is rejected by the recompute.
    small = {"records_affected": 12, "data_categories": ["display_name"]}
    candidate = inv.CandidateFact(
        kind=inv.KIND_TRIGGER, regime="GDPR Art 34",
        field="gdpr_art34_communication_required", value="yes")
    verdict = inv.verify_derivation(candidate, small)
    assert verdict.confirmed is False
    assert verdict.recomputed_value == "no"


def test_trigger_admitted_when_model_correctly_says_no():
    small = {"records_affected": 12, "data_categories": ["display_name"]}
    candidate = inv.CandidateFact(
        kind=inv.KIND_TRIGGER, regime="GDPR Art 34",
        field="gdpr_art34_communication_required", value="no")
    verdict = inv.verify_derivation(candidate, small)
    assert verdict.confirmed is True
    assert verdict.recomputed_value == "no"


def test_unverifiable_kind_is_rejected():
    candidate = inv.CandidateFact(
        kind="freeform_opinion", regime="X", field="f", value="anything")
    verdict = inv.verify_derivation(candidate, CANONICAL_FACTS)
    assert verdict.confirmed is False


# ---------------------------------------------------------------------------
# investigate(): partitions admitted vs rejected; admitted_facts() exposes only
# the confirmed derivations (the only thing that ever reaches a prompt).
# ---------------------------------------------------------------------------
def test_investigate_admits_only_confirmed():
    anchor = CANONICAL_FACTS["incident_start_utc"]
    good_deadline = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2", field="nis2_deadline",
        value=_correct_deadline(anchor, 72), anchor_ts=anchor, window_hours=72)
    bad_deadline = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2", field="bad_deadline",
        value=_correct_deadline(anchor, 96), anchor_ts=anchor, window_hours=72)
    good_trigger = inv.CandidateFact(
        kind=inv.KIND_TRIGGER, regime="GDPR Art 34",
        field="art34_required", value="yes")
    result = inv.investigate(
        CANONICAL_FACTS, [good_deadline, bad_deadline, good_trigger])
    admitted = result.admitted_facts()
    assert "nis2_deadline" in admitted
    assert "art34_required" in admitted
    # The miscounted derivation is NOT admitted, so it never reaches a prompt.
    assert "bad_deadline" not in admitted
    assert len(result.admitted) == 2
    assert len(result.rejected) == 1


def test_verify_derivation_is_read_only_over_clocks():
    """The recompute constructs a throwaway engine and never mutates a live clock.
    A live ClockEngine with a started clock is unchanged after verify runs."""
    live = ClockEngine()
    live.start_hours("live", "live", CANONICAL_FACTS["incident_start_utc"], 24)
    before = live.get("live").deadline
    anchor = CANONICAL_FACTS["incident_start_utc"]
    inv.verify_derivation(
        inv.CandidateFact(kind=inv.KIND_DEADLINE, regime="NIS2", field="x",
                          value=_correct_deadline(anchor, 72),
                          anchor_ts=anchor, window_hours=72),
        CANONICAL_FACTS)
    # The live clock is untouched: verify built its own engine.
    assert live.get("live").deadline == before
    assert len(live.all()) == 1


# ---------------------------------------------------------------------------
# parse_candidates: the LLM derivation block parses into structured candidates;
# malformed lines are dropped, so a bad derivation never becomes a candidate.
# ---------------------------------------------------------------------------
def test_parse_candidates_parses_block():
    text = (
        "Here are my derivations.\n"
        "[DERIVATION]\n"
        "kind=deadline;regime=NIS2;field=nis2_deadline;value=2026-06-19T02:14:00+00:00;"
        "anchor_ts=2026-06-16T02:14:00+00:00;window_hours=72;basis=Art 23\n"
        "kind=trigger;regime=GDPR Art 34;field=art34;value=yes;basis=high risk\n"
        "kind=bogus;field=;value=x\n"          # dropped: bad kind and no field
        "[/DERIVATION]")
    candidates = inv.parse_candidates(text)
    assert len(candidates) == 2
    assert candidates[0].kind == inv.KIND_DEADLINE
    assert candidates[0].window_hours == 72
    assert candidates[1].kind == inv.KIND_TRIGGER


def test_parse_candidates_tolerant_of_no_block():
    assert inv.parse_candidates("no block here") == []
    assert inv.parse_candidates("[DERIVATION]\nunclosed") == []


# ---------------------------------------------------------------------------
# Smarter negotiation: the bounded multi-turn exchange terminates within the
# round bound and settles on a shared phrasing.
# ---------------------------------------------------------------------------
def test_bounded_exchange_converges_immediately():
    # The concurrer echoes the proposal: the exchange converges on the first turn.
    def proposer(role, counterpart):
        return "We characterize 2,100,000 affected records as a major breach."

    def concurrer(role, counterpart):
        return counterpart  # immediate agreement

    exchange = negotiate_characterization(
        proposer_fn=proposer, concurrer_fn=concurrer, max_rounds=3)
    assert isinstance(exchange, CharacterizationExchange)
    assert exchange.converged is True
    assert exchange.agreed_text.startswith("We characterize 2,100,000")
    # Two turns: propose then concur.
    assert len(exchange.turns) == 2
    assert exchange.turns[-1].role == "concur"


def test_bounded_exchange_is_bounded_when_never_agreeing():
    # The two never agree; the exchange must still terminate at the round bound.
    calls = {"n": 0}

    def proposer(role, counterpart):
        calls["n"] += 1
        return f"proposal variant {calls['n']}"

    def concurrer(role, counterpart):
        return "a different sentence every time " + str(calls["n"])

    exchange = negotiate_characterization(
        proposer_fn=proposer, concurrer_fn=concurrer, max_rounds=2)
    # Bounded: at most 2 + 2*max_rounds turns, and it terminated.
    assert len(exchange.turns) <= 2 + 2 * 2
    assert exchange.turns[-1].role == "concur"
    # It did not converge (never agreed), but it settled on a shared phrasing.
    assert exchange.converged is False
    assert exchange.agreed_text != ""


# ---------------------------------------------------------------------------
# The deterministic figure-equality arbitration over amended filings.
# ---------------------------------------------------------------------------
def test_figure_check_agrees_when_both_state_the_figure():
    filings = [
        {"branch": "sec", "text": "Amended 8-K: records affected revised to "
                                   "2,100,000.\n\n[CLAIMS]\nrecords_affected=2100000\n[/CLAIMS]"},
        {"branch": "nis2", "text": "NIS2 intermediate report: 2,100,000 records "
                                    "affected.\n\n[CLAIMS]\nrecords_affected=2100000\n[/CLAIMS]"},
    ]
    check = check_figure_equality(filings, 2_100_000)
    assert check.agree is True
    assert check.expected == "2100000"


def test_figure_check_disagrees_when_prose_diverges():
    filings = [
        {"branch": "sec", "text": "Amended 8-K: records affected revised to 2,100,000."},
        {"branch": "nis2", "text": "NIS2 report: 1,200,000 records affected."},
    ]
    check = check_figure_equality(filings, 2_100_000)
    assert check.agree is False
    assert "nis2" in check.reason or "1200000" in check.reason


def test_figure_check_in_amendment_run(tmp_path):
    """The deterministic figure check arbitrates the default amendment run and the
    packet carries it green."""
    packet = _run_amendment(tmp_path)
    fc = packet["reconciliation"]["figure_check"]
    assert fc["agree"] is True
    assert fc["expected"] == str(AMENDED_RECORDS)


# ---------------------------------------------------------------------------
# Hard constraint: investigation + negotiation are additive and default-off, so
# the four sealed captures' run-log shas and byte-identical replay are unchanged.
# ---------------------------------------------------------------------------
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
                    f"{claim_facts['records_affected']} records.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _amend_draft_fns():
    fns = _stub_draft_fns()
    fns["sec:characterize"] = lambda counterpart: (
        f"Both filings characterize {AMENDED_RECORDS:,} affected records as a "
        "single reconciled figure.")
    fns["nis2:characterize"] = lambda counterpart: (
        f"Both filings characterize {AMENDED_RECORDS:,} affected records as a "
        "single reconciled figure.")
    return fns


def _run_amendment(tmp_path, **kwargs):
    room, clients = _build_clients()
    return run_floor(
        out_dir=str(tmp_path), mode="amendment", clients=clients,
        draft_fns=_amend_draft_fns(), **kwargs)


def _run_mode(tmp_path, mode, draft_fns=None, **kwargs):
    room, clients = _build_clients()
    return run_floor(
        out_dir=str(tmp_path), mode=mode, clients=clients,
        draft_fns=draft_fns or _stub_draft_fns(), **kwargs)


@pytest.mark.parametrize("name,sha_prefix", sorted(SEALED.items()))
def test_sealed_run_log_shas_unchanged(name, sha_prefix):
    """The four sealed CANONICAL run-log shas are byte-frozen; E9.7 is additive and
    default-off, so each capture's canonical run-log sha (the one the audit prints
    and the signature binds) still starts with its frozen prefix."""
    from warden.replay import RunLog
    path = DATA / f"run-inc-8842-{name}.jsonl"
    if not path.exists():
        pytest.skip(f"sealed capture {path} not present in this checkout")
    sha = RunLog.load(path).sha256()
    assert sha.startswith(sha_prefix), (
        f"sealed capture {name} canonical sha changed: {sha} does not start with "
        f"{sha_prefix}")


def test_default_amendment_replay_byte_identical(tmp_path):
    """The default amendment run (no smarter-negotiation opt-in) still replays
    byte-identically: the figure check is out-of-log."""
    packet = _run_amendment(tmp_path)
    assert packet["replay"]["byte_identical"] is True
    # The default run did NOT run the bounded exchange (opt-in), so no transcript.
    assert packet["reconciliation"]["characterization_exchange"] is None


def test_investigation_on_keeps_replay_byte_identical(tmp_path):
    """Investigation ON (with an injected candidate that is ADMITTED) feeds the
    prompt only, never the [CLAIMS] gate, so replay stays byte-identical and the
    packet carries the investigation receipt."""
    anchor = CANONICAL_FACTS["incident_start_utc"]
    admit = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2", field="nis2_full_deadline",
        value=_correct_deadline(anchor, 72), anchor_ts=anchor, window_hours=72)
    reject = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2", field="wrong_deadline",
        value=_correct_deadline(anchor, 96), anchor_ts=anchor, window_hours=72)

    packet = _run_mode(
        tmp_path, "normal", investigate=True,
        investigate_fn=lambda fr: [admit, reject])
    assert packet["replay"]["byte_identical"] is True
    block = packet["investigation"]
    assert block["admitted_count"] == 1
    assert block["rejected_count"] == 1
    fields = {c["field"]: c["admitted"] for c in block["candidates"]}
    assert fields["nis2_full_deadline"] is True
    assert fields["wrong_deadline"] is False


def test_admitted_facts_never_enter_claims_gate(tmp_path):
    """An admitted derived fact feeds the prompt but NEVER the [CLAIMS] envelope:
    the final claims the Warden gated on are exactly the canonical fact-record
    values, unchanged by the investigation."""
    anchor = CANONICAL_FACTS["incident_start_utc"]
    admit = inv.CandidateFact(
        kind=inv.KIND_DEADLINE, regime="NIS2", field="nis2_full_deadline",
        value=_correct_deadline(anchor, 72), anchor_ts=anchor, window_hours=72)
    packet = _run_mode(
        tmp_path, "normal", investigate=True,
        investigate_fn=lambda fr: [admit])
    # The gated claims still carry the canonical records_affected, NOT a derived
    # field: the derived deadline is a prompt aid only.
    for branch, claims in packet["diff"]["final_claims"].items():
        assert claims["records_affected"] == CANONICAL_FACTS["records_affected"]
        assert "nis2_full_deadline" not in claims


def test_smart_negotiation_run_is_additive(tmp_path):
    """With smarter negotiation opted in, the amendment run carries a bounded
    deliberation transcript AND the deterministic figure check, and still replays
    byte-identically (the transcript is out-of-log)."""
    packet = _run_amendment(tmp_path, negotiate_rounds=2)
    rec = packet["reconciliation"]
    assert rec["figure_check"]["agree"] is True
    exchange = rec["characterization_exchange"]
    assert exchange is not None
    assert exchange["turns"]
    assert packet["replay"]["byte_identical"] is True
