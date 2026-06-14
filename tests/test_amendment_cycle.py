"""test_amendment_cycle.py (A1), proves the agent-to-agent collaboration is
real and deterministic: FACT_AMENDED reopens released branches, the SEC
amendment cannot advance until a concur envelope exists, the bounded loop
terminates, and post-reconciliation amendments pass the UTC-canonicalized
contradiction diff."""


from warden.negotiation import (MAX_ROUNDS, NegotiationEnvelope,
                                NegotiationGuard, Verdict)
from warden.replay import replay
from warden.simulate import AMENDED_RECORDS, run_incident
from warden.state_machine import Event, ProtocolStateMachine, Rejection, State

T = "2026-06-16T08:14:00+00:00"


def _env(rnd=1, frm="sec_drafter", to="nis2_drafter", verdict=Verdict.PROPOSE,
         value=AMENDED_RECORDS, prior=None):
    return NegotiationEnvelope(
        correlation_id="inc-1:sec", amend_round=rnd, from_agent=frm, to_agent=to,
        fact_key="records_affected", proposed_value=value,
        characterization="approximately 2.1 million records",
        data_category_bounds=("name", "address"), containment_framing="contained",
        verdict=verdict, ts_utc=T, prior_envelope_hash=prior)


# --- state machine: the reopen sub-cycle ---------------------------------

def _drive_to_released(sm, corr):
    for ev, role in [(Event.FACT_RECORD_POSTED, "triage"), (Event.DRAFT_STARTED, "drafter"),
                     (Event.DRAFT_POSTED, "drafter"), (Event.DIFF_PASSED, "warden"),
                     (Event.SIGNOFF_OPENED, "warden"), (Event.HUMAN_RELEASED, "human_owner")]:
        sm.apply(corr, ev, T, actor_role=role)
    assert sm.state(corr) == State.RELEASED


def test_fact_amended_reopens_released_branch():
    sm = ProtocolStateMachine()
    _drive_to_released(sm, "inc-1:sec")
    r = sm.apply("inc-1:sec", Event.FACT_AMENDED, T, actor="triage", actor_role="triage")
    assert r.admitted and sm.state("inc-1:sec") == State.AMENDING


def test_released_rejects_everything_except_fact_amended():
    sm = ProtocolStateMachine()
    _drive_to_released(sm, "inc-1:nis2")
    for ev, role in [(Event.DRAFT_POSTED, "drafter"), (Event.HUMAN_RELEASED, "human_owner"),
                     (Event.DIFF_PASSED, "warden")]:
        r = sm.apply("inc-1:nis2", ev, T, actor_role=role)
        assert isinstance(r, Rejection)


def test_only_triage_can_amend():
    sm = ProtocolStateMachine()
    _drive_to_released(sm, "inc-1:sec")
    r = sm.apply("inc-1:sec", Event.FACT_AMENDED, T, actor="sec_drafter", actor_role="drafter")
    assert isinstance(r, Rejection) and "authority violation" in r.reason


def test_fact_amended_on_unreleased_branch_is_illegal():
    sm = ProtocolStateMachine()
    sm.apply("inc-1:dora", Event.FACT_RECORD_POSTED, T, actor_role="triage")
    r = sm.apply("inc-1:dora", Event.FACT_AMENDED, T, actor_role="triage")
    assert isinstance(r, Rejection) and "illegal transition" in r.reason


# --- negotiation guard -----------------------------------------------------

def test_amendment_is_noop_until_concur():
    g = NegotiationGuard()
    g.post(_env())  # propose only
    gate = g.can_submit_amendment("inc-1:sec", 1)
    assert not gate.allowed and "no concur" in gate.reason


def test_concur_must_hash_link_to_what_it_answers():
    g = NegotiationGuard()
    d = g.post(_env(verdict=Verdict.CONCUR, frm="nis2_drafter", to="sec_drafter", prior=None))
    assert not d.allowed
    d2 = g.post(_env(verdict=Verdict.CONCUR, frm="nis2_drafter", prior="deadbeef"))
    assert not d2.allowed and "unknown prior" in d2.reason


def test_bounded_loop_round_beyond_max_rejected():
    g = NegotiationGuard()
    d = g.post(_env(rnd=MAX_ROUNDS + 1))
    assert not d.allowed and "outside" in d.reason


def test_value_mismatch_across_branches_blocks_diff():
    g = NegotiationGuard()
    p = _env()
    g.post(p)
    g.post(_env(verdict=Verdict.CONCUR, frm="nis2_drafter", to="sec_drafter", prior=p.sha256()))
    gate = g.can_pass_diff(1, {"sec": AMENDED_RECORDS, "nis2": 2_000_000})
    assert not gate.allowed and "diverge" in gate.reason


# --- full run --------------------------------------------------------------

def test_full_amendment_run_direct_concur():
    r = run_incident(amendment=True)
    assert set(r.amendments) == {"sec", "nis2"}
    assert all(a["claims"]["records_affected"] == AMENDED_RECORDS for a in r.amendments.values())
    amendment_diffs = [e for e in r.log.entries()
                       if e["type"] == "diff" and e["payload"].get("phase") == "amendment"]
    assert amendment_diffs and amendment_diffs[0]["payload"]["conflicts"] == []


def test_full_amendment_run_with_counter_round():
    r = run_incident(amendment=True, nis2_counters_first=True)
    assert r.negotiation_rounds == 2
    verdicts = [e["payload"]["verdict"] for e in r.log.entries() if e["type"] == "negotiation"]
    assert verdicts == ["propose", "counter", "propose", "concur"]
    assert set(r.amendments) == {"sec", "nis2"}


def test_amendment_run_replays_byte_identical():
    r = run_incident(amendment=True, nis2_counters_first=True)
    assert replay(r.log).sha256() == r.log.sha256()


def test_amendment_does_not_disturb_original_filings():
    plain = run_incident().filings
    amended = run_incident(amendment=True)
    assert amended.filings == plain  # originals untouched; amendments are separate records


def test_chaos_plus_amendment_still_exactly_once_and_replayable():
    from warden.simulate import KillSchedule
    r = run_incident(kill_schedule=KillSchedule({("nis2", 1): "B", ("sec", 1): "A"}),
                     contradiction_in="dora", amendment=True, nis2_counters_first=True)
    assert set(r.amendments) == {"sec", "nis2"}
    assert replay(r.log).sha256() == r.log.sha256()
