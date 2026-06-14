"""test_illegal_transition.py, every out-of-order handoff and every
authority violation is rejected BEFORE any downstream message is sent."""


from warden.state_machine import Event, ProtocolStateMachine, Rejection, State
from warden.simulate import run_incident


T = "2026-06-16T03:00:00+00:00"


def test_draft_before_fact_record_rejected():
    sm = ProtocolStateMachine()
    r = sm.apply("inc-1:nis2", Event.DRAFT_POSTED, T, actor="nis2_drafter", actor_role="drafter")
    assert isinstance(r, Rejection)
    assert "illegal transition" in r.reason
    assert sm.state("inc-1:nis2") == State.INITIATED  # state untouched


def test_release_without_signoff_rejected():
    sm = ProtocolStateMachine()
    sm.apply("inc-1:sec", Event.FACT_RECORD_POSTED, T, actor_role="triage")
    sm.apply("inc-1:sec", Event.DRAFT_STARTED, T, actor_role="drafter")
    sm.apply("inc-1:sec", Event.DRAFT_POSTED, T, actor_role="drafter")
    r = sm.apply("inc-1:sec", Event.HUMAN_RELEASED, T, actor="lena", actor_role="human_owner")
    assert isinstance(r, Rejection)  # signoff gate not opened by the Warden yet


def test_drafter_cannot_release_even_at_signoff():
    sm = ProtocolStateMachine()
    for ev, role in [(Event.FACT_RECORD_POSTED, "triage"), (Event.DRAFT_STARTED, "drafter"),
                     (Event.DRAFT_POSTED, "drafter"), (Event.DIFF_PASSED, "warden"),
                     (Event.SIGNOFF_OPENED, "warden")]:
        sm.apply("inc-1:dora", ev, T, actor_role=role)
    r = sm.apply("inc-1:dora", Event.HUMAN_RELEASED, T, actor="dora_drafter", actor_role="drafter")
    assert isinstance(r, Rejection)
    assert "authority violation" in r.reason


def test_only_warden_opens_signoff():
    sm = ProtocolStateMachine()
    for ev, role in [(Event.FACT_RECORD_POSTED, "triage"), (Event.DRAFT_STARTED, "drafter"),
                     (Event.DRAFT_POSTED, "drafter"), (Event.DIFF_PASSED, "warden")]:
        sm.apply("inc-1:nis2", ev, T, actor_role=role)
    r = sm.apply("inc-1:nis2", Event.SIGNOFF_OPENED, T, actor="nis2_drafter", actor_role="drafter")
    assert isinstance(r, Rejection)


def test_terminal_states_are_final():
    sm = ProtocolStateMachine()
    sm.apply("inc-1:sec", Event.SUPPRESS, T, actor_role="materiality")
    assert sm.state("inc-1:sec") == State.SUPPRESSED
    r = sm.apply("inc-1:sec", Event.DRAFT_STARTED, T, actor_role="drafter")
    assert isinstance(r, Rejection)
    assert "terminal" in r.reason


def test_full_run_records_the_self_release_rejection():
    r = run_incident()
    rejected = [e for e in r.log.entries()
                if e["type"] == "protocol_event" and not e["payload"]["admitted"]
                and e["payload"].get("reason") and "authority violation" in e["payload"]["reason"]]
    assert len(rejected) >= 1
