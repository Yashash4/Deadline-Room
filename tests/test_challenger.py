"""The adversarial Challenger and its deterministic grounding-oracle adjudication.

Two layers are pinned here:

  1. The unit layer (floor/challenger.py + floor/challenge_adjudicate.py): the
     [CHALLENGE] block parses deterministically; each objection is CONFIRMED only
     when the existing pure-Python grounding scorer independently flags an
     ungrounded span of the matching dimension, and OVERTURNED otherwise. The LLM
     critiques; Python adjudicates. The adjudicator is a pure function: same
     inputs, identical result.

  2. The floor layer (floor/run_floor.py): with a Challenger client and stub
     challenge functions injected, the FakeBand room contains, per filing, the
     Challenger [CHALLENGE] post @mentioning the drafter and the drafter's
     REVISE/REBUT reply @mentioning the Challenger and the Warden; the packet's
     adversarial-review section reports the grounding-oracle adjudication
     (objections raised, confirmed, overturned); and the gate decisions, the
     run-log sha, and byte-identical replay are UNCHANGED by the whole exchange,
     exactly like the already-shipped Warden-speaks-in-room and peer-
     reconciliation posts.
"""

import json
from pathlib import Path

import pytest

from floor.challenger import (
    Challenge, Objection, TARGET_ATTACKER, TARGET_INCIDENT_START, TARGET_RECORDS,
    parse_challenge)
from floor.challenge_adjudicate import (
    CONFIRMED, OVERTURNED, adjudicate)
from floor.drafter import DrafterError
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom

FACTS = {
    "incident_id": "inc-8842",
    "incident_start_utc": "2026-06-16T02:14:00+00:00",
    "records_affected": 48211,
    "attacker": "LockBit 3.0",
    "containment": "partially_contained",
    "systems": ["core banking ledger", "customer KYC store"],
    "regulated_entity": "Meridian Trust Bank N.V.",
}

# A filing whose record count disagrees with the fact-record (99999 vs 48211):
# the deterministic grounding oracle flags it, so an objection targeting the
# record count is CONFIRMED.
WEAK_FILING = ("Approximately 99999 customer records were affected in the "
               "LockBit 3.0 incident on 2026-06-16.\n\n[CLAIMS]\nbranch=sec\n"
               "incident_start_utc=2026-06-16T02:14:00+00:00\n"
               "records_affected=48211\nattacker=LockBit 3.0\n"
               "containment=partially_contained\n[/CLAIMS]")

# A faithful filing: every load-bearing span traces to the fact-record, so an
# objection is OVERTURNED by the oracle.
FAITHFUL_FILING = ("Approximately 48211 records were affected. The breach actor "
                   "was LockBit 3.0; the incident began on 2026-06-16.\n\n"
                   "[CLAIMS]\nbranch=nis2\n"
                   "incident_start_utc=2026-06-16T02:14:00+00:00\n"
                   "records_affected=48211\nattacker=LockBit 3.0\n"
                   "containment=partially_contained\n[/CLAIMS]")


# ---- the [CHALLENGE] parse -------------------------------------------------

def test_parse_challenge_extracts_objections_and_memo():
    text = (
        "The record count looks inflated and the actor is unsupported.\n"
        "[CHALLENGE]\n"
        "target=records_affected;claim=99999 records;reason=does not match the "
        "fact-record\n"
        "target=attacker;claim=BlackCat;reason=not the named actor\n"
        "[/CHALLENGE]")
    ch = parse_challenge(text, branch="sec", source="featherless:Qwen")
    assert ch.branch == "sec"
    assert ch.source == "featherless:Qwen"
    assert "inflated" in ch.memo
    assert "[CHALLENGE]" not in ch.memo
    assert len(ch.objections) == 2
    assert ch.objections[0].target == "records_affected"
    assert ch.objections[0].claim == "99999 records"
    assert ch.objections[1].target == "attacker"


def test_parse_challenge_none_body_means_zero_objections():
    ch = parse_challenge("Faithful.\n[CHALLENGE]\nnone\n[/CHALLENGE]", branch="dora")
    assert ch.objections == []


def test_parse_challenge_missing_block_raises():
    with pytest.raises(DrafterError):
        parse_challenge("no fenced block here", branch="sec")


# ---- the deterministic adjudication ----------------------------------------

def test_objection_confirmed_when_oracle_flags_the_span():
    ch = Challenge(branch="sec", source="stub",
                   objections=[Objection(TARGET_RECORDS, "99999 records",
                                         "inflated count")])
    result = adjudicate(ch, WEAK_FILING, FACTS)
    assert result.raised == 1
    assert result.confirmed == 1
    assert result.overturned == 0
    assert result.objections[0].verdict == CONFIRMED
    # the deterministic evidence names the oracle's own flagged span
    assert "99999" in result.objections[0].evidence


def test_objection_overturned_when_oracle_finds_it_grounded():
    ch = Challenge(branch="nis2", source="stub",
                   objections=[Objection(TARGET_RECORDS, "48211 records",
                                         "claims this is wrong")])
    result = adjudicate(ch, FAITHFUL_FILING, FACTS)
    assert result.raised == 1
    assert result.confirmed == 0
    assert result.overturned == 1
    assert result.objections[0].verdict == OVERTURNED


def test_objection_with_uncheckable_target_is_overturned():
    # An objection the deterministic oracle has no surface for cannot be confirmed
    # by it, so it is honestly OVERTURNED (not silently accepted).
    ch = Challenge(branch="sec", source="stub",
                   objections=[Objection("tone", "too alarming", "subjective")])
    result = adjudicate(ch, WEAK_FILING, FACTS)
    assert result.objections[0].verdict == OVERTURNED


def test_adjudication_is_pure_and_deterministic():
    ch = Challenge(branch="sec", source="stub",
                   objections=[Objection(TARGET_RECORDS, "99999", "inflated"),
                               Objection(TARGET_ATTACKER, "BlackCat", "wrong actor")])
    a = adjudicate(ch, WEAK_FILING, FACTS).as_dict()
    b = adjudicate(ch, WEAK_FILING, FACTS).as_dict()
    assert a == b


def test_date_objection_maps_to_date_kind():
    # incident_start objection over a faithful date is overturned (date matches).
    ch = Challenge(branch="nis2", source="stub",
                   objections=[Objection(TARGET_INCIDENT_START, "2026-06-16",
                                         "claims the date is wrong")])
    assert adjudicate(ch, FAITHFUL_FILING, FACTS).objections[0].verdict == OVERTURNED


# ---- the floor: the room exchange + the packet section ---------------------

def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
        "challenger": FakeBandClient(room, "challenger-id", "challenger",
                                     "challenger"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return room, clients


def _stub_draft_fns():
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _stub_challenge_fns():
    """Per-branch Challenger stub. Every branch raises one record-count objection.
    The default stub drafter prose is FAITHFUL (it states the canonical 48211), so
    the deterministic grounding oracle OVERTURNS each objection. This exercises the
    adjudication path end to end with no network and proves the oracle, not the
    LLM, decides the verdict. The CONFIRMED path (a weak filing) is driven
    separately in test_confirmed_objection_surfaces_when_filing_is_weak."""
    def make(branch):
        def fn(filing_text, fact_record):
            return Challenge(
                branch=branch, source="stub:challenger",
                memo="record count looks off",
                objections=[Objection(TARGET_RECORDS, "the affected count",
                                      "claims the count is misstated")])
        return fn
    return {r.branch: make(r.branch) for r in DRAFTER_ROLES}


def _run(mode, tmp_path):
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                       draft_fns=_stub_draft_fns(),
                       challenge_fns=_stub_challenge_fns())
    return room, packet


def _challenger_messages(room):
    return [m for m in room.messages if m["sender"] == "challenger-id"]


def test_room_has_challenge_post_mentioning_each_drafter(tmp_path):
    room, _ = _run("normal", tmp_path)
    ch_msgs = _challenger_messages(room)
    # one challenge per drafted filing (NIS2, SEC, DORA)
    assert len(ch_msgs) == 3
    for r in DRAFTER_ROLES:
        mine = [m for m in ch_msgs
                if "[CHALLENGE]" in m["content"]
                and f"{r.branch}-id" in m["mentions"]]
        assert len(mine) == 1, f"one Challenger post @mentioning {r.regime}"
        assert "adversarial review" in mine[0]["content"]


def test_drafter_revises_or_rebuts_mentioning_challenger_and_warden(tmp_path):
    room, _ = _run("normal", tmp_path)
    for r in DRAFTER_ROLES:
        replies = [m for m in room.messages
                   if m["sender"] == f"{r.branch}-id"
                   and ("REVISE" in m["content"] or "REBUT" in m["content"])]
        assert len(replies) == 1, f"{r.regime} must revise or rebut once"
        # the reply @mentions both the Challenger and the Warden back
        assert "challenger-id" in replies[0]["mentions"]
        assert "warden-id" in replies[0]["mentions"]


def test_challenge_exchange_is_ordered_challenge_then_reply(tmp_path):
    room, _ = _run("normal", tmp_path)

    def index_of(predicate):
        for i, m in enumerate(room.messages):
            if predicate(m):
                return i
        return -1

    for r in DRAFTER_ROLES:
        ch_i = index_of(lambda m, r=r: m["sender"] == "challenger-id"
                        and f"{r.branch}-id" in m["mentions"])
        reply_i = index_of(lambda m, r=r: m["sender"] == f"{r.branch}-id"
                           and "challenger-id" in m["mentions"]
                           and ("REVISE" in m["content"] or "REBUT" in m["content"]))
        assert ch_i != -1 and reply_i != -1
        assert ch_i < reply_i, f"{r.regime}: challenge precedes the reply"


def test_packet_reports_grounding_oracle_adjudication(tmp_path):
    _, packet = _run("normal", tmp_path)
    ar = packet["adversarial_review"]
    # three filings challenged
    assert len(ar["reviews"]) == 3
    # totals are the sum across reviews
    assert ar["objections_raised"] == sum(c["raised"] for c in ar["reviews"])
    assert ar["objections_confirmed"] == sum(c["confirmed"] for c in ar["reviews"])
    assert ar["objections_overturned"] == sum(c["overturned"] for c in ar["reviews"])
    # the faithful stub filings carry no count-shaped mismatch, so the oracle
    # OVERTURNS the stub objections (the deterministic oracle is the adjudicator,
    # not the LLM's say-so)
    assert ar["objections_raised"] >= 3
    assert ar["objections_overturned"] == ar["objections_raised"]
    assert ar["objections_confirmed"] == 0
    # every objection carries a deterministic verdict + evidence
    for rev in ar["reviews"]:
        for o in rev["objections"]:
            assert o["verdict"] in (CONFIRMED, OVERTURNED)
            assert o["evidence"]


def test_packet_html_renders_adversarial_review_section(tmp_path):
    _, packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Adversarial review" in html
    assert "objection(s) raised" in html
    assert "OVERTURNED" in html


def test_confirmed_objection_surfaces_when_filing_is_weak(tmp_path):
    # Drive a CONFIRMED verdict end to end: a SEC drafter whose prose carries a
    # mismatched count, plus a Challenger that objects to the count. The
    # deterministic oracle independently flags the count, so the objection is
    # CONFIRMED in the packet and the SEC drafter REVISES.
    room, clients = _build_clients()

    def weak_sec_draft(claim_facts):
        return ("SEC 8-K Item 1.05. Approximately 99999 customer records were "
                "affected by the LockBit 3.0 incident on 2026-06-16.")

    draft_fns = _stub_draft_fns()
    draft_fns["sec"] = weak_sec_draft

    def sec_challenge(filing_text, fact_record):
        return Challenge(branch="sec", source="stub:challenger",
                         memo="count looks inflated",
                         objections=[Objection(TARGET_RECORDS, "99999",
                                               "overstates the record count")])
    challenge_fns = _stub_challenge_fns()
    challenge_fns["sec"] = sec_challenge

    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=draft_fns, challenge_fns=challenge_fns)
    ar = packet["adversarial_review"]
    sec_rev = next(r for r in ar["reviews"] if r["branch"] == "sec")
    assert sec_rev["confirmed"] == 1
    assert sec_rev["disposition"] == "REVISE"
    assert sec_rev["objections"][0]["verdict"] == CONFIRMED
    # the SEC drafter posted a REVISE reply in the room
    revise = [m for m in room.messages
              if m["sender"] == "sec-id" and "REVISE" in m["content"]]
    assert len(revise) == 1
    # the typed claims block the Warden gates is UNCHANGED: the gate still passed
    # green and the SEC branch released through the legal path
    assert packet["diff"]["green"] is True
    released = [t for t in packet["state_transitions"]
                if t["admitted"] and t["to_state"] == "released"]
    assert len(released) == 3


# ---- the invariant: gate + sha + replay unchanged by the Challenger ---------

def test_gate_and_replay_unchanged_with_challenger(tmp_path):
    _, packet = _run("normal", tmp_path)
    # no transition was rejected; every branch released; replay byte-identical
    rejected = [t for t in packet["state_transitions"] if not t["admitted"]]
    assert rejected == []
    assert packet["diff"]["green"] is True
    assert packet["diff"]["blocked_conflicts"] == []
    assert packet["replay"]["byte_identical"] is True


def test_challenger_posts_do_not_change_run_log_sha(tmp_path):
    # The Challenger is a pure additive Band/trace side-effect. A run WITH the
    # Challenger and a run WITHOUT it (challenge=False) must produce the IDENTICAL
    # run-log sha and both replay byte-identically: nothing the Challenger does
    # enters the hashed log.
    room_with, clients_with = _build_clients()
    p_with = run_floor(out_dir=str(tmp_path / "with"), mode="normal",
                       clients=clients_with, draft_fns=_stub_draft_fns(),
                       challenge_fns=_stub_challenge_fns())
    room_without, clients_without = _build_clients()
    p_without = run_floor(out_dir=str(tmp_path / "without"), mode="normal",
                          clients=clients_without, draft_fns=_stub_draft_fns(),
                          challenge=False)
    # the Challenger DID speak in the with-run and did NOT in the without-run
    assert _challenger_messages(room_with)
    assert not _challenger_messages(room_without)
    # identical deterministic sha, both replay byte-exact
    assert p_with["replay"]["original_sha256"] == p_without["replay"]["original_sha256"]
    assert p_with["replay"]["byte_identical"] is True
    assert p_without["replay"]["byte_identical"] is True


def test_challenger_does_not_change_sha_across_runs(tmp_path):
    # Two Challenger runs produce the identical run-log sha (determinism), and the
    # adversarial-review exchange happened in both rooms.
    room_a, _ = _run("normal", tmp_path / "a")
    p_a = json.loads(
        (tmp_path / "a" / "examiner-packet.json").read_text(encoding="utf-8"))
    room_b, _ = _run("normal", tmp_path / "b")
    p_b = json.loads(
        (tmp_path / "b" / "examiner-packet.json").read_text(encoding="utf-8"))
    assert _challenger_messages(room_a) and _challenger_messages(room_b)
    assert p_a["replay"]["original_sha256"] == p_b["replay"]["original_sha256"]


def test_challenger_runs_in_contradiction_and_chaos_modes(tmp_path):
    # The Challenger is always-on and must not break the other beats. (The
    # amendment beat needs separate characterization stubs unrelated to the
    # Challenger; it is covered by test_amendment_floor.py, where the Challenger is
    # off because that harness injects no challenger client.)
    for mode in ("inject_contradiction", "chaos"):
        room, packet = _run(mode, tmp_path / mode)
        assert _challenger_messages(room), f"Challenger ran in {mode}"
        assert packet["replay"]["byte_identical"] is True
        assert packet["adversarial_review"]["reviews"]


def test_run_log_sha_matches_baseline_without_challenger(tmp_path):
    # The captured-scenario invariant: a normal run with the Challenger ON has the
    # SAME run-log sha as the same run with it OFF, proving the hashed event stream
    # is byte-for-byte the pre-Challenger baseline.
    _, clients_on = _build_clients()
    p_on = run_floor(out_dir=str(tmp_path / "on"), mode="normal",
                     clients=clients_on, draft_fns=_stub_draft_fns(),
                     challenge_fns=_stub_challenge_fns())
    _, clients_off = _build_clients()
    p_off = run_floor(out_dir=str(tmp_path / "off"), mode="normal",
                      clients=clients_off, draft_fns=_stub_draft_fns(),
                      challenge=False)
    assert p_on["replay"]["original_sha256"] == p_off["replay"]["original_sha256"]
