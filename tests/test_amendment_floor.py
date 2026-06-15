"""test_amendment_floor.py -- the FULL floor amendment beat (the agent-to-agent
reconciliation money beat) end to end with injected fake Band clients and stub
drafters (no network, no LLM).

What this proves about the live --amendment mode:
  - FACT_AMENDED reopens the released SEC and NIS2 branches (released -> amending);
  - the Warden's deterministic guard holds the amended diff BLOCKED until the two
    drafters have CONCURRED (amendment is a no-op until concur);
  - the reconciliation is a real agent-to-agent exchange through Band: the SEC
    Drafter @mentions the NIS2 Drafter, the NIS2 Drafter @mentions back;
  - the exchange rides hash-linked reconciliation envelopes (the concur links to
    the proposal by SHA-256, so the chain is tamper-evident and replay-verifiable);
  - the amended filings pass GREEN only after concurrence, then re-release;
  - the whole run still replays byte for byte.
"""

import json
from pathlib import Path


from floor.negotiation_envelope import emit_envelope, parse_envelope
from floor.run_floor import (AMENDED_RECORDS, AMENDMENT_BRANCHES, DRAFTER_ROLES,
                             run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.negotiation import NegotiationEnvelope, Verdict


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
    """Filing-prose stubs for every drafter, plus the two characterization stubs
    the reconciliation turns use (keyed f'{branch}:characterize'). All
    deterministic so the run replays byte for byte."""
    fns = {}
    for r in DRAFTER_ROLES:
        regime = r.regime

        def make(regime):
            def fn(claim_facts):
                return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                        f"reports an incident starting {claim_facts['incident_start_utc']} "
                        f"affecting {claim_facts['records_affected']} records, attacker "
                        f"{claim_facts['attacker']}, containment "
                        f"{claim_facts['containment']}. Deterministic test stub.")
            return fn
        fns[r.branch] = make(regime)

    def sec_characterize(counterpart_text):
        return "approximately 2.1 million affected records, data categories bounded"

    def nis2_characterize(counterpart_text):
        # Concur: echo the proposed shared characterization deterministically.
        return counterpart_text

    fns["sec:characterize"] = sec_characterize
    fns["nis2:characterize"] = nis2_characterize
    return fns


def _run(tmp_path):
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="amendment", clients=clients,
                       draft_fns=_stub_draft_fns())
    return room, packet


# ---- the reopen --------------------------------------------------------------

def test_amendment_reopens_released_branches(tmp_path):
    _, packet = _run(tmp_path)
    events = [(t["correlation_id"], t["event"], t["admitted"])
              for t in packet["state_transitions"]]
    # both amendment branches reached released, then FACT_AMENDED reopened them
    for b in AMENDMENT_BRANCHES:
        corr = f"inc-8842:{b}"
        assert (corr, "human_released", True) in events
        assert (corr, "fact_amended", True) in events
    # the amending branch then re-posts a draft and re-releases
    amended_releases = [t for t in packet["state_transitions"]
                        if t["admitted"] and t["event"] == "human_released"
                        and t["correlation_id"] in
                        {f"inc-8842:{b}" for b in AMENDMENT_BRANCHES}]
    # each amendment branch is released twice: original + amended
    assert len(amended_releases) == 2 * len(AMENDMENT_BRANCHES)


def test_only_released_branches_reopen(tmp_path):
    # DORA was not part of the amendment; it must never see FACT_AMENDED.
    _, packet = _run(tmp_path)
    dora_amended = [t for t in packet["state_transitions"]
                    if t["correlation_id"] == "inc-8842:dora"
                    and t["event"] == "fact_amended"]
    assert dora_amended == []


# ---- the guard holds the diff blocked until concur ---------------------------

def test_diff_blocked_until_concur(tmp_path):
    _, packet = _run(tmp_path)
    rec = packet["reconciliation"]
    # the guard refused the amendment before any reconciliation happened
    assert rec["blocked_before_reconciliation"] is True
    assert "no concur" in rec["block_reason"]
    # ... and the amended diff only passed after concurrence
    assert rec["diff_passed_only_after_concur"] is True


def test_guard_block_recorded_in_run_log(tmp_path):
    room, packet = _run(tmp_path)
    # read the saved jsonl run log and find the pre-reconciliation guard block
    lines = Path(packet["_paths"]["run_log"]).read_text(encoding="utf-8").splitlines()
    entries = [json.loads(x) for x in lines if x.strip()]
    pre = [e for e in entries if e["type"] == "negotiation_guard"
           and e["payload"].get("phase") == "pre_reconciliation"]
    assert pre and pre[0]["payload"]["allowed"] is False
    post = [e for e in entries if e["type"] == "negotiation_guard"
            and e["payload"].get("phase") == "post_reconciliation"]
    assert post and all(p["payload"]["allowed"] for p in post)


# ---- the agent-to-agent exchange is real -------------------------------------

def test_reconciliation_is_agent_to_agent_through_band(tmp_path):
    room, packet = _run(tmp_path)
    rec = packet["reconciliation"]
    exchange = rec["exchange"]
    assert len(exchange) == 2
    propose, concur = exchange
    assert propose["from"] == "SEC Drafter" and propose["to"] == "NIS2 Drafter"
    assert propose["verdict"] == "propose"
    assert concur["from"] == "NIS2 Drafter" and concur["to"] == "SEC Drafter"
    assert concur["verdict"] == "concur"
    # both turns are real posted Band messages with ids
    assert propose["band_message_id"] and concur["band_message_id"]

    # the SEC proposal message actually @mentions the NIS2 drafter, and vice versa
    propose_msgs = [m for m in room.messages
                    if "reconcile:inc-8842:sec:round-1" in m["content"]]
    concur_msgs = [m for m in room.messages
                   if "reconcile:inc-8842:nis2:round-1" in m["content"]]
    assert len(propose_msgs) == 1 and "nis2-id" in propose_msgs[0]["mentions"]
    assert len(concur_msgs) == 1 and "sec-id" in concur_msgs[0]["mentions"]


def test_concurred_figure_is_the_amended_records(tmp_path):
    _, packet = _run(tmp_path)
    rec = packet["reconciliation"]
    assert rec["concurred_value"] == AMENDED_RECORDS
    assert rec["new_value"] == AMENDED_RECORDS
    assert rec["old_value"] == 48211


# ---- the hash-linked envelope chain ------------------------------------------

def test_envelope_chain_hash_links_correctly(tmp_path):
    _, packet = _run(tmp_path)
    chain = packet["reconciliation"]["envelope_chain"]
    assert len(chain) == 2
    propose, concur = chain
    assert propose["verdict"] == "propose"
    assert propose["prior_envelope_hash"] is None
    assert concur["verdict"] == "concur"
    # the concur links to the proposal by its exact SHA-256
    assert concur["prior_envelope_hash"] == propose["sha256"]


def test_envelope_block_round_trips_over_band():
    # The serialization the live exchange rides survives a parse byte-for-byte.
    env = NegotiationEnvelope(
        correlation_id="inc-8842:sec", amend_round=1, from_agent="sec_drafter",
        to_agent="nis2_drafter", fact_key="records_affected",
        proposed_value=AMENDED_RECORDS,
        characterization="approximately 2.1 million records",
        data_category_bounds=("name", "address", "account_number"),
        containment_framing="contained as of 2026-06-16T07:00:00+00:00",
        verdict=Verdict.PROPOSE, ts_utc="2026-06-16T08:14:00+00:00",
        prior_envelope_hash=None)
    body = "SEC proposal.\n\n" + emit_envelope(env) + "\n[dedup_key:reconcile:x]"
    parsed = parse_envelope(body)
    assert parsed.sha256() == env.sha256()


# ---- amended filings ---------------------------------------------------------

def test_amended_filings_carry_the_reconciled_figure(tmp_path):
    _, packet = _run(tmp_path)
    amended = [f for f in packet["filings"] if "amended" in f["text"].lower()
               or "intermediate report" in f["text"].lower()
               or "Amended 8-K" in f["text"]]
    # both SEC and NIS2 produced an amended filing
    assert len(amended) == 2
    for f in amended:
        assert "2,100,000" in f["text"]


def test_amended_room_has_exactly_one_amendment_per_branch(tmp_path):
    room, _ = _run(tmp_path)
    for b in AMENDMENT_BRANCHES:
        posts = [m for m in room.messages
                 if f"draft:{b}:inc-8842:amend-1" in m["content"]]
        assert len(posts) == 1


# ---- replay + determinism ----------------------------------------------------

def test_amendment_run_replays_byte_identical(tmp_path):
    _, packet = _run(tmp_path)
    assert packet["replay"]["byte_identical"] is True
    from warden.replay import RunLog, replay
    loaded = RunLog.load(Path(packet["_paths"]["run_log"]))
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]


def test_amendment_run_is_deterministic_across_runs(tmp_path):
    _, p1 = _run(tmp_path / "a")
    _, p2 = _run(tmp_path / "b")
    assert p1["reconciliation"]["envelope_chain"] == p2["reconciliation"]["envelope_chain"]
    assert p1["replay"]["original_sha256"] == p2["replay"]["original_sha256"]


def test_no_rejected_transitions_in_amendment_run(tmp_path):
    _, packet = _run(tmp_path)
    rejected = [t for t in packet["state_transitions"] if not t["admitted"]]
    assert rejected == []


# ---- the packet renders the beat ---------------------------------------------

def test_packet_html_shows_reconciliation_audit_trail(tmp_path):
    _, packet = _run(tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    # user-facing framing is deliberation/audit trail, never "negotiation"
    assert "transparent deliberation with an audit trail" in html
    assert "negotiat" not in html.lower()
    assert "hash-linked envelope chain" in html
    assert "CONCURRED" in html
    assert "2,100,000" in html


# ---- the Warden narrates the amendment gating in the room --------------------

def test_warden_narrates_amendment_block_and_release(tmp_path):
    room, _ = _run(tmp_path)
    warden_msgs = [m for m in room.messages if m["sender"] == "warden-id"]
    blob = "\n".join(m["content"] for m in warden_msgs)
    # the Warden posts the amendment BLOCK, @mentioning both reconciling drafters
    blocks = [m for m in warden_msgs if m["content"].startswith("AMENDMENT BLOCKED.")]
    assert len(blocks) == 1
    assert "sec-id" in blocks[0]["mentions"]
    assert "nis2-id" in blocks[0]["mentions"]
    # and posts the green-after-concurrence note at the reconciled figure
    assert "Concurrence recorded." in blob
    assert "Amended diff GREEN" in blob
    # and narrates the two-key re-release for both amended branches
    assert blob.count("RELEASED. Clock stopped.") >= 2
