"""test_full_floor.py -- the FULL floor (Triage agent + three racing drafters +
the deterministic Warden) end to end with injected fake Band clients and stub
drafters (no network, no LLM).

Covers the three demo beats:
  - normal:               three filings, diff GREEN, byte-identical replay.
  - inject_contradiction: the Warden's deterministic diff fires on the injected
                          conflict, BLOCKS signoff, then the corrected fact clears
                          it GREEN and signoff is admitted.
  - chaos:                a drafter is killed at crash position B; on recovery the
                          dedup ledger drops the duplicate, so the filing lands
                          exactly once (no double draft, no double-count).
"""

import json
from pathlib import Path

from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom


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
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _run(mode, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                     draft_fns=_stub_draft_fns())


# ---- normal mode -----------------------------------------------------------

def test_normal_three_filings_and_green_diff(tmp_path):
    packet = _run("normal", tmp_path)
    regimes = [f["regime"] for f in packet["filings"]]
    assert regimes == ["NIS2", "SEC", "DORA"]
    assert packet["diff"]["blocked_conflicts"] == []
    assert packet["diff"]["green"] is True
    assert packet["diff"]["resolution"] is None
    assert packet["breached_clocks"] == []


def test_normal_all_transitions_admitted(tmp_path):
    packet = _run("normal", tmp_path)
    rejected = [t for t in packet["state_transitions"] if not t["admitted"]]
    assert rejected == []
    # every branch reaches released through the legal path
    released = [t for t in packet["state_transitions"]
               if t["admitted"] and t["to_state"] == "released"]
    assert len(released) == 3


def test_normal_replay_byte_identical(tmp_path):
    packet = _run("normal", tmp_path)
    assert packet["replay"]["byte_identical"] is True
    from warden.replay import RunLog, replay
    loaded = RunLog.load(Path(packet["_paths"]["run_log"]))
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]


def test_packet_written_with_chaos_and_diff_sections(tmp_path):
    packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Cross-filing contradiction diff" in html
    # all three regime filings are rendered
    for regime in ("NIS2", "SEC", "DORA"):
        assert f"{regime} filing" in html


# ---- inject_contradiction mode --------------------------------------------

def test_injected_contradiction_blocks_signoff(tmp_path):
    packet = _run("inject_contradiction", tmp_path)
    blocked = packet["diff"]["blocked_conflicts"]
    assert blocked, "the diff must catch the injected conflict"
    joined = " ".join(blocked)
    # the exact conflicting load-bearing values appear in the red diff
    assert "incident_start_utc" in joined
    assert "2026-06-16T02:14:00+00:00" in joined  # canonical
    assert "2026-06-16T02:41:00+00:00" in joined  # the injected fault
    assert "Submission blocked" in joined


def test_injected_contradiction_is_deterministic_diff_not_llm(tmp_path):
    # The diff is a pure Python condition over the structured claims: run it twice
    # and the conflict set is identical.
    p1 = _run("inject_contradiction", tmp_path / "a")
    p2 = _run("inject_contradiction", tmp_path / "b")
    assert p1["diff"]["blocked_conflicts"] == p2["diff"]["blocked_conflicts"]


def test_injected_contradiction_resolves_green_and_releases(tmp_path):
    packet = _run("inject_contradiction", tmp_path)
    res = packet["diff"]["resolution"]
    assert res is not None
    assert res["fixed_branch"] == "sec"
    assert res["corrected_field"] == "incident_start_utc"
    assert res["to_value"] == "2026-06-16T02:14:00+00:00"
    # after resolution the diff is green and every branch released, legally
    assert packet["diff"]["green"] is True
    rejected = [t for t in packet["state_transitions"] if not t["admitted"]]
    assert rejected == []
    released = [t for t in packet["state_transitions"]
               if t["admitted"] and t["to_state"] == "released"]
    assert len(released) == 3


def test_injected_contradiction_state_path_blocks_then_passes(tmp_path):
    packet = _run("inject_contradiction", tmp_path)
    events = [t["event"] for t in packet["state_transitions"] if t["admitted"]]
    # the diff blocked at least once before it passed
    assert "diff_blocked" in events
    assert "diff_passed" in events
    assert events.index("diff_blocked") < events.index("diff_passed")
    # signoff opens only after the diff passes (the block held)
    assert events.index("diff_passed") < events.index("signoff_opened")


def test_clean_run_never_blocks(tmp_path):
    packet = _run("normal", tmp_path)
    events = [t["event"] for t in packet["state_transitions"] if t["admitted"]]
    assert "diff_blocked" not in events


# ---- chaos mode ------------------------------------------------------------

def test_chaos_exactly_once_no_double_draft(tmp_path):
    packet = _run("chaos", tmp_path)
    chaos = packet["chaos"]
    assert chaos["duplicates_dropped"] == 1
    # the killed branch shows a kill then a recovery
    phases = [(e["branch"], e["phase"]) for e in chaos["events"]]
    assert ("sec", "kill") in phases
    assert ("sec", "recovery") in phases
    # exactly one ACCEPTED ledger entry for the killed branch's round-1 draft
    accepted = [e for e in chaos["ledger"]
                if e["key"] == "draft:sec:inc-8842:round-1"
                and e["disposition"] == "accepted"]
    dropped = [e for e in chaos["ledger"]
               if e["key"] == "draft:sec:inc-8842:round-1"
               and e["disposition"] == "duplicate_dropped"]
    assert len(accepted) == 1
    assert len(dropped) == 1


def test_chaos_still_files_all_three_and_releases(tmp_path):
    packet = _run("chaos", tmp_path)
    regimes = [f["regime"] for f in packet["filings"]]
    assert regimes == ["NIS2", "SEC", "DORA"]
    rejected = [t for t in packet["state_transitions"] if not t["admitted"]]
    assert rejected == []
    assert packet["replay"]["byte_identical"] is True


def test_chaos_room_has_exactly_one_sec_draft(tmp_path):
    # The exactly-once guarantee at the transport level: despite the kill and
    # re-drain, the SEC drafter's round-1 draft appears once in the room.
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="chaos", clients=clients,
              draft_fns=_stub_draft_fns())
    sec_drafts = [m for m in room.messages
                  if "draft:sec:inc-8842:round-1" in m["content"]]
    assert len(sec_drafts) == 1


def test_chaos_packet_shows_exactly_once_evidence(tmp_path):
    packet = _run("chaos", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "exactly-once recovery" in html
    assert "Duplicates dropped" in html


# ---- liveness loop (heartbeat -> declared-dead -> recovery) ----------------

def test_chaos_declares_dead_then_recovers_exactly_once(tmp_path):
    # The killed SEC drafter is detected (declared dead past the liveness
    # threshold) AND recovered, with the filing landing exactly once: 0 double
    # files. This is the detection -> declaration -> recovery loop made visible
    # over the exactly-once recovery that already worked.
    packet = _run("chaos", tmp_path)
    lv = packet["operability"]["liveness"]
    assert lv is not None
    assert lv["declared_dead_count"] == 1
    assert lv["recovered_count"] == 1
    assert lv["all_recovered"] is True
    assert lv["double_files"] == 0
    assert lv["declared_dead"][0]["branch"] == "sec"
    # the filing still landed exactly once (the existing exactly-once guarantee)
    assert packet["chaos"]["duplicates_dropped"] == 1
    accepted = [e for e in packet["chaos"]["ledger"]
                if e["key"] == "draft:sec:inc-8842:round-1"
                and e["disposition"] == "accepted"]
    assert len(accepted) == 1


def test_chaos_liveness_threshold_is_logical_and_deterministic(tmp_path):
    # The detection threshold is a LOGICAL (drain-cycle) bound, not wall-clock:
    # two runs of the same chaos beat declare the agent dead at the same logical
    # tick with the same detection latency, and replay stays byte-identical.
    import time
    p_a = _run("chaos", tmp_path / "a")
    time.sleep(0.05)  # real time passes; a wall-clock threshold would drift
    p_b = _run("chaos", tmp_path / "b")
    dead_a = p_a["operability"]["liveness"]["declared_dead"][0]
    dead_b = p_b["operability"]["liveness"]["declared_dead"][0]
    assert dead_a["tick"] == dead_b["tick"]
    assert dead_a["detection_latency_ticks"] == dead_b["detection_latency_ticks"]
    # the run-log sha and replay are unmoved by the liveness layer
    assert p_a["replay"]["original_sha256"] == p_b["replay"]["original_sha256"]
    assert p_a["replay"]["byte_identical"] is True
    assert p_b["replay"]["byte_identical"] is True


def test_healthy_run_declares_no_one_dead(tmp_path):
    # A normal run advances every drafter every cycle: no agent is ever declared
    # dead, so the operability liveness section is absent (no false positive).
    packet = _run("normal", tmp_path)
    assert packet["operability"]["liveness"] is None


def test_warden_narrates_declared_dead_and_recovery_in_room(tmp_path):
    # The Warden posts the declared-dead and recovered narration into the Band
    # room (additive visibility), @mentioning the killed drafter.
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="chaos", clients=clients,
              draft_fns=_stub_draft_fns())
    warden_msgs = _warden_messages(room)
    dead = [m for m in warden_msgs if "missed its heartbeat" in m["content"]]
    recovered = [m for m in warden_msgs
                 if "recovered" in m["content"]
                 and "Exactly-once held across the declared-dead window"
                 in m["content"]]
    assert len(dead) == 1, "the Warden must declare the killed drafter dead"
    assert len(recovered) == 1, "the Warden must narrate the recovery"
    assert "sec-id" in dead[0]["mentions"]
    assert "sec-id" in recovered[0]["mentions"]


def test_liveness_posts_do_not_change_sha_or_replay(tmp_path):
    # The liveness narration is additive (room posts + out-of-log operability),
    # never in the hashed run-log: the chaos run-log sha is identical run to run
    # and replay holds. This is the same sha-neutral guarantee the other Warden
    # room posts carry.
    room_a, clients_a = _build_clients()
    p_a = run_floor(out_dir=str(tmp_path / "a"), mode="chaos", clients=clients_a,
                    draft_fns=_stub_draft_fns())
    room_b, clients_b = _build_clients()
    p_b = run_floor(out_dir=str(tmp_path / "b"), mode="chaos", clients=clients_b,
                    draft_fns=_stub_draft_fns())
    # the Warden DID narrate liveness in both rooms
    assert any("missed its heartbeat" in m["content"]
               for m in _warden_messages(room_a))
    assert any("missed its heartbeat" in m["content"]
               for m in _warden_messages(room_b))
    assert p_a["replay"]["original_sha256"] == p_b["replay"]["original_sha256"]
    assert p_a["replay"]["byte_identical"] is True
    assert p_b["replay"]["byte_identical"] is True


def test_liveness_section_renders_in_packet_html(tmp_path):
    packet = _run("chaos", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Liveness loop" in html
    assert "declared-dead" in html
    assert "logical" in html.lower()


# ---- claims envelope -------------------------------------------------------

def test_drafters_emit_parsable_structured_claims(tmp_path):
    from floor.claims import parse_claims
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
              draft_fns=_stub_draft_fns())
    # every drafter's posted message carries a parsable [CLAIMS] block
    for r in DRAFTER_ROLES:
        posts = [m for m in room.messages
                 if f"draft:{r.branch}:inc-8842:round-1" in m["content"]]
        assert len(posts) == 1
        claims = parse_claims(posts[0]["content"])
        assert claims.branch == r.branch
        assert claims.records_affected == 48211


def test_disk_packet_records_mode_and_room(tmp_path):
    packet = _run("inject_contradiction", tmp_path)
    disk = json.loads(Path(packet["_paths"]["json"]).read_text(encoding="utf-8"))
    assert disk["incident"]["mode"] == "inject_contradiction"
    assert disk["incident"]["band_room_id"] == "fake-room-1"


# ---- the Warden speaks IN the room (visible referee) -----------------------

def _warden_messages(room):
    """Every message the Warden authored into the shared room."""
    return [m for m in room.messages if m["sender"] == "warden-id"]


def test_warden_posts_acks_diff_and_release_in_normal_flow(tmp_path):
    # In the normal flow the Warden is no longer a silent in-process referee: it
    # posts its own decisions into the room as it makes them.
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns())
    warden_msgs = _warden_messages(room)
    texts = [m["content"] for m in warden_msgs]
    blob = "\n".join(texts)

    # one per-filing ack for each drafter, @mentioning that drafter
    for r in DRAFTER_ROLES:
        acks = [m for m in warden_msgs
                if f"recorded {r.regime} filing" in m["content"]
                and f"{r.branch}-id" in m["mentions"]]
        assert len(acks) == 1, f"expected one Warden ack for {r.regime}"
    # the green-diff announcement and the CONSOLIDATED release announcements: the
    # room narration is two messages (first key across all branches, then second
    # key across all branches), not six near-identical per-branch broadcasts.
    assert "Contradiction diff GREEN" in blob
    key1 = [m for m in warden_msgs
            if "First of two" in m["content"] and "Awaiting" in m["content"]]
    key2 = [m for m in warden_msgs
            if "Both keys present on all" in m["content"]
            and "RELEASED, clocks stopped." in m["content"]]
    assert len(key1) == 1, "one consolidated first-key (GC) message, not three"
    assert len(key2) == 1, "one consolidated second-key (Lena) message, not three"
    # the single consolidated pair names every released branch once
    for regime in ("NIS2", "SEC", "DORA"):
        assert regime in key1[0]["content"]
        assert regime in key2[0]["content"]
    # the OLD six-broadcast form is gone
    assert blob.count("Awaiting second key") == 0
    assert blob.count("RELEASED. Clock stopped.") == 0

    # the gate decisions and replay are UNCHANGED by the Warden talking: every
    # branch still recorded two distinct keys in the run log (per-branch gate
    # intact), only the room narration was consolidated.
    run_log = (tmp_path / "run-inc-8842-normal.jsonl").read_text(encoding="utf-8")
    entries = [json.loads(line) for line in run_log.splitlines() if line.strip()]
    signoffs = [e["payload"] for e in entries if e["type"] == "release_signoff"]
    # two distinct human keys per released branch (3 branches -> 6 signoffs)
    assert len(signoffs) == 6
    by_corr: dict[str, set] = {}
    for s in signoffs:
        by_corr.setdefault(s["correlation_id"], set()).add(s["role"])
    assert len(by_corr) == 3
    for roles in by_corr.values():
        assert roles == {"general_counsel", "head_of_ir"}

    assert packet["diff"]["green"] is True
    assert packet["diff"]["blocked_conflicts"] == []
    assert packet["replay"]["byte_identical"] is True


def test_warden_posts_block_mentioning_conflicting_drafters(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="inject_contradiction", clients=clients,
              draft_fns=_stub_draft_fns())
    warden_msgs = _warden_messages(room)
    blocks = [m for m in warden_msgs if m["content"].startswith("BLOCKED.")]
    assert len(blocks) == 1, "the Warden must post its BLOCK into the room"
    block = blocks[0]
    # the exact conflicting values appear in the Warden's BLOCK
    assert "incident_start_utc" in block["content"]
    assert "2026-06-16T02:14:00+00:00" in block["content"]
    assert "2026-06-16T02:41:00+00:00" in block["content"]
    # the BLOCK @mentions the two conflicting drafters (SEC and one peer)
    assert "sec-id" in block["mentions"]
    assert len(block["mentions"]) == 2
    # on the corrected re-run the Warden posts the resolution
    resolved = [m for m in warden_msgs if m["content"].startswith("Resolved.")]
    assert len(resolved) == 1


def test_blocked_drafter_visibly_refiles_between_block_and_resolution(tmp_path):
    # The contradiction beat must be a REAL round-trip: the blocked SEC drafter
    # speaks its own corrected re-filing in the room, @mentioning the Warden,
    # AFTER the Warden's BLOCK and BEFORE the Warden's GREEN resolution. The room
    # shows the actual corrected filing (corrected [CLAIMS], incident_start 02:14),
    # not just the Warden narrating a silent in-process fix.
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="inject_contradiction",
                       clients=clients, draft_fns=_stub_draft_fns())

    # locate the three messages by author and content
    def index_of(predicate):
        for i, m in enumerate(room.messages):
            if predicate(m):
                return i
        return -1

    block_i = index_of(
        lambda m: m["sender"] == "warden-id" and m["content"].startswith("BLOCKED."))
    refile_i = index_of(
        lambda m: m["sender"] == "sec-id"
        and "corrected re-filing" in m["content"])
    resolved_i = index_of(
        lambda m: m["sender"] == "warden-id" and m["content"].startswith("Resolved."))

    assert block_i != -1, "the Warden must post its BLOCK"
    assert refile_i != -1, "the SEC drafter must post its corrected re-filing"
    assert resolved_i != -1, "the Warden must post the GREEN resolution"
    # strict ordering: BLOCK -> SEC corrected re-file -> GREEN resolution
    assert block_i < refile_i < resolved_i

    block = room.messages[block_i]
    refile = room.messages[refile_i]

    # the Warden BLOCK @mentions SEC and its conflicting peer
    assert "sec-id" in block["mentions"]
    assert len(block["mentions"]) == 2

    # the SEC re-filing is authored by the SEC drafter and @mentions the Warden
    assert refile["sender"] == "sec-id"
    assert refile["mentions"] == ["warden-id"]

    # the corrected re-filing carries the corrected [CLAIMS] block: branch sec,
    # incident_start the canonical 02:14. The claims block (the load-bearing
    # facts the Warden diffs) holds 02:14 and NOT the perturbed 02:41.
    content = refile["content"]
    claims_block = content[content.index("[CLAIMS]"):content.index("[/CLAIMS]")]
    assert "branch=sec" in claims_block
    assert "incident_start_utc=2026-06-16T02:14:00+00:00" in claims_block
    assert "2026-06-16T02:41:00+00:00" not in claims_block

    # the gate decisions and replay are UNCHANGED by the drafter speaking: the
    # diff blocked then resolved, and byte-identical replay holds
    assert packet["diff"]["blocked_conflicts"]
    assert packet["diff"]["resolution"]["fixed_branch"] == "sec"
    assert packet["replay"]["byte_identical"] is True


def test_contradiction_is_two_way_peer_reconciliation(tmp_path):
    # The contradiction beat is a GENUINE two-way conversation, not the Warden
    # dictating. After the Warden BLOCK the two conflicting drafters TALK to each
    # other: SEC @mentions NIS2 asking which value is canonical, NIS2 @mentions
    # SEC back confirming the fact-record value, THEN SEC re-files @Warden, THEN
    # the Warden posts GREEN. Full exchange in order:
    #   Warden BLOCK @SEC @NIS2
    #   -> SEC @NIS2 reconcile
    #   -> NIS2 @SEC confirm
    #   -> SEC corrected re-file @Warden (incident_start 02:14 in [CLAIMS])
    #   -> Warden GREEN
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="inject_contradiction",
                       clients=clients, draft_fns=_stub_draft_fns())

    def index_of(predicate):
        for i, m in enumerate(room.messages):
            if predicate(m):
                return i
        return -1

    block_i = index_of(
        lambda m: m["sender"] == "warden-id" and m["content"].startswith("BLOCKED."))
    reconcile_i = index_of(
        lambda m: m["sender"] == "sec-id"
        and m["content"].startswith("@NIS2 Drafter")
        and "Which is canonical" in m["content"])
    confirm_i = index_of(
        lambda m: m["sender"] == "nis2-id"
        and m["content"].startswith("@SEC Drafter")
        and "is canonical per the fact-record" in m["content"])
    refile_i = index_of(
        lambda m: m["sender"] == "sec-id" and "corrected re-filing" in m["content"])
    green_i = index_of(
        lambda m: m["sender"] == "warden-id" and m["content"].startswith("Resolved."))

    assert block_i != -1, "the Warden must post its BLOCK"
    assert reconcile_i != -1, "SEC must @mention NIS2 to reconcile"
    assert confirm_i != -1, "NIS2 must @mention SEC back confirming the canonical value"
    assert refile_i != -1, "SEC must post its corrected re-filing"
    assert green_i != -1, "the Warden must post the GREEN resolution"

    # strict ordering of the full two-way exchange
    assert block_i < reconcile_i < confirm_i < refile_i < green_i

    # SEC -> NIS2 reconcile @mentions NIS2 and names both conflicting values
    reconcile = room.messages[reconcile_i]
    assert reconcile["mentions"] == ["nis2-id"]
    assert "2026-06-16T02:14:00+00:00" in reconcile["content"]
    assert "2026-06-16T02:41:00+00:00" in reconcile["content"]

    # NIS2 -> SEC confirm @mentions SEC back and states the canonical value
    confirm = room.messages[confirm_i]
    assert confirm["mentions"] == ["sec-id"]
    assert "2026-06-16T02:14:00+00:00" in confirm["content"]

    # the corrected re-file carries the canonical 02:14 in its [CLAIMS] block
    refile = room.messages[refile_i]
    content = refile["content"]
    claims_block = content[content.index("[CLAIMS]"):content.index("[/CLAIMS]")]
    assert "incident_start_utc=2026-06-16T02:14:00+00:00" in claims_block
    assert "2026-06-16T02:41:00+00:00" not in claims_block

    # gate decisions + replay UNCHANGED by the peer talk (additive visibility)
    assert packet["diff"]["blocked_conflicts"]
    assert packet["diff"]["resolution"]["fixed_branch"] == "sec"
    assert packet["replay"]["byte_identical"] is True


def test_peer_reconciliation_does_not_change_replay_or_sha(tmp_path):
    # The SEC<->NIS2 reconciliation posts are additive visibility side-effects,
    # NOT in the hashed run-log. Two contradiction runs produce the identical sha.
    room_a, clients_a = _build_clients()
    p_a = run_floor(out_dir=str(tmp_path / "a"), mode="inject_contradiction",
                    clients=clients_a, draft_fns=_stub_draft_fns())
    room_b, clients_b = _build_clients()
    p_b = run_floor(out_dir=str(tmp_path / "b"), mode="inject_contradiction",
                    clients=clients_b, draft_fns=_stub_draft_fns())
    # the peer talk happened in both rooms
    assert any(m["sender"] == "sec-id" and "Which is canonical" in m["content"]
               for m in room_a.messages)
    assert any(m["sender"] == "nis2-id" and "is canonical per the fact-record" in m["content"]
               for m in room_b.messages)
    # identical deterministic sha, replay byte-exact, SEC deadline unchanged
    assert p_a["replay"]["original_sha256"] == p_b["replay"]["original_sha256"]
    assert p_a["replay"]["byte_identical"] is True
    assert p_b["replay"]["byte_identical"] is True


def test_blocked_drafter_refile_does_not_change_replay_or_sha(tmp_path):
    # The corrected re-filing is an additive visibility side-effect, NOT in the
    # hashed run-log. Two contradiction runs produce the same sha and replay holds.
    room_a, clients_a = _build_clients()
    p_a = run_floor(out_dir=str(tmp_path / "a"), mode="inject_contradiction",
                    clients=clients_a, draft_fns=_stub_draft_fns())
    room_b, clients_b = _build_clients()
    p_b = run_floor(out_dir=str(tmp_path / "b"), mode="inject_contradiction",
                    clients=clients_b, draft_fns=_stub_draft_fns())
    # the SEC drafter DID re-file in both rooms
    assert any("corrected re-filing" in m["content"]
               for m in room_a.messages if m["sender"] == "sec-id")
    assert any("corrected re-filing" in m["content"]
               for m in room_b.messages if m["sender"] == "sec-id")
    # the deterministic run-log sha is identical run to run, replay byte-exact
    assert p_a["replay"]["original_sha256"] == p_b["replay"]["original_sha256"]
    assert p_a["replay"]["byte_identical"] is True
    assert p_b["replay"]["byte_identical"] is True


def test_warden_posts_dedup_drop_on_chaos(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="chaos", clients=clients,
              draft_fns=_stub_draft_fns())
    warden_msgs = _warden_messages(room)
    drops = [m for m in warden_msgs
             if "Exactly-once held, no double-file." in m["content"]]
    assert len(drops) == 1, "the Warden must narrate the duplicate drop"
    assert "duplicate SEC filing dropped" in drops[0]["content"]
    assert "sec-id" in drops[0]["mentions"]


def test_warden_room_posts_do_not_change_replay_or_sha(tmp_path):
    # The Warden's room posts are an additive visibility side-effect, NOT in the
    # hashed run-log. Two runs produce the same original sha and replay holds.
    room_a, clients_a = _build_clients()
    p_a = run_floor(out_dir=str(tmp_path / "a"), mode="normal", clients=clients_a,
                    draft_fns=_stub_draft_fns())
    room_b, clients_b = _build_clients()
    p_b = run_floor(out_dir=str(tmp_path / "b"), mode="normal", clients=clients_b,
                    draft_fns=_stub_draft_fns())
    # the Warden DID speak in both rooms
    assert _warden_messages(room_a)
    assert _warden_messages(room_b)
    # and the deterministic run-log sha is identical run to run, replay byte-exact
    assert p_a["replay"]["original_sha256"] == p_b["replay"]["original_sha256"]
    assert p_a["replay"]["byte_identical"] is True
    assert p_b["replay"]["byte_identical"] is True
