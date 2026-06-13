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
