"""test_floor_orchestration.py -- the floor run end to end with injected fake
Band clients and a stub drafter (no network, no LLM). Asserts the @mention
handoff, the message lifecycle, the typed state-machine path, the contradiction
diff, the byte-identical replay, and that the Examiner Packet is written."""

import json
from pathlib import Path

from floor.run_floor import run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom


def _build(room=None):
    room = room or FakeRoom()
    warden = FakeBandClient(room, agent_id="warden-id", agent_name="warden",
                            dedup_namespace="warden")
    drafter = FakeBandClient(room, agent_id="drafter-id", agent_name="nis2_drafter",
                             dedup_namespace="draft:nis2")
    return room, warden, drafter


def _stub_draft(fact_record):
    return ("NIS2 72-hour notification. Meridian Trust Bank N.V. reports a "
            "ransomware incident attributed to LockBit 3.0 affecting 48211 "
            "records. Containment partial. This is a deterministic test stub.")


def test_floor_run_produces_packet(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)

    # packet was written to disk (HTML + JSON sidecar)
    html_path = Path(packet["_paths"]["html"])
    json_path = Path(packet["_paths"]["json"])
    assert html_path.exists() and html_path.stat().st_size > 0
    assert json_path.exists()
    disk = json.loads(json_path.read_text())
    assert disk["incident"]["incident_id"] == "inc-8842"
    assert disk["incident"]["band_room_id"] == "fake-room-1"


def test_mention_handoff_trace_is_recorded(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)
    kinds = [h["kind"] for h in packet["handoff_trace"]]
    assert kinds == ["fact_record", "draft"]
    # the fact-record handoff went Warden -> NIS2 Drafter; the draft came back
    assert packet["handoff_trace"][0]["from"] == "Warden"
    assert packet["handoff_trace"][0]["to"] == "NIS2 Drafter"
    assert packet["handoff_trace"][1]["from"] == "NIS2 Drafter"


def test_drafter_drafted_and_posted_back_with_dedup(tmp_path):
    room, warden, drafter = _build()
    run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
              draft_fn=_stub_draft)
    # the drafter posted exactly one message back, carrying the round-1 dedup key
    draft_posts = [p for p in drafter.posted
                   if "draft:nis2:inc-8842:round-1" in p["content"]]
    assert len(draft_posts) == 1
    # it mentioned the warden
    assert draft_posts[0]["mentions"] == ["warden-id"]


def test_state_machine_reaches_released_via_legal_path(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)
    admitted = [t for t in packet["state_transitions"] if t["admitted"]]
    events = [t["event"] for t in admitted]
    # the canonical legal sequence for the nis2 branch
    assert events == [
        "fact_record_posted", "draft_started", "draft_posted",
        "diff_passed", "signoff_opened", "human_released",
    ]
    # final state is released
    assert admitted[-1]["to_state"] == "released"


def test_diff_is_green_with_single_drafter(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)
    assert packet["diff"]["conflicts"] == []


def test_message_lifecycle_states_captured(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)
    # both the drafter (on the fact-record) and the warden (on the draft)
    # carried a message through processing -> processed
    for entry in packet["message_lifecycle"]:
        assert entry["states"] == ["processing", "processed"]
    assert len(packet["message_lifecycle"]) == 2


def test_replay_is_byte_identical(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)
    assert packet["replay"]["byte_identical"] is True
    assert packet["replay"]["original_sha256"] == packet["replay"]["replayed_sha256"]
    # the saved run log on disk replays to the same hash
    from warden.replay import RunLog, replay
    run_log = Path(packet["_paths"]["run_log"])
    loaded = RunLog.load(run_log)
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]


def test_pending_notes_the_sec_drafter_seam(tmp_path):
    room, warden, drafter = _build()
    packet = run_floor(out_dir=str(tmp_path), warden=warden, drafter=drafter,
                       draft_fn=_stub_draft)
    joined = " ".join(packet["pending"])
    assert "SEC Drafter" in joined
    assert "contradiction" in joined.lower()
