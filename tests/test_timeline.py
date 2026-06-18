"""test_timeline.py -- the unified incident timeline and after-action (E4.10).

The UNIFIED INCIDENT TIMELINE reconstructs the single chronological incident
timeline from the sealed run (every clock start, draft, gate, veto, release,
recruit, with its UTC timestamp + actor), the first artifact the board and the
examiner ask for. The AFTER-ACTION artifact is the structured post-incident
summary derived from the same run (the response-time margin per clock, where the
facts changed, what the Challenger caught, the controls that operated, any
breaches). Both are pure derived reads over the assembled packet, exactly like the
control-evidence register (E4.4) and the consistency sheet (E4.3).

Layers:

  Unit layer over floor/timeline.py: the timeline folds the packet's transitions,
  clock starts / stops, and recruits into one chronologically ordered list, each
  tied to the run's chain head; the ordering is deterministic; the after-action
  computes the per-clock margin and the amendment delta.

  Render layer over the packet HTML: the timeline table and the after-action
  summary render.

  Derived layer: no LLM surface, no run-log mutation, deterministic across runs.

  Guard layer: the four DEFAULT sealed captures' run-log shas are byte-for-byte
  unchanged by this render/derive-only feature.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.timeline as timeline_mod
from floor.timeline import (
    KIND_CLOCK_START,
    KIND_CLOCK_STOP,
    KIND_FACT_CHANGE,
    KIND_RECRUIT,
    after_action_record,
    build_after_action,
    build_timeline,
    timeline_record,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "web" / "data"
DEFAULT_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


def _packet(mode: str) -> dict:
    return json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))


# ---- unit layer: the timeline is chronological and complete -----------------

def test_timeline_is_chronologically_ordered():
    # Every default capture's timeline is non-empty and sorted by UTC timestamp.
    for mode in DEFAULT_MODES:
        tl = build_timeline(_packet(mode))
        assert tl.entries, f"{mode}: timeline must not be empty"
        timestamps = [e.ts for e in tl.entries if e.ts]
        assert timestamps == sorted(timestamps), (
            f"{mode}: timeline entries are not chronologically ordered")


def test_timeline_covers_the_key_lifecycle_events():
    # The normal run starts a clock, posts the fact-record, drafts, gates the diff,
    # opens signoff, releases, and stops a clock. The timeline must surface them.
    tl = build_timeline(_packet("normal"))
    events = {e.event for e in tl.entries}
    for required in ("clock_started", "fact_record_posted", "draft_posted",
                     "diff_passed", "human_released", "clock_stopped"):
        assert required in events, f"timeline missing {required}"


def test_amendment_run_marks_the_fact_change():
    # The amendment run revised a load-bearing fact; the timeline tags it as a fact
    # change so the board sees exactly when the facts moved.
    tl = build_timeline(_packet("amendment"))
    fact_changes = [e for e in tl.entries if e.kind == KIND_FACT_CHANGE]
    assert fact_changes, "the amendment run must carry a fact-change timeline entry"
    assert all(e.event == "fact_amended" for e in fact_changes)


def test_recruit_appears_when_a_late_jurisdiction_was_recruited():
    # The submit capture recruits the UK ICO at runtime; the timeline must show the
    # recruit pinned at the late clock's start. A capture without it shows none.
    submit = DATA / "packet-submit.json"
    if submit.exists():
        tl = build_timeline(json.loads(submit.read_text(encoding="utf-8")))
        recruits = [e for e in tl.entries if e.kind == KIND_RECRUIT]
        assert recruits, "the submit capture recruits a late jurisdiction"
    # A clean run with no recruit shows no recruit entry.
    clean = build_timeline(_packet("normal"))
    assert not [e for e in clean.entries if e.kind == KIND_RECRUIT]


def test_timeline_references_the_chain_head():
    # Each timeline is tied to the run's chain head, so it is tamper-evident (a
    # reorder of the log moves the head and visibly reorders the timeline).
    for mode in DEFAULT_MODES:
        packet = _packet(mode)
        tl = build_timeline(packet)
        assert tl.chain_head == packet["replay"]["chain_head"]
        assert len(tl.chain_head) == 64


def test_clock_start_and_stop_carry_the_deadline_context():
    tl = build_timeline(_packet("normal"))
    starts = [e for e in tl.entries if e.kind == KIND_CLOCK_START]
    stops = [e for e in tl.entries if e.kind == KIND_CLOCK_STOP]
    assert starts and stops
    assert all(e.deadline_note for e in starts), "clock starts must carry a note"
    assert all(e.deadline_note for e in stops), "clock stops must carry a note"


def test_only_admitted_transitions_are_on_the_timeline():
    # A rejected (illegal) transition never executed, so it is not on the timeline.
    packet = {
        "replay": {"chain_head": "a" * 64},
        "state_transitions": [
            {"event": "human_released", "ts": "2026-06-16T05:00:00+00:00",
             "actor": "lena", "admitted": False, "correlation_id": "x"},
            {"event": "diff_passed", "ts": "2026-06-16T04:00:00+00:00",
             "actor": "warden", "admitted": True, "correlation_id": "x"},
        ],
    }
    tl = build_timeline(packet)
    events = [e.event for e in tl.entries]
    assert "diff_passed" in events
    assert "human_released" not in events


def test_timeline_record_empty_when_no_events():
    assert timeline_record({}) == {}
    assert build_timeline({}).entries == ()


# ---- unit layer: the after-action summary -----------------------------------

def test_after_action_reports_the_deadline_margins():
    aa = build_after_action(_packet("normal"))
    assert aa["deadlines_filed"] >= 1
    assert aa["deadlines_met"] == aa["deadlines_filed"]  # the clean run meets all
    assert aa["deadlines_breached"] == 0
    assert aa["clock_margins"], "the per-clock margin table must be present"
    for m in aa["clock_margins"]:
        assert "margin_human" in m


def test_after_action_captures_the_amendment_delta():
    aa = build_after_action(_packet("amendment"))
    fc = aa["fact_change"]
    assert fc is not None, "the amendment run must record where the facts changed"
    assert fc["fact_key"] == "records_affected"
    assert fc["old_value"] != fc["new_value"]
    assert fc["reopened_branches"]


def test_after_action_lists_findings():
    aa = build_after_action(_packet("amendment"))
    assert aa["findings"], "the after-action must summarize findings"
    joined = " ".join(aa["findings"])
    assert "deadline" in joined.lower()


def test_after_action_record_empty_without_clocks():
    assert after_action_record({}) == {}


# ---- derived: no LLM surface, no run-log mutation, deterministic -------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    src = inspect.getsource(timeline_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", ".save("):
        assert token not in src, f"timeline module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    packet = _packet("amendment")
    before = json.dumps(packet, sort_keys=True)
    build_timeline(packet)
    timeline_record(packet)
    build_after_action(packet)
    after_action_record(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_timeline_is_deterministic_across_two_derivations():
    packet = _packet("amendment")
    a = timeline_record(packet)
    b = timeline_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    aa1 = after_action_record(packet)
    aa2 = after_action_record(packet)
    assert json.dumps(aa1, sort_keys=True) == json.dumps(aa2, sort_keys=True)


# ---- render layer -----------------------------------------------------------

def test_packet_html_renders_the_timeline_and_after_action():
    from floor.packet import _render_html
    packet = _packet("amendment")
    packet["timeline"] = timeline_record(packet)
    packet["after_action"] = after_action_record(packet)
    html = _render_html(packet)
    assert "Unified incident timeline" in html
    assert "After-action review" in html
    assert packet["replay"]["chain_head"] in html  # the tamper-evident seal


# ---- guard layer: the sealed captures are byte-for-byte unchanged ------------

_SEALED_SHAS = {
    "normal": (
        "4721e56cced08b2cfc663b0bca2e392bddae18ceec919f8a386a544f2d17b625",
        "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3"),
    "inject_contradiction": (
        "4de0c9d86e6afab0923801d2aa258d50a59db88c83ddfd6c88fd3c90e26487a6",
        "f1f2223aa57b4bace83bf3fcfc5886e2a657d86f15b5d9ed0762646142e34e98"),
    "chaos": (
        "81ecd17595336435f6e3bb73dbc32f7f79cb729e462d7d5fdd0bd9de6cdfa463",
        "303c437140df55fc6694780d6b54715921e9eed017eb8b9c4a348907b268b520"),
    "amendment": (
        "a10940ab4df880cd2e3aa6f9ec1a4095ac18c5e1e338bf7510e11429317eeaf4",
        "0ca07fb0a1f975a84de67966d2724137210c4b7ede1b5ddde96a53650d0c8bbc"),
}


def test_sealed_run_log_shas_unchanged_by_this_derive_only_feature():
    for mode in DEFAULT_MODES:
        jsonl = DATA / f"run-inc-8842-{mode}.jsonl"
        sig = json.loads((DATA / f"run-inc-8842-{mode}.jsonl.sig.json")
                         .read_text(encoding="utf-8"))
        file_sha = hashlib.sha256(jsonl.read_bytes()).hexdigest()
        expected_file_sha, expected_signed_sha = _SEALED_SHAS[mode]
        assert file_sha == expected_file_sha, (
            f"{mode}: on-disk run-log bytes changed; the timeline / after-action "
            f"feature must be render-only and never touch the sealed log")
        assert sig["sha256"] == expected_signed_sha, (
            f"{mode}: signed run-log sha changed; the timeline must never enter the "
            f"hashed run-log")
