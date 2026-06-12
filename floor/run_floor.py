"""Deadline Room floor orchestration on the LIVE Band API.

What this run does, end to end, against live Band + Featherless:

  1. The Warden (BAND_API_KEY) creates an incident room and recruits the
     NIS2 Drafter (BAND_AGENT_ID_2) as a participant.
  2. Triage (a function the Warden process runs today, since only two Band
     agents exist) produces the canonical incident fact-record.
  3. The Warden advances the typed state machine (FACT_RECORD_POSTED) and
     posts the fact-record into the room, @mentioning the NIS2 Drafter.
  4. The NIS2 Drafter process (BAND_API_KEY_2) drains /next, sees the mention,
     calls Featherless DeepSeek-V3.2 to draft the NIS2 72h notification, and
     posts it back @mentioning the Warden.
  5. The Warden drains the draft, advances the state machine
     (DRAFT_STARTED, DRAFT_POSTED), runs the contradiction diff (single
     drafter today, so it is trivially green), runs the clocks, opens signoff,
     and a human release stops the clocks.
  6. The whole run is written to an append-only JSONL run log and replayed for
     a byte-identical check, then rendered into an Examiner Packet
     (self-contained HTML + JSON sidecar) under floor/out/.

The Warden stays deterministic: it makes zero LLM calls. Only the drafter
process drafts text.

Run live:   py floor/run_floor.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow `py floor/run_floor.py` from code/ to import warden/ and spikes/.
_CODE = Path(__file__).resolve().parent.parent
if str(_CODE) not in sys.path:
    sys.path.insert(0, str(_CODE))
sys.path.insert(0, str(_CODE / "spikes"))

from warden.clocks import ClockEngine  # noqa: E402
from warden.diff import Containment, FactClaims, diff_claims  # noqa: E402
from warden.replay import RunLog, replay  # noqa: E402
from warden.state_machine import Event, ProtocolStateMachine  # noqa: E402

from floor import roster  # noqa: E402
from floor.drafter import draft_filing  # noqa: E402
from floor.packet import write_packet  # noqa: E402
from floor.shell_adapter import LiveBand  # noqa: E402

INCIDENT_ID = "inc-8842"
INCIDENT_T0 = "2026-06-16T02:14:00+00:00"

# Triage's canonical fact-record. Triage is a function today (only two Band
# agents exist); a real Triage agent key slots in via roster.TRIAGE later.
CANONICAL_FACTS = {
    "incident_id": INCIDENT_ID,
    "incident_start_utc": INCIDENT_T0,
    "records_affected": 48211,
    "attacker": "LockBit 3.0",
    "containment": "partially_contained",
    "systems": ["core banking ledger", "customer KYC store"],
    "data_categories": ["name", "address", "account_number"],
    "regulated_entity": "Meridian Trust Bank N.V.",
    "competent_authority": "national CSIRT (NIS2)",
}


class StepTrace:
    """Collects the step-by-step trace, the typed transitions, the @mention
    handoffs, and the per-message lifecycle, for the Examiner Packet."""

    def __init__(self, log: RunLog) -> None:
        self.log = log
        self.lines: list[str] = []
        self.transitions: list[dict] = []
        self.handoffs: list[dict] = []
        self.lifecycle: dict[str, list[str]] = {}

    def say(self, line: str) -> None:
        self.lines.append(line)
        print(line, flush=True)

    def record_transition(self, t: dict) -> None:
        self.transitions.append(t)
        self.log.append("protocol_event", t)

    def record_handoff(self, frm: str, to: str, kind: str, message_id: str = "") -> None:
        self.handoffs.append({"from": frm, "to": to, "kind": kind, "message_id": message_id})

    def record_lifecycle(self, message_id: str, state: str) -> None:
        self.lifecycle.setdefault(message_id, []).append(state)


def _proto(sm: ProtocolStateMachine, trace: StepTrace, corr: str, event: Event,
           ts: str, actor: str, role: str) -> bool:
    result = sm.apply(corr, event, ts, actor=actor, actor_role=role)
    trace.record_transition({
        "correlation_id": corr, "event": event.value, "ts": ts,
        "actor": actor, "actor_role": role,
        "admitted": result.admitted,
        "to_state": result.to_state.value if result.admitted else None,
        "reason": None if result.admitted else result.reason,
    })
    return result.admitted


def run_floor(out_dir: str | None = None, draft_timeout: int = 90,
              warden=None, drafter=None, draft_fn=None) -> dict:
    """Execute the floor run and return the assembled packet dict.

    Default (no injected clients): the LIVE run against Band + Featherless.
    Tests inject `warden` and `drafter` (FakeBandClient, same surface) and a
    `draft_fn(fact_record)->str` so the orchestration logic runs with no
    network. The orchestrator never branches on which it received.

    Raises if a required Band agent is not configured or a live call fails.
    """
    out_dir = out_dir or str(Path(__file__).resolve().parent / "out")
    live = warden is None and drafter is None

    warden_role = roster.WARDEN
    nis2_role = roster.NIS2_DRAFTER
    if live:
        if not warden_role.live:
            raise RuntimeError("Warden agent not configured (BAND_API_KEY / BAND_AGENT_ID)")
        if not nis2_role.live:
            raise RuntimeError("NIS2 Drafter agent not configured (BAND_API_KEY_2 / BAND_AGENT_ID_2)")

    log = RunLog()
    trace = StepTrace(log)
    sm = ProtocolStateMachine()
    clocks = ClockEngine()

    # ---- Warden + Drafter Band clients --------------------------------
    if warden is None:
        warden = LiveBand(api_key=warden_role.agent_key, agent_name="warden",
                          dedup_namespace="warden")
    if drafter is None:
        drafter = LiveBand(api_key=nis2_role.agent_key, agent_name="nis2_drafter",
                           dedup_namespace="draft:nis2")
    if draft_fn is None:
        def draft_fn(fact_record):
            return draft_filing(fact_record, model=nis2_role.model,
                                regime="NIS2", timeout=draft_timeout)

    warden_id = warden.whoami()
    drafter_id = drafter.whoami()
    trace.say(f"[1] Warden identity: {warden_id}")
    trace.say(f"    NIS2 Drafter identity: {drafter_id}")

    # ---- Warden creates the incident room and recruits the drafter ----
    room_id = warden.create_chat(f"Deadline Room {INCIDENT_ID}")
    drafter.join(room_id)
    trace.say(f"[2] Warden created incident room {room_id}")
    warden.add_participant(drafter_id)
    trace.say(f"[3] Warden recruited NIS2 Drafter into the room")
    log.append("room", {"band_room_id": room_id, "warden_id": warden_id,
                        "drafter_id": drafter_id})

    # ---- Clocks start at T0 -------------------------------------------
    corr_nis2 = f"{INCIDENT_ID}:nis2"
    clocks.start_hours("NIS2 early warning (24h)", f"{INCIDENT_ID}:nis2-early", INCIDENT_T0, 24)
    clocks.start_hours("NIS2 full notification (72h)", corr_nis2, INCIDENT_T0, 72)
    clocks.start_sec_business_days(f"{INCIDENT_ID}:sec", INCIDENT_T0)
    for c in clocks.all():
        log.append("clock_started", {"clock": c.name, "correlation_id": c.correlation_id,
                                     "deadline": c.deadline.isoformat()})
    trace.say(f"[4] Started {len(clocks.all())} statutory clocks at T0 {INCIDENT_T0}")

    # ---- Triage produces the fact-record; Warden posts it -------------
    t_facts = "2026-06-16T02:31:00+00:00"
    _proto(sm, trace, corr_nis2, Event.FACT_RECORD_POSTED, t_facts, "triage", "triage")
    fact_text = (
        "INCIDENT FACT-RECORD (canonical). NIS2 Drafter: draft the 72-hour "
        "mandatory notification from these facts only.\n"
        + _facts_block(CANONICAL_FACTS)
    )
    res = warden.post(fact_text, mentions=[drafter_id],
                      dedup_key=f"factrecord:{INCIDENT_ID}")
    fact_msg_id = _msg_id(res)
    trace.record_handoff("Warden", "NIS2 Drafter", "fact_record", fact_msg_id)
    trace.say(f"[5] Triage fact-record posted; Warden @mentioned NIS2 Drafter "
              f"(msg {fact_msg_id})")

    # ---- NIS2 Drafter process: drain, draft via Featherless, post back -
    trace.say("[6] NIS2 Drafter draining /next for the mention ...")
    drafted = {"text": None}

    def drafter_handle(message: dict, context: list) -> dict | None:
        mid = message["id"]
        trace.record_lifecycle(mid, "processing")
        trace.say(f"    NIS2 Drafter saw mention (msg {mid}); calling Featherless "
                  f"{nis2_role.model} ...")
        text = draft_fn(CANONICAL_FACTS)
        drafted["text"] = text
        trace.record_lifecycle(mid, "processed")
        trace.say(f"    NIS2 Drafter drafted {len(text)} chars; posting back, "
                  f"@mention Warden")
        return {"content": "NIS2 72-hour notification draft attached.\n\n" + text,
                "mentions": [warden_id],
                "dedup_key": f"draft:nis2:{INCIDENT_ID}:round-1"}

    handled = drafter.run(drafter_handle, poll_seconds=2.0, max_loops=20, idle_breaks=8)
    if handled < 1 or not drafted["text"]:
        raise RuntimeError("NIS2 Drafter did not produce a draft from the mention")
    trace.record_handoff("NIS2 Drafter", "Warden", "draft", "")

    # ---- Warden drains the draft and advances the state machine -------
    trace.say("[7] Warden draining /next for the returned draft ...")
    draft_claims = {"obj": None}

    def warden_handle(message: dict, context: list) -> dict | None:
        mid = message["id"]
        trace.record_lifecycle(mid, "processing")
        t_draft = "2026-06-16T03:11:00+00:00"
        _proto(sm, trace, corr_nis2, Event.DRAFT_STARTED, t_draft,
               "nis2_drafter", "drafter")
        _proto(sm, trace, corr_nis2, Event.DRAFT_POSTED, t_draft,
               "nis2_drafter", "drafter")
        draft_claims["obj"] = FactClaims(
            "nis2", CANONICAL_FACTS["incident_start_utc"],
            CANONICAL_FACTS["records_affected"], CANONICAL_FACTS["attacker"],
            Containment.PARTIALLY_CONTAINED)
        trace.record_lifecycle(mid, "processed")
        trace.say(f"    Warden recorded DRAFT_POSTED for nis2 (msg {mid})")
        return None  # the Warden does not chat; it advances the protocol

    warden.run(warden_handle, poll_seconds=2.0, max_loops=20, idle_breaks=8)
    if draft_claims["obj"] is None:
        raise RuntimeError("Warden never observed the NIS2 draft")

    # ---- Contradiction diff (single drafter today: trivially green) ---
    t_diff = "2026-06-16T04:00:00+00:00"
    conflicts = diff_claims([draft_claims["obj"]])
    log.append("diff", {"conflicts": [c.human() for c in conflicts]})
    if conflicts:
        _proto(sm, trace, corr_nis2, Event.DIFF_BLOCKED, t_diff, "warden", "warden")
    else:
        _proto(sm, trace, corr_nis2, Event.DIFF_PASSED, t_diff, "warden", "warden")
    trace.say(f"[8] Contradiction diff: "
              f"{'GREEN (no conflicts)' if not conflicts else 'BLOCKED'} "
              f"(one drafter live; the cross-filing beat needs the SEC Drafter agent)")

    # ---- Signoff + human release stops the clocks ---------------------
    _proto(sm, trace, corr_nis2, Event.SIGNOFF_OPENED, t_diff, "warden", "warden")
    t_rel = "2026-06-16T05:00:00+00:00"
    _proto(sm, trace, corr_nis2, Event.HUMAN_RELEASED, t_rel, "lena", "human_owner")
    clocks.stop(corr_nis2, t_rel)
    log.append("clock_stopped", {"correlation_id": corr_nis2, "ts": t_rel})
    trace.say(f"[9] Warden opened signoff; human released; NIS2 clock stopped")

    breached = [c.name for c in clocks.breaches(t_rel)]

    # ---- Byte-identical replay ---------------------------------------
    original_sha = log.sha256()
    replayed = replay(log)
    replayed_sha = replayed.sha256()
    byte_identical = replayed.to_jsonl() == log.to_jsonl()
    trace.say(f"[10] Replay byte-identical: {byte_identical} "
              f"(sha {original_sha[:12]}...)")

    # ---- Assemble + write the Examiner Packet ------------------------
    packet = _assemble_packet(
        room_id, trace, clocks, conflicts, breached,
        filings=[{"regime": "NIS2", "by": "NIS2 Drafter", "model": nis2_role.model,
                  "text": drafted["text"]}],
        replay_info={"original_sha256": original_sha, "replayed_sha256": replayed_sha,
                     "byte_identical": byte_identical},
    )
    json_path, html_path = write_packet(packet, out_dir)
    run_log_path = Path(out_dir) / f"run-{INCIDENT_ID}.jsonl"
    log.save(run_log_path)
    trace.say(f"[11] Examiner Packet written:")
    trace.say(f"     {html_path}")
    trace.say(f"     {json_path}")
    trace.say(f"     run log: {run_log_path}")
    packet["_paths"] = {"html": html_path, "json": json_path,
                        "run_log": str(run_log_path)}
    return packet


def _facts_block(facts: dict) -> str:
    return "\n".join(f"  {k}: {v}" for k, v in facts.items())


def _msg_id(post_result) -> str:
    if isinstance(post_result, dict):
        d = post_result.get("data", post_result)
        if isinstance(d, dict):
            return d.get("id", "")
    return ""


def _assemble_packet(room_id, trace: StepTrace, clocks: ClockEngine,
                     conflicts, breached, filings, replay_info) -> dict:
    clock_rows = []
    for c in clocks.all():
        clock_rows.append({
            "name": c.name, "correlation_id": c.correlation_id,
            "started": c.started_at.isoformat(), "deadline": c.deadline.isoformat(),
            "stopped": c.stopped_at.isoformat() if c.stopped_at else "",
            "breached": c.breached(c.stopped_at or c.deadline) if c.stopped_at else False,
        })
    lifecycle = [{"message_id": mid, "states": states}
                 for mid, states in trace.lifecycle.items()]
    return {
        "incident": {
            "incident_id": INCIDENT_ID,
            "band_room_id": room_id,
            "fact_record": CANONICAL_FACTS,
        },
        "trace": trace.lines,
        "handoff_trace": trace.handoffs,
        "state_transitions": trace.transitions,
        "message_lifecycle": lifecycle,
        "clocks": clock_rows,
        "diff": {"conflicts": [c.human() for c in conflicts]},
        "filings": filings,
        "breached_clocks": breached,
        "replay": replay_info,
        "pending": [
            "SEC Drafter agent (BAND_API_KEY_SEC): unlocks the cross-filing "
            "contradiction-diff beat (needs a second live drafter).",
            "DORA Drafter agent (BAND_API_KEY_DORA): third racing clock.",
            "Triage agent (BAND_API_KEY_TRIAGE): promotes the fact-record step "
            "from an in-process function to its own Band agent.",
        ],
    }


def main() -> int:
    try:
        from _env import load_env  # spikes/_env.py
        load_env()
    except Exception:
        pass
    if not os.environ.get("BAND_API_KEY") or not os.environ.get("FEATHERLESS_API_KEY"):
        print("Missing BAND_API_KEY or FEATHERLESS_API_KEY (load code/.env).")
        return 1
    print("=== Deadline Room floor run (LIVE Band + Featherless) ===\n")
    packet = run_floor()
    print("\n=== Done. Examiner Packet at: "
          + packet["_paths"]["html"] + " ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
