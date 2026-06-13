"""Deadline Room floor orchestration on the LIVE Band API.

This is the FULL floor: a Triage Band agent, three racing regulatory drafters
(NIS2, SEC, DORA) on independent Featherless models, the deterministic Warden
refereeing every typed handoff, the cross-filing contradiction diff, the
exactly-once chaos-recovery beat, byte-identical replay, and the Examiner Packet.

Three runnable modes, each against live Band + Featherless:

  normal               every filing drafted, claims agree, diff GREEN, release.
  inject_contradiction one drafter is fed a perturbed incident_start_utc, so two
                       filings disagree on a load-bearing fact. The Warden's
                       deterministic diff catches it and BLOCKS signoff; the
                       packet shows the red conflict; then the fact is corrected,
                       the diff goes GREEN, and release proceeds.
  chaos                one drafter is killed mid-handoff (crash position B: it
                       posts, then is killed before marking the message
                       processed). On recovery it re-drains /next, the dedup
                       ledger drops the duplicate, and the filing lands exactly
                       once. No double draft.

Drafters run SEQUENTIALLY: Featherless allows only one big model at a time and
caps model switches, so the racing-clocks STORY is carried by the Warden tracking
all clocks, not by literal simultaneous inference.

The Warden makes ZERO LLM calls. Only drafter processes draft text.

Run live:
  py floor/run_floor.py                       (normal)
  py floor/run_floor.py --inject-contradiction
  py floor/run_floor.py --chaos
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow `py floor/run_floor.py` from code/ to import warden/ and spikes/.
_CODE = Path(__file__).resolve().parent.parent
if str(_CODE) not in sys.path:
    sys.path.insert(0, str(_CODE))
sys.path.insert(0, str(_CODE / "spikes"))

from warden.clocks import ClockEngine  # noqa: E402
from warden.diff import diff_claims  # noqa: E402
from warden.ledger import Disposition, IdempotencyLedger  # noqa: E402
from warden.replay import RunLog, replay  # noqa: E402
from warden.state_machine import Event, ProtocolStateMachine  # noqa: E402

from floor import roster  # noqa: E402
from floor.claims import parse_claims  # noqa: E402
from floor.drafter import build_draft_body, draft_filing  # noqa: E402
from floor.packet import write_packet  # noqa: E402
from floor.shell_adapter import LiveBand  # noqa: E402

INCIDENT_ID = "inc-8842"
INCIDENT_T0 = "2026-06-16T02:14:00+00:00"

# Triage's canonical fact-record. In normal/chaos runs every drafter draws from
# this. In inject_contradiction the SEC drafter is handed a perturbed copy.
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

# The perturbed incident_start the SEC drafter reports in --inject-contradiction:
# 02:41 UTC against the canonical 02:14 UTC. A real transposition error, the kind
# the diff exists to catch. UTC-canonical so it is a genuine disagreement, not a
# timezone artifact.
CONTRADICTION_START_UTC = "2026-06-16T02:41:00+00:00"

# The drafters of the full floor, in deterministic sequential order. Featherless
# runs one big model at a time, so the Warden walks them one after another.
DRAFTER_ROLES = [roster.NIS2_DRAFTER, roster.SEC_DRAFTER, roster.DORA_DRAFTER]

# Demo-mode timestamps for the protocol clock. Fixed so replay is byte-stable.
TS_FACTS = "2026-06-16T02:31:00+00:00"
TS_DRAFT = "2026-06-16T03:11:00+00:00"
TS_DIFF = "2026-06-16T04:00:00+00:00"
TS_RESOLVE = "2026-06-16T04:20:00+00:00"
TS_RELEASE = "2026-06-16T05:00:00+00:00"


class StepTrace:
    """Collects the step-by-step trace, the typed transitions, the @mention
    handoffs, and the per-message lifecycle, for the Examiner Packet."""

    def __init__(self, log: RunLog) -> None:
        self.log = log
        self.lines: list[str] = []
        self.transitions: list[dict] = []
        self.handoffs: list[dict] = []
        self.lifecycle: dict[str, list[str]] = {}
        self.chaos_events: list[dict] = []

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

    def record_chaos(self, event: dict) -> None:
        self.chaos_events.append(event)
        self.log.append("chaos", event)


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


# ----------------------------------------------------------------------------
# Public entry point. Dispatches the legacy single-drafter path (kept verbatim
# for the existing injected-client tests) and the full floor path.
# ----------------------------------------------------------------------------
def run_floor(out_dir: str | None = None, draft_timeout: int = 90,
              warden=None, drafter=None, draft_fn=None,
              mode: str = "normal", clients: dict | None = None,
              draft_fns: dict | None = None) -> dict:
    """Execute a floor run and return the assembled Examiner Packet dict.

    Two injection shapes:

      Legacy single-drafter (existing tests): pass warden=, drafter=, draft_fn=.
      Runs the original NIS2-only floor unchanged.

      Full floor: pass nothing (LIVE) or clients={role_key: FakeBandClient} plus
      draft_fns={branch: fn} for the multi-drafter path. mode selects the beat:
      "normal", "inject_contradiction", or "chaos".

    Raises if a required Band agent is not configured or a live call fails.
    """
    out_dir = out_dir or str(Path(__file__).resolve().parent / "out")
    legacy = warden is not None or drafter is not None or draft_fn is not None
    if legacy:
        return _run_single_drafter_floor(out_dir, draft_timeout, warden, drafter, draft_fn)
    return _run_full_floor(out_dir, draft_timeout, mode, clients, draft_fns)


# ----------------------------------------------------------------------------
# Full floor: Triage agent + three drafters + Warden + diff + chaos + replay.
# ----------------------------------------------------------------------------
def _run_full_floor(out_dir: str, draft_timeout: int, mode: str,
                    clients: dict | None, draft_fns: dict | None) -> dict:
    if mode not in ("normal", "inject_contradiction", "chaos"):
        raise ValueError(f"unknown mode: {mode}")
    live = clients is None

    if live:
        _require_live(roster.WARDEN, "Warden", "BAND_API_KEY / BAND_AGENT_ID")
        _require_live(roster.TRIAGE, "Triage", "BAND_API_KEY_TRIAGE / BAND_AGENT_ID_TRIAGE")
        for r in DRAFTER_ROLES:
            _require_live(r, f"{r.regime} Drafter", f"{r.key_env} / {r.id_env}")

    log = RunLog()
    trace = StepTrace(log)
    sm = ProtocolStateMachine()
    clocks = ClockEngine()
    ledger = IdempotencyLedger()

    # ---- Band clients: Warden, Triage, one per drafter ----------------
    warden = _client(clients, "warden", roster.WARDEN, "warden", "warden")
    triage = _client(clients, "triage", roster.TRIAGE, "triage", "triage")
    drafters = {
        r.branch: _client(clients, r.branch, r, f"{r.branch}_drafter", f"draft:{r.branch}")
        for r in DRAFTER_ROLES
    }

    warden_id = warden.whoami()
    triage_id = triage.whoami()
    drafter_ids = {b: d.whoami() for b, d in drafters.items()}
    trace.say(f"[1] Warden identity:  {warden_id}")
    trace.say(f"    Triage identity:  {triage_id}")
    for r in DRAFTER_ROLES:
        trace.say(f"    {r.regime} Drafter:  {drafter_ids[r.branch]} ({r.model})")

    # ---- Warden creates the room and recruits Triage + every drafter ---
    room_id = warden.create_chat(f"Deadline Room {INCIDENT_ID} [{mode}]")
    triage.join(room_id)
    warden.add_participant(triage_id)
    for r in DRAFTER_ROLES:
        drafters[r.branch].join(room_id)
        warden.add_participant(drafter_ids[r.branch])
    trace.say(f"[2] Warden created incident room {room_id} and recruited "
              f"Triage + {len(DRAFTER_ROLES)} drafters")
    log.append("room", {"band_room_id": room_id, "warden_id": warden_id,
                        "triage_id": triage_id, "drafter_ids": drafter_ids,
                        "mode": mode})

    # ---- Statutory clocks start at T0 ---------------------------------
    branch_corr = {r.branch: f"{INCIDENT_ID}:{r.branch}" for r in DRAFTER_ROLES}
    clocks.start_hours("NIS2 early warning (24h)", f"{INCIDENT_ID}:nis2-early", INCIDENT_T0, 24)
    clocks.start_hours("NIS2 full notification (72h)", branch_corr["nis2"], INCIDENT_T0, 72)
    clocks.start_hours("DORA major-incident (72h)", branch_corr["dora"], INCIDENT_T0, 72)
    clocks.start_sec_business_days(branch_corr["sec"], INCIDENT_T0)
    for c in clocks.all():
        log.append("clock_started", {"clock": c.name, "correlation_id": c.correlation_id,
                                     "deadline": c.deadline.isoformat()})
    trace.say(f"[3] Started {len(clocks.all())} statutory clocks at T0 {INCIDENT_T0}")

    # ---- Triage posts the canonical fact-record, @mentioning drafters --
    # Each branch's protocol opens with FACT_RECORD_POSTED, emitted by Triage.
    for r in DRAFTER_ROLES:
        _proto(sm, trace, branch_corr[r.branch], Event.FACT_RECORD_POSTED,
               TS_FACTS, "triage", "triage")
    mention_all = list(drafter_ids.values())
    fact_text = (
        "INCIDENT FACT-RECORD (canonical). Drafters: each draft your regime's "
        "mandatory notification from these facts only and post it back "
        "@mentioning the Warden.\n" + _facts_block(CANONICAL_FACTS)
    )
    res = triage.post(fact_text, mentions=mention_all,
                      dedup_key=f"factrecord:{INCIDENT_ID}")
    fact_msg_id = _msg_id(res)
    for r in DRAFTER_ROLES:
        trace.record_handoff("Triage", f"{r.regime} Drafter", "fact_record", fact_msg_id)
    trace.say(f"[4] Triage posted the fact-record, @mentioned all drafters "
              f"(msg {fact_msg_id})")

    # ---- Drafters run SEQUENTIALLY (Featherless: one big model at a time)
    filings: list[dict] = []
    claims_by_branch: dict[str, object] = {}
    chaos_branch = "sec" if mode == "chaos" else None

    for r in DRAFTER_ROLES:
        branch = r.branch
        corr = branch_corr[branch]
        client = drafters[branch]
        # The facts this drafter asserts. In inject_contradiction the SEC drafter
        # carries a perturbed incident_start; everyone else carries canonical.
        claim_facts = _claim_facts_for(branch, mode, corrupted=True)
        fn = _draft_fn_for(branch, r, draft_fns, draft_timeout)

        trace.say(f"[5.{branch}] {r.regime} Drafter draining /next for the mention ...")
        landed = _drive_drafter(
            client=client, warden_id=warden_id, branch=branch, regime=r.regime,
            claim_facts=claim_facts, draft_fn=fn, ledger=ledger, trace=trace,
            chaos=(branch == chaos_branch),
        )
        if not landed.get("text"):
            raise RuntimeError(f"{r.regime} Drafter did not produce a draft")
        trace.record_handoff(f"{r.regime} Drafter", "Warden", "draft",
                             landed.get("message_id", ""))
        filings.append({"regime": r.regime, "by": f"{r.regime} Drafter",
                        "model": r.model, "text": landed["text"]})

        # ---- Warden drains this draft, parses claims, advances the SM ----
        trace.say(f"[6.{branch}] Warden draining /next for the {r.regime} draft ...")
        observed = _warden_observe_draft(
            warden=warden, sm=sm, trace=trace, corr=corr, branch=branch,
        )
        if observed is None:
            raise RuntimeError(f"Warden never observed the {r.regime} draft")
        claims_by_branch[branch] = observed

    # ---- Cross-filing contradiction diff (the money beat) -------------
    blocked, resolved = _diff_and_gate(
        sm, trace, log, clocks, branch_corr, claims_by_branch, mode,
    )

    # ---- Signoff + human release stops every released branch's clock --
    for r in DRAFTER_ROLES:
        corr = branch_corr[r.branch]
        if sm.state(corr).value != "contradiction_checked":
            continue
        _proto(sm, trace, corr, Event.SIGNOFF_OPENED, TS_DIFF, "warden", "warden")
        _proto(sm, trace, corr, Event.HUMAN_RELEASED, TS_RELEASE, "lena", "human_owner")
        clocks.stop(corr, TS_RELEASE)
        log.append("clock_stopped", {"correlation_id": corr, "ts": TS_RELEASE})
    trace.say(f"[8] Warden opened signoff; human released; clocks stopped")

    breached = [c.name for c in clocks.breaches(TS_RELEASE)]

    # ---- Byte-identical replay ----------------------------------------
    original_sha = log.sha256()
    replayed = replay(log)
    replayed_sha = replayed.sha256()
    byte_identical = replayed.to_jsonl() == log.to_jsonl()
    trace.say(f"[9] Replay byte-identical: {byte_identical} (sha {original_sha[:12]}...)")

    # ---- Assemble + write the Examiner Packet -------------------------
    packet = _assemble_packet(
        room_id, trace, clocks, claims_by_branch, blocked, resolved,
        breached, filings, mode, ledger,
        replay_info={"original_sha256": original_sha, "replayed_sha256": replayed_sha,
                     "byte_identical": byte_identical},
    )
    json_path, html_path = write_packet(packet, out_dir)
    run_log_path = Path(out_dir) / f"run-{INCIDENT_ID}-{mode}.jsonl"
    log.save(run_log_path)
    trace.say(f"[10] Examiner Packet written:")
    trace.say(f"     {html_path}")
    trace.say(f"     {json_path}")
    trace.say(f"     run log: {run_log_path}")
    packet["_paths"] = {"html": html_path, "json": json_path,
                        "run_log": str(run_log_path)}
    return packet


def _drive_drafter(*, client, warden_id, branch, regime, claim_facts, draft_fn,
                   ledger: IdempotencyLedger, trace: StepTrace, chaos: bool) -> dict:
    """Run one drafter through the live handoff by driving the message lifecycle
    by hand (drain /next, mark processing, draft via Featherless, post back with
    a dedup key, mark processed). Driving it manually lets the chaos beat model a
    REAL crash position B: the draft is posted but the drafter dies BEFORE it
    marks the fact-record processed, so the live /next cursor has not advanced
    and re-serves the same message. On recovery the dedup ledger drops the
    re-post, so the filing lands exactly once with no double draft.

    Returns {"text": <draft prose+claims>, "message_id": <band id>}."""
    result = {"text": None, "message_id": ""}
    dedup_key = f"draft:{branch}:{INCIDENT_ID}:round-1"

    def draft_and_post(mid: str, attempt: int) -> None:
        # Exactly-once guard: a re-run after a kill checks the dedup key against
        # the room before re-posting. If the draft already landed, the ledger
        # records a DUPLICATE_DROPPED and we do not draft again.
        if client.already_posted(dedup_key):
            entry = ledger.record(dedup_key, attempt, TS_DRAFT)
            trace.record_chaos({
                "branch": branch, "phase": "recovery", "attempt": attempt,
                "disposition": entry.disposition.value,
                "note": (f"{regime} Drafter re-drained /next after the kill; its "
                         f"round-1 draft is already in the room, so the dedup "
                         f"ledger drops the duplicate. Filed exactly once."),
            })
            trace.say(f"    {regime} Drafter recovered: duplicate dropped "
                      f"(ledger {entry.disposition.value}), no double draft")
            return
        trace.say(f"    {regime} Drafter saw the mention (msg {mid}); calling "
                  f"Featherless ...")
        prose = draft_fn(claim_facts)
        body = build_draft_body(prose, branch, claim_facts)
        ledger.record(dedup_key, attempt, TS_DRAFT)
        post_res = client.post(
            "{} mandatory notification draft attached.\n\n{}".format(regime, body),
            mentions=[warden_id], dedup_key=dedup_key)
        result["text"] = body
        result["message_id"] = _msg_id(post_res)
        trace.say(f"    {regime} Drafter drafted {len(prose)} chars, posted back "
                  f"@mention Warden (msg {result['message_id']})")

    poll = 0.0 if _is_fake(client) else 2.0
    # ---- Attempt 1: drain the fact-record mention, draft, post --------
    msg = _drain(client, regime, trace, poll=poll)
    if not msg:
        raise RuntimeError(f"{regime} Drafter never saw the fact-record mention")
    mid = msg["id"]
    client.mark(mid, "processing")
    trace.record_lifecycle(mid, "processing")
    draft_and_post(mid, attempt=1)

    if chaos:
        # Crash position B: kill the process here, AFTER the draft is in the room
        # but BEFORE marking the fact-record processed. The cursor does not move.
        trace.record_chaos({
            "branch": branch, "phase": "kill", "attempt": 1,
            "disposition": "killed_position_B",
            "note": (f"{regime} Drafter killed AFTER posting its draft, BEFORE "
                     f"marking the fact-record processed. The draft is in the "
                     f"room; the /next cursor has not advanced."),
        })
        trace.say(f"    [CHAOS] {regime} Drafter killed at position B "
                  f"(posted, not yet acked); /next will re-serve the mention")
        # A fresh container has no in-memory handled set; model the restart.
        _forget_handled(client)

        # ---- Recovery: re-drain (same message re-served), dedup drops it -
        trace.say(f"    {regime} Drafter restarting, re-draining /next ...")
        msg2 = _drain(client, regime, trace, poll=poll)
        if not msg2:
            raise RuntimeError(f"{regime} Drafter recovery saw no re-served message")
        mid2 = msg2["id"]
        client.mark(mid2, "processing")
        trace.record_lifecycle(mid2, "processing")
        draft_and_post(mid2, attempt=2)
        client.mark(mid2, "processed")
        trace.record_lifecycle(mid2, "processed")
    else:
        client.mark(mid, "processing")  # idempotent; no-op if already processing
        client.mark(mid, "processed")
        trace.record_lifecycle(mid, "processed")

    return result


def _drain(client, regime, trace, poll: float = 2.0, max_loops: int = 12):
    """Poll /next for the next mentioned message, bounded. Returns the message or
    None. A thin loop because /next re-serves until the lifecycle advances."""
    import time
    for _ in range(max_loops):
        msg = client.next_message()
        if msg:
            return msg
        if poll:
            time.sleep(poll)
    return None


def _is_fake(client) -> bool:
    return client.__class__.__name__ == "FakeBandClient"


def _forget_handled(client) -> None:
    """Model a restarted container: drop the client's in-memory record of which
    message ids it has carried, so its re-drain re-sees the message that /next
    re-serves. Exactly-once is upheld by the dedup ledger and the read-then-act
    guard against the room, never by this local set."""
    handled = getattr(client, "_handled", None)
    if isinstance(handled, set):
        handled.clear()


def _warden_observe_draft(*, warden, sm, trace, corr, branch):
    """Warden drains /next for one drafter's reply, parses the structured claims
    block (deterministic, no LLM), and advances the typed state machine. Returns
    the parsed FactClaims, or None if the draft was never seen."""
    observed = {"claims": None}

    def handle(message: dict, context: list) -> dict | None:
        mid = message["id"]
        trace.record_lifecycle(mid, "processing")
        content = message.get("content", "")
        claims = parse_claims(content)  # pure string parse, Warden side
        _proto(sm, trace, corr, Event.DRAFT_STARTED, TS_DRAFT, f"{branch}_drafter", "drafter")
        _proto(sm, trace, corr, Event.DRAFT_POSTED, TS_DRAFT, f"{branch}_drafter", "drafter")
        observed["claims"] = claims
        trace.record_lifecycle(mid, "processed")
        trace.say(f"    Warden parsed {branch} claims, recorded DRAFT_POSTED (msg {mid})")
        return None

    warden.run(handle, poll_seconds=2.0, max_loops=12, idle_breaks=6)
    return observed["claims"]


def _diff_and_gate(sm, trace, log, clocks, branch_corr, claims_by_branch, mode):
    """Run the deterministic cross-filing diff. On a conflict the Warden BLOCKS:
    it emits DIFF_BLOCKED on every drafted branch (signoff cannot open) and the
    packet shows the red conflict. Then the resolution path corrects the fact,
    the diff is re-run GREEN, and DIFF_PASSED admits signoff.

    Returns (blocked_conflicts, resolution) where blocked_conflicts is the list
    of human-readable conflicts caught (empty if the run was clean) and
    resolution describes the corrected fact (or None)."""
    drafted = [b for b in branch_corr if b in claims_by_branch]
    claims = [claims_by_branch[b] for b in drafted]
    conflicts = diff_claims(claims)
    log.append("diff", {"round": 1, "conflicts": [c.human() for c in conflicts]})

    if not conflicts:
        for b in drafted:
            _proto(sm, trace, branch_corr[b], Event.DIFF_PASSED, TS_DIFF, "warden", "warden")
        trace.say(f"[7] Contradiction diff: GREEN (no conflicts across "
                  f"{len(drafted)} filings)")
        return [], None

    # Red. Block signoff on every drafted branch.
    blocked_human = [c.human() for c in conflicts]
    for b in drafted:
        _proto(sm, trace, branch_corr[b], Event.DIFF_BLOCKED, TS_DIFF, "warden", "warden")
    trace.say(f"[7] Contradiction diff: BLOCKED. The Warden refused signoff.")
    for line in blocked_human:
        trace.say(f"        RED: {line}")

    # Resolution: Triage corrects the perturbed fact, the offending drafter
    # re-asserts the canonical value, the diff is re-run and goes green.
    fixed_branch = _contradicted_branch(claims_by_branch)
    corrected = parse_claims(
        "[CLAIMS]\nbranch={}\nincident_start_utc={}\nrecords_affected={}\n"
        "attacker={}\ncontainment={}\n[/CLAIMS]".format(
            fixed_branch, CANONICAL_FACTS["incident_start_utc"],
            CANONICAL_FACTS["records_affected"], CANONICAL_FACTS["attacker"],
            CANONICAL_FACTS["containment"]))
    claims_by_branch[fixed_branch] = corrected
    # DIFF_BLOCKED bounced EVERY drafted branch back to DRAFTING. To re-open the
    # gate each branch must re-submit: the corrected branch re-posts its fixed
    # draft, the others re-affirm their unchanged drafts. Then the diff re-runs.
    for b in drafted:
        _proto(sm, trace, branch_corr[b], Event.DRAFT_POSTED, TS_RESOLVE,
               f"{b}_drafter", "drafter")

    claims2 = [claims_by_branch[b] for b in drafted]
    conflicts2 = diff_claims(claims2)
    log.append("diff", {"round": 2, "conflicts": [c.human() for c in conflicts2]})
    if conflicts2:
        raise RuntimeError(f"resolution did not clear the contradiction: {conflicts2}")
    for b in drafted:
        _proto(sm, trace, branch_corr[b], Event.DIFF_PASSED, TS_RESOLVE, "warden", "warden")
    resolution = {
        "fixed_branch": fixed_branch,
        "corrected_field": "incident_start_utc",
        "from_value": CONTRADICTION_START_UTC,
        "to_value": CANONICAL_FACTS["incident_start_utc"],
    }
    trace.say(f"[7b] Fact corrected on {fixed_branch.upper()}; diff re-run GREEN; "
              f"signoff unblocked.")
    return blocked_human, resolution


# ----------------------------------------------------------------------------
# Helpers shared by the full floor.
# ----------------------------------------------------------------------------
def _require_live(role, label, envs) -> None:
    if not role.live:
        raise RuntimeError(f"{label} agent not configured ({envs})")


def _client(clients, key, role, name, ns):
    if clients is not None:
        return clients[key]
    return LiveBand(api_key=role.agent_key, agent_name=name, dedup_namespace=ns)


def _claim_facts_for(branch: str, mode: str, *, corrupted: bool) -> dict:
    """The facts a drafter asserts. In inject_contradiction the SEC branch is fed
    a perturbed incident_start; everyone else (and every other mode) gets the
    canonical facts."""
    facts = {k: CANONICAL_FACTS[k] for k in
             ("incident_start_utc", "records_affected", "attacker", "containment")}
    if mode == "inject_contradiction" and branch == "sec" and corrupted:
        facts["incident_start_utc"] = CONTRADICTION_START_UTC
    return facts


def _draft_fn_for(branch, role, draft_fns, timeout):
    if draft_fns is not None:
        return draft_fns[branch]

    def fn(claim_facts):
        # The LLM drafts prose from the FULL canonical fact-record body plus the
        # branch's asserted incident_start; the structured claims are attached by
        # the drafter process, not formatted by the model.
        body_facts = dict(CANONICAL_FACTS)
        body_facts["incident_start_utc"] = claim_facts["incident_start_utc"]
        return draft_filing(body_facts, model=role.model, regime=role.regime,
                            timeout=timeout)
    return fn


def _contradicted_branch(claims_by_branch) -> str:
    """Pick the branch whose incident_start disagrees with the majority. In our
    injected case that is the SEC branch; this finds it generically."""
    starts: dict[str, list[str]] = {}
    for b, c in claims_by_branch.items():
        starts.setdefault(c.canonical()["incident_start_utc"], []).append(b)
    if len(starts) <= 1:
        return "sec"
    minority = min(starts.values(), key=len)
    return minority[0]


def _facts_block(facts: dict) -> str:
    return "\n".join(f"  {k}: {v}" for k, v in facts.items())


def _msg_id(post_result) -> str:
    if isinstance(post_result, dict):
        d = post_result.get("data", post_result)
        if isinstance(d, dict):
            return d.get("id", "")
    return ""


def _assemble_packet(room_id, trace, clocks, claims_by_branch, blocked, resolved,
                     breached, filings, mode, ledger, replay_info) -> dict:
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
    final_claims = {b: c.canonical() for b, c in claims_by_branch.items()}
    return {
        "incident": {
            "incident_id": INCIDENT_ID,
            "band_room_id": room_id,
            "mode": mode,
            "fact_record": CANONICAL_FACTS,
        },
        "trace": trace.lines,
        "handoff_trace": trace.handoffs,
        "state_transitions": trace.transitions,
        "message_lifecycle": lifecycle,
        "clocks": clock_rows,
        "diff": {
            "blocked_conflicts": blocked,
            "resolution": resolved,
            "final_claims": final_claims,
            "green": not blocked or resolved is not None,
        },
        "filings": filings,
        "chaos": {
            "events": trace.chaos_events,
            "duplicates_dropped": ledger.duplicates_dropped(),
            "ledger": [{"key": e.dedup_key, "attempt": e.attempt,
                        "disposition": e.disposition.value}
                       for e in ledger.history()],
        },
        "breached_clocks": breached,
        "replay": replay_info,
        "pending": [],
    }


# ----------------------------------------------------------------------------
# Legacy single-drafter floor (NIS2 only). Kept verbatim so the original
# injected-client orchestration tests stay valid. The live full floor above
# supersedes it.
# ----------------------------------------------------------------------------
def _run_single_drafter_floor(out_dir, draft_timeout, warden, drafter, draft_fn) -> dict:
    from warden.diff import Containment, FactClaims

    nis2_role = roster.NIS2_DRAFTER
    if draft_fn is None:
        def draft_fn(fact_record):
            return draft_filing(fact_record, model=nis2_role.model,
                                regime="NIS2", timeout=draft_timeout)

    log = RunLog()
    trace = StepTrace(log)
    sm = ProtocolStateMachine()
    clocks = ClockEngine()

    if warden is None:
        warden = LiveBand(api_key=roster.WARDEN.agent_key, agent_name="warden",
                          dedup_namespace="warden")
    if drafter is None:
        drafter = LiveBand(api_key=nis2_role.agent_key, agent_name="nis2_drafter",
                           dedup_namespace="draft:nis2")

    warden_id = warden.whoami()
    drafter_id = drafter.whoami()
    trace.say(f"[1] Warden identity: {warden_id}")
    trace.say(f"    NIS2 Drafter identity: {drafter_id}")

    room_id = warden.create_chat(f"Deadline Room {INCIDENT_ID}")
    drafter.join(room_id)
    trace.say(f"[2] Warden created incident room {room_id}")
    warden.add_participant(drafter_id)
    trace.say(f"[3] Warden recruited NIS2 Drafter into the room")
    log.append("room", {"band_room_id": room_id, "warden_id": warden_id,
                        "drafter_id": drafter_id})

    corr_nis2 = f"{INCIDENT_ID}:nis2"
    clocks.start_hours("NIS2 early warning (24h)", f"{INCIDENT_ID}:nis2-early", INCIDENT_T0, 24)
    clocks.start_hours("NIS2 full notification (72h)", corr_nis2, INCIDENT_T0, 72)
    clocks.start_sec_business_days(f"{INCIDENT_ID}:sec", INCIDENT_T0)
    for c in clocks.all():
        log.append("clock_started", {"clock": c.name, "correlation_id": c.correlation_id,
                                     "deadline": c.deadline.isoformat()})
    trace.say(f"[4] Started {len(clocks.all())} statutory clocks at T0 {INCIDENT_T0}")

    _proto(sm, trace, corr_nis2, Event.FACT_RECORD_POSTED, TS_FACTS, "triage", "triage")
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

    trace.say("[7] Warden draining /next for the returned draft ...")
    draft_claims = {"obj": None}

    def warden_handle(message: dict, context: list) -> dict | None:
        mid = message["id"]
        trace.record_lifecycle(mid, "processing")
        _proto(sm, trace, corr_nis2, Event.DRAFT_STARTED, TS_DRAFT,
               "nis2_drafter", "drafter")
        _proto(sm, trace, corr_nis2, Event.DRAFT_POSTED, TS_DRAFT,
               "nis2_drafter", "drafter")
        draft_claims["obj"] = FactClaims(
            "nis2", CANONICAL_FACTS["incident_start_utc"],
            CANONICAL_FACTS["records_affected"], CANONICAL_FACTS["attacker"],
            Containment.PARTIALLY_CONTAINED)
        trace.record_lifecycle(mid, "processed")
        trace.say(f"    Warden recorded DRAFT_POSTED for nis2 (msg {mid})")
        return None

    warden.run(warden_handle, poll_seconds=2.0, max_loops=20, idle_breaks=8)
    if draft_claims["obj"] is None:
        raise RuntimeError("Warden never observed the NIS2 draft")

    conflicts = diff_claims([draft_claims["obj"]])
    log.append("diff", {"conflicts": [c.human() for c in conflicts]})
    if conflicts:
        _proto(sm, trace, corr_nis2, Event.DIFF_BLOCKED, TS_DIFF, "warden", "warden")
    else:
        _proto(sm, trace, corr_nis2, Event.DIFF_PASSED, TS_DIFF, "warden", "warden")
    trace.say(f"[8] Contradiction diff: "
              f"{'GREEN (no conflicts)' if not conflicts else 'BLOCKED'} "
              f"(one drafter live; the cross-filing beat needs the SEC Drafter agent)")

    _proto(sm, trace, corr_nis2, Event.SIGNOFF_OPENED, TS_DIFF, "warden", "warden")
    _proto(sm, trace, corr_nis2, Event.HUMAN_RELEASED, TS_RELEASE, "lena", "human_owner")
    clocks.stop(corr_nis2, TS_RELEASE)
    log.append("clock_stopped", {"correlation_id": corr_nis2, "ts": TS_RELEASE})
    trace.say(f"[9] Warden opened signoff; human released; NIS2 clock stopped")

    breached = [c.name for c in clocks.breaches(TS_RELEASE)]

    original_sha = log.sha256()
    replayed = replay(log)
    replayed_sha = replayed.sha256()
    byte_identical = replayed.to_jsonl() == log.to_jsonl()
    trace.say(f"[10] Replay byte-identical: {byte_identical} "
              f"(sha {original_sha[:12]}...)")

    packet = _assemble_legacy_packet(
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


def _assemble_legacy_packet(room_id, trace, clocks, conflicts, breached, filings,
                            replay_info) -> dict:
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
    parser = argparse.ArgumentParser(description="Deadline Room floor run (live Band + Featherless)")
    parser.add_argument("--inject-contradiction", action="store_true",
                        help="feed one drafter a perturbed fact so the Warden's diff blocks, then resolve")
    parser.add_argument("--chaos", action="store_true",
                        help="kill a drafter mid-handoff; show exactly-once recovery")
    args = parser.parse_args()
    if args.inject_contradiction and args.chaos:
        print("Pick one of --inject-contradiction or --chaos, not both.")
        return 1
    mode = "inject_contradiction" if args.inject_contradiction else \
           "chaos" if args.chaos else "normal"

    try:
        from _env import load_env  # spikes/_env.py
        load_env()
    except Exception:
        pass
    import os
    if not os.environ.get("BAND_API_KEY") or not os.environ.get("FEATHERLESS_API_KEY"):
        print("Missing BAND_API_KEY or FEATHERLESS_API_KEY (load code/.env).")
        return 1
    print(f"=== Deadline Room floor run (LIVE Band + Featherless) mode={mode} ===\n")
    packet = run_floor(mode=mode)
    print("\n=== Done. Examiner Packet at: "
          + packet["_paths"]["html"] + " ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
