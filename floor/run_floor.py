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
  amendment            AFTER the SEC and NIS2 filings are released, Triage posts
                       a fact amendment (records_affected jumps from 48,211 to
                       2,100,000). The Warden's FACT_AMENDED transition reopens
                       the two released branches into the amending state. The SEC
                       Drafter @mentions the NIS2 Drafter through Band proposing
                       how to characterize the revised figure; the NIS2 Drafter
                       replies @mentioning back. The exchange rides hash-linked
                       reconciliation envelopes (warden/negotiation.py) so the
                       chain is tamper-evident and replay-verifiable. The Warden's
                       deterministic guard holds the amended diff BLOCKED until
                       the two drafters have concurred on the shared figure; only
                       then do the amended filings pass green and re-release.

Drafters run SEQUENTIALLY: Featherless allows only one big model at a time and
caps model switches, so the racing-clocks STORY is carried by the Warden tracking
all clocks, not by literal simultaneous inference.

The Warden makes ZERO LLM calls. Only drafter processes draft text.

Run live:
  py floor/run_floor.py                       (normal)
  py floor/run_floor.py --inject-contradiction
  py floor/run_floor.py --chaos
  py floor/run_floor.py --amendment
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
from warden.diff import Containment, FactClaims, diff_claims  # noqa: E402
from warden.ledger import Disposition, IdempotencyLedger  # noqa: E402
from warden.materiality import MaterialityVerdict, gate as materiality_gate  # noqa: E402
from warden.negotiation import (  # noqa: E402
    NegotiationEnvelope, NegotiationGuard, Verdict)
from warden.release_gate import REQUIRED_ROLES, TwoKeyReleaseGate  # noqa: E402
from warden.replay import RunLog, replay  # noqa: E402
from warden.state_machine import Event, ProtocolStateMachine  # noqa: E402

from floor import roster  # noqa: E402
from floor.claims import parse_claims  # noqa: E402
from floor.drafter import (  # noqa: E402
    build_draft_body, draft_characterization, draft_filing)
from floor.materiality import assess_materiality  # noqa: E402
from floor.negotiation_envelope import emit_envelope, parse_envelope  # noqa: E402
from floor.packet import write_packet  # noqa: E402
from floor.recruit import (  # noqa: E402
    UK_ICO_TARGET, find_peer, jurisdiction_in_blast_radius, peer_id)
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
# Two-key release: the GC signs first, then Lena (Head of IR). Fixed, distinct
# timestamps so replay is byte-stable and the order is visible in the packet.
TS_SIGN_GC = "2026-06-16T04:50:00+00:00"
TS_RELEASE = "2026-06-16T05:00:00+00:00"

# The two distinct human signers of the two-key release gate (segregation of
# duties). One key alone never releases; both are required.
RELEASE_SIGNERS = (
    ("general_counsel", "gc", TS_SIGN_GC),
    ("head_of_ir", "lena", TS_RELEASE),
)

# UK runtime recruit: the moment a UK subsidiary is found in the blast radius and
# the UK ICO Drafter is recruited. Its 72h GDPR clock starts HERE, not at T0.
TS_UK_RECRUIT = "2026-06-16T03:40:00+00:00"
TS_UK_FACTS = "2026-06-16T03:41:00+00:00"
TS_UK_DRAFT = "2026-06-16T03:55:00+00:00"

# A fact-record whose blast radius INCLUDES a UK subsidiary: the content that
# drives the runtime recruit. The no-recruit fixture uses CANONICAL_FACTS, whose
# blast radius does NOT name the UK, proving the recruit is content-driven.
UK_IN_SCOPE_FACTS = {
    **CANONICAL_FACTS,
    "blast_radius": ["EU: Meridian Trust Bank N.V.",
                     "UK: Meridian Trust UK Ltd (London subsidiary)"],
}
# The default blast radius names only the EU entity, so the UK recruit never
# fires on a normal run.
CANONICAL_FACTS["blast_radius"] = ["EU: Meridian Trust Bank N.V."]

# Materiality fixtures. The MATERIAL fact-record is the real incident (millions of
# regulated records, core banking). The IMMATERIAL one is a small, contained,
# non-sensitive event that does not start the SEC clock. The verdict is the LLM's;
# these only choose which fact-record the assessor sees.
SEC_MATERIAL_FACTS = dict(CANONICAL_FACTS)
SEC_IMMATERIAL_FACTS = {
    **CANONICAL_FACTS,
    "records_affected": 12,
    "systems": ["internal staff cafeteria menu board"],
    "data_categories": ["lunch_preferences"],
    "containment": "contained",
}

# A1: the hour-6 fact amendment beat. records_affected is revised upward as
# forensics complete; the SEC and NIS2 branches reopen and reconcile.
AMENDED_RECORDS = 2_100_000
AMENDMENT_BRANCHES = ("sec", "nis2")
TS_AMEND = "2026-06-16T08:14:00+00:00"     # Triage posts the revision (~hour 6)
TS_AMEND_RELEASE = "2026-06-16T09:00:00+00:00"
# The containment framing the amended filings settle on (deterministic, attached
# by the drafter process, not the model).
AMEND_CONTAINMENT_FRAMING = "contained as of 2026-06-16T07:00:00+00:00"
AMEND_DATA_BOUNDS = ("name", "address", "account_number")


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
        self.negotiation: list[dict] = []

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

    def record_negotiation(self, event: dict) -> None:
        self.negotiation.append(event)
        self.log.append("negotiation", event)


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
              draft_fns: dict | None = None,
              provider_set: str = roster.PROVIDER_DEV,
              uk_recruit: bool = False, materiality: bool = False,
              materiality_fn=None, sec_facts: dict | None = None,
              uk_peers: list | None = None) -> dict:
    """Execute a floor run and return the assembled Examiner Packet dict.

    Two injection shapes:

      Legacy single-drafter (existing tests): pass warden=, drafter=, draft_fn=.
      Runs the original NIS2-only floor unchanged.

      Full floor: pass nothing (LIVE) or clients={role_key: FakeBandClient} plus
      draft_fns={branch: fn} for the multi-drafter path. mode selects the beat:
      "normal", "inject_contradiction", or "chaos".

    provider_set selects which LLM provider configuration the drafters use:
      "dev"  (default): every role on Featherless, zero AI/ML credit spent.
      "prod": the prize-winning split (parallel racing drafters on AI/ML API,
              hero open-model roles on Featherless). Only ever active when
              explicitly requested, so dev runs never touch AI/ML.

    Raises if a required Band agent is not configured or a live call fails.
    """
    out_dir = out_dir or str(Path(__file__).resolve().parent / "out")
    legacy = warden is not None or drafter is not None or draft_fn is not None
    if legacy:
        return _run_single_drafter_floor(out_dir, draft_timeout, warden, drafter, draft_fn)
    return _run_full_floor(out_dir, draft_timeout, mode, clients, draft_fns,
                           provider_set, uk_recruit=uk_recruit, materiality=materiality,
                           materiality_fn=materiality_fn, sec_facts=sec_facts,
                           uk_peers=uk_peers)


# ----------------------------------------------------------------------------
# Full floor: Triage agent + three drafters + Warden + diff + chaos + replay.
# ----------------------------------------------------------------------------
def _run_full_floor(out_dir: str, draft_timeout: int, mode: str,
                    clients: dict | None, draft_fns: dict | None,
                    provider_set: str = roster.PROVIDER_DEV,
                    uk_recruit: bool = False,
                    materiality: bool = False,
                    materiality_fn=None,
                    sec_facts: dict | None = None,
                    uk_peers: list | None = None) -> dict:
    """uk_recruit: drive the content-driven UK ICO runtime-recruit beat. The
    recruit fires only when the fact-record blast radius names a UK subsidiary.

    materiality: run the SEC materiality assessment before the SEC branch drafts.
    If the verdict is not material, the Warden SUPPRESSES the SEC branch (terminal,
    no SEC filing). materiality_fn injects the verdict in tests; sec_facts chooses
    which fact-record the assessor sees on a live run.

    The two-key release gate (Lena AND the GC) is ALWAYS active: every release on
    the full floor requires both distinct human keys."""
    if mode not in ("normal", "inject_contradiction", "chaos", "amendment"):
        raise ValueError(f"unknown mode: {mode}")
    if provider_set not in (roster.PROVIDER_DEV, roster.PROVIDER_PROD):
        raise ValueError(f"unknown provider set: {provider_set!r}")
    live = clients is None
    # The amendment beat reuses the clean release path as its base, then layers
    # the FACT_AMENDED reopen + agent-to-agent reconciliation on top.
    base_mode = "normal" if mode == "amendment" else mode
    # When the UK recruit beat runs, Triage's fact-record carries a blast radius
    # naming a UK subsidiary; that content is what drives the recruit.
    fact_record = UK_IN_SCOPE_FACTS if uk_recruit else CANONICAL_FACTS
    release_gate = TwoKeyReleaseGate()

    if live:
        _require_live(roster.WARDEN, "Warden", "BAND_API_KEY / BAND_AGENT_ID")
        _require_live(roster.TRIAGE, "Triage", "BAND_API_KEY_TRIAGE / BAND_AGENT_ID_TRIAGE")
        for r in DRAFTER_ROLES:
            _require_live(r, f"{r.regime} Drafter", f"{r.key_env} / {r.id_env}")
        if uk_recruit:
            _require_live(roster.UK_DRAFTER, "UK ICO Drafter",
                          f"{roster.UK_DRAFTER.key_env} / {roster.UK_DRAFTER.id_env}")

    log = RunLog()
    trace = StepTrace(log)
    sm = ProtocolStateMachine()
    clocks = ClockEngine()
    ledger = IdempotencyLedger()

    # ---- Provider set: state plainly which LLM configuration is active --------
    provider_validation = _announce_provider_set(trace, log, provider_set, live)

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
        provider, model = roster.resolve(r, provider_set)
        trace.say(f"    {r.regime} Drafter:  {drafter_ids[r.branch]} "
                  f"({provider}:{model})")

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
    # branch_corr maps every branch that could exist this run to its correlation
    # id, including the UK branch which only materializes if the runtime recruit
    # fires. DRAFTER_BRANCHES_THIS_RUN tracks which branches actually drafted, so
    # the diff and the two-key release iterate the live set (UK appended only on
    # an actual recruit).
    branch_corr = {r.branch: f"{INCIDENT_ID}:{r.branch}" for r in DRAFTER_ROLES}
    branch_corr["uk"] = f"{INCIDENT_ID}:uk"
    DRAFTER_BRANCHES_THIS_RUN = [r.branch for r in DRAFTER_ROLES]
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
        "@mentioning the Warden.\n" + _facts_block(fact_record)
    )
    res = triage.post(fact_text, mentions=mention_all,
                      dedup_key=f"factrecord:{INCIDENT_ID}")
    fact_msg_id = _msg_id(res)
    for r in DRAFTER_ROLES:
        trace.record_handoff("Triage", f"{r.regime} Drafter", "fact_record", fact_msg_id)
    trace.say(f"[4] Triage posted the fact-record, @mentioned all drafters "
              f"(msg {fact_msg_id})")

    # ---- Materiality: decide whether the SEC clock is even triggered ---
    # The materiality assessment is an LLM judgment role; its verdict crosses into
    # the deterministic warden/materiality.py gate as data. If "not material", the
    # Warden emits SUPPRESS on the SEC branch (terminal SUPPRESSED): no SEC filing,
    # SEC clock stopped. The DECISION is the LLM's; the gating is deterministic.
    materiality_record = None
    suppressed_branches: set[str] = set()
    if materiality:
        materiality_record = _materiality_phase(
            sm=sm, trace=trace, log=log, clocks=clocks,
            branch_corr=branch_corr, provider_set=provider_set,
            materiality_fn=materiality_fn,
            sec_facts=sec_facts if sec_facts is not None else fact_record,
            draft_timeout=draft_timeout)
        if not materiality_record["material"]:
            suppressed_branches.add("sec")

    # ---- Drafters run SEQUENTIALLY (Featherless: one big model at a time)
    filings: list[dict] = []
    claims_by_branch: dict[str, object] = {}
    chaos_branch = "sec" if base_mode == "chaos" else None

    for r in DRAFTER_ROLES:
        branch = r.branch
        corr = branch_corr[branch]
        client = drafters[branch]
        if branch in suppressed_branches:
            # A suppressed branch is terminal; it drafts nothing. The Warden does
            # not drain a draft it will never receive.
            trace.say(f"[5.{branch}] {r.regime} branch SUPPRESSED (not material); "
                      f"no filing drafted.")
            continue
        # The facts this drafter asserts. In inject_contradiction the SEC drafter
        # carries a perturbed incident_start; everyone else carries canonical.
        claim_facts = _claim_facts_for(branch, base_mode, corrupted=True)
        fn = _draft_fn_for(branch, r, draft_fns, draft_timeout, provider_set)
        _provider, _model = roster.resolve(r, provider_set)

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
                        "model": _model, "provider": _provider,
                        "text": landed["text"]})

        # ---- Warden drains this draft, parses claims, advances the SM ----
        trace.say(f"[6.{branch}] Warden draining /next for the {r.regime} draft ...")
        observed = _warden_observe_draft(
            warden=warden, sm=sm, trace=trace, corr=corr, branch=branch,
        )
        if observed is None:
            raise RuntimeError(f"Warden never observed the {r.regime} draft")
        claims_by_branch[branch] = observed

    # ---- UK runtime recruit (content-driven). The UK ICO Drafter is discovered
    # and recruited LIVE only if the blast radius names a UK subsidiary. Its 72h
    # GDPR clock starts at the recruit moment, not at T0. -----------------
    recruit_record = None
    if uk_recruit:
        recruit_record = _uk_recruit_phase(
            sm=sm, trace=trace, log=log, clocks=clocks, ledger=ledger,
            warden=warden, triage=triage, drafters=drafters, clients=clients,
            warden_id=warden_id, triage_id=triage_id, room_id=room_id,
            fact_record=fact_record, branch_corr=branch_corr,
            draft_fns=draft_fns, draft_timeout=draft_timeout,
            provider_set=provider_set, uk_peers=uk_peers, live=live,
        )
        if recruit_record["recruited"]:
            DRAFTER_BRANCHES_THIS_RUN.append("uk")
            # The raw FactClaims is for the diff only; it is not JSON-serializable,
            # so pop it out of the record that lands in the Examiner Packet.
            claims_by_branch["uk"] = recruit_record.pop("claims")
            filings.append(recruit_record.pop("filing"))

    # ---- Cross-filing contradiction diff (the money beat) -------------
    blocked, resolved = _diff_and_gate(
        sm, trace, log, clocks, branch_corr, claims_by_branch, base_mode,
    )

    # ---- Two-key signoff + human release. Segregation of duties: a filing
    # releases only when BOTH Lena (Head of IR) AND the GC sign. One key alone
    # never turns the lock. The gate is deterministic, composed outside the SM
    # table; the Warden admits HUMAN_RELEASED only once the gate reports two keys.
    for corr in [branch_corr[b] for b in DRAFTER_BRANCHES_THIS_RUN]:
        if sm.state(corr).value != "contradiction_checked":
            continue
        _proto(sm, trace, corr, Event.SIGNOFF_OPENED, TS_DIFF, "warden", "warden")
        _two_key_release(sm, trace, log, release_gate, corr)
        clocks.stop(corr, TS_RELEASE)
        log.append("clock_stopped", {"correlation_id": corr, "ts": TS_RELEASE})
    trace.say(f"[8] Warden opened signoff; two-key release (GC + Lena); "
              f"clocks stopped")

    # ---- A1: the amendment beat (agent-to-agent reconciliation) --------
    amendment = None
    if mode == "amendment":
        amendment = _amendment_phase(
            sm=sm, trace=trace, log=log, clocks=clocks, ledger=ledger,
            triage=triage, warden=warden, drafters=drafters,
            warden_id=warden_id, triage_id=triage_id, drafter_ids=drafter_ids,
            branch_corr=branch_corr, draft_fns=draft_fns, draft_timeout=draft_timeout,
            provider_set=provider_set,
        )
        # The amended figure becomes the reconciled record of those branches.
        for b in AMENDMENT_BRANCHES:
            claims_by_branch[b] = amendment["amended_claims"][b]

    breached = [c.name for c in clocks.breaches(TS_AMEND_RELEASE if mode == "amendment"
                                               else TS_RELEASE)]

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
        amendment=amendment,
        provider_set=provider_set, provider_validation=provider_validation,
        materiality=materiality_record, recruit=recruit_record,
        release_gate=release_gate,
        released_branches=[b for b in DRAFTER_BRANCHES_THIS_RUN
                           if sm.state(branch_corr[b]).value == "released"],
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
                  f"its assigned model ...")
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


def _drain_for_envelope(client, regime, trace, poll: float = 2.0,
                        max_loops: int = 12):
    """Drain /next until a message carrying a [RECONCILE] block surfaces, marking
    any intervening mentioned messages (for example the Triage fact-amendment
    fan-out) processed so the cursor advances. Returns the reconciliation message
    or None."""
    for _ in range(max_loops):
        msg = _drain(client, regime, trace, poll=poll, max_loops=1)
        if not msg:
            return None
        if "[RECONCILE]" in (msg.get("content", "") or ""):
            return msg
        # Not the reconciliation envelope: clear it so /next advances.
        mid = msg["id"]
        client.mark(mid, "processing")
        client.mark(mid, "processed")
        trace.record_lifecycle(mid, "processed")
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
# A1: the amendment beat. AFTER release, Triage revises records_affected. The SEC
# and NIS2 branches reopen (FACT_AMENDED). The two drafters reconcile through
# Band, agent to agent (SEC @mentions NIS2; NIS2 @mentions back), riding
# hash-linked reconciliation envelopes. The Warden's deterministic guard holds
# the amended diff BLOCKED until a concur envelope exists; only then do the
# amended filings pass green and re-release. Zero LLM in the Warden: the drafters'
# characterization prose is the only model output.
# ----------------------------------------------------------------------------
def _amendment_phase(*, sm, trace, log, clocks, ledger, triage, warden, drafters,
                     warden_id, triage_id, drafter_ids, branch_corr,
                     draft_fns, draft_timeout,
                     provider_set=roster.PROVIDER_DEV) -> dict:
    guard = NegotiationGuard()
    sec, nis2 = "sec", "nis2"
    sec_id, nis2_id = drafter_ids[sec], drafter_ids[nis2]
    old_records = CANONICAL_FACTS["records_affected"]

    # 1. Triage posts the fact amendment, @mentioning both affected drafters. The
    #    Warden fires FACT_AMENDED on each released branch: released -> amending.
    amend_text = (
        "FACT AMENDMENT. Forensics revised records_affected from "
        f"{old_records:,} to {AMENDED_RECORDS:,}. SEC and NIS2 Drafters: reopen "
        "your released filings, reconcile one shared characterization of the new "
        "figure with each other, then re-file.\n"
        f"[AMENDMENT]\nfact_key=records_affected\nold={old_records}\n"
        f"new={AMENDED_RECORDS}\n[/AMENDMENT]"
    )
    amend_res = triage.post(amend_text, mentions=[sec_id, nis2_id],
                            dedup_key=f"amend:{INCIDENT_ID}:records_affected")
    amend_msg_id = _msg_id(amend_res)
    trace.record_handoff("Triage", "SEC Drafter", "fact_amendment", amend_msg_id)
    trace.record_handoff("Triage", "NIS2 Drafter", "fact_amendment", amend_msg_id)
    log.append("fact_amendment", {"fact_key": "records_affected", "old": old_records,
                                  "new": AMENDED_RECORDS, "ts": TS_AMEND,
                                  "band_message_id": amend_msg_id})
    for b in AMENDMENT_BRANCHES:
        _proto(sm, trace, branch_corr[b], Event.FACT_AMENDED, TS_AMEND, "triage", "triage")
    trace.say(f"[A1] Triage posted the fact amendment {old_records:,} -> "
              f"{AMENDED_RECORDS:,}; SEC and NIS2 branches reopened to amending "
              f"(msg {amend_msg_id})")

    # 2. The guard is consulted BEFORE any reconciliation: with no concur
    #    envelope for the round, the amended diff is BLOCKED. This is the
    #    "amendment is a no-op until concur" invariant, shown live.
    pre = guard.can_submit_amendment(branch_corr[sec], amend_round=1)
    log.append("negotiation_guard", {"check": "can_submit_amendment",
                                     "phase": "pre_reconciliation",
                                     "allowed": pre.allowed, "reason": pre.reason})
    if pre.allowed:
        raise RuntimeError("guard let the amendment through before reconciliation")
    trace.say(f"[A2] Warden guard BLOCKED the amendment before reconciliation: "
              f"{pre.reason}")

    # 3. SEC Drafter drains the amendment mention, drafts its proposed
    #    characterization (Featherless), and posts a PROPOSE envelope @mentioning
    #    the NIS2 Drafter. A real agent-to-agent Band message, mention by id.
    sec_client = drafters[sec]
    sec_msg = _drain(sec_client, "SEC", trace, poll=(0.0 if _is_fake(sec_client) else 2.0))
    if not sec_msg:
        raise RuntimeError("SEC Drafter never saw the fact amendment")
    sec_client.mark(sec_msg["id"], "processing")
    trace.record_lifecycle(sec_msg["id"], "processing")

    propose_fn = _characterize_fn_for(sec, "SEC", "propose", draft_fns,
                                      draft_timeout, provider_set)
    propose_char = propose_fn("")
    proposal = NegotiationEnvelope(
        correlation_id=branch_corr[sec], amend_round=1, from_agent="sec_drafter",
        to_agent="nis2_drafter", fact_key="records_affected",
        proposed_value=AMENDED_RECORDS, characterization=propose_char,
        data_category_bounds=AMEND_DATA_BOUNDS,
        containment_framing=AMEND_CONTAINMENT_FRAMING, verdict=Verdict.PROPOSE,
        ts_utc=TS_AMEND, prior_envelope_hash=None)
    propose_res = sec_client.post(
        "SEC Drafter reconciliation proposal for the revised figure.\n\n"
        + emit_envelope(proposal),
        mentions=[nis2_id], dedup_key=f"reconcile:{INCIDENT_ID}:sec:round-1")
    propose_mid = _msg_id(propose_res)
    sec_client.mark(sec_msg["id"], "processing")
    sec_client.mark(sec_msg["id"], "processed")
    trace.record_lifecycle(sec_msg["id"], "processed")
    trace.record_handoff("SEC Drafter", "NIS2 Drafter", "reconcile_propose", propose_mid)
    trace.say(f"[A3] SEC Drafter @mentioned NIS2 Drafter proposing how to "
              f"characterize {AMENDED_RECORDS:,} (msg {propose_mid})")

    # 4. NIS2 Drafter drains the proposal mention, drafts a concurring
    #    characterization (Featherless), and posts a CONCUR envelope hash-linked
    #    to the proposal, @mentioning the SEC Drafter back. The NIS2 inbox may
    #    still hold the Triage fact-amendment mention ahead of the proposal;
    #    /next serves oldest-first, so clear intervening mentions until the
    #    reconciliation envelope surfaces.
    nis2_client = drafters[nis2]
    nis2_msg = _drain_for_envelope(nis2_client, "NIS2", trace,
                                   poll=(0.0 if _is_fake(nis2_client) else 2.0))
    if not nis2_msg:
        raise RuntimeError("NIS2 Drafter never saw the SEC reconciliation proposal")
    nis2_client.mark(nis2_msg["id"], "processing")
    trace.record_lifecycle(nis2_msg["id"], "processing")

    # The Warden parses the proposal envelope off the room (no LLM) and admits it
    # to the guard. This is the deterministic side: structure, not judgment.
    parsed_proposal = parse_envelope(nis2_msg.get("content", ""))
    pd = guard.post(parsed_proposal)
    log.append("negotiation_guard", {"check": "post_propose", "allowed": pd.allowed,
                                     "reason": pd.reason})
    if not pd.allowed:
        raise RuntimeError(f"guard rejected the proposal envelope: {pd.reason}")
    trace.record_negotiation({**parsed_proposal.canonical(),
                              "envelope_sha256": parsed_proposal.sha256(),
                              "band_message_id": propose_mid})

    concur_fn = _characterize_fn_for(nis2, "NIS2", "concur", draft_fns,
                                     draft_timeout, provider_set)
    concur_char = concur_fn(parsed_proposal.characterization)
    concur = NegotiationEnvelope(
        correlation_id=branch_corr[nis2], amend_round=1, from_agent="nis2_drafter",
        to_agent="sec_drafter", fact_key="records_affected",
        proposed_value=AMENDED_RECORDS, characterization=concur_char,
        data_category_bounds=AMEND_DATA_BOUNDS,
        containment_framing=AMEND_CONTAINMENT_FRAMING, verdict=Verdict.CONCUR,
        ts_utc=TS_AMEND, prior_envelope_hash=parsed_proposal.sha256())
    concur_res = nis2_client.post(
        "NIS2 Drafter concurs on the shared characterization.\n\n"
        + emit_envelope(concur),
        mentions=[sec_id], dedup_key=f"reconcile:{INCIDENT_ID}:nis2:round-1")
    concur_mid = _msg_id(concur_res)
    nis2_client.mark(nis2_msg["id"], "processed")
    trace.record_lifecycle(nis2_msg["id"], "processed")
    trace.record_handoff("NIS2 Drafter", "SEC Drafter", "reconcile_concur", concur_mid)
    trace.say(f"[A4] NIS2 Drafter @mentioned SEC Drafter back, CONCUR "
              f"(hash-linked to the proposal, msg {concur_mid})")

    # The Warden admits the concur envelope (deterministic hash-link check).
    cd = guard.post(concur)
    log.append("negotiation_guard", {"check": "post_concur", "allowed": cd.allowed,
                                     "reason": cd.reason})
    if not cd.allowed:
        raise RuntimeError(f"guard rejected the concur envelope: {cd.reason}")
    trace.record_negotiation({**concur.canonical(), "envelope_sha256": concur.sha256(),
                              "band_message_id": concur_mid})

    # 5. A concur now exists. Each branch may submit its amendment. Both produce
    #    the amended filing with the reconciled figure and post it back.
    amended_claims: dict[str, FactClaims] = {}
    amended_filings: list[dict] = []
    for b in AMENDMENT_BRANCHES:
        corr = branch_corr[b]
        gate = guard.can_submit_amendment(corr, amend_round=1)
        log.append("negotiation_guard", {"check": "can_submit_amendment",
                                         "phase": "post_reconciliation", "branch": b,
                                         "allowed": gate.allowed, "reason": gate.reason})
        if not gate.allowed:
            raise RuntimeError(f"guard still blocks {b} after concur: {gate.reason}")
        amend_facts = {
            "incident_start_utc": CANONICAL_FACTS["incident_start_utc"],
            "records_affected": AMENDED_RECORDS,
            "attacker": CANONICAL_FACTS["attacker"],
            "containment": Containment.CONTAINED.value,
        }
        body = build_draft_body(
            f"{('Amended 8-K (Item 1.05)' if b == 'sec' else 'NIS2 intermediate report')}: "
            f"records affected revised to {AMENDED_RECORDS:,}. "
            f"{concur.characterization}", b, amend_facts)
        entry = ledger.record(f"draft:{b}:{INCIDENT_ID}:amend-1", 1, TS_AMEND)
        log.append("ledger", {"key": entry.dedup_key, "attempt": 1,
                              "disposition": entry.disposition.value})
        drafters[b].post(
            "{} amended filing attached.\n\n{}".format(b.upper(), body),
            mentions=[warden_id], dedup_key=f"draft:{b}:{INCIDENT_ID}:amend-1")
        _proto(sm, trace, corr, Event.DRAFT_POSTED, TS_AMEND, f"{b}_drafter", "drafter")
        amended_claims[b] = parse_claims(body)
        amend_role = roster.SEC_DRAFTER if b == "sec" else roster.NIS2_DRAFTER
        amend_provider, amend_model = roster.resolve(amend_role, provider_set)
        amended_filings.append({
            "regime": "SEC" if b == "sec" else "NIS2",
            "by": ("SEC" if b == "sec" else "NIS2") + " Drafter",
            "model": amend_model, "provider": amend_provider,
            "text": body})
    trace.say(f"[A5] Both branches submitted their amendments at the reconciled "
              f"figure {AMENDED_RECORDS:,}")

    # 6. Amendment diff: the value-match gate (concurred figure must match across
    #    both branches) AND the full UTC-canonicalized contradiction diff.
    value_gate = guard.can_pass_diff(
        1, {b: c.canonical()["records_affected"] for b, c in amended_claims.items()})
    log.append("negotiation_guard", {"check": "can_pass_diff",
                                     "allowed": value_gate.allowed,
                                     "reason": value_gate.reason})
    if not value_gate.allowed:
        raise RuntimeError(f"amended branches diverge from the concurred figure: "
                           f"{value_gate.reason}")
    conflicts = diff_claims(list(amended_claims.values()))
    log.append("diff", {"phase": "amendment",
                        "conflicts": [c.human() for c in conflicts]})
    if conflicts:
        raise RuntimeError(f"amended filings still contradict: {conflicts}")
    for b in AMENDMENT_BRANCHES:
        corr = branch_corr[b]
        _proto(sm, trace, corr, Event.DIFF_PASSED, TS_AMEND_RELEASE, "warden", "warden")
        _proto(sm, trace, corr, Event.SIGNOFF_OPENED, TS_AMEND_RELEASE, "warden", "warden")
        _proto(sm, trace, corr, Event.HUMAN_RELEASED, TS_AMEND_RELEASE, "lena", "human_owner")
    trace.say(f"[A6] Amended diff GREEN only after concurrence; both amendments "
              f"signed and released")

    return {
        "fact_key": "records_affected",
        "old_value": old_records,
        "new_value": AMENDED_RECORDS,
        "reopened_branches": list(AMENDMENT_BRANCHES),
        "amend_message_id": amend_msg_id,
        "pre_reconciliation_block": {"allowed": pre.allowed, "reason": pre.reason},
        "exchange": [
            {"from": "SEC Drafter", "to": "NIS2 Drafter", "verdict": "propose",
             "proposed_value": AMENDED_RECORDS, "characterization": proposal.characterization,
             "band_message_id": propose_mid, "envelope_sha256": proposal.sha256(),
             "prior_envelope_hash": None},
            {"from": "NIS2 Drafter", "to": "SEC Drafter", "verdict": "concur",
             "proposed_value": AMENDED_RECORDS, "characterization": concur.characterization,
             "band_message_id": concur_mid, "envelope_sha256": concur.sha256(),
             "prior_envelope_hash": parsed_proposal.sha256()},
        ],
        "concurred_value": AMENDED_RECORDS,
        "concurred_characterization": concur.characterization,
        "diff_passed_only_after_concur": True,
        "amended_filings": amended_filings,
        "amended_claims": amended_claims,
        "envelope_history": [
            {"verdict": e.verdict.value, "from": e.from_agent, "to": e.to_agent,
             "sha256": e.sha256(), "prior_envelope_hash": e.prior_envelope_hash}
            for e in guard.history()
        ],
    }


# ----------------------------------------------------------------------------
# Two-key release gate (segregation of duties). A filing at AWAITING_HUMAN_SIGNOFF
# releases only when BOTH distinct human keys sign: the GC, then Lena (Head of
# IR). The gate is pure Python composed OUTSIDE the state-machine table. The
# Warden records each sign-off, asks the gate, and admits HUMAN_RELEASED only
# once two distinct keys are present. One key alone is recorded as withheld and
# the branch stays in awaiting_human_signoff.
# ----------------------------------------------------------------------------
def _two_key_release(sm, trace, log, release_gate, corr: str) -> bool:
    """Drive the two-key release for one branch. Returns True iff the branch
    reached RELEASED. Records each sign-off and the withheld/released decisions in
    the run log, so the segregation of duties is replay-verifiable."""
    for role, actor, ts in RELEASE_SIGNERS:
        decision = release_gate.sign(corr, role, actor, ts)
        log.append("release_signoff", {
            "correlation_id": corr, "role": role, "actor": actor, "ts": ts,
            "released": decision.released,
            "have_roles": sorted(decision.have_roles),
            "missing_roles": sorted(decision.missing_roles),
            "reason": decision.reason,
        })
        if not decision.released:
            # First key only: the lock is NOT turned. The Warden does NOT emit
            # HUMAN_RELEASED; the branch waits for the second distinct key.
            trace.say(f"    [release] {corr}: {role} ({actor}) signed; "
                      f"{decision.reason}")
            continue
        # Both keys present. NOW the Warden admits the HUMAN_RELEASED transition.
        trace.say(f"    [release] {corr}: {role} ({actor}) signed; "
                  f"both keys present, release admitted")
        admitted = _proto(sm, trace, corr, Event.HUMAN_RELEASED, ts,
                          actor, "human_owner")
        if not admitted:
            raise RuntimeError(f"two-key release rejected by the state machine for {corr}")
        return True
    return False


# ----------------------------------------------------------------------------
# Materiality phase. An LLM judgment role applies the SEC "substantial likelihood"
# materiality standard to the fact-record. Its typed verdict crosses into the
# deterministic warden/materiality.py gate as data. If "not material", the Warden
# emits SUPPRESS on the SEC branch (terminal SUPPRESSED): no SEC filing, SEC clock
# stopped. The DECISION is the LLM's; the Warden's gating of the branch is
# deterministic and replay-verifiable.
# ----------------------------------------------------------------------------
def _materiality_phase(*, sm, trace, log, clocks, branch_corr, provider_set,
                       materiality_fn, sec_facts, draft_timeout) -> dict:
    corr = branch_corr["sec"]
    # 1. Obtain the verdict. Tests inject materiality_fn(fact_record) -> verdict;
    #    live runs call the Featherless materiality assessor.
    if materiality_fn is not None:
        verdict = materiality_fn(sec_facts)
    else:
        provider, model = roster.resolve(roster.MATERIALITY, provider_set)
        verdict = assess_materiality(
            sec_facts, model=model, provider=provider, branch="sec",
            timeout=draft_timeout)
    if not isinstance(verdict, MaterialityVerdict):
        raise RuntimeError("materiality assessor did not return a MaterialityVerdict")
    log.append("materiality", {
        "branch": "sec", "material": verdict.material,
        "disposition": verdict.disposition(), "source": verdict.source,
        "memo": verdict.memo,
    })

    # 2. Deterministic gate: proceed iff material.
    proceed = materiality_gate(verdict)
    trace.say(f"[4m] Materiality assessment (SEC): "
              f"{'MATERIAL, clock stands' if proceed else 'NOT MATERIAL, suppressing'} "
              f"(source {verdict.source})")

    if not proceed:
        # 3. The Warden drives the SEC branch to the terminal SUPPRESSED state.
        #    SUPPRESS is legal from INITIATED (the SEC branch has only had
        #    FACT_RECORD_POSTED), so move FACT_RECORD_READY -> SUPPRESSED.
        admitted = _proto(sm, trace, corr, Event.SUPPRESS, TS_FACTS,
                         "materiality", "materiality")
        if not admitted:
            raise RuntimeError("materiality SUPPRESS rejected by the state machine")
        clocks.stop(corr, TS_FACTS)
        log.append("clock_stopped", {"correlation_id": corr, "ts": TS_FACTS,
                                     "reason": "sec_suppressed_not_material"})
        trace.say(f"[4m] SEC branch SUPPRESSED (terminal); SEC 4-business-day "
                  f"clock stopped, no filing.")

    return {
        "branch": "sec",
        "material": verdict.material,
        "disposition": verdict.disposition(),
        "memo": verdict.memo,
        "source": verdict.source,
    }


# ----------------------------------------------------------------------------
# UK runtime-recruit phase. Triage's fact-record reveals a UK subsidiary in the
# blast radius; ONLY THEN does the Warden discover the UK ICO Drafter over the
# live Band peer list (token-match, since /agent/peers offers only not_in_chat),
# recruit it with add_participant, start the UK 72h GDPR clock AT THE RECRUIT
# MOMENT (not T0), and the UK drafter files. If the blast radius does NOT name
# the UK, no recruit happens: the recruit is content-driven, not hardcoded.
# ----------------------------------------------------------------------------
def _uk_recruit_phase(*, sm, trace, log, clocks, ledger, warden, triage, drafters,
                      clients, warden_id, triage_id, room_id, fact_record,
                      branch_corr, draft_fns, draft_timeout, provider_set,
                      uk_peers, live) -> dict:
    target = UK_ICO_TARGET
    in_scope = jurisdiction_in_blast_radius(fact_record, target.jurisdiction)
    log.append("recruit_scan", {
        "jurisdiction": target.jurisdiction,
        "blast_radius": fact_record.get("blast_radius", []),
        "in_scope": in_scope,
    })
    if not in_scope:
        # Content-driven: the blast radius does not touch the UK, so the Warden
        # does NOT recruit. This is the proof that the recruit is not hardcoded.
        trace.say(f"[R] Blast radius does not name a {target.jurisdiction} "
                  f"subsidiary; no runtime recruit. ({fact_record.get('blast_radius', [])})")
        return {"recruited": False, "in_scope": False,
                "blast_radius": fact_record.get("blast_radius", [])}

    trace.say(f"[R1] Triage fact-record reveals a {target.jurisdiction} subsidiary "
              f"in the blast radius. Warden discovering the {target.regime} Drafter "
              f"over the live peer list ...")

    # 1. Discover the UK ICO Drafter among peers NOT yet in the room (token-match).
    peers = uk_peers if uk_peers is not None else warden.peers(not_in_chat=room_id)
    peer = find_peer(peers, target.name_tokens)
    if peer is None:
        raise RuntimeError(
            f"{target.regime} Drafter not found among peers for runtime recruit "
            f"(tokens {target.name_tokens}); peers seen: {peers}")
    uk_id = peer_id(peer)
    if not uk_id:
        raise RuntimeError(f"discovered {target.regime} peer has no id: {peer}")
    log.append("recruit", {"jurisdiction": target.jurisdiction, "branch": target.branch,
                           "peer_id": uk_id, "ts": TS_UK_RECRUIT,
                           "matched_tokens": list(target.name_tokens)})
    trace.say(f"[R2] Found {target.regime} Drafter peer {uk_id} by token-match; "
              f"recruiting into room {room_id} via add_participant ...")

    # 2. Recruit it into the live room.
    warden.add_participant(uk_id, room_id)
    trace.record_handoff("Warden", f"{target.regime} Drafter", "runtime_recruit", "")

    # 3. The UK 72h GDPR clock starts AT THE RECRUIT MOMENT, not at T0. This is
    #    the late-started fifth clock the Examiner Packet shows.
    corr = branch_corr[target.branch]
    clocks.start_hours(target.clock_name, corr, TS_UK_RECRUIT, target.clock_hours)
    log.append("clock_started", {"clock": target.clock_name, "correlation_id": corr,
                                 "started_at": TS_UK_RECRUIT,
                                 "deadline": clocks.get(corr).deadline.isoformat(),
                                 "late_started_at_recruit": True})
    trace.say(f"[R3] {target.clock_name} started at the recruit moment "
              f"{TS_UK_RECRUIT} (NOT incident T0).")

    # 4. The UK branch opens its protocol: Triage @mentions the recruited drafter
    #    with the fact-record. FACT_RECORD_POSTED on the UK branch.
    _proto(sm, trace, corr, Event.FACT_RECORD_POSTED, TS_UK_FACTS, "triage", "triage")

    # 5. Build the live UK client (or use the injected one), join, draft, post.
    uk_client = _uk_client(clients, drafters, peer, uk_id)
    uk_client.join(room_id)
    uk_facts = {k: fact_record[k] for k in
                ("incident_start_utc", "records_affected", "attacker", "containment")}
    uk_fn = _uk_draft_fn(draft_fns, draft_timeout, provider_set)

    _proto(sm, trace, corr, Event.DRAFT_STARTED, TS_UK_DRAFT, "uk_drafter", "drafter")
    prose = uk_fn(uk_facts)
    body = build_draft_body(prose, target.branch, uk_facts)
    dedup_key = f"draft:{target.branch}:{INCIDENT_ID}:round-1"
    ledger.record(dedup_key, 1, TS_UK_DRAFT)
    uk_client.post(
        f"{target.regime} mandatory notification draft attached.\n\n{body}",
        mentions=[warden_id], dedup_key=dedup_key)
    _proto(sm, trace, corr, Event.DRAFT_POSTED, TS_UK_DRAFT, "uk_drafter", "drafter")
    trace.record_handoff(f"{target.regime} Drafter", "Warden", "draft", "")
    claims = parse_claims(body)
    uk_provider, uk_model = roster.resolve(roster.UK_DRAFTER, provider_set)
    trace.say(f"[R4] {target.regime} Drafter (recruited at runtime) filed on "
              f"{uk_provider}:{uk_model}.")

    return {
        "recruited": True,
        "in_scope": True,
        "blast_radius": fact_record.get("blast_radius", []),
        "jurisdiction": target.jurisdiction,
        "regime": target.regime,
        "branch": target.branch,
        "peer_id": uk_id,
        "recruit_ts": TS_UK_RECRUIT,
        "clock_name": target.clock_name,
        "clock_started_at": TS_UK_RECRUIT,
        "claims": claims,
        "filing": {"regime": target.regime, "by": f"{target.regime} Drafter",
                   "model": uk_model, "provider": uk_provider, "text": body,
                   "recruited_at_runtime": True},
    }


def _uk_client(clients, drafters, peer, uk_id):
    """Resolve the UK drafter client. Tests inject it under clients['uk']; live
    runs build a LiveBand on the UK agent key."""
    if clients is not None and "uk" in clients:
        return clients["uk"]
    return LiveBand(api_key=roster.UK_DRAFTER.agent_key, agent_name="uk_drafter",
                    dedup_namespace="draft:uk")


def _uk_draft_fn(draft_fns, timeout, provider_set):
    if draft_fns is not None and "uk" in draft_fns:
        return draft_fns["uk"]
    provider, model = roster.resolve(roster.UK_DRAFTER, provider_set)

    def fn(claim_facts):
        body_facts = dict(claim_facts)
        # MiniMax-M2 is a reasoning model: it spends a few hundred tokens on an
        # internal preamble before any visible content, so a 700-token budget can
        # return empty. A larger budget draws the filing out. Featherless is
        # flat-rate, so the extra tokens cost nothing on the dev plan.
        return draft_filing(body_facts, model=model, provider=provider,
                            regime=roster.UK_DRAFTER.regime, timeout=timeout,
                            max_tokens=2000)
    return fn


def _characterize_fn_for(branch, regime, role, draft_fns, timeout,
                         provider_set=roster.PROVIDER_DEV):
    """Resolve the characterization drafter for one reconciliation turn. Tests
    inject draft_fns keyed by f'{branch}:characterize'; live runs call the active
    provider for that branch's role. Returns a fn(counterpart_text) -> one-sentence
    characterization. `role` is the turn ("propose" | "concur")."""
    if draft_fns is not None:
        injected = draft_fns.get(f"{branch}:characterize")
        if injected is not None:
            return injected

    branch_role = roster.SEC_DRAFTER if branch == "sec" else roster.NIS2_DRAFTER
    provider, model = roster.resolve(branch_role, provider_set)

    def fn(counterpart_text: str) -> str:
        return draft_characterization(
            regime=regime, old_records=CANONICAL_FACTS["records_affected"],
            new_records=AMENDED_RECORDS, role=role,
            counterpart_text=counterpart_text,
            model=model, provider=provider, timeout=timeout)
    return fn


# ----------------------------------------------------------------------------
# Helpers shared by the full floor.
# ----------------------------------------------------------------------------
def _require_live(role, label, envs) -> None:
    if not role.live:
        raise RuntimeError(f"{label} agent not configured ({envs})")


def _announce_provider_set(trace, log, provider_set: str, live: bool) -> dict:
    """State plainly which LLM provider configuration is active, and for prod do a
    cheap live availability check on each AI/ML model (one tiny completion each).

    The note is one line in the run output. dev burns zero AI/ML credit by
    construction: nothing here calls AI/ML unless provider_set is prod AND the run
    is live. Returns the validation result dict (empty for dev / non-live)."""
    if provider_set == roster.PROVIDER_DEV:
        trace.say("[0] Provider set: DEV (every role on Featherless, zero AI/ML "
                  "credit spent).")
        log.append("provider_set", {"set": provider_set, "aiml_validation": {}})
        return {}

    # prod: name the split, then validate the AI/ML models if this is a live run.
    aiml_models = roster.prod_aiml_validation_models()
    hero_models = roster.prod_featherless_hero_models()
    trace.say("[0] Provider set: PROD (AI/ML API parallel racing drafters + "
              "Featherless hero open models).")
    trace.say("    AI/ML drafters: "
              + ", ".join(f"{role}={m}" for role, m in aiml_models.items()))
    trace.say("    Featherless heroes: "
              + ", ".join(f"{role}={m}" for role, m in hero_models.items()))

    validation: dict = {}
    if live:
        validation = _validate_aiml_models(trace, aiml_models)
    else:
        trace.say("    (offline run: skipping the live AI/ML availability check)")
    log.append("provider_set", {"set": provider_set,
                                "aiml_models": aiml_models,
                                "featherless_hero_models": hero_models,
                                "aiml_validation": validation})
    return validation


def _validate_aiml_models(trace, aiml_models: dict) -> dict:
    """Fire one tiny AI/ML completion per prod AI/ML model to prove it answers on
    the key. Keeps spend minimal (max_tokens small). A model id that is
    unavailable is reported clearly and does NOT crash the run, so a single bad id
    can be swapped without losing the others."""
    from floor.drafter import DrafterError, llm_complete

    results: dict = {}
    trace.say("    Validating AI/ML model availability (one tiny call each) ...")
    for role_label, model in aiml_models.items():
        try:
            # 512 tokens, not 8: some AI/ML models (gemini-3.5-flash) are reasoning
            # models that spend a few hundred tokens on an internal preamble before
            # any visible content, so a tiny budget returns empty even though the
            # model is live and answers fine at the drafter's real 700-token budget.
            # A short concrete prompt (not "reply ready") draws visible content out.
            # This is still well under a cent per call.
            reply = llm_complete(
                roster.AIMLAPI, model,
                [{"role": "user",
                  "content": "In one short sentence, confirm you can draft a "
                             "regulatory breach notification."}],
                max_tokens=512, temperature=0.0, timeout=60)
            results[model] = {"role": role_label, "available": True,
                              "reply": reply}
            trace.say(f"      OK   {role_label:14s} {model}  -> {reply!r}")
        except DrafterError as e:
            results[model] = {"role": role_label, "available": False,
                              "error": str(e)}
            trace.say(f"      MISS {role_label:14s} {model}  UNAVAILABLE: {e}")
    answered = [m for m, r in results.items() if r.get("available")]
    trace.say(f"    AI/ML models that answered: {len(answered)}/{len(aiml_models)}")
    return results


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


def _draft_fn_for(branch, role, draft_fns, timeout, provider_set=roster.PROVIDER_DEV):
    if draft_fns is not None:
        return draft_fns[branch]

    provider, model = roster.resolve(role, provider_set)

    def fn(claim_facts):
        # The LLM drafts prose from the FULL canonical fact-record body plus the
        # branch's asserted incident_start; the structured claims are attached by
        # the drafter process, not formatted by the model. The provider + model
        # come from the active provider set (dev = Featherless, prod = the split).
        body_facts = dict(CANONICAL_FACTS)
        body_facts["incident_start_utc"] = claim_facts["incident_start_utc"]
        return draft_filing(body_facts, model=model, provider=provider,
                            regime=role.regime, timeout=timeout)
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
                     breached, filings, mode, ledger, replay_info,
                     amendment=None, provider_set=roster.PROVIDER_DEV,
                     provider_validation=None, materiality=None, recruit=None,
                     release_gate=None, released_branches=None) -> dict:
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
    all_filings = list(filings)
    if amendment is not None:
        all_filings = all_filings + amendment["amended_filings"]
    packet = {
        "incident": {
            "incident_id": INCIDENT_ID,
            "band_room_id": room_id,
            "mode": mode,
            "provider_set": provider_set,
            "fact_record": CANONICAL_FACTS,
        },
        "providers": {
            "provider_set": provider_set,
            "aiml_drafters": roster.prod_aiml_validation_models()
            if provider_set == roster.PROVIDER_PROD else {},
            "featherless_heroes": roster.prod_featherless_hero_models()
            if provider_set == roster.PROVIDER_PROD else {},
            "aiml_validation": provider_validation or {},
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
        "filings": all_filings,
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
    if amendment is not None:
        # User-facing framing: transparent deliberation with an audit trail, not
        # "negotiation". The hash-linked envelope chain is the audit trail.
        packet["reconciliation"] = {
            "fact_key": amendment["fact_key"],
            "old_value": amendment["old_value"],
            "new_value": amendment["new_value"],
            "reopened_branches": amendment["reopened_branches"],
            "amend_message_id": amendment["amend_message_id"],
            "blocked_before_reconciliation": not amendment["pre_reconciliation_block"]["allowed"],
            "block_reason": amendment["pre_reconciliation_block"]["reason"],
            "exchange": amendment["exchange"],
            "concurred_value": amendment["concurred_value"],
            "concurred_characterization": amendment["concurred_characterization"],
            "diff_passed_only_after_concur": amendment["diff_passed_only_after_concur"],
            "envelope_chain": amendment["envelope_history"],
        }
    if materiality is not None:
        packet["materiality"] = materiality
    if recruit is not None:
        packet["recruit"] = recruit
    if release_gate is not None:
        packet["release"] = {
            "required_roles": sorted(REQUIRED_ROLES),
            "signoffs": [
                {"correlation_id": s.correlation_id, "role": s.role,
                 "actor": s.actor, "ts": s.ts}
                for b in (released_branches or [])
                for s in release_gate.signoffs(f"{INCIDENT_ID}:{b}")
            ],
            "released_branches": released_branches or [],
        }
    return packet


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
        trace.say(f"    NIS2 Drafter saw mention (msg {mid}); calling its model "
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
    parser.add_argument("--amendment", action="store_true",
                        help="after release, Triage revises a load-bearing fact; the SEC "
                             "and NIS2 Drafters reconcile through Band before re-filing")
    parser.add_argument("--provider", choices=[roster.PROVIDER_DEV, roster.PROVIDER_PROD],
                        default=roster.PROVIDER_DEV,
                        help="LLM provider set: dev (default, all Featherless, zero "
                             "AI/ML credit) or prod (AI/ML racing drafters + Featherless "
                             "hero open models)")
    parser.add_argument("--uk-recruit", action="store_true",
                        help="content-driven UK ICO runtime recruit: Triage's blast "
                             "radius names a UK subsidiary, so the Warden discovers and "
                             "recruits the UK ICO Drafter live and starts a 5th clock at "
                             "the recruit moment")
    parser.add_argument("--materiality", action="store_true",
                        help="run the SEC materiality assessment; if the incident is "
                             "not material the SEC branch is suppressed (no filing)")
    parser.add_argument("--immaterial", action="store_true",
                        help="with --materiality, feed the assessor the immaterial "
                             "fixture so the SEC branch is suppressed on camera")
    args = parser.parse_args()
    if sum([args.inject_contradiction, args.chaos, args.amendment]) > 1:
        print("Pick one of --inject-contradiction, --chaos, or --amendment.")
        return 1
    if args.immaterial and not args.materiality:
        print("--immaterial requires --materiality.")
        return 1
    mode = "inject_contradiction" if args.inject_contradiction else \
           "chaos" if args.chaos else \
           "amendment" if args.amendment else "normal"
    sec_facts = SEC_IMMATERIAL_FACTS if (args.materiality and args.immaterial) \
        else SEC_MATERIAL_FACTS if args.materiality else None

    try:
        from _env import load_env  # spikes/_env.py
        load_env()
    except Exception:
        pass
    import os
    if not os.environ.get("BAND_API_KEY") or not os.environ.get("FEATHERLESS_API_KEY"):
        print("Missing BAND_API_KEY or FEATHERLESS_API_KEY (load code/.env).")
        return 1
    if args.provider == roster.PROVIDER_PROD and not os.environ.get("AIML_API_KEY"):
        print("Provider prod needs AIML_API_KEY (load code/.env).")
        return 1
    banner = ("LIVE Band + Featherless" if args.provider == roster.PROVIDER_DEV
              else "LIVE Band + AI/ML API split (prod)")
    print(f"=== Deadline Room floor run ({banner}) mode={mode} "
          f"provider={args.provider} ===\n")
    packet = run_floor(mode=mode, provider_set=args.provider,
                       uk_recruit=args.uk_recruit, materiality=args.materiality,
                       sec_facts=sec_facts)
    print("\n=== Done. Examiner Packet at: "
          + packet["_paths"]["html"] + " ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
