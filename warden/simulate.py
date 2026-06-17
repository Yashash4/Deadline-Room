"""Incident simulation harness: runs the full Deadline Room protocol over
the fake Band, with an injectable kill schedule. This is what the property
tests drive with randomized kill points.

Drafter behavior is a deterministic stub (the real LLM drafters plug in
behind the same envelope); the Warden never knows the difference,
which is the point.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .clocks import ClockEngine
from .diff import Containment, FactClaims, diff_claims
from .fake_band import FakeBand
from .ledger import Disposition, IdempotencyLedger
from .negotiation import (NegotiationEnvelope, NegotiationGuard, Verdict)
from .replay import RunLog
from .state_machine import Event, ProtocolStateMachine

INCIDENT_T0 = "2026-06-16T02:14:00+00:00"

BRANCHES = ["nis2", "dora", "sec"]

# The asymmetric-failure mode tokens the richer fuzz drives through the FULL
# pipeline (E1.5). These ride alongside the legacy "A"/"B" crash positions and
# are routed through the interleaved drain below, never through the legacy
# per-branch loop, so the sealed schedules and byte-identical replay are
# untouched.
#   "A"        crash position A: died before posting (kill_in_flight, attempt+1).
#   "B"        crash position B: posted, died before the ack (kill_in_flight,
#              attempt+1); the re-delivered post is a duplicate the ledger drops.
#   "ack_lost" the asymmetric lost-ack partition: posted and succeeded, but the
#              ack was lost; /next re-serves the IDENTICAL message (attempt
#              UNCHANGED). The read-then-act dedup must drop the redelivery.
FAILURE_POSITIONS = ("A", "B", "ack_lost")

CANONICAL_FACTS = {
    "incident_start_ts": INCIDENT_T0,
    "records_affected": 48000,
    "attacker": "LockBit 3.0",
    "containment": Containment.PARTIALLY_CONTAINED,
}

AMENDED_RECORDS = 2_100_000  # A1: the hour-6 forensic revision (spec 2.11)


@dataclass
class KillSchedule:
    """kill[(branch, attempt)] = 'A' or 'B', crash that attempt at that position."""
    kills: dict[tuple[str, int], str] = field(default_factory=dict)


@dataclass
class FailureSchedule:
    """The richer, full-pipeline failure model (E1.5).

    failures[(branch, attempt)] in {"A", "B", "ack_lost"} injects that failure
    on that branch's attempt. Unlike KillSchedule, this is consumed by the
    INTERLEAVED drain (drain_order), which steps every branch's lifecycle one
    message at a time in a randomized cross-branch order against the ONE shared
    ledger + state machine + clocks, so a dropped SEC duplicate and an accepted
    NIS2 first-file are processed back to back. That interleaving, plus the
    asymmetric "ack_lost" redelivery (which re-serves the identical message with
    the attempt counter UNCHANGED), is exactly the concurrency the legacy
    per-branch for-loop hid.

    drain_order is the randomized, fair interleaving of branch ids the driver
    walks. It is seeded by the caller so every schedule is reproducible.
    """
    failures: dict[tuple[str, int], str] = field(default_factory=dict)
    drain_order: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    filings: dict[str, dict]          # branch -> the single accepted draft
    duplicates_dropped: int
    rejections: int
    log: RunLog
    breached_clocks: list[str]
    amendments: dict[str, dict] = field(default_factory=dict)   # A1
    negotiation_rounds: int = 0                                  # A1


def _claims_for(branch: str, contradiction_in: str | None) -> FactClaims:
    """The load-bearing claims a branch asserts. In a contradiction run the named
    branch carries the wrong incident_start; everyone else carries canonical."""
    start_ts = CANONICAL_FACTS["incident_start_ts"]
    if contradiction_in == branch:
        start_ts = "2026-06-16T02:41:00+00:00"  # the wrong start time
    return FactClaims(branch, start_ts, CANONICAL_FACTS["records_affected"],
                      CANONICAL_FACTS["attacker"], CANONICAL_FACTS["containment"])


def _drive_sequential(incident_id, band, ledger, log, proto, kills,
                      contradiction_in, posted_claims) -> int:
    """The legacy per-branch drain (positions A and B), drained one branch at a
    time. Extracted verbatim from run_incident so the new interleaved driver can
    sit beside it; behavior, log entries, and ordering are byte-identical to the
    prior inline loop, which the sealed schedules and replay tests pin."""
    rejections = 0
    for b in BRANCHES:
        corr = f"{incident_id}:{b}"
        agent = f"{b}_drafter"
        done = False
        while not done:
            msg = band.messages_next(agent)
            if msg is None:
                break
            attempt = msg.attempt
            t_draft = f"2026-06-16T03:{10 + attempt:02d}:00+00:00"
            proto(corr, Event.DRAFT_STARTED, t_draft, agent, "drafter")

            kill = kills.get((b, attempt))
            if kill == "A":
                band.kill_in_flight(agent)  # died before posting anything
                log.append("chaos", {"branch": b, "attempt": attempt, "position": "A"})
                # state machine: branch is stuck in DRAFTING; the retry's
                # DRAFT_STARTED will be rejected as illegal, which is fine,
                # the Warden treats a repeat DRAFT_STARTED on a DRAFTING
                # branch as a recovery no-op (recorded as a rejection).
                continue

            # The drafter posts its draft (with the claims envelope)
            claims = _claims_for(b, contradiction_in)
            entry = ledger.record(msg.body["dedup_key"], attempt, t_draft)
            log.append("ledger", {"key": entry.dedup_key, "attempt": attempt,
                                  "disposition": entry.disposition.value})
            if entry.disposition is Disposition.ACCEPTED:
                posted_claims[b] = claims
                band.post_to_room(agent, {"draft": f"{b.upper()} filing", "claims": claims.canonical()})
                admitted = proto(corr, Event.DRAFT_POSTED, t_draft, agent, "drafter")
                if not admitted:
                    rejections += 1

            if kill == "B":
                band.kill_in_flight(agent)  # died AFTER posting, before processed
                log.append("chaos", {"branch": b, "attempt": attempt, "position": "B"})
                continue  # the re-delivered message will be a duplicate; ledger drops it

            band.mark_processed(msg)
            done = True

        # drain any leftover re-delivered duplicates (position-B aftermath)
        while (dup := band.messages_next(agent)) is not None:
            entry = ledger.record(dup.body["dedup_key"], dup.attempt,
                                  "2026-06-16T03:30:00+00:00")
            log.append("ledger", {"key": entry.dedup_key, "attempt": dup.attempt,
                                  "disposition": entry.disposition.value})
            band.mark_processed(dup)
    return rejections


def _drive_interleaved(incident_id, band, sm, ledger, log, proto, schedule,
                       contradiction_in, posted_claims) -> int:
    """The E1.5 interleaved full-pipeline driver.

    Every branch's lifecycle is stepped ONE message at a time, in the randomized
    cross-branch drain_order, against the ONE shared ledger + state machine. A
    branch is "settled" once its single round-1 filing has been marked processed
    with nothing left to re-serve. Each visit to a still-unsettled branch:

      1. drains /next (the SAME message is re-served until processed),
      2. marks processing, fires DRAFT_STARTED,
      3. consults the failure schedule for (branch, attempt):
           "A"        kill before posting (kill_in_flight, attempt+1); no post.
           "B"        post (ledger.record + DRAFT_POSTED), then kill_in_flight
                      (attempt+1); the re-delivered post is a fresh-attempt
                      duplicate the ledger must drop.
           "ack_lost" post (ledger.record + DRAFT_POSTED), then kill_after_ack_lost
                      (attempt UNCHANGED); /next re-serves the IDENTICAL message,
                      a true at-least-once redelivery the read-then-act dedup
                      (the ledger keyed on the attempt-independent natural key)
                      must drop. This is the asymmetric partition the legacy kill
                      never modeled.
           none       post (if not already recorded), mark processed, settle.

    The DRAFT_POSTED transition is fired ONLY on an ACCEPTED ledger disposition,
    exactly as the sequential path does: a dropped duplicate is recorded in the
    ledger and marked processed but never re-fires DRAFT_POSTED (which the state
    machine would reject from DRAFT_SUBMITTED anyway). So the full pipeline, not
    just the ledger, is exercised, and exactly-once is what makes it hold.
    """
    rejections = 0
    order = schedule.drain_order or list(BRANCHES)
    settled: set[str] = set()
    # Each scheduled failure point fires AT MOST ONCE. This is the honest model:
    # the chaos event (the kill, the lost ack) happens once; what we are proving
    # is that the RECOVERY (the re-served redelivery) lands exactly once. Without
    # this, an "ack_lost" point, which does not advance the attempt counter,
    # would re-fire on its own redelivery forever and the agent would never get
    # to recover, which is not a real failure, just an un-recovering harness.
    consumed: set[tuple[str, int]] = set()
    # Guard against a pathological schedule that never settles a branch (it
    # cannot happen now that each failure fires once, but a bound keeps the fuzz
    # honest and fast).
    max_visits = 64 * len(BRANCHES)
    visits = 0
    while len(settled) < len(BRANCHES) and visits < max_visits:
        for b in order:
            if b in settled:
                continue
            visits += 1
            corr = f"{incident_id}:{b}"
            agent = f"{b}_drafter"
            msg = band.messages_next(agent)
            if msg is None:
                # Nothing to serve right now: the branch posted and was marked
                # processed by a prior visit. It is settled.
                settled.add(b)
                continue
            attempt = msg.attempt
            t_draft = f"2026-06-16T03:{10 + attempt:02d}:00+00:00"
            proto(corr, Event.DRAFT_STARTED, t_draft, agent, "drafter")

            failure = schedule.failures.get((b, attempt))
            if (b, attempt) in consumed:
                # This failure point already fired; the re-served message is the
                # recovery redelivery, which must process normally (and, if it
                # already posted, be dropped as a duplicate). Do not re-inject.
                failure = None
            if failure == "A":
                consumed.add((b, attempt))
                band.kill_in_flight(agent)  # died before posting anything
                log.append("chaos", {"branch": b, "attempt": attempt,
                                      "position": "A", "mode": "interleaved"})
                continue

            claims = _claims_for(b, contradiction_in)
            entry = ledger.record(msg.body["dedup_key"], attempt, t_draft)
            log.append("ledger", {"key": entry.dedup_key, "attempt": attempt,
                                  "disposition": entry.disposition.value})
            if entry.disposition is Disposition.ACCEPTED:
                posted_claims[b] = claims
                band.post_to_room(agent, {"draft": f"{b.upper()} filing",
                                          "claims": claims.canonical()})
                admitted = proto(corr, Event.DRAFT_POSTED, t_draft, agent, "drafter")
                if not admitted:
                    rejections += 1
            # else: a DUPLICATE_DROPPED redelivery. The post already landed and
            # DRAFT_POSTED already fired on the accepting visit; we do NOT re-fire
            # it. This is the read-then-act dedup catching the redelivery.

            if failure == "B":
                consumed.add((b, attempt))
                band.kill_in_flight(agent)  # posted, died before the ack (attempt+1)
                log.append("chaos", {"branch": b, "attempt": attempt,
                                      "position": "B", "mode": "interleaved"})
                continue
            if failure == "ack_lost":
                consumed.add((b, attempt))
                band.kill_after_ack_lost(agent)  # posted, ack lost (attempt UNCHANGED)
                log.append("chaos", {"branch": b, "attempt": attempt,
                                      "position": "ack_lost", "mode": "interleaved"})
                continue

            band.mark_processed(msg)
            settled.add(b)

    if len(settled) < len(BRANCHES):
        # A schedule that could not settle is a harness bug, not an exactly-once
        # result. Surface it loudly rather than silently reporting a clean run.
        raise RuntimeError(
            f"interleaved drain did not settle all branches "
            f"(settled={sorted(settled)}, visits={visits})")
    return rejections


def run_incident(
    incident_id: str = "inc-8842",
    kill_schedule: KillSchedule | None = None,
    contradiction_in: str | None = None,  # branch that initially mis-states the start time
    amendment: bool = False,              # A1: fire the hour-6 fact revision beat
    nis2_counters_first: bool = False,    # A1: exercise the bounded counter round
    failure_schedule: FailureSchedule | None = None,  # E1.5: interleaved full-pipeline failures
) -> RunResult:
    kills = (kill_schedule or KillSchedule()).kills
    band = FakeBand()
    sm = ProtocolStateMachine()
    ledger = IdempotencyLedger()
    clocks = ClockEngine()
    log = RunLog()

    def proto(corr: str, event: Event, ts: str, actor: str, role: str) -> bool:
        result = sm.apply(corr, event, ts, actor=actor, actor_role=role)
        log.append("protocol_event", {
            "correlation_id": corr, "event": event.value, "ts": ts,
            "actor": actor, "actor_role": role,
            "admitted": result.admitted,
            "to_state": result.to_state.value if result.admitted else None,
            "reason": None if result.admitted else result.reason,
        })
        return result.admitted

    # --- T0: alert + clocks -------------------------------------------
    clocks.start_hours("NIS2 full (72h)", f"{incident_id}:nis2", INCIDENT_T0, 72)
    clocks.start_hours("DORA (72h)", f"{incident_id}:dora", INCIDENT_T0, 72)
    clocks.start_sec_business_days(f"{incident_id}:sec", INCIDENT_T0)
    for c in clocks.all():
        log.append("clock_started", {"clock": c.name, "correlation_id": c.correlation_id,
                                     "deadline": c.deadline.isoformat()})

    # --- Triage posts the fact record; one message fans out -----------
    ts = "2026-06-16T02:31:00+00:00"
    for b in BRANCHES:
        proto(f"{incident_id}:{b}", Event.FACT_RECORD_POSTED, ts, "triage", "triage")
        band.send(f"{b}_drafter", {"fact_record": dict(CANONICAL_FACTS), "branch": b,
                                   "dedup_key": f"draft:{b}:{incident_id}:round-1"})

    # --- Drafting races with chaos ------------------------------------
    rejections = 0
    posted_claims: dict[str, FactClaims] = {}
    if failure_schedule is not None:
        # E1.5: the richer, interleaved full-pipeline failure model. The drain
        # is cross-branch and the failures are asymmetric (including the lost-ack
        # redelivery), but every branch lands its filing through the SAME ledger,
        # state machine, and clocks, so the same exactly-once invariant holds.
        rejections += _drive_interleaved(
            incident_id, band, sm, ledger, log, proto, failure_schedule,
            contradiction_in, posted_claims)
    else:
        rejections += _drive_sequential(
            incident_id, band, ledger, log, proto, kills,
            contradiction_in, posted_claims)

    # --- Contradiction check ------------------------------------------
    t_diff = "2026-06-16T04:00:00+00:00"
    conflicts = diff_claims(list(posted_claims.values()))
    log.append("diff", {"conflicts": [c.human() for c in conflicts]})
    if conflicts:
        for b in BRANCHES:
            proto(f"{incident_id}:{b}", Event.DIFF_BLOCKED, t_diff, "warden", "warden")
        # the offending drafter corrects and re-posts (round 2)
        bad = contradiction_in
        corr = f"{incident_id}:{bad}"
        t_fix = "2026-06-16T04:20:00+00:00"
        proto(corr, Event.DRAFT_STARTED, t_fix, f"{bad}_drafter", "drafter")
        fixed = FactClaims(bad, CANONICAL_FACTS["incident_start_ts"],
                           CANONICAL_FACTS["records_affected"],
                           CANONICAL_FACTS["attacker"], CANONICAL_FACTS["containment"])
        entry = ledger.record(f"draft:{bad}:{incident_id}:round-2", 1, t_fix)
        log.append("ledger", {"key": entry.dedup_key, "attempt": 1,
                              "disposition": entry.disposition.value})
        posted_claims[bad] = fixed
        band.post_to_room(f"{bad}_drafter", {"draft": f"{bad.upper()} filing (corrected)",
                                             "claims": fixed.canonical()})
        proto(corr, Event.DRAFT_POSTED, t_fix, f"{bad}_drafter", "drafter")
        # others re-post unchanged (round 2 keys), then re-diff
        for b in BRANCHES:
            if b != bad:
                c2 = f"{incident_id}:{b}"
                proto(c2, Event.DRAFT_STARTED, t_fix, f"{b}_drafter", "drafter")
                proto(c2, Event.DRAFT_POSTED, t_fix, f"{b}_drafter", "drafter")
        conflicts = diff_claims(list(posted_claims.values()))
        log.append("diff", {"conflicts": [c.human() for c in conflicts]})

    t_pass = "2026-06-16T04:30:00+00:00"
    for b in BRANCHES:
        corr = f"{incident_id}:{b}"
        proto(corr, Event.DIFF_PASSED, t_pass, "warden", "warden")
        proto(corr, Event.SIGNOFF_OPENED, t_pass, "warden", "warden")

    # --- Authority check: a drafter trying to self-release is rejected -
    r = sm.apply(f"{incident_id}:nis2", Event.HUMAN_RELEASED, t_pass,
                 actor="nis2_drafter", actor_role="drafter")
    log.append("protocol_event", {
        "correlation_id": f"{incident_id}:nis2", "event": Event.HUMAN_RELEASED.value,
        "ts": t_pass, "actor": "nis2_drafter", "actor_role": "drafter",
        "admitted": r.admitted, "to_state": None, "reason": r.reason})
    rejections += 1

    # --- Humans release -------------------------------------------------
    t_rel = "2026-06-16T05:00:00+00:00"
    for b in BRANCHES:
        corr = f"{incident_id}:{b}"
        proto(corr, Event.HUMAN_RELEASED, t_rel, "lena", "human_owner")
        clocks.stop(corr, t_rel)
        log.append("clock_stopped", {"correlation_id": corr, "ts": t_rel})

    filings = {b: {"claims": posted_claims[b].canonical()} for b in BRANCHES}

    # =====================================================================
    # A1: the fact-amendment beat (spec v2 section 2.11)
    # =====================================================================
    amendments: dict[str, dict] = {}
    negotiation_rounds = 0
    if amendment:
        guard = NegotiationGuard()
        t_amend = "2026-06-16T08:14:00+00:00"  # ~hour 6 demo time

        # 1. Triage posts the revision; SEC and NIS2 branches reopen.
        log.append("fact_amendment", {"fact_key": "records_affected",
                                      "old": CANONICAL_FACTS["records_affected"],
                                      "new": AMENDED_RECORDS, "ts": t_amend})
        for b in ("sec", "nis2"):
            proto(f"{incident_id}:{b}", Event.FACT_AMENDED, t_amend, "triage", "triage")

        # 2. Premature submission attempt: SEC tries to post its amendment
        #    BEFORE any reconciliation. The negotiation guard blocks it.
        early = guard.can_submit_amendment(f"{incident_id}:sec", amend_round=1)
        log.append("negotiation_guard", {"check": "can_submit_amendment",
                                         "allowed": early.allowed, "reason": early.reason})
        assert not early.allowed  # invariant: amendment is a no-op until concur

        # 3. The SEC Drafter @mentions the NIS2 Drafter with its proposal.
        def envelope(rnd, frm, to, verdict, value, character, prior=None):
            return NegotiationEnvelope(
                correlation_id=f"{incident_id}:{'sec' if frm == 'sec_drafter' else 'nis2'}",
                amend_round=rnd, from_agent=frm, to_agent=to,
                fact_key="records_affected", proposed_value=value,
                characterization=character,
                data_category_bounds=("name", "address", "account_number"),
                containment_framing="contained as of 2026-06-16T07:00:00+00:00",
                verdict=verdict, ts_utc=t_amend, prior_envelope_hash=prior,
            )

        proposal = envelope(1, "sec_drafter", "nis2_drafter", Verdict.PROPOSE,
                            AMENDED_RECORDS, "approximately 2.1 million records")
        guard.post(proposal)
        log.append("negotiation", proposal.canonical())
        negotiation_rounds = 1

        if nis2_counters_first:
            # 4a. NIS2 counters with a tighter characterization; SEC re-proposes.
            counter = envelope(1, "nis2_drafter", "sec_drafter", Verdict.COUNTER,
                               AMENDED_RECORDS, "2,100,000 records (categories bounded)",
                               prior=proposal.sha256())
            guard.post(counter)
            log.append("negotiation", counter.canonical())
            reproposal = envelope(2, "sec_drafter", "nis2_drafter", Verdict.PROPOSE,
                                  AMENDED_RECORDS, "2,100,000 records (categories bounded)",
                                  prior=counter.sha256())
            guard.post(reproposal)
            log.append("negotiation", reproposal.canonical())
            concur = envelope(2, "nis2_drafter", "sec_drafter", Verdict.CONCUR,
                              AMENDED_RECORDS, "2,100,000 records (categories bounded)",
                              prior=reproposal.sha256())
            guard.post(concur)
            log.append("negotiation", concur.canonical())
            negotiation_rounds = 2
            final_round = 2
        else:
            # 4b. NIS2 concurs directly.
            concur = envelope(1, "nis2_drafter", "sec_drafter", Verdict.CONCUR,
                              AMENDED_RECORDS, "approximately 2.1 million records",
                              prior=proposal.sha256())
            guard.post(concur)
            log.append("negotiation", concur.canonical())
            final_round = 1

        # 5. Concur exists: both branches may now submit their amendments.
        amended_claims: dict[str, FactClaims] = {}
        for b in ("sec", "nis2"):
            corr = f"{incident_id}:{b}"
            gate = guard.can_submit_amendment(corr, amend_round=final_round)
            log.append("negotiation_guard", {"check": "can_submit_amendment",
                                             "allowed": gate.allowed, "reason": gate.reason})
            assert gate.allowed
            entry = ledger.record(f"draft:{b}:{incident_id}:amend-{final_round}", 1, t_amend)
            log.append("ledger", {"key": entry.dedup_key, "attempt": 1,
                                  "disposition": entry.disposition.value})
            amended_claims[b] = FactClaims(b, CANONICAL_FACTS["incident_start_ts"],
                                           AMENDED_RECORDS, CANONICAL_FACTS["attacker"],
                                           Containment.CONTAINED)
            band.post_to_room(f"{b}_drafter", {
                "draft": ("Amended 8-K (Item 1.05)" if b == "sec"
                          else "NIS2 intermediate report"),
                "claims": amended_claims[b].canonical()})
            proto(corr, Event.DRAFT_POSTED, t_amend, f"{b}_drafter", "drafter")

        # 6. Amendment diff: value-match gate + the full UTC-canonicalized diff.
        value_gate = guard.can_pass_diff(final_round, {
            b: c.canonical()["records_affected"] for b, c in amended_claims.items()})
        log.append("negotiation_guard", {"check": "can_pass_diff",
                                         "allowed": value_gate.allowed,
                                         "reason": value_gate.reason})
        assert value_gate.allowed
        conflicts = diff_claims(list(amended_claims.values()))
        log.append("diff", {"conflicts": [c.human() for c in conflicts], "phase": "amendment"})

        t_amend_rel = "2026-06-16T09:00:00+00:00"
        for b in ("sec", "nis2"):
            corr = f"{incident_id}:{b}"
            proto(corr, Event.DIFF_PASSED, t_amend_rel, "warden", "warden")
            proto(corr, Event.SIGNOFF_OPENED, t_amend_rel, "warden", "warden")
            proto(corr, Event.HUMAN_RELEASED, t_amend_rel, "lena", "human_owner")
        amendments = {b: {"claims": c.canonical()} for b, c in amended_claims.items()}

    breached = [c.name for c in clocks.breaches(t_rel)]
    return RunResult(filings, ledger.duplicates_dropped(), rejections, log, breached,
                     amendments, negotiation_rounds)
