"""Deterministic decision-rationale ledger (E9.1).

ONE source of truth for the plain-English "why" behind every Warden decision.
Before this module the room post (run_floor `_warden_announce`), the Examiner
Packet ("Decision rationale" section), and the web copy (`deriveGate`) each
hand-typed their own sentence for the same decision; three strings that could
drift. This module emits a single typed DecisionRationale per decision, and all
three render from it, so the room text, the packet text, and the web text are the
SAME bytes.

A rationale is built from three deterministic ingredients, nothing else:
  1. which transition fired (the Event / Conflict / verdict that already
     happened in the deterministic core),
  2. which rule governs it (a static rule-id -> plain-English template), and
  3. which fact drove it (the EXACT driving fact value, named verbatim).

This module is PURE: zero gating, zero LLM, zero I/O, no now(). It NEVER decides
anything; it only describes a decision the deterministic core already made. It is
assembled at render / announce time and is NEVER appended to the hashed run-log
JSONL, so the sealed run-log shas and byte-identical replay are untouched.

Coverage is enforced by tests/test_rationale.py: every Event in the protocol
state machine and every decision kind has a template, so a new gate cannot ship
without a rationale.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from warden.diff import Conflict
from warden.replay import _canon
from warden.state_machine import Event, Rejection, Transition


@dataclass(frozen=True)
class RuleTemplate:
    """A static rule: its id and the plain-English template the rationale fills.

    The template names the exact ingredient slots it consumes; explain() fills
    them with the driving fact values and never invents text beyond them.
    """

    rule_id: str
    template: str


@dataclass(frozen=True)
class DecisionRationale:
    """The typed, deterministic explanation of one Warden decision.

    rule_id    the governing rule (see RULES).
    plain_why  the single plain-English sentence(s), naming the exact driving
               fact. The ONE string the room post, the packet, and the web read.
    decided_by the determinism class of THIS decision (see DECIDED_BY): whether a
               fixed Warden rule decided it with no AI judgment
               (deterministic_rule), an LLM drafted the content that a fixed rule
               then checked (llm_content_with_deterministic_check), or it is LLM
               content only (llm_content). It is a STATIC property of the decision
               kind, never inferred at runtime, so the chip never lies.
    """

    kind: str
    rule_id: str
    plain_why: str
    decided_by: str = ""


# ---------------------------------------------------------------------------
# The static rule catalog: rule-id -> plain-English template. One entry per
# decision the Warden narrates. The {slots} are filled by explain() from the
# already-produced decision; the words around them are fixed.
# ---------------------------------------------------------------------------
RULES: dict[str, RuleTemplate] = {
    # The Warden recorded a drafter's filing (FACT_RECORD_POSTED ack / DRAFT_POSTED).
    "draft_recorded": RuleTemplate(
        "WARDEN-RULE-DRAFT-RECORDED",
        "Recorded the {regime} filing. Its load-bearing claims are "
        "incident_start {incident_start_utc}, records {records_affected}, "
        "attacker {attacker}, containment {containment}. State advanced to "
        "DRAFT_POSTED.",
    ),
    # The cross-filing contradiction diff passed (DIFF_PASSED on a clean run).
    "diff_green": RuleTemplate(
        "WARDEN-RULE-DIFF-GREEN",
        "Cross-filing contradiction diff is GREEN across {filing_count} filings: "
        "every load-bearing fact agrees. Opening signoff.",
    ),
    # The cross-filing contradiction diff blocked (DIFF_BLOCKED on a conflict).
    "diff_blocked": RuleTemplate(
        "WARDEN-RULE-CONTRADICTION-VETO",
        "BLOCKED on a cross-filing contradiction: {branch_a} says "
        "{field}={value_a} while {branch_b} says {field}={value_b}. No signoff "
        "until these agree.",
    ),
    # A blocked contradiction was resolved and the diff re-ran green (DIFF_PASSED).
    "diff_resolved": RuleTemplate(
        "WARDEN-RULE-DIFF-RESOLVED",
        "Resolved: {fixed_branch} re-filed {corrected_field} {to_value}. The "
        "diff re-ran GREEN across {filing_count} filings. Opening signoff.",
    ),
    # The first of the two-key human release (one key present).
    "release_key1": RuleTemplate(
        "WARDEN-RULE-TWO-KEY-FIRST",
        "{actor} ({role}) signed {branch_list}: the first of two release keys on "
        "each. Awaiting the second key before release.",
    ),
    # The second of the two-key human release (both keys present, RELEASED).
    "release_key2": RuleTemplate(
        "WARDEN-RULE-TWO-KEY-SECOND",
        "{actor} ({role}) signed {branch_list}: both keys present on all "
        "{branch_count}. RELEASED, clocks stopped.",
    ),
    # Exactly-once: a redelivered duplicate filing was dropped by the ledger.
    "dedup_dropped": RuleTemplate(
        "WARDEN-RULE-EXACTLY-ONCE",
        "Duplicate {regime} filing dropped by the idempotency ledger "
        "({disposition}). Exactly-once held; no double-file.",
    ),
    # Liveness: the watchdog declared a stalled drafter offline.
    "liveness_dead": RuleTemplate(
        "WARDEN-RULE-LIVENESS-DEAD",
        "{regime} Drafter missed its heartbeat (no progress for "
        "{latency_ticks} logical drain cycle(s), past the {threshold_ticks}-cycle "
        "liveness threshold). Declaring it offline; awaiting redelivery and "
        "recovery.",
    ),
    # Liveness: the declared-dead drafter recovered with no double-file.
    "liveness_recovered": RuleTemplate(
        "WARDEN-RULE-LIVENESS-RECOVERED",
        "{regime} Drafter recovered: its work was already recorded, the "
        "redelivered duplicate was dropped, no double-file. Exactly-once held "
        "across the declared-dead window.",
    ),
    # The negotiation guard blocked an amendment before a concur envelope exists.
    "amend_blocked": RuleTemplate(
        "WARDEN-RULE-AMEND-GUARD",
        "AMENDMENT BLOCKED: {fact_key} revised {old_value} to {new_value}. No "
        "re-release until {branch_list} concur on one shared figure. {guard_reason}",
    ),
}


# Which RULES entry governs each protocol Event. Every Event that the Warden
# narrates in the room maps to a rule; the enforced coverage test reads this so a
# new Event cannot ship without a governing rule.
EVENT_RULE: dict[Event, str] = {
    Event.FACT_RECORD_POSTED: "draft_recorded",
    Event.DRAFT_STARTED: "draft_recorded",
    Event.DRAFT_POSTED: "draft_recorded",
    Event.DIFF_PASSED: "diff_green",
    Event.DIFF_BLOCKED: "diff_blocked",
    Event.SIGNOFF_OPENED: "release_key1",
    Event.HUMAN_RELEASED: "release_key2",
    Event.SUPPRESS: "diff_blocked",
    Event.CLOCK_BREACHED: "liveness_dead",
    Event.FACT_AMENDED: "amend_blocked",
}


# ---------------------------------------------------------------------------
# The determinism class of each decision kind (E9.2 determinism chip). It is a
# STATIC property of the rule, decided here once, NEVER inferred from runtime
# data, so the chip can never overstate or understate how a decision was made:
#
#   deterministic_rule                    a fixed Warden rule decided it with zero
#                                         AI judgment (the diff, the two-key gate,
#                                         the dedup ledger, the liveness watchdog,
#                                         the amendment guard). These gate, block,
#                                         release, count, or clock.
#   llm_content_with_deterministic_check  an LLM drafted the content, then a fixed
#                                         rule checked it (a filing the diff then
#                                         compares; a resolution the diff re-runs).
#   llm_content                           LLM content only, gating nothing.
#
# Every kind in RULES has an entry; the coverage audit (scripts/explain_audit.py)
# and tests/test_rationale.py both assert this map is total, so a new gate cannot
# ship without declaring how it was decided.
DECIDED_BY: dict[str, str] = {
    "draft_recorded": "llm_content_with_deterministic_check",
    "diff_green": "deterministic_rule",
    "diff_blocked": "deterministic_rule",
    "diff_resolved": "llm_content_with_deterministic_check",
    "release_key1": "deterministic_rule",
    "release_key2": "deterministic_rule",
    "dedup_dropped": "deterministic_rule",
    "liveness_dead": "deterministic_rule",
    "liveness_recovered": "deterministic_rule",
    "amend_blocked": "deterministic_rule",
}


# The short human label each determinism class renders as, in the packet chip and
# the web chip (the SAME bytes, so the badge reads identically in both surfaces).
DECIDED_BY_LABEL: dict[str, str] = {
    "deterministic_rule": "fixed rule (no AI judgment)",
    "llm_content_with_deterministic_check": "AI drafted, fixed rule checked",
    "llm_content": "AI content (gates nothing)",
}


# Which protocol Events a decision kind RESTS ON. The provenance trail (E9.2)
# binds each explanation to the exact run-log entries (the admitted state-machine
# transitions for these events) by content hash, so a reader sees which input
# entries the rationale was computed from. A kind with no driving transition
# event (none here) resolves to an empty evidence list.
EVIDENCE_EVENTS: dict[str, tuple[Event, ...]] = {
    "draft_recorded": (Event.DRAFT_POSTED,),
    "diff_green": (Event.DIFF_PASSED,),
    "diff_blocked": (Event.DIFF_BLOCKED,),
    "diff_resolved": (Event.DIFF_PASSED,),
    "release_key1": (Event.SIGNOFF_OPENED,),
    "release_key2": (Event.HUMAN_RELEASED,),
    "dedup_dropped": (Event.DRAFT_POSTED,),
    "liveness_dead": (Event.CLOCK_BREACHED,),
    "liveness_recovered": (Event.DRAFT_POSTED,),
    "amend_blocked": (Event.FACT_AMENDED,),
}


def entry_content_hash(transition: dict) -> str:
    """The content hash of ONE run-log protocol-event entry, bound to the exact
    input entry by content. A run-log protocol_event payload is byte-identical to
    a packet state_transition row (same fields), so this hash is the SAME whether
    computed from the packet here or from the bundled run-log entries in the
    browser. It uses the SAME canonicalizer the hash chain uses (warden.replay
    _canon), read-only: it reads the entry, it never writes one and never re-keys
    the chain."""
    return hashlib.sha256(_canon(transition).encode()).hexdigest()


def evidence_entry_hashes(packet: dict, kind: str) -> list[str]:
    """The per-entry content hashes of the run-log entries decision `kind` rests
    on, resolved READ-ONLY from the packet's admitted state-machine transitions
    for the kind's driving events. Deterministic and order-preserving; returns []
    when the kind has no driving transition in this run."""
    events = {e.value for e in EVIDENCE_EVENTS.get(kind, ())}
    if not events:
        return []
    out: list[str] = []
    for t in packet.get("state_transitions", []) or []:
        if t.get("admitted") and t.get("event") in events:
            out.append(entry_content_hash(t))
    return out


def _fmt(value: object) -> str:
    """Render a driving fact value the way the room and the packet both show it:
    integers grouped with thousands separators, everything else verbatim."""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


# ---------------------------------------------------------------------------
# explain(): the single entry point. It takes ONE already-produced decision
# (a Transition / Rejection, a Conflict, or a small typed payload carrying the
# driving facts) and returns the typed DecisionRationale. It fills the governing
# template with the exact driving fact value and never invents text.
# ---------------------------------------------------------------------------
def explain(decision: object) -> DecisionRationale:
    if isinstance(decision, Conflict):
        return _explain_conflict(decision)
    if isinstance(decision, (Transition, Rejection)):
        return _explain_transition(decision)
    if isinstance(decision, _RationaleDecision):
        return _build(decision.kind, decision.facts)
    raise TypeError(
        f"rationale.explain cannot describe {type(decision).__name__}; pass a "
        "Transition, Rejection, Conflict, or a decision built by this module's "
        "constructors")


@dataclass(frozen=True)
class _RationaleDecision:
    """A typed carrier for decisions that are not a single Transition/Conflict
    (a two-key release, a dedup drop, a liveness verdict, an amendment block).
    Built only by the constructor functions below, never hand-assembled."""

    kind: str
    facts: dict


def _build(kind: str, facts: dict) -> DecisionRationale:
    rule = RULES[kind]
    safe = {k: _fmt(v) for k, v in facts.items()}
    return DecisionRationale(
        kind, rule.rule_id, rule.template.format(**safe),
        decided_by=DECIDED_BY[kind])


def _explain_conflict(c: Conflict) -> DecisionRationale:
    return _build("diff_blocked", {
        "field": c.field,
        "branch_a": c.branch_a.upper(),
        "value_a": c.value_a,
        "branch_b": c.branch_b.upper(),
        "value_b": c.value_b,
    })


def _explain_transition(t: Transition | Rejection) -> DecisionRationale:
    kind = EVENT_RULE[t.event]
    # A Transition / Rejection alone names the event and branch; the driving fact
    # values for the richer rules (claims, conflict, release keys) are carried in
    # its meta. explain() pulls them straight from there, naming the exact value.
    meta = dict(getattr(t, "meta", {}) or {})
    return _build(kind, meta)


# ---------------------------------------------------------------------------
# Constructor functions: the call sites build a decision through these so the
# driving fact values are named once, here, and flow identically into the room
# post, the packet, and the web copy.
# ---------------------------------------------------------------------------
def draft_recorded(regime: str, claims: dict) -> DecisionRationale:
    return explain(_RationaleDecision("draft_recorded", {
        "regime": regime,
        "incident_start_utc": claims["incident_start_utc"],
        "records_affected": claims["records_affected"],
        "attacker": claims["attacker"],
        "containment": claims["containment"],
    }))


def diff_green(filing_count: int) -> DecisionRationale:
    return explain(_RationaleDecision("diff_green", {"filing_count": filing_count}))


def diff_blocked(conflict: Conflict) -> DecisionRationale:
    return explain(conflict)


def diff_resolved(fixed_branch: str, corrected_field: str, to_value: object,
                  filing_count: int) -> DecisionRationale:
    return explain(_RationaleDecision("diff_resolved", {
        "fixed_branch": fixed_branch.upper(),
        "corrected_field": corrected_field,
        "to_value": to_value,
        "filing_count": filing_count,
    }))


def release_key1(actor: str, role: str, branch_list: str) -> DecisionRationale:
    return explain(_RationaleDecision("release_key1", {
        "actor": actor.upper(), "role": role, "branch_list": branch_list,
    }))


def release_key2(actor: str, role: str, branch_list: str,
                 branch_count: int) -> DecisionRationale:
    return explain(_RationaleDecision("release_key2", {
        "actor": actor.upper(), "role": role, "branch_list": branch_list,
        "branch_count": branch_count,
    }))


def dedup_dropped(regime: str, disposition: str) -> DecisionRationale:
    return explain(_RationaleDecision("dedup_dropped", {
        "regime": regime, "disposition": disposition,
    }))


def liveness_dead(regime: str, latency_ticks: int,
                  threshold_ticks: int) -> DecisionRationale:
    return explain(_RationaleDecision("liveness_dead", {
        "regime": regime, "latency_ticks": latency_ticks,
        "threshold_ticks": threshold_ticks,
    }))


def liveness_recovered(regime: str) -> DecisionRationale:
    return explain(_RationaleDecision("liveness_recovered", {"regime": regime}))


def amend_blocked(fact_key: str, old_value: object, new_value: object,
                  branch_list: str, guard_reason: str) -> DecisionRationale:
    return explain(_RationaleDecision("amend_blocked", {
        "fact_key": fact_key, "old_value": old_value, "new_value": new_value,
        "branch_list": branch_list, "guard_reason": guard_reason,
    }))


# ---------------------------------------------------------------------------
# rationale_record(): the packet-side derive. Built at packet-ASSEMBLY time from
# the already-assembled packet (its state_transitions + its diff), it produces a
# per-decision-kind map of {rule_id, plain_why} that the packet renders and the
# web reads. Pure read over the packet; NEVER written to the hashed run-log.
# ---------------------------------------------------------------------------
def rationale_record(packet: dict) -> dict:
    """Derive the decision-rationale ledger for the assembled packet. Keyed by
    decision kind; each value is {"rule_id", "plain_why"}. The block / amend
    entries are the single source the web's gate panel reads, so the web copy and
    the packet copy are the same bytes."""
    transitions = packet.get("state_transitions", []) or []
    diff = packet.get("diff", {}) or {}
    out: dict[str, dict] = {}

    def put(r: DecisionRationale) -> None:
        # Each ledger entry carries the governing rule, the one plain-English
        # why, the determinism chip (decided_by), and the provenance trail
        # (evidence_entry_hashes binding the explanation to the exact input
        # run-log entries by content hash). All four are derived READ-ONLY at
        # packet-assembly time; none is appended to the hashed run-log.
        out[r.kind] = {
            "rule_id": r.rule_id,
            "plain_why": r.plain_why,
            "decided_by": r.decided_by or DECIDED_BY.get(r.kind, ""),
            "decided_by_label": DECIDED_BY_LABEL.get(
                r.decided_by or DECIDED_BY.get(r.kind, ""), ""),
            "evidence_entry_hashes": evidence_entry_hashes(packet, r.kind),
        }

    drafted = [b for b in (diff.get("final_claims") or {})]
    filing_count = len(drafted) if drafted else sum(
        1 for t in transitions
        if t.get("event") == "draft_posted" and t.get("admitted"))

    blocked = diff.get("blocked_conflicts") or diff.get("conflicts") or []
    if blocked:
        # The blocked_conflicts list carries the human-rendered conflict; the
        # exact driving values are in the packet's pre-reconciliation diff. We
        # rebuild the rationale from the first conflict's parsed parts so the
        # block rationale names the exact field and the two disagreeing values.
        c = _parse_human_conflict(blocked[0])
        if c is not None:
            put(diff_blocked(c))
        resolution = diff.get("resolution")
        if resolution:
            put(diff_resolved(
                resolution.get("fixed_branch", ""),
                resolution.get("corrected_field", ""),
                resolution.get("to_value", ""),
                filing_count))
    else:
        if filing_count:
            put(diff_green(filing_count))

    rec = packet.get("reconciliation") or {}
    if rec and rec.get("blocked_before_reconciliation"):
        reopened = rec.get("reopened_branches") or []
        branch_list = " and ".join(b.upper() for b in reopened) or "the reopened branches"
        put(amend_blocked(
            rec.get("fact_key", ""), rec.get("old_value", ""),
            rec.get("new_value", ""), branch_list, rec.get("block_reason", "")))
    return out


def _parse_human_conflict(human: str) -> Conflict | None:
    """Rebuild a Conflict from its Conflict.human() rendering so the packet-side
    rationale names the exact field and the two values. The human form is
    'A says field=va; B says field=vb. Submission blocked.' Returns None if the
    string does not match (defensive; the renderer falls back gracefully)."""
    try:
        head = human.split(". Submission blocked.")[0]
        left, right = head.split("; ", 1)
        ba, rest_a = left.split(" says ", 1)
        field_a, value_a = rest_a.split("=", 1)
        bb, rest_b = right.split(" says ", 1)
        field_b, value_b = rest_b.split("=", 1)
    except ValueError:
        return None
    if field_a != field_b:
        return None
    return Conflict(field_a, ba.lower(), value_a, bb.lower(), value_b)
