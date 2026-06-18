"""The separation-of-duties MATRIX, proven across the WHOLE run (E4.5).

The two-key release gate (warden/release_gate.py) proves segregation of duties on
ONE action: a filing cannot release without two DISTINCT human keys. An auditor's
SoD question is broader. They want a MATRIX: which identity performed which protocol
actions across the entire run, and proof that NO single identity ever spanned a pair
of duties that must stay separated (author a filing AND release it; gate a filing AND
author it). The data to prove it is already in the run: every state-machine transition
carries an actor and an actor_role, and every two-key release records its (actor, role)
keys. This module turns those events into the actor x action matrix and ASSERTS the
segregation invariants hold on every path.

What it is, precisely:

  A PURE DERIVED render over the assembled packet. From packet["state_transitions"]
  (each carries actor + actor_role + the admitted event) and packet["release"]
  ["signoffs"] (the two-key release records) it builds:

    - the observed (actor, role, actions[]) set: per identity, the role it acted as
      and every protocol action it performed in this run; and

    - a list of named SoD invariants, each PASS / FAIL with the exact evidence events
      that prove or break it. The invariants are:

        SOD-M1  the two release keys are DISTINCT roles AND distinct actors per branch
                (general_counsel vs head_of_ir; gc vs lena). The two-key gate's promise,
                re-proven from the recorded keys across every released branch.
        SOD-M2  no single actor both AUTHORED a filing (draft_started / draft_posted)
                and RELEASED it (signed a release key). Drafting and releasing are
                segregated identities.
        SOD-M3  the gatekeeper (the Warden) never AUTHORED a filing it then gated. The
                identity that runs the diff / opens signoff / clocks never appears as a
                drafter author.
        SOD-M4  the human release roles (general_counsel, head_of_ir) are DISJOINT from
                the drafter roles. No role both drafts and releases.

  The role model is EVENT_AUTHORITY (warden/state_machine.py): the authoritative map of
  which role class may emit which event. The action->duty classification (author / gate
  / release / triage) is derived from that same authority table, so the matrix speaks
  the Warden's own role vocabulary rather than a parallel one.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The same
  packet always derives the byte-identical matrix. It reads the packet dict only; it
  never enters the hashed run-log, never gates a Warden transition, never clocks or
  counts anything inside the core. It is an auditor-side READ over the Warden's output,
  exactly like the control-evidence register (E4.4) and the consistency sheet (E4.3).

  CRITICAL (no green-wash): the matrix is the real check, not a decoration. If a run
  surfaces a genuine SoD violation (one actor on both sides of a conflicting duty), the
  invariant is FAIL and names the violating actor and the evidence events. The system
  enforces two distinct keys at release, so on a real capture it holds; the cross-run
  matrix is the independent proof that it holds everywhere, not only at the gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from warden.state_machine import EVENT_AUTHORITY, Event

# The two distinct release-key roles, mirrored from warden/release_gate.REQUIRED_ROLES.
# Stated here as a literal so the matrix asserts its own segregation contract and does
# not depend on importing the live gate that produced the run.
RELEASE_ROLES: frozenset[str] = frozenset({"head_of_ir", "general_counsel"})

# The role class that AUTHORS a filing's content (a drafter), named so the author duty
# is anchored to the Warden's own role vocabulary rather than a parallel one.
AUTHOR_ROLE: str = "drafter"

# The protocol events that AUTHOR a filing's content: exactly the events the Warden's
# authority table (EVENT_AUTHORITY) grants to the `drafter` role class. Derived from
# that table rather than hardcoded, so the author duty is defined by the Warden's own
# authority model and stays in lockstep if the table changes (draft_started,
# draft_posted today).
AUTHOR_EVENTS: frozenset[str] = frozenset(
    event.value for event, roles in EVENT_AUTHORITY.items()
    if AUTHOR_ROLE in roles)

# The protocol event that releases a filing: the human-release transition. A human
# owner/admin emits it; the two-key gate records the keys that backed it.
RELEASE_EVENT: str = Event.HUMAN_RELEASED.value

# The four duty classes the matrix segregates, named so the matrix and the receipt
# branch on the code rather than a free string.
DUTY_AUTHOR = "author"        # draft a filing's content (drafter)
DUTY_GATE = "gate"            # run the diff, open signoff, clock (the Warden gatekeeper)
DUTY_RELEASE = "release"      # sign a two-key release (a human release key)
DUTY_TRIAGE = "triage"        # post / amend the canonical fact-record (triage)

# The two invariant dispositions.
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"


def _duty_for_role(role: str) -> str:
    """Map an actor_role to the duty class it performs, using the SAME role vocabulary
    EVENT_AUTHORITY defines. The Warden's gatekeeper events (diff, signoff, clock) are
    authored by the `warden` role; the drafter role authors filings; the human
    owner/admin roles release; triage owns the fact-record. An unrecognized role is
    classed as its own raw role string so it still surfaces in the matrix rather than
    being silently dropped."""
    if role == "drafter":
        return DUTY_AUTHOR
    if role == "warden":
        return DUTY_GATE
    if role in ("human_owner", "human_admin") or role in RELEASE_ROLES:
        return DUTY_RELEASE
    if role == "triage":
        return DUTY_TRIAGE
    return role


@dataclass(frozen=True)
class ActorActions:
    """One identity's row in the matrix: the actor, the role(s) it acted as, the duty
    class(es) those roles constitute, and every admitted protocol action it performed.

    actor    the identity string (e.g. "nis2_drafter", "gc", "lena", "warden").
    roles    the actor_role(s) the run shows this identity acting under, sorted.
    duties   the duty class(es) those roles map to (author / gate / release / triage),
             sorted. An identity that ever spans two conflicting duties is the SoD
             violation the invariants catch.
    actions  the admitted protocol event(s) this identity performed, sorted, deduped.
    """
    actor: str
    roles: tuple[str, ...]
    duties: tuple[str, ...]
    actions: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "actor": self.actor,
            "roles": list(self.roles),
            "duties": list(self.duties),
            "actions": list(self.actions),
        }


@dataclass(frozen=True)
class SodInvariant:
    """One named SoD invariant's verdict: a stable id, a one-line statement of what it
    proves, PASS / FAIL, a human-readable detail, and the evidence events that prove or
    break it.

    id         the stable invariant id (e.g. "SOD-M1").
    title      the segregation property it asserts, in one line.
    status     STATUS_PASS / STATUS_FAIL.
    detail     the basis: on PASS, what held; on FAIL, the violating actor and what was
               spanned.
    evidence   the concrete events / records that back the verdict (each a small dict
               naming the actor, the duty, and the action), so an auditor can trace the
               verdict to the run.
    """
    id: str
    title: str
    status: str
    detail: str
    evidence: tuple[dict, ...]

    @property
    def passed(self) -> bool:
        return self.status == STATUS_PASS

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "passed": self.passed,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class SeparationOfDutiesMatrix:
    """The separation-of-duties matrix over one run: the observed actor x action set
    plus the named SoD invariants, each PASS / FAIL with evidence.

    actors      one ActorActions row per identity that acted in the run, sorted by
                actor.
    invariants  the named SoD invariants (SOD-M1..SOD-M4), in id order.
    """
    actors: tuple[ActorActions, ...]
    invariants: tuple[SodInvariant, ...]

    @property
    def total_invariants(self) -> int:
        return len(self.invariants)

    @property
    def passed_count(self) -> int:
        return sum(1 for inv in self.invariants if inv.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for inv in self.invariants if not inv.passed)

    @property
    def all_hold(self) -> bool:
        """Every invariant holds AND there was at least one invariant to check. A run
        that exercised no release / no draft proves nothing, so all_hold is False when
        there are no invariants (the verdict says so)."""
        return self.total_invariants > 0 and self.failed_count == 0

    @property
    def verdict(self) -> str:
        """The one-line verdict an audit committee reads first."""
        if self.total_invariants == 0:
            return ("NOT PROVEN: this run exercised no separation-of-duties path "
                    "(no release, no draft to segregate)")
        if self.all_hold:
            return (f"SEGREGATED: all {self.total_invariants} separation-of-duties "
                    f"invariants hold across the whole run; no identity spanned a "
                    f"conflicting pair of duties")
        return (f"VIOLATION: {self.failed_count} of {self.total_invariants} "
                f"separation-of-duties invariant"
                f"{'' if self.failed_count == 1 else 's'} FAILED; an identity spanned "
                f"a conflicting pair of duties (see the failing row)")

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet. Stable key order so the
        packet render and any guard see identical bytes."""
        return {
            "total_invariants": self.total_invariants,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "all_hold": self.all_hold,
            "verdict": self.verdict,
            "actors": [a.as_dict() for a in self.actors],
            "invariants": [inv.as_dict() for inv in self.invariants],
        }


def _admitted_transitions(packet: dict) -> list[dict]:
    """The admitted state-machine transitions this run produced, each carrying actor,
    actor_role, and event. Only ADMITTED transitions are real actions an identity
    performed; a rejected (illegal) transition never executed, so it is not an action
    in the matrix. Pure read; never mutates."""
    out: list[dict] = []
    for t in packet.get("state_transitions", []) or []:
        if not t.get("admitted", False):
            continue
        actor = str(t.get("actor", "") or "")
        role = str(t.get("actor_role", "") or "")
        event = str(t.get("event", "") or "")
        if not actor or not event:
            continue
        out.append({"actor": actor, "role": role, "event": event,
                    "correlation_id": str(t.get("correlation_id", "") or "")})
    return out


def _release_signoffs(packet: dict) -> list[dict]:
    """The two-key release records this run produced, each a (correlation_id, role,
    actor) key. These are the recorded release keys the two-key gate collected; they
    are the RELEASE duty's authoritative evidence (the human_released transition itself
    is fired by one of the two keys, but the keys are recorded here)."""
    out: list[dict] = []
    release = packet.get("release", {}) or {}
    for s in release.get("signoffs", []) or []:
        actor = str(s.get("actor", "") or "")
        role = str(s.get("role", "") or "")
        if not actor or not role:
            continue
        out.append({"actor": actor, "role": role,
                    "correlation_id": str(s.get("correlation_id", "") or "")})
    return out


def _build_actor_rows(transitions: list[dict],
                      signoffs: list[dict]) -> tuple[ActorActions, ...]:
    """Collapse the admitted transitions and the release signoffs into one
    (actor -> roles, duties, actions) row per identity. A release signoff contributes
    the RELEASE duty and the release role to its actor (the human_released transition
    contributes the transition actor too; both are folded into the same identity)."""
    roles_by_actor: dict[str, set[str]] = {}
    actions_by_actor: dict[str, set[str]] = {}

    for t in transitions:
        actor = t["actor"]
        roles_by_actor.setdefault(actor, set())
        if t["role"]:
            roles_by_actor[actor].add(t["role"])
        actions_by_actor.setdefault(actor, set()).add(t["event"])

    for s in signoffs:
        actor = s["actor"]
        roles_by_actor.setdefault(actor, set()).add(s["role"])
        # The release action an actor performed: signing the two-key release. Recorded
        # as the human-release event so the action vocabulary stays the protocol's.
        actions_by_actor.setdefault(actor, set()).add("release_signoff")

    rows: list[ActorActions] = []
    for actor in sorted(roles_by_actor):
        roles = tuple(sorted(roles_by_actor[actor]))
        duties = tuple(sorted({_duty_for_role(r) for r in roles}))
        actions = tuple(sorted(actions_by_actor.get(actor, set())))
        rows.append(ActorActions(actor=actor, roles=roles, duties=duties,
                                 actions=actions))
    return tuple(rows)


def _authors(transitions: list[dict]) -> dict[str, set[str]]:
    """actor -> set of branches that actor AUTHORED (fired an author event on)."""
    out: dict[str, set[str]] = {}
    for t in transitions:
        if t["event"] in AUTHOR_EVENTS:
            out.setdefault(t["actor"], set()).add(t["correlation_id"])
    return out


def _check_distinct_release_keys(signoffs: list[dict]) -> SodInvariant:
    """SOD-M1: per released branch, the two recorded release keys are DISTINCT roles
    and distinct actors. Two of the same key never turns the lock; this proves the lock
    actually collected two different identities on every branch it released."""
    keys_by_branch: dict[str, list[dict]] = {}
    for s in signoffs:
        keys_by_branch.setdefault(s["correlation_id"], []).append(s)

    evidence: list[dict] = []
    violations: list[str] = []
    for branch in sorted(keys_by_branch):
        keys = keys_by_branch[branch]
        roles = {k["role"] for k in keys}
        actors = {k["actor"] for k in keys}
        for k in keys:
            evidence.append({"branch": branch, "actor": k["actor"],
                             "role": k["role"], "duty": DUTY_RELEASE})
        # Both required roles present AND mapped to distinct actors.
        if roles != set(RELEASE_ROLES):
            violations.append(
                f"{branch}: keys are roles {sorted(roles)}, not the two required "
                f"{sorted(RELEASE_ROLES)}")
        elif len(actors) < 2:
            violations.append(
                f"{branch}: both keys came from the same actor {sorted(actors)}")

    if not keys_by_branch:
        return SodInvariant(
            "SOD-M1",
            "The two release keys are distinct roles and distinct actors per branch",
            STATUS_PASS,
            "no release was exercised in this run; the distinct-key contract is "
            "vacuously satisfied (no branch released on one key)",
            tuple(evidence))
    if violations:
        return SodInvariant(
            "SOD-M1",
            "The two release keys are distinct roles and distinct actors per branch",
            STATUS_FAIL,
            "a branch released without two distinct keys: " + "; ".join(violations),
            tuple(evidence))
    n = len(keys_by_branch)
    return SodInvariant(
        "SOD-M1",
        "The two release keys are distinct roles and distinct actors per branch",
        STATUS_PASS,
        f"all {n} released branch(es) collected two distinct keys "
        f"(general_counsel + head_of_ir, distinct actors)",
        tuple(evidence))


def _check_no_draft_and_release(transitions: list[dict],
                                signoffs: list[dict]) -> SodInvariant:
    """SOD-M2: no single actor both AUTHORED a filing and RELEASED it. Drafting and
    releasing are segregated identities across the whole run."""
    authored = _authors(transitions)
    releasers = {s["actor"] for s in signoffs}

    evidence: list[dict] = []
    violations: list[str] = []
    for actor in sorted(authored):
        branches = sorted(authored[actor])
        evidence.append({"actor": actor, "duty": DUTY_AUTHOR,
                         "branches": branches})
        if actor in releasers:
            violations.append(
                f"{actor} both authored ({', '.join(branches)}) and signed a release")
    for actor in sorted(releasers):
        evidence.append({"actor": actor, "duty": DUTY_RELEASE,
                         "action": "release_signoff"})

    if not authored or not releasers:
        return SodInvariant(
            "SOD-M2",
            "No single actor both drafted a filing and released it",
            STATUS_PASS,
            "no actor both authored and released in this run (one side of the pair was "
            "not exercised); the segregation holds vacuously",
            tuple(evidence))
    if violations:
        return SodInvariant(
            "SOD-M2",
            "No single actor both drafted a filing and released it",
            STATUS_FAIL,
            "an identity both drafted and released: " + "; ".join(violations),
            tuple(evidence))
    return SodInvariant(
        "SOD-M2",
        "No single actor both drafted a filing and released it",
        STATUS_PASS,
        f"the {len(authored)} drafter identit(y/ies) and the "
        f"{len(releasers)} release-key identit(y/ies) are disjoint; no overlap",
        tuple(evidence))


def _check_warden_does_not_author(transitions: list[dict]) -> SodInvariant:
    """SOD-M3: the gatekeeper (the Warden) never AUTHORED a filing it then gated. The
    identity that runs the diff / opens signoff / clocks never appears as a drafter
    author."""
    gatekeepers = {t["actor"] for t in transitions
                   if _duty_for_role(t["role"]) == DUTY_GATE}
    authored = _authors(transitions)

    evidence: list[dict] = []
    for actor in sorted(gatekeepers):
        gate_events = sorted({t["event"] for t in transitions
                              if t["actor"] == actor
                              and _duty_for_role(t["role"]) == DUTY_GATE})
        evidence.append({"actor": actor, "duty": DUTY_GATE,
                         "actions": gate_events})

    violations = sorted(actor for actor in gatekeepers if actor in authored)
    if violations:
        detail_parts = []
        for actor in violations:
            detail_parts.append(
                f"{actor} gated AND authored ({', '.join(sorted(authored[actor]))})")
        return SodInvariant(
            "SOD-M3",
            "The Warden (gatekeeper) never authored a filing it then gated",
            STATUS_FAIL,
            "the gatekeeper authored a filing it gated: " + "; ".join(detail_parts),
            tuple(evidence))
    if not gatekeepers:
        return SodInvariant(
            "SOD-M3",
            "The Warden (gatekeeper) never authored a filing it then gated",
            STATUS_PASS,
            "no gatekeeper action was exercised in this run; the contract holds "
            "vacuously",
            tuple(evidence))
    return SodInvariant(
        "SOD-M3",
        "The Warden (gatekeeper) never authored a filing it then gated",
        STATUS_PASS,
        f"the gatekeeper identit(y/ies) {sorted(gatekeepers)} ran only gate actions; "
        f"none appears as a drafter author",
        tuple(evidence))


def _check_release_roles_disjoint_from_drafter_roles(
        transitions: list[dict], signoffs: list[dict]) -> SodInvariant:
    """SOD-M4: the human release roles (general_counsel, head_of_ir) are DISJOINT from
    the roles that drafted. No role both drafts and releases."""
    drafter_roles = {t["role"] for t in transitions if t["event"] in AUTHOR_EVENTS}
    release_roles = {s["role"] for s in signoffs}

    evidence = [
        {"duty": DUTY_AUTHOR, "roles": sorted(drafter_roles)},
        {"duty": DUTY_RELEASE, "roles": sorted(release_roles)},
    ]
    overlap = sorted(drafter_roles & release_roles)
    if overlap:
        return SodInvariant(
            "SOD-M4",
            "The human release roles are distinct from the drafter roles",
            STATUS_FAIL,
            f"role(s) {overlap} both drafted and released",
            tuple(evidence))
    if not drafter_roles or not release_roles:
        return SodInvariant(
            "SOD-M4",
            "The human release roles are distinct from the drafter roles",
            STATUS_PASS,
            "one side of the role pair was not exercised in this run; the disjointness "
            "holds vacuously",
            tuple(evidence))
    return SodInvariant(
        "SOD-M4",
        "The human release roles are distinct from the drafter roles",
        STATUS_PASS,
        f"drafter role(s) {sorted(drafter_roles)} and release role(s) "
        f"{sorted(release_roles)} do not overlap",
        tuple(evidence))


def matrix_from_packet(packet: dict) -> SeparationOfDutiesMatrix:
    """The separation-of-duties matrix for one assembled packet: the observed actor x
    action set plus the named SoD invariants, each PASS / FAIL with evidence.

    Pure derived: it reads packet["state_transitions"] (the admitted transitions, each
    with actor + actor_role) and packet["release"]["signoffs"] (the two-key release
    records). No LLM, no now(); the same packet derives the byte-identical matrix. It
    never enters the hashed run-log and gates nothing.

    The invariants are the real check: each is computed from the run's events, and a
    genuine SoD violation (an identity spanning a conflicting duty pair) makes its
    invariant FAIL and names the violating actor with the evidence."""
    transitions = _admitted_transitions(packet)
    signoffs = _release_signoffs(packet)

    actors = _build_actor_rows(transitions, signoffs)
    invariants = (
        _check_distinct_release_keys(signoffs),
        _check_no_draft_and_release(transitions, signoffs),
        _check_warden_does_not_author(transitions),
        _check_release_roles_disjoint_from_drafter_roles(transitions, signoffs),
    )
    return SeparationOfDutiesMatrix(actors=actors, invariants=invariants)


def sod_record(packet: dict) -> dict:
    """The packet-ready separation-of-duties matrix block: the actor x action rows plus
    the named SoD invariants and the overall verdict, JSON-serializable.

    Returns {} only when the run produced no admitted transition and no release signoff
    (nothing to build a matrix over), so the renderer can omit the section cleanly. A
    run with any protocol activity yields a full matrix with the invariants asserted.
    No LLM, no now(); the same packet derives the byte-identical block."""
    if not (packet.get("state_transitions") or
            (packet.get("release", {}) or {}).get("signoffs")):
        return {}
    matrix = matrix_from_packet(packet)
    if not matrix.actors and matrix.total_invariants == 0:
        return {}
    return matrix.as_dict()
