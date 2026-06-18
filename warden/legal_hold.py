"""Legal-hold / preservation obligation: the typed, validatable record of the
duty to PRESERVE evidence that attaches the instant a breach is reasonably
anticipated to lead to litigation or a regulatory inquiry.

The moment this war room convenes, a litigation-hold / preservation duty
attaches: the entity must preserve the relevant evidence and SUSPEND routine
deletion over the affected systems and data. Failure to issue the hold is
independent spoliation liability, sanctionable under FRCP 37(e), entirely
separate from the breach itself. A breach-response system that races notification
clocks but never issues or tracks the litigation hold is missing an obligation
that has sunk real companies (the spoliation rulings counsel cites). So the room
raises the hold AS a tracked obligation at incident detection, scoped from the
canonical fact-record, recorded with its trigger time and its preservation basis.

This module is the deterministic Warden side. It owns:

  * the typed record shape: the `trigger_event` (incident detection) and its
    `attached_at` timestamp, the preservation `scope` (a list of typed
    PreservationScopeItems, each naming the EXACT canonical fact-record FIELD it
    rests on, so no scope item is free-text; the affected systems and data
    categories are the preservation scope), the `basis` (the FRCP 37(e)
    spoliation / preservation duty), the STATE (active until released), and the
    RELEASE record (set only by an explicit human signoff, never auto-set);
  * a PURE validator (`validate_legal_hold`) that checks every scope item's cited
    field EXISTS in the fact-record, exactly like the determination validator
    (warden/determination.py::validate_determination). It is a SCORER / RECORDER,
    never a gate: nothing here blocks a filing, moves a transition, stops a
    statutory clock, or releases a filing. The hold is a PARALLEL preservation
    obligation; it never gates the breach-notification track.

No LLM call happens here, and none happens anywhere in the hold lifecycle: the
hold ATTACHES by rule at incident detection, and RELEASES only when a human signs
off. The scope->fact binding, the record shape, and this validation are
deterministic Python, so the record is hash-chained, replayed, and signed
byte-identically like every other run-log event.
"""

from __future__ import annotations

from dataclasses import dataclass

# The fixed legal basis the hold rests on: the duty to preserve evidence once
# litigation is reasonably anticipated, and the spoliation exposure of failing it.
# This is a statement of the obligation, not an LLM judgment; it is the same for
# every incident this room handles.
PRESERVATION_BASIS = (
    "Litigation reasonably anticipated on breach detection: the duty to preserve "
    "relevant evidence attaches and routine deletion over the affected systems "
    "and data must be suspended. Failure to issue the hold is independent "
    "spoliation liability under FRCP 37(e)."
)

# The two states a hold can be in. It attaches ACTIVE and stays ACTIVE until an
# explicit human release moves it to RELEASED. There is no auto-release state: a
# hold is never lifted by a clock, a filing, or any rule.
STATE_ACTIVE = "active"
STATE_RELEASED = "released"


@dataclass(frozen=True)
class PreservationScopeItem:
    """One item in the preservation scope, bound to a load-bearing fact.

    `category` names what is preserved ("Affected systems", "Affected data
    categories"). `value` is the scope value rendered as a string for the record
    (e.g. "core banking ledger, customer KYC store"). `fact_field` is the EXACT
    canonical fact-record key the item rests on (e.g. "systems"): the binding that
    makes the scope grounded rather than free-text, exactly like a determination
    factor binds to a fact field. The affected systems and data categories ARE the
    preservation scope, read straight off the canonical record."""
    category: str
    value: str
    fact_field: str

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "value": self.value,
            "fact_field": self.fact_field,
        }


@dataclass(frozen=True)
class LegalHoldRelease:
    """The record of a human releasing the hold.

    A hold is RELEASED only when a human (counsel) explicitly signs off; it is
    never auto-released by a rule, a clock, or a filing. `released_by` is the human
    role that lifted the hold (e.g. "general_counsel"), `actor` the named signer,
    `ts` the release timestamp, and `reason` the human's recorded basis for lifting
    it. The presence of this record is the ONLY thing that moves a hold out of the
    active state."""
    released_by: str
    actor: str
    ts: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "released_by": self.released_by,
            "actor": self.actor,
            "ts": self.ts,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class LegalHold:
    """The typed legal-hold / preservation obligation for one incident.

    `incident_id` identifies the incident. `trigger_event` names the event the
    hold attaches on (incident detection); `attached_at` is the timestamp it
    attached, anchored at the incident-detection moment (INCIDENT_T0). `scope` is
    the ordered preservation scope, each item bound to a canonical fact-record
    field (the affected systems and data categories). `basis` is the fixed
    preservation / spoliation duty. `release` is None while the hold is ACTIVE and
    carries the human release record once a human has signed off; the `state`
    property derives active/released from it, so the state is never set
    independently of the release record. A hold is never auto-released: only an
    explicit human release record moves it to released."""
    incident_id: str
    trigger_event: str
    attached_at: str
    scope: tuple[PreservationScopeItem, ...]
    basis: str = PRESERVATION_BASIS
    release: LegalHoldRelease | None = None

    @property
    def state(self) -> str:
        """ACTIVE until an explicit human release record is present, then
        RELEASED. Derived from the release record, never set independently, so a
        hold can only be released by recording a human signoff."""
        return STATE_RELEASED if self.release is not None else STATE_ACTIVE

    @property
    def active(self) -> bool:
        return self.release is None

    def cited_fields(self) -> list[str]:
        """The canonical fact-record fields every scope item binds to, in order."""
        return [item.fact_field for item in self.scope]

    def released_hold(self, *, released_by: str, actor: str, ts: str,
                      reason: str) -> "LegalHold":
        """Return a new hold carrying the human release record (the dataclass is
        frozen, so release is a pure transition to a new value, never a mutation).

        Raises if the hold is already released, so a double-release is structural
        rather than silently overwriting the original release record."""
        if self.release is not None:
            raise LegalHoldAlreadyReleased(
                f"legal hold for {self.incident_id} is already released by "
                f"{self.release.actor} ({self.release.released_by}) at "
                f"{self.release.ts}; it cannot be released twice.")
        return LegalHold(
            incident_id=self.incident_id,
            trigger_event=self.trigger_event,
            attached_at=self.attached_at,
            scope=self.scope,
            basis=self.basis,
            release=LegalHoldRelease(
                released_by=released_by, actor=actor, ts=ts, reason=reason),
        )

    def as_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "trigger_event": self.trigger_event,
            "attached_at": self.attached_at,
            "state": self.state,
            "active": self.active,
            "basis": self.basis,
            "scope": [item.as_dict() for item in self.scope],
            "release": self.release.as_dict() if self.release is not None else None,
        }


class LegalHoldAlreadyReleased(RuntimeError):
    """A second release was attempted on an already-released hold.

    Raised instead of silently overwriting the original human release record,
    which would lose the contemporaneous account of who first lifted the hold and
    when. A hold releases once, by a human, and that record stands."""


@dataclass(frozen=True)
class PreservationScopeCheck:
    """The validation verdict over a legal hold's preservation scope.

    `complete` is True iff every scope item binds to a field the fact-record
    actually carries (no fabricated scope item). `missing_items` lists, in order,
    the (category, cited field) pairs whose cited field does not exist in the
    fact-record. This is a RECORDER's verdict, never a gate: a scope item citing a
    missing field is flagged in the packet, it does not block, release, or change
    any filing decision."""
    incident_id: str
    complete: bool
    cited_fields: tuple[str, ...]
    missing_items: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "complete": self.complete,
            "cited_fields": list(self.cited_fields),
            "missing_items": [
                {"category": category, "fact_field": fieldname}
                for category, fieldname in self.missing_items
            ],
        }


def validate_legal_hold(hold: LegalHold, fact_record: dict) -> PreservationScopeCheck:
    """Pure validator: does every preservation scope item cite a field the
    fact-record actually carries?

    Deterministic and side-effect free, exactly like
    warden/determination.validate_determination: same (hold, fact_record) always
    yields the same PreservationScopeCheck. It is a SCORER / RECORDER only. Nothing
    here gates, blocks a filing, moves a transition, stops a statutory clock, or
    releases anything: it reads a hold that was already attached and reports
    whether each scope item is grounded in a real fact-record field. A scope item
    whose cited fact_field is absent from the fact-record is a fabricated scope
    item and is reported in `missing_items`; it is never silently dropped and it
    never changes the file/suppress decision of any branch."""
    keys = set(fact_record.keys())
    cited: list[str] = []
    missing: list[tuple[str, str]] = []
    for item in hold.scope:
        cited.append(item.fact_field)
        if item.fact_field not in keys:
            missing.append((item.category, item.fact_field))
    return PreservationScopeCheck(
        incident_id=hold.incident_id,
        complete=not missing,
        cited_fields=tuple(cited),
        missing_items=tuple(missing),
    )
