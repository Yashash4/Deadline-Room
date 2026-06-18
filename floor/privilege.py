"""Privilege / work-product designation over the war-room record (E4.10).

A breach war-room record is a litigation goldmine for plaintiffs UNLESS it is
structured to support attorney-client privilege and attorney work-product
protection. After Capital One, Wengui / Clark Hill, and Rutter's, courts pierce
privilege when the incident record looks like ordinary business / IR work rather
than counsel-directed legal analysis. The room produces ONE flat record where the
materiality / reportability rationale, the determination memos, the
agent-to-agent negotiation, the legal-hold counsel direction, and the regulator
filings are indistinguishable. A litigator needs each artifact TAGGED by its
nature: privileged legal advice and attorney work-product on one side, the
disclosable filings and the statutory-required content on the other, so counsel
can hand a regulator the disclosable set WITHOUT waiving privilege over the
deliberation.

This module produces that split.

What it is, precisely:

  A PURE DERIVED classification over the assembled packet, keyed ENTIRELY by the
  run-log EVENT TYPE the artifact came from, never an LLM judging privilege. A
  static event-type -> privilege-basis map (the PRIVILEGE_CLASS table below)
  sorts every artifact the run produced into one of four bases:

    privileged_legal      privileged legal advice: the materiality / reportability
                          rationale, the reasonable-basis determination memos, the
                          legal-hold counsel direction, the cross-border human
                          legal resolution.
    work_product          attorney work-product prepared in anticipation of
                          litigation: the internal deliberation, the
                          agent-to-agent reconciliation / negotiation, the
                          adversarial Challenger critique.
    disclosable_filing    the regulator filings themselves, meant to be disclosed.
    non_privileged_regulatory  the statutory-required, non-privileged regulatory
                          content (the completeness / consistency screens, the
                          submission receipts, the deadline attestation).

  The DISCLOSABLE SET is the union of disclosable_filing and
  non_privileged_regulatory; the PRIVILEGED SET is the union of privileged_legal
  and work_product. The split is the whole point: counsel produces the disclosable
  set to a regulator and withholds the privileged set, and the renderer never
  leaks one bucket into the other.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The
  classification is a static lookup on the event type, so the same packet always
  derives the byte-identical designation. It reads the packet dict only; it never
  enters the hashed run-log, never gates a Warden transition, never clocks or
  counts anything inside the core. It is a counsel-side READ over the Warden's
  output, exactly like the control-evidence register (E4.4) and the
  separation-of-duties matrix (E4.5).
"""

from __future__ import annotations

from dataclasses import dataclass

# The four privilege bases, named so the packet and the receipt branch on the code
# rather than a free string.
BASIS_PRIVILEGED_LEGAL = "privileged_legal"
BASIS_WORK_PRODUCT = "work_product"
BASIS_DISCLOSABLE_FILING = "disclosable_filing"
BASIS_NON_PRIVILEGED_REGULATORY = "non_privileged_regulatory"

# The two top-level sets counsel actually hands out (disclosable) or withholds
# (privileged). Each basis rolls up into exactly one set.
SET_DISCLOSABLE = "disclosable"
SET_PRIVILEGED = "privileged"

_SET_FOR_BASIS = {
    BASIS_PRIVILEGED_LEGAL: SET_PRIVILEGED,
    BASIS_WORK_PRODUCT: SET_PRIVILEGED,
    BASIS_DISCLOSABLE_FILING: SET_DISCLOSABLE,
    BASIS_NON_PRIVILEGED_REGULATORY: SET_DISCLOSABLE,
}

# Human labels for each basis, for the rendered designation log.
BASIS_LABEL = {
    BASIS_PRIVILEGED_LEGAL: "Privileged legal advice (attorney-client)",
    BASIS_WORK_PRODUCT: "Attorney work-product (prepared in anticipation of litigation)",
    BASIS_DISCLOSABLE_FILING: "Disclosable regulator filing",
    BASIS_NON_PRIVILEGED_REGULATORY: "Non-privileged statutory / regulatory content",
}

# The work-product / privilege footer banner counsel stamps on the privileged set,
# the standard legend that signals the material was prepared at counsel's direction
# for the purpose of providing legal advice.
PRIVILEGE_BANNER = (
    "PRIVILEGED AND CONFIDENTIAL: ATTORNEY-CLIENT COMMUNICATION / ATTORNEY "
    "WORK-PRODUCT. Prepared at the direction of counsel for the purpose of "
    "providing legal advice in anticipation of litigation. Not for disclosure."
)

# The static event-type -> privilege-basis map. The KEY is the packet/run-log
# event type (or a packet section that mirrors a run-log event); the VALUE is the
# privilege basis. This is the whole classifier: a pure lookup, never a judgment.
# Each artifact a run produces is classified by WHICH event type it came from, so
# the designation is replayable and explainable.
PRIVILEGE_CLASS: dict[str, str] = {
    # Privileged legal advice: the legal JUDGMENT artifacts and counsel direction.
    "materiality": BASIS_PRIVILEGED_LEGAL,
    "reportability": BASIS_PRIVILEGED_LEGAL,
    "determination_record": BASIS_PRIVILEGED_LEGAL,
    "affected_party_high_risk": BASIS_PRIVILEGED_LEGAL,
    "legal_hold_attached": BASIS_PRIVILEGED_LEGAL,
    "legal_hold_released": BASIS_PRIVILEGED_LEGAL,
    "cross_border_resolution": BASIS_PRIVILEGED_LEGAL,
    "lead_authority_routing": BASIS_PRIVILEGED_LEGAL,
    # Attorney work-product: the internal deliberation prepared in anticipation of
    # litigation. The reconciliation / negotiation exchange and the adversarial
    # Challenger critique are the room's work toward a defensible position.
    "reconciliation": BASIS_WORK_PRODUCT,
    "negotiation": BASIS_WORK_PRODUCT,
    "negotiation_guard": BASIS_WORK_PRODUCT,
    "fact_amendment": BASIS_WORK_PRODUCT,
    "adversarial_review": BASIS_WORK_PRODUCT,
    "cross_border_scan": BASIS_WORK_PRODUCT,
    "cross_border_block": BASIS_WORK_PRODUCT,
    # The regulator filings themselves: meant to be disclosed.
    "filings": BASIS_DISCLOSABLE_FILING,
    "submission_receipt": BASIS_DISCLOSABLE_FILING,
    "submission": BASIS_DISCLOSABLE_FILING,
    "edgar_export": BASIS_DISCLOSABLE_FILING,
    # Non-privileged statutory / regulatory content: the structured screens and the
    # timeliness attestation a regulator receives or cross-reads.
    "completeness": BASIS_NON_PRIVILEGED_REGULATORY,
    "consistency": BASIS_NON_PRIVILEGED_REGULATORY,
    "regulator_intake": BASIS_NON_PRIVILEGED_REGULATORY,
    "deficiency": BASIS_NON_PRIVILEGED_REGULATORY,
    "attestation": BASIS_NON_PRIVILEGED_REGULATORY,
}

# How a packet section is described on the designation log, so a reader sees what
# the classified artifact actually is rather than a bare event token. The map is
# read-only; an unmapped present section falls back to its raw key.
_ARTIFACT_DESCRIPTION = {
    "materiality": "SEC materiality assessment and suppression rationale",
    "reportability": "Per-regime reportability / duty-to-notify rationale and memos",
    "determination_record": "Reasonable-basis determination record (factor table)",
    "affected_party_high_risk": "GDPR Art 34 high-risk assessment rationale",
    "legal_hold_attached": "Legal-hold / preservation direction (FRCP 37(e))",
    "legal_hold_released": "Legal-hold release direction (counsel signoff)",
    "cross_border_resolution": "Cross-border obligation-conflict human legal resolution",
    "lead_authority_routing": "GDPR Art 56 lead-authority routing analysis",
    "reconciliation": "Agent-to-agent reconciliation deliberation (amendment exchange)",
    "negotiation": "Amendment-negotiation envelope chain",
    "negotiation_guard": "Amendment-negotiation guard decisions",
    "fact_amendment": "Fact-revision deliberation",
    "adversarial_review": "Adversarial Challenger critique of the filings",
    "cross_border_scan": "Cross-border obligation-conflict internal scan",
    "cross_border_block": "Cross-border obligation-conflict block",
    "filings": "The drafted regulator filings",
    "submission_receipt": "The filed-receipt records from the regulator channel",
    "submission": "The machine-readable submission artifacts",
    "edgar_export": "The EDGAR-shaped Form 8-K Item 1.05 export",
    "completeness": "Submission completeness screen (mandated-field matrix)",
    "consistency": "Cross-filing consistency assertion",
    "regulator_intake": "Modeled-regulator intake reviews",
    "deficiency": "Deficiency-notice / cure roundtrip",
    "attestation": "Deadline-compliance attestation",
}

# Which packet sections carry the classifiable artifacts. A section is "present"
# when the packet actually holds it with content; an absent section produces no
# designation row (the artifact was not part of this run). The submission and the
# legal-hold artifacts are derived from sub-keys, handled in _present_artifacts.
_SECTION_EVENTS = (
    "materiality", "reportability", "affected_party", "reconciliation",
    "adversarial_review", "cross_border", "filings", "submission", "deficiency",
    "completeness", "consistency", "attestation", "edgar_export", "legal_hold",
)


@dataclass(frozen=True)
class PrivilegeItem:
    """One classified artifact on the designation log.

    event        the run-log / packet event type the artifact came from.
    description  a human-readable description of the artifact.
    basis        the privilege basis (one of the four BASIS_* constants).
    privilege_set the top-level set the basis rolls into (disclosable / privileged).
    count        how many records the artifact carries (e.g. the number of filings),
                 for the designation log; 1 for a singleton section.
    """
    event: str
    description: str
    basis: str
    privilege_set: str
    count: int

    @property
    def disclosable(self) -> bool:
        return self.privilege_set == SET_DISCLOSABLE

    def as_dict(self) -> dict:
        return {
            "event": self.event,
            "description": self.description,
            "basis": self.basis,
            "basis_label": BASIS_LABEL.get(self.basis, self.basis),
            "privilege_set": self.privilege_set,
            "count": self.count,
        }


@dataclass(frozen=True)
class PrivilegeDesignation:
    """The full privilege / work-product designation over one run: every classified
    artifact, split into the disclosable set and the privileged set."""
    items: tuple[PrivilegeItem, ...]

    @property
    def disclosable_items(self) -> tuple[PrivilegeItem, ...]:
        return tuple(i for i in self.items if i.disclosable)

    @property
    def privileged_items(self) -> tuple[PrivilegeItem, ...]:
        return tuple(i for i in self.items if not i.disclosable)

    @property
    def verdict(self) -> str:
        """The one-line verdict counsel reads first."""
        d = len(self.disclosable_items)
        p = len(self.privileged_items)
        return (
            f"{len(self.items)} classified artifact(s): {d} in the DISCLOSABLE set "
            f"(filings and statutory content), {p} in the PRIVILEGED set (legal "
            f"advice and attorney work-product, withheld).")

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet. Stable key order so the
        packet render and any guard see identical bytes."""
        return {
            "verdict": self.verdict,
            "banner": PRIVILEGE_BANNER,
            "disclosable_count": len(self.disclosable_items),
            "privileged_count": len(self.privileged_items),
            "disclosable": [i.as_dict() for i in self.disclosable_items],
            "privileged": [i.as_dict() for i in self.privileged_items],
            "all_items": [i.as_dict() for i in self.items],
        }


def _present(packet: dict, key: str) -> bool:
    """True when the packet carries the section with genuine content. An empty
    dict / list / "" / None is absent (the artifact was not produced this run)."""
    value = packet.get(key)
    if value is None:
        return False
    if isinstance(value, (list, tuple, dict, str)):
        return len(value) > 0
    return True


def _count(value: object) -> int:
    """How many records an artifact carries, for the designation log. A list yields
    its length; a present dict / scalar counts as one."""
    if isinstance(value, (list, tuple)):
        return len(value)
    return 1


def _emit(packet: dict, event: str, value: object,
          items: list[PrivilegeItem]) -> None:
    """Classify one present artifact by its event type and append a PrivilegeItem.
    The basis is a static lookup; an event with no mapped basis is skipped (it is
    not a classifiable legal/regulatory artifact)."""
    basis = PRIVILEGE_CLASS.get(event)
    if basis is None:
        return
    items.append(PrivilegeItem(
        event=event,
        description=_ARTIFACT_DESCRIPTION.get(event, event),
        basis=basis,
        privilege_set=_SET_FOR_BASIS[basis],
        count=_count(value)))


def designate(packet: dict) -> PrivilegeDesignation:
    """The privilege / work-product designation for one assembled packet.

    Pure derived: it walks the packet's structured sections (the mirror of the
    sealed run-log) and classifies each present artifact by its event type through
    the static PRIVILEGE_CLASS map. No LLM, no now(); the same packet derives the
    byte-identical designation. It never enters the hashed run-log and gates
    nothing."""
    items: list[PrivilegeItem] = []

    # The reportability section also carries the per-regime reasonable-basis
    # determination records and the rationale memos: privileged legal advice, kept
    # as their own designation row so the determination memos are visibly withheld.
    if _present(packet, "reportability"):
        _emit(packet, "reportability", packet["reportability"].get("regimes", []),
              items)
        determinations = [r for r in packet["reportability"].get("regimes", [])
                          if r.get("determination")]
        if determinations:
            _emit(packet, "determination_record", determinations, items)
    if _present(packet, "materiality"):
        _emit(packet, "materiality", packet["materiality"], items)
        if packet["materiality"].get("determination"):
            _emit(packet, "determination_record",
                  packet["materiality"]["determination"], items)

    # The affected-party high-risk assessment is the Art 34 legal judgment.
    if _present(packet, "affected_party"):
        _emit(packet, "affected_party_high_risk", packet["affected_party"], items)

    # The legal hold: the counsel direction to preserve, and its release signoff.
    if _present(packet, "legal_hold"):
        hold = packet["legal_hold"]
        _emit(packet, "legal_hold_attached", hold, items)
        if hold.get("release"):
            _emit(packet, "legal_hold_released", hold["release"], items)

    # The cross-border conflict: the internal scan and block (work-product) and the
    # human legal resolution (privileged legal advice).
    if _present(packet, "cross_border"):
        cb = packet["cross_border"]
        _emit(packet, "cross_border_scan", cb.get("conflicts", []) or [cb], items)
        if cb.get("resolution"):
            _emit(packet, "cross_border_resolution", cb["resolution"], items)
        if cb.get("lead_authority"):
            _emit(packet, "lead_authority_routing", cb["lead_authority"], items)

    # The amendment deliberation: the reconciliation exchange (work-product).
    if _present(packet, "reconciliation"):
        _emit(packet, "reconciliation",
              packet["reconciliation"].get("exchange", []), items)

    # The adversarial Challenger critique: attorney work-product.
    if _present(packet, "adversarial_review"):
        _emit(packet, "adversarial_review",
              packet["adversarial_review"].get("reviews", []), items)

    # The disclosable set: the filings, the submission receipts, the EDGAR export,
    # and the non-privileged statutory screens / attestations.
    if _present(packet, "filings"):
        _emit(packet, "filings", packet["filings"], items)
    if _present(packet, "submission"):
        _emit(packet, "submission_receipt",
              packet["submission"].get("submissions", []), items)
    if _present(packet, "edgar_export"):
        _emit(packet, "edgar_export", packet["edgar_export"], items)
    if _present(packet, "deficiency"):
        _emit(packet, "regulator_intake", packet["deficiency"], items)
    if _present(packet, "completeness"):
        _emit(packet, "completeness", packet["completeness"].get("sheets", []), items)
    if _present(packet, "consistency"):
        _emit(packet, "consistency", packet["consistency"].get("facts", []), items)
    if _present(packet, "attestation"):
        _emit(packet, "attestation", packet["attestation"].get("regimes", []), items)

    return PrivilegeDesignation(items=tuple(items))


def privilege_record(packet: dict) -> dict:
    """The packet-ready privilege / work-product designation block: the disclosable
    set and the privileged set, the banner, and the verdict, JSON-serializable.

    Returns {} when the packet carries no classifiable artifact (a bare packet with
    no filings, memos, or screens), so the renderer can omit the section cleanly.
    No LLM, no now(); the same packet derives the byte-identical block. It never
    enters the hashed run-log and gates nothing."""
    designation = designate(packet)
    if not designation.items:
        return {}
    return designation.as_dict()
