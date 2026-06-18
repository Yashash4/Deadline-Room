"""The control-evidence register: named-framework control mapping (E4.4).

An auditor does not accept "two-key release" as a control statement. They accept
"Control SOD-01 (SOC 2 CC1.3 segregation of duties; ISO/IEC 27001 A.5.3; NIST CSF
PR.AA-05): two distinct human roles signed before HUMAN_RELEASED. Evidence:
run-log release_signoff events on three branches, sealed at chain head 6fa0...".
This module turns the Warden's existing mechanisms into exactly that: per control
in the declarative catalog (floor/controls.yaml), the named framework references,
the EVIDENCE that the control OPERATED in THIS run (the exact run-log event
type(s) found + the chain head that seals them), and an OPERATED / NOT-EXERCISED
status.

What it is, precisely:

  A PURE DERIVED render over the assembled packet. The catalog declares, per
  control, which run-log event TYPE(S) prove the control operated and WHERE in
  the packet the renderer reads that proof (the same structured sections the
  Warden logged: release.signoffs for release_signoff, diff.blocked_conflicts
  for diff_blocked, chaos.ledger for the ledger, clocks for the statutory
  clocks, reportability for the decision gate, replay.chain_head + the
  signature for the provenance seal). A control is OPERATED iff its proving
  event is present in this run's packet; NOT-EXERCISED otherwise (e.g. the veto
  on a clean run with no planted contradiction). The evidence on every OPERATED
  control points at the real run-log event(s) and the run's chain head, so an
  auditor can trace the row back to the bytes in the sealed JSONL.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The
  same packet always derives the byte-identical register. It reads the packet
  dict only; it never enters the hashed run-log, never gates a Warden
  transition, never clocks or counts anything inside the core. It is an
  auditor-side READ over the Warden's output, exactly like the completeness
  screen (E4.2) and the consistency sheet (E4.3).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_CATALOG_PATH = Path(__file__).resolve().parent / "controls.yaml"

# The two control dispositions, named so the packet and the receipt branch on
# the code rather than a free string. OPERATED: the proving run-log event is
# present in this run, so the control demonstrably operated. NOT_EXERCISED: the
# control's mechanism did not fire in this run (e.g. the veto on a run with no
# contradiction planted). NOT-EXERCISED is not a failure: it is the honest
# statement that this run did not exercise that control path.
STATUS_OPERATED = "OPERATED"
STATUS_NOT_EXERCISED = "NOT-EXERCISED"


@dataclass(frozen=True)
class FrameworkRef:
    """One named-framework control reference a mechanism satisfies.

    standard   the framework name (e.g. "SOC 2", "ISO/IEC 27001:2022", "NIST CSF 2.0").
    ref        the REAL control id in that framework (e.g. "CC1.3", "A.5.3", "PR.AA-05").
    criterion  a one-line faithful summary of that control's intent, for the auditor.
    """
    standard: str
    ref: str
    criterion: str

    def as_dict(self) -> dict:
        return {"standard": self.standard, "ref": self.ref,
                "criterion": self.criterion}


@dataclass(frozen=True)
class ControlSpec:
    """One declarative control lifted from floor/controls.yaml: a Warden mechanism,
    the named-framework controls it satisfies, and the run-log evidence that proves
    it operated. Pure config; no run is read here."""
    id: str
    title: str
    objective: str
    mechanism: str
    frameworks: tuple[FrameworkRef, ...]
    run_log_events: tuple[str, ...]
    packet_path: str
    seal: str
    exercised_when: str


@dataclass(frozen=True)
class ControlEvidence:
    """The evidence that one control OPERATED (or did not) in one run.

    found_events     the proving run-log event type(s) the renderer actually
                     found present in this run's packet (a subset of the spec's
                     declared run_log_events). Empty when NOT-EXERCISED.
    detail           a short human-readable basis: the count of proving events
                     and where they were read, or the reason the control was not
                     exercised. Never the full prose.
    chain_head       the run's per-entry hash chain head that seals these events
                     (replay.chain_head); "" when the packet carries no seal.
    signature_fp     the Ed25519 signer fingerprint over the chain head, binding
                     the evidence to a tamper-evident, attributable seal; "" when
                     the packet is unsigned.
    """
    found_events: tuple[str, ...]
    detail: str
    chain_head: str
    signature_fp: str

    def as_dict(self) -> dict:
        return {
            "found_events": list(self.found_events),
            "detail": self.detail,
            "chain_head": self.chain_head,
            "signature_fp": self.signature_fp,
        }


@dataclass(frozen=True)
class ControlResult:
    """One control's row in the register: the named-framework mapping plus the
    per-run evidence and an OPERATED / NOT-EXERCISED status."""
    id: str
    title: str
    objective: str
    mechanism: str
    frameworks: tuple[FrameworkRef, ...]
    status: str
    evidence: ControlEvidence
    exercised_when: str

    @property
    def operated(self) -> bool:
        return self.status == STATUS_OPERATED

    @property
    def framework_refs(self) -> str:
        """The compact named-framework reference string an auditor reads first,
        e.g. "SOC 2 CC1.3; ISO/IEC 27001:2022 A.5.3; NIST CSF 2.0 PR.AA-05"."""
        return "; ".join(f"{f.standard} {f.ref}" for f in self.frameworks)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "objective": self.objective,
            "mechanism": self.mechanism,
            "frameworks": [f.as_dict() for f in self.frameworks],
            "framework_refs": self.framework_refs,
            "status": self.status,
            "operated": self.operated,
            "evidence": self.evidence.as_dict(),
            "exercised_when": self.exercised_when,
        }


@dataclass(frozen=True)
class ControlEvidenceRegister:
    """The full control-evidence register over one run: one ControlResult per
    catalogued control, with the framework mapping and the per-run evidence."""
    controls: tuple[ControlResult, ...]

    @property
    def total(self) -> int:
        return len(self.controls)

    @property
    def operated_count(self) -> int:
        return sum(1 for c in self.controls if c.operated)

    @property
    def not_exercised_count(self) -> int:
        return sum(1 for c in self.controls if not c.operated)

    @property
    def verdict(self) -> str:
        """The one-line register verdict an audit committee reads first."""
        n = self.not_exercised_count
        not_exercised = (
            f"{n} was not exercised by this run's scenario" if n == 1 else
            f"{n} were not exercised by this run's scenario")
        return (
            f"{self.operated_count} of {self.total} catalogued controls OPERATED "
            f"and are evidenced in this run; {not_exercised}.")

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet. Stable key order so
        the packet render and any guard see identical bytes."""
        return {
            "total": self.total,
            "operated_count": self.operated_count,
            "not_exercised_count": self.not_exercised_count,
            "verdict": self.verdict,
            "controls": [c.as_dict() for c in self.controls],
        }


def load_catalog() -> list[ControlSpec]:
    """Parse floor/controls.yaml into typed ControlSpec records. Pure data
    plumbing; reads the file, makes no LLM call, touches nothing in warden/."""
    raw = yaml.safe_load(_CATALOG_PATH.read_text(encoding="utf-8")) or {}
    specs: list[ControlSpec] = []
    for entry in raw.get("controls", []):
        frameworks = tuple(
            FrameworkRef(
                standard=str(fw.get("standard", "")).strip(),
                ref=str(fw.get("ref", "")).strip(),
                criterion=" ".join(str(fw.get("criterion", "")).split()))
            for fw in entry.get("frameworks", []))
        ev = entry.get("evidence", {}) or {}
        specs.append(ControlSpec(
            id=str(entry.get("id", "")).strip(),
            title=str(entry.get("title", "")).strip(),
            objective=" ".join(str(entry.get("objective", "")).split()),
            mechanism=" ".join(str(entry.get("mechanism", "")).split()),
            frameworks=frameworks,
            run_log_events=tuple(str(e).strip()
                                 for e in ev.get("run_log_events", [])),
            packet_path=str(ev.get("packet_path", "")).strip(),
            seal=str(ev.get("seal", "")).strip(),
            exercised_when=" ".join(str(ev.get("exercised_when", "")).split())))
    return specs


def _dig(packet: dict, dotted: str):
    """Read a dotted path (e.g. "diff.blocked_conflicts") out of the packet dict.
    Returns None when any segment is absent. Pure read; never mutates."""
    cur: object = packet
    for seg in dotted.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return None
        cur = cur[seg]
    return cur


def _transition_events(packet: dict) -> set[str]:
    """The set of state-machine transition EVENT names this run admitted, read
    from packet["state_transitions"]. These back the "protocol_event:<event>"
    evidence tokens (e.g. "protocol_event:human_released")."""
    events: set[str] = set()
    for t in packet.get("state_transitions", []) or []:
        ev = t.get("event")
        # Only ADMITTED transitions count as the control operating; a rejected
        # (illegal) transition is not evidence the control's path ran.
        if ev and t.get("admitted", True):
            events.add(str(ev))
    return events


def _present_payload(value: object) -> bool:
    """True when a packet section read for evidence carries genuine content. A
    list with entries, a non-empty dict, or a non-empty scalar is present; an
    empty list / dict / "" / None is absent (the control did not operate)."""
    if value is None:
        return False
    if isinstance(value, (list, tuple, dict, str)):
        return len(value) > 0
    return True


def _chain_seal(packet: dict) -> tuple[str, str]:
    """The run's provenance seal: the per-entry hash chain head and the Ed25519
    signer fingerprint over it, read from packet["replay"]. The chain head binds
    every named evidence event to the exact ordered run; the fingerprint
    attributes that seal to the Warden's key. ("", "") when the packet is
    unsealed/unsigned (an older or partial packet)."""
    replay = packet.get("replay", {}) or {}
    head = str(replay.get("chain_head", "") or "")
    sig = replay.get("signature", {}) or {}
    fp = str(sig.get("pubkey_fingerprint", "") or "")
    return head, fp


def _evaluate_control(spec: ControlSpec, packet: dict,
                      transition_events: set[str], chain_head: str,
                      signature_fp: str) -> ControlResult:
    """Derive one control's row: which of its declared proving events are present
    in this run, the OPERATED / NOT-EXERCISED status, and the sealed evidence.

    An event token is either a plain run-log entry type (e.g. "release_signoff",
    "ledger", "clocks") whose presence is read from the declared packet_path, or
    a "protocol_event:<event>" token matched against the admitted state-machine
    transitions. A control OPERATED iff at least one of its declared proving
    events is present in this run."""
    found: list[str] = []
    payload = _dig(packet, spec.packet_path) if spec.packet_path else None
    section_present = _present_payload(payload)

    for token in spec.run_log_events:
        if token.startswith("protocol_event:"):
            event_name = token.split(":", 1)[1]
            if event_name in transition_events:
                found.append(token)
        else:
            # A plain run-log entry type. Its proof is the declared packet
            # section carrying content (the structured mirror of those logged
            # entries). The first such token that resolves to a present section
            # is the evidence anchor; we record every declared type the section
            # backs so the auditor sees the full event set behind the row.
            if section_present:
                found.append(token)

    operated = len(found) > 0
    status = STATUS_OPERATED if operated else STATUS_NOT_EXERCISED

    if operated:
        n = _evidence_count(payload)
        where = spec.packet_path or "packet"
        if n:
            detail = (f"{n} proving run-log event(s) present, read from "
                      f"packet.{where}, sealed at the run chain head")
        else:
            detail = (f"proving run-log event(s) present, read from "
                      f"packet.{where}, sealed at the run chain head")
    else:
        detail = (f"not exercised by this run: no {', '.join(spec.run_log_events)} "
                  f"event present at packet.{spec.packet_path or '(n/a)'}")

    evidence = ControlEvidence(
        found_events=tuple(found),
        detail=detail,
        chain_head=chain_head if operated else "",
        signature_fp=signature_fp if operated else "")

    return ControlResult(
        id=spec.id, title=spec.title, objective=spec.objective,
        mechanism=spec.mechanism, frameworks=spec.frameworks,
        status=status, evidence=evidence, exercised_when=spec.exercised_when)


def _evidence_count(payload: object) -> int:
    """How many proving entries the evidence section carries (for the detail
    line). A list/dict yields its length; a present scalar (e.g. a chain head
    string) counts as one."""
    if isinstance(payload, (list, tuple, dict)):
        return len(payload)
    if payload:
        return 1
    return 0


def register_for_packet(packet: dict) -> ControlEvidenceRegister:
    """The control-evidence register for one assembled packet: per catalogued
    control, the named-framework mapping plus the per-run OPERATED / NOT-EXERCISED
    evidence pointing at the real run-log event(s) and the run's chain head.

    Pure derived: it reads the packet's structured sections (the mirror of the
    logged events) and the run's chain head + signature fingerprint. No LLM, no
    now(); the same packet derives the byte-identical register. It never enters
    the hashed run-log and gates nothing."""
    transition_events = _transition_events(packet)
    chain_head, signature_fp = _chain_seal(packet)
    results = tuple(
        _evaluate_control(spec, packet, transition_events, chain_head,
                          signature_fp)
        for spec in load_catalog())
    return ControlEvidenceRegister(controls=results)


def controls_record(packet: dict) -> dict:
    """The packet-ready control-evidence register block: the per-control rows plus
    the overall verdict, JSON-serializable.

    Returns {} only when the catalog is empty (no control to evaluate), so the
    renderer can omit the section cleanly. A run that exercises no control still
    yields a full register (every row NOT-EXERCISED), which is itself the honest
    auditor statement, so the register is rendered whenever controls exist. No
    LLM, no now(); the same packet derives the byte-identical block."""
    register = register_for_packet(packet)
    if register.total == 0:
        return {}
    return register.as_dict()
