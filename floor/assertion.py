"""The signed management assertion: a SOC-2-style attestation letter (E4.8).

An audit engagement does not begin with evidence. It begins with a MANAGEMENT
ASSERTION: a signed statement in which the organization's management asserts that
the controls relevant to a system operated effectively over a stated period, and
THEN points at the supporting evidence. The auditor tests that assertion against
the evidence. The control-evidence register (E4.4, floor/controls.py) already IS
the supporting evidence: per control, the named-framework references, an
OPERATED / NOT-EXERCISED status, and the run-log event(s) + chain head that seal
it. What the register does not yet carry is the assertion that sits ON TOP of it,
the one-page letter that says "management asserts these controls operated, here is
the evidence, signed".

This module derives that assertion and renders it as a formal attestation LETTER.

What it is, precisely:

  A PURE DERIVED summary over the SAME control-evidence register the packet's
  controls block is built from (floor/controls.register_for_packet). From the
  register it produces a typed ManagementAssertion: the standard SOC-2-style
  preamble (management asserts the controls relevant to the incident-reporting
  system operated effectively over the period), the asserted controls (each
  control id, its framework references, OPERATED / NOT-EXERCISED, and the sealed
  evidence), the assertion PERIOD (the run window, derived from the statutory
  clocks the packet already carries), and the one-line assertion verdict. It
  renders as a formal attestation letter (plain text) that an audit committee
  reads.

  The assertion document is then canonicalized (sorted-keys, no-whitespace JSON,
  the same recipe the run log, the bound signing payload, and the
  deadline-compliance attestation use, with NO now() and no RNG) and hashed once
  to `assertion_digest`. That digest is signed with a SEPARATE, DETACHED Ed25519
  signature (warden/signing.sign_bytes), NOT folded into the run-log bound
  payload. The assertion is an artifact that rests on top of the sealed run; it
  does not change what the run-log signature attests, and it never enters the
  hashed run-log. So the run-log sha, the chain head, the run-log bound
  signature, and byte-identical replay are all completely untouched: this module
  reads the packet, it never writes the log.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The
  same packet always derives the byte-identical assertion and therefore the same
  digest and the same signature (Ed25519 is deterministic). It reads the packet
  dict only; it never gates a Warden transition, never clocks or counts anything
  inside the core. It is an auditor-side READ over the Warden's output, exactly
  like the control-evidence register (E4.4) and the OSCAL export (E4.7).

Honest demo-key caveat: the private key shipped with this repo is a DEMONSTRATION
key (warden/signing.py). The signature MECHANISM is fully real (one flipped byte
of the assertion makes it INVALID), but the key's SECRECY is not production-grade
because anyone with the repo holds it. The same caveat that travels with the
run-log signature travels with this one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from floor.controls import ControlEvidenceRegister, register_for_packet
from warden.signing import (
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
    sign_bytes,
    verify_bytes,
)

# The standard SOC-2-style assertion preamble. Management asserts, for the stated
# period, that the controls relevant to the incident-reporting system were suitably
# designed and operated effectively. It is fixed prose (no run data) so it reads as
# the management letter an auditor expects; the per-run specifics live in the
# controls, the period, and the verdict below.
ASSERTION_PREAMBLE = (
    "Management asserts that, throughout the period stated below, the controls "
    "relevant to the regulated incident-reporting system were suitably designed "
    "and operated effectively to meet the applicable control objectives. The "
    "controls enumerated below were exercised by the incident run identified in "
    "this assertion; for each, the supporting evidence is the run-log event(s) "
    "named and the per-entry hash chain head that seals them, independently "
    "re-derivable from the sealed run. Controls marked NOT-EXERCISED were not "
    "invoked by this run's scenario; their absence from this run is stated "
    "honestly and is not a deficiency."
)

# The signer's stated role on the letter. The same identity the run-log signature
# attributes the seal to, so the assertion letter and the run-log seal name one
# attesting party.
ASSERTION_SIGNER = "Deadline Warden, on behalf of management"


@dataclass(frozen=True)
class AssertedControl:
    """One control as it appears in the management assertion: the control id, its
    title, the named-framework reference string, the OPERATED / NOT-EXERCISED
    status, and the sealed evidence basis (the proving run-log event(s) and the
    detail line). Derived 1:1 from a ControlResult in the register."""
    id: str
    title: str
    framework_refs: str
    status: str
    operated: bool
    found_events: tuple[str, ...]
    evidence_detail: str

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "framework_refs": self.framework_refs,
            "status": self.status,
            "operated": self.operated,
            "found_events": list(self.found_events),
            "evidence_detail": self.evidence_detail,
        }


@dataclass(frozen=True)
class AssertionPeriod:
    """The period the assertion covers: the run window, derived from the statutory
    clocks the packet already carries. `start` is the earliest clock start (the
    incident anchor); `end` is the latest clock deadline (the furthest statutory
    horizon the run was held to). Both are ISO-8601 strings copied verbatim from
    the packet's clock rows, so the period is a deterministic function of the run,
    never now(). `("", "")` when the packet carries no clocks."""
    start: str
    end: str

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end}


@dataclass(frozen=True)
class ManagementAssertion:
    """The full management assertion over one run: the standard preamble, the
    incident reference and reporting entity, the asserted controls, the period, the
    counts, and the one-line verdict. A pure summary view of the control-evidence
    register, signed separately and rendered as a formal attestation letter."""
    incident_id: str
    regulated_entity: str
    preamble: str
    period: AssertionPeriod
    controls: tuple[AssertedControl, ...]
    chain_head: str
    signature_fp: str

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
        """The one-line assertion verdict an audit committee reads first."""
        n = self.not_exercised_count
        not_exercised = (
            f"{n} was not exercised by this run's scenario" if n == 1 else
            f"{n} were not exercised by this run's scenario")
        return (
            f"Management asserts {self.operated_count} of {self.total} catalogued "
            f"controls OPERATED and are evidenced in this run; {not_exercised}.")

    def as_document(self) -> dict:
        """The canonical assertion DOCUMENT: the exact JSON the digest is taken
        over and the signature attests. Stable key order so the digest is
        byte-stable. This is the signed object; the rendered letter and the packet
        block are views of it."""
        return {
            "incident_id": self.incident_id,
            "regulated_entity": self.regulated_entity,
            "preamble": self.preamble,
            "signer": ASSERTION_SIGNER,
            "period": self.period.as_dict(),
            "verdict": self.verdict,
            "total": self.total,
            "operated_count": self.operated_count,
            "not_exercised_count": self.not_exercised_count,
            "chain_head": self.chain_head,
            "signature_fp": self.signature_fp,
            "controls": [c.as_dict() for c in self.controls],
        }


def _period_from_clocks(packet: dict) -> AssertionPeriod:
    """Derive the assertion period (the run window) from the packet's clock rows:
    the earliest clock start to the latest clock deadline. Both are ISO-8601
    instants the run already produced, copied verbatim, so the period is a
    deterministic function of the run, never now(). Returns empty strings when no
    clock carries a parseable instant."""
    starts: list[tuple[datetime, str]] = []
    ends: list[tuple[datetime, str]] = []
    for c in packet.get("clocks", []) or []:
        start_raw = str(c.get("started", "") or "")
        end_raw = str(c.get("deadline", "") or "")
        start_dt = _parse_ts(start_raw)
        end_dt = _parse_ts(end_raw)
        if start_dt is not None:
            starts.append((start_dt, start_raw))
        if end_dt is not None:
            ends.append((end_dt, end_raw))
    start = min(starts, key=lambda p: p[0])[1] if starts else ""
    end = max(ends, key=lambda p: p[0])[1] if ends else ""
    return AssertionPeriod(start=start, end=end)


def _parse_ts(value: str) -> datetime | None:
    """Parse an ISO-8601 instant to an aware UTC datetime, or None when absent or
    unparseable. Used only to ORDER the clock instants for the period bounds; the
    period strings themselves are the verbatim packet values, so the rendered
    period is exactly what the clocks recorded."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_assertion(packet: dict) -> ManagementAssertion:
    """Build the management assertion for one assembled packet from the SAME
    control-evidence register the packet's controls block is built from.

    Pure derived: it reads the register (which reads the packet's structured
    sections), the period from the packet's clocks, and the incident reference and
    entity from the packet. No LLM, no now(); the same packet derives the
    byte-identical assertion. It never enters the hashed run-log and gates
    nothing."""
    register: ControlEvidenceRegister = register_for_packet(packet)
    asserted = tuple(
        AssertedControl(
            id=c.id,
            title=c.title,
            framework_refs=c.framework_refs,
            status=c.status,
            operated=c.operated,
            found_events=c.evidence.found_events,
            evidence_detail=c.evidence.detail)
        for c in register.controls)

    incident = packet.get("incident", {}) or {}
    fact = incident.get("fact_record", {}) or {}
    incident_id = str(incident.get("incident_id", "")
                      or fact.get("incident_id", "") or "")
    entity = str(fact.get("regulated_entity", "") or "")

    # The seal the assertion references: the run's chain head and the run-log
    # signer fingerprint. The assertion points at the SAME seal the register's
    # evidence is bound to, so an auditor follows one head back to the sealed run.
    replay = packet.get("replay", {}) or {}
    chain_head = str(replay.get("chain_head", "") or "")
    sig = replay.get("signature", {}) or {}
    signature_fp = str(sig.get("pubkey_fingerprint", "") or "")

    return ManagementAssertion(
        incident_id=incident_id,
        regulated_entity=entity,
        preamble=ASSERTION_PREAMBLE,
        period=_period_from_clocks(packet),
        controls=asserted,
        chain_head=chain_head,
        signature_fp=signature_fp)


def canonical_assertion_bytes(document: dict) -> bytes:
    """The assertion document serialized to canonical JSON bytes.

    Uses the SAME canonicalization recipe as the run log, the bound signing
    payload, and the deadline-compliance attestation
    (`json.dumps(..., sort_keys=True, separators=(",",":"))`), with no now() and
    no RNG, so the same assertion always yields the same bytes and therefore the
    same digest. A verifier rebuilds these exact bytes from the re-derived
    assertion to check the signature."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def assertion_digest(document: dict) -> str:
    """The sha256 over the canonical assertion bytes. This is the digest the
    detached Ed25519 signature is taken over, so a single edited field in the
    assertion moves it and breaks the signature."""
    return hashlib.sha256(canonical_assertion_bytes(document)).hexdigest()


def render_letter(assertion: ManagementAssertion) -> str:
    """Render the management assertion as a formal SOC-2-style attestation LETTER
    (plain text), the one-page document an audit committee reads.

    Pure formatting of the already-derived assertion: no LLM, no now(); the same
    assertion renders the byte-identical letter. The letter states the preamble,
    the period, the asserted controls with their framework references and sealed
    evidence, the verdict, and the signer."""
    lines: list[str] = []
    lines.append("MANAGEMENT ASSERTION")
    lines.append("Regulated incident-reporting system: control operation over the "
                 "reporting period")
    lines.append("")
    if assertion.regulated_entity:
        lines.append(f"Reporting entity   : {assertion.regulated_entity}")
    if assertion.incident_id:
        lines.append(f"Incident reference : {assertion.incident_id}")
    period = assertion.period
    if period.start or period.end:
        lines.append(f"Period asserted    : {period.start or '(open)'} through "
                     f"{period.end or '(open)'} (UTC)")
    lines.append("")
    lines.append(assertion.preamble)
    lines.append("")
    lines.append(f"Asserted controls ({assertion.operated_count} of "
                 f"{assertion.total} OPERATED):")
    lines.append("")
    for c in assertion.controls:
        lines.append(f"  [{c.status}] {c.id}: {c.title}")
        lines.append(f"      Frameworks : {c.framework_refs}")
        if c.found_events:
            lines.append(f"      Evidence   : {', '.join(c.found_events)}")
        lines.append(f"                   {c.evidence_detail}")
        lines.append("")
    if assertion.chain_head:
        lines.append(f"Evidence seal (per-entry hash chain head): "
                     f"{assertion.chain_head}")
        if assertion.signature_fp:
            lines.append(f"Run-log signer fingerprint               : "
                         f"{assertion.signature_fp}")
        lines.append("")
    lines.append(assertion.verdict)
    lines.append("")
    lines.append(f"Asserted and signed by: {ASSERTION_SIGNER}")
    return "\n".join(lines)


def sign_assertion(document: dict, private_key=None) -> dict:
    """Sign the assertion DOCUMENT with a SEPARATE, DETACHED Ed25519 signature and
    return the signature record that lands in the assertion sidecar.

    The signature is taken over the assertion digest's canonical bytes (the same
    bytes `assertion_digest` hashes), with the committed demo key by default. It is
    DETACHED and SEPARATE from the run-log bound signature: it attests the
    assertion document only, it is never folded into the run-log bound payload, and
    it never enters the hashed run-log. So the run-log sha, the chain head, the
    run-log signature, and byte-identical replay are all untouched.

    The record carries the digest, the detached signature, the public key, its
    fingerprint, and the honest demo-key caveat, so a verifier re-derives the
    assertion, recomputes the digest, rebuilds the signed bytes, and checks the
    signature with no private key."""
    digest = assertion_digest(document)
    signed_bytes = canonical_assertion_bytes(document)
    signature_hex = sign_bytes(signed_bytes, private_key)
    pub_hex = load_public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "separate_from_run_log_signature": True,
        "signed_payload": "canonical_json(management_assertion)",
        "assertion_digest": digest,
        "signature": signature_hex,
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": ASSERTION_SIGNER,
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_assertion_signature(document: dict, signature_record: dict) -> bool:
    """Verify a detached assertion signature against a re-derived assertion
    document. True only when the digest the record carries matches the digest of
    the canonical bytes of THIS document AND the Ed25519 signature is valid over
    those bytes under the record's public key.

    The digest is recomputed from the document handed in, not trusted from the
    record, so an edit to any asserted field (the digest moves) breaks the check.
    Returns False on any mismatch or malformed input rather than raising, so a
    verifier prints INVALID and exits nonzero without a stack trace on a tampered
    assertion."""
    recomputed = assertion_digest(document)
    if recomputed != str(signature_record.get("assertion_digest", "")):
        return False
    return verify_bytes(
        canonical_assertion_bytes(document),
        signature_record.get("signature", ""),
        signature_record.get("public_key"))


def assertion_record(packet: dict) -> dict:
    """The packet-ready management-assertion block for the Examiner Packet: the
    rendered attestation letter, the typed assertion document, and the assertion
    digest, JSON-serializable.

    Returns {} only when the packet carries no catalogued control to assert (an
    empty register), so the renderer can omit the section cleanly. A run that
    exercises no control still yields a full assertion (every control
    NOT-EXERCISED), which is itself the honest management statement. No LLM, no
    now(); the same packet derives the byte-identical block.

    This block carries the digest and the letter but NOT the signature: the
    signature is a SEPARATE detached sidecar (web/data/assertion-<scenario>.json),
    so the packet render stays a pure derived view and the signing step is an
    explicit, auditable artifact a verifier checks on its own."""
    assertion = build_assertion(packet)
    if assertion.total == 0:
        return {}
    document = assertion.as_document()
    return {
        "document": document,
        "digest": assertion_digest(document),
        "letter": render_letter(assertion),
        "verdict": assertion.verdict,
        "operated_count": assertion.operated_count,
        "total": assertion.total,
    }
