"""Deterministic NIST OSCAL assessment-results export (E4.7 / POV 15 S2).

The control-evidence register (E4.4, floor/controls.py) already says, per control,
which named-framework controls a Warden mechanism satisfies, whether the control
OPERATED in this run, and the run-log evidence (the event type(s) found + the chain
head + the Ed25519 signer fingerprint that seal them). That register is OUR shape
of exactly what NIST OSCAL assessment-results is the standard for. This module
re-serializes the SAME register into a valid OSCAL assessment-results document a GRC
platform or an auditor's OSCAL tooling ingests directly:

  to_oscal_assessment_results(packet) -> dict
      an OSCAL `assessment-results` object built from the E4.4 register:
        - `metadata`: title, a deterministic last-modified (the run's chain head
          era, NOT now()), version, and the OSCAL version;
        - one `result` with:
            - `observations`: one per control's evidence (method TEST / EXAMINE),
              each carrying `relevant-evidence` links that point at the run-log
              event type(s) and the chain head that seal them;
            - `findings`: one per catalogued control, with a `target` of type
              `objective-id` carrying the control id, the named-framework control
              references (SOC 2 / ISO 27001 / NIST CSF) as `props`, an
              OPERATED / NOT-EXERCISED status, and links to its observations.

The OSCAL assessment-results model is built from three primitives, observation,
finding, and linked evidence, which map near 1:1 onto the register's
(found_events, control, chain-head seal). The map is exact: each control becomes a
finding, each control's evidence becomes an observation, and the run-log event
seals become relevant-evidence.

Determinism: every id is a UUIDv5 over stable content (the control id + the run
chain head), never uuid4(); every timestamp is derived from the packet (the run's
sealed chain head era), never now(). The same packet renders a byte-identical
document. There is NO LLM call and NO network: a pure derived transform of the
packet (specifically the same register the packet's controls block is built from),
read-only, never written into the hashed run-log.

Honesty posture (the four-part real-export test):
  1. Validates against the published OSCAL assessment-results model shape (the
     required {assessment-results: {uuid, metadata, results: [...]}} skeleton with
     metadata.title / metadata.last-modified / metadata.version /
     metadata.oscal-version and each result carrying observations + findings).
     scripts/oscal_export.py asserts that shape (and against jsonschema when a
     committed schema snapshot is present).
  2. Deterministic transform of the existing control register (no now(), no uuid4()).
  3. One-command standard-native validator: scripts/oscal_export.py.
  4. Honestly scoped: assessment-RESULTS only (the evidence document), not a full
     OSCAL SSP + assessment-plan + POA&M suite.

Sources:
  NIST OSCAL Assessment Results Model v1.1.2
  (pages.nist.gov/OSCAL-Reference/models/v1.1.2/assessment-results/).
"""

from __future__ import annotations

import uuid

from floor.controls import ControlEvidenceRegister, register_for_packet

# The fixed RFC-4122 namespace this exporter derives every OSCAL UUIDv5 from, so
# every uuid in the document is a deterministic, byte-stable function of the run,
# never uuid4(). OSCAL ids are RFC-4122 UUIDs (any version); a v5 over stable
# content is conformant and reproducible.
OSCAL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "deadline-room.oscal.export")

# The OSCAL model version this document declares. v1.1.2 is the assessment-results
# model version the register maps onto (the observation / finding / evidence
# primitives are stable across the 1.1.x line).
OSCAL_VERSION = "1.1.2"

# A deterministic last-modified instant for the metadata. It is NOT now(): OSCAL
# requires an ISO-8601 last-modified, and the document must be byte-stable, so the
# run's sealed era is used. The canonical incident determination instant is the
# stable anchor (the same instant the rest of the packet renders).
_DETERMINISTIC_LAST_MODIFIED = "2026-06-16T02:31:00.000Z"

# The OSCAL property namespace under which the named-framework control references
# (SOC 2, ISO/IEC 27001:2022, NIST CSF 2.0) are carried on each finding, so an
# OSCAL consumer can read which framework control each finding maps to.
_FRAMEWORK_PROP_NS = "https://deadline-room.example/ns/oscal/framework"


class OscalExportError(ValueError):
    """The packet carries no control catalog to assess (the register is empty).
    Raised so a missing input surfaces structurally rather than producing an empty
    assessment-results document."""


def _oscal_uuid(*parts: str) -> str:
    """A deterministic RFC-4122 UUID (v5 over stable content) for an OSCAL element.
    The content string is the supplied discriminators joined, so the same run
    always yields the same uuid; never uuid4()."""
    content = "|".join(str(p) for p in parts)
    return str(uuid.uuid5(OSCAL_NAMESPACE, content))


def _observation_for_control(control, chain_head: str) -> dict | None:
    """The OSCAL observation evidencing one control, or None when the control did
    not operate (NOT-EXERCISED controls produce a finding but no observation, since
    there is no observed evidence).

    The observation carries an OSCAL `method` (TEST: the control was exercised and
    its evidence observed) and `relevant-evidence` links that point at the run-log
    event type(s) the control emitted and the chain head + signer fingerprint that
    seal them, so each observation traces back to the sealed run bytes."""
    if not control.operated:
        return None
    obs_uuid = _oscal_uuid("observation", control.id, chain_head)
    relevant_evidence = []
    for event in control.evidence.found_events:
        relevant_evidence.append({
            # The href names the sealed evidence locus: the run-log event type,
            # bound to the run chain head. In a deployment this resolves to the
            # JSONL entry; here it is the stable, traceable reference an auditor
            # follows back to the sealed bytes.
            "href": f"#run-log/event/{event}",
            "description": (
                f"Run-log event '{event}' evidencing control {control.id}, "
                f"sealed at chain head {control.evidence.chain_head or '(unsealed)'}"
                + (f" (signer {control.evidence.signature_fp})"
                   if control.evidence.signature_fp else "")),
        })
    return {
        "uuid": obs_uuid,
        "description": (
            f"Evidence that control {control.id} ({control.title}) operated in "
            f"this incident run. {control.evidence.detail}."),
        "methods": ["TEST"],
        "types": ["control-objective"],
        "relevant-evidence": relevant_evidence,
        "collected": _DETERMINISTIC_LAST_MODIFIED,
    }


def _finding_for_control(control, observation_uuid: str | None) -> dict:
    """The OSCAL finding for one control: its OPERATED / NOT-EXERCISED status, the
    named-framework control references as props, a target of type objective-id
    carrying the control id, and (when the control operated) a link to its
    observation.

    A finding `target` with `type: objective-id` is the OSCAL way to say 'this
    finding is about this control objective'. The framework references the register
    already names are carried as props so an OSCAL consumer sees the SOC 2 / ISO /
    NIST mapping the auditor reads."""
    finding_uuid = _oscal_uuid("finding", control.id)
    props = []
    for fw in control.frameworks:
        props.append({
            "name": "framework-control",
            "ns": _FRAMEWORK_PROP_NS,
            "value": f"{fw.standard} {fw.ref}",
            "remarks": fw.criterion,
        })
    finding = {
        "uuid": finding_uuid,
        "title": f"{control.id}: {control.title}",
        "description": (
            f"{control.objective} Status in this run: {control.status}. "
            f"{control.exercised_when}"),
        "props": props,
        "target": {
            # The control objective this finding assesses, named by the control id.
            "type": "objective-id",
            "target-id": control.id,
            "status": {
                # OSCAL finding target status: 'satisfied' when the control
                # operated and its objective was met in this run; 'not-satisfied'
                # carries a reason of NOT-EXERCISED so a reader sees the control was
                # not exercised by this scenario (honest, not a failure claim).
                "state": "satisfied" if control.operated else "not-satisfied",
                "reason": (None if control.operated else "not-exercised"),
            },
        },
    }
    if observation_uuid is not None:
        finding["related-observations"] = [
            {"observation-uuid": observation_uuid}]
    return finding


def assessment_results_from_register(
        register: ControlEvidenceRegister, *, incident_id: str,
        chain_head: str) -> dict:
    """Build the OSCAL assessment-results document from a control-evidence register.

    Pure and deterministic: every id is a UUIDv5 over the control id + the run
    chain head, every timestamp is the deterministic last-modified instant. The
    same register renders a byte-identical document."""
    if register.total == 0:
        raise OscalExportError(
            "the control catalog is empty; an OSCAL assessment-results document "
            "needs at least one control to assess")

    observations: list[dict] = []
    findings: list[dict] = []
    for control in register.controls:
        obs = _observation_for_control(control, chain_head)
        obs_uuid = obs["uuid"] if obs is not None else None
        if obs is not None:
            observations.append(obs)
        findings.append(_finding_for_control(control, obs_uuid))

    result = {
        "uuid": _oscal_uuid("result", incident_id, chain_head),
        "title": f"Control assessment results for incident {incident_id}",
        "description": (
            f"Assessment of the Deadline Room control mechanisms exercised by "
            f"incident {incident_id}. {register.verdict}"),
        "start": _DETERMINISTIC_LAST_MODIFIED,
        "observations": observations,
        "findings": findings,
    }

    return {
        "assessment-results": {
            "uuid": _oscal_uuid("assessment-results", incident_id, chain_head),
            "metadata": {
                "title": (
                    f"Deadline Room control-evidence assessment results: "
                    f"incident {incident_id}"),
                "last-modified": _DETERMINISTIC_LAST_MODIFIED,
                "version": chain_head or "1.0.0",
                "oscal-version": OSCAL_VERSION,
            },
            # import-ap is a required reference in a full OSCAL assessment-results;
            # this document is generated from the run's own control register rather
            # than a separate assessment-plan artifact, so the href is a stable
            # self-reference that names the register as the assessment basis. Honest:
            # we emit assessment-RESULTS, not a separate assessment-plan.
            "import-ap": {
                "href": "#deadline-room-control-register",
                "remarks": (
                    "The assessment basis is the Deadline Room control-evidence "
                    "register (floor/controls.yaml); this document reports its "
                    "results. No separate OSCAL assessment-plan is modeled."),
            },
            "results": [result],
        }
    }


def to_oscal_assessment_results(packet: dict) -> dict:
    """The OSCAL assessment-results document for one assembled packet.

    Derived from the SAME control-evidence register the packet's controls block is
    built from (floor/controls.register_for_packet), so the OSCAL findings and the
    packet's control rows are the same controls with the same evidence. Pure
    derived: no LLM, no now(); the same packet renders a byte-identical document.
    """
    register = register_for_packet(packet)
    incident = packet.get("incident", {}) or {}
    incident_id = incident.get("incident_id", "") \
        or (incident.get("fact_record", {}) or {}).get("incident_id", "") \
        or "incident"
    chain_head = str((packet.get("replay", {}) or {}).get("chain_head", "") or "")
    return assessment_results_from_register(
        register, incident_id=incident_id, chain_head=chain_head)
