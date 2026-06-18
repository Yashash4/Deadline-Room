"""Deterministic OASIS STIX 2.1 bundle export of the incident (E4.7 / POV 15 S1).

The run already holds, in structured form, every object a STIX 2.1 incident bundle
wants: the canonical fact-record (attacker "LockBit 3.0", the regulated entity, the
affected systems and data-subject categories, the incident timing), the
contradiction diff, and the control-evidence register that says which Warden
controls operated and which findings the Challenger / oracle confirmed. This module
turns those facts into a valid STIX 2.1 `bundle` the threat-intel ecosystem
(MISP, OpenCTI, Anomali, Sentinel, Splunk ES, carried over TAXII 2.1) ingests:

  to_stix_bundle(packet) -> dict
      a STIX 2.1 bundle of:
        - a `threat-actor` SDO and a `malware` SDO for the attacker (LockBit 3.0 is
          a named ransomware family, so it is both an actor label and a malware
          family), linked actor --uses--> malware;
        - an `identity` SDO (class=organization) for the regulated entity (the
          victim);
        - an `incident` SDO carrying the recommended CORE INCIDENT EXTENSION
          (extension-definition--ef765651-680c-498d-9894-99799f2fa126), which turns
          the deliberately-stub STIX Incident SDO into a real, aggregatable incident
          record (status, determination, first-seen);
        - an `observed-data` SDO summarizing the affected systems and data-subject
          categories the incident touched;
        - a `course-of-action` SDO per oracle-CONFIRMED control failure / contradiction
          finding (the CISA best-practice pattern for recording the relevant /
          remediating controls of an incident), linked incident --related-to-->
          course-of-action;
        - `relationship` SROs tying the actor to the malware, the incident to the
          actor (attributed-to), the incident to the victim (targets), the incident
          to the observed data, and the incident to each course-of-action.

Determinism: every SDO id is a STIX-conformant id `<type>--<UUIDv5>` where the
UUIDv5 is computed over a stable content string (the incident id + the object kind
+ a stable discriminator), NEVER uuid4() and NEVER now(). Every `created` /
`modified` / incident-timing timestamp is a fact-record value (or a fixed derived
instant), so the same packet renders a byte-identical bundle and replay is
untouched. There is NO LLM call and NO network: it is a pure derived transform of
the packet, read-only, never written into the hashed run-log.

Honesty posture (the four-part real-export test):
  1. Validates against the published STIX 2.1 spec: the bundle is `{type: bundle,
     id, objects: [...]}`, every SDO carries `type`, `spec_version: "2.1"`, a
     spec-conformant `id`, `created`, `modified`; every SRO carries
     `relationship_type`, `source_ref`, `target_ref`. scripts/stix_export.py
     round-trips it through the `stix2` reference library when that library is
     importable, and otherwise asserts the required SDO properties + the id format.
  2. Deterministic transform of existing packet data (no now(), no uuid4()).
  3. One-command standard-native validator: scripts/stix_export.py.
  4. Honestly scoped: we emit a conformant bundle for the canonical incident; we do
     not push it over a live TAXII server (that is the documented [STUB]).

Sources:
  OASIS STIX 2.1 Open Standard (docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).
  STIX core incident extension definition id
  (extension-definition--ef765651-680c-498d-9894-99799f2fa126), the OASIS-published
  Incident Core Extension recommended for real incident records.
  CISA STIX Best Practices Guide (courses-of-action for the relevant controls of an
  incident).
"""

from __future__ import annotations

import uuid

from floor.controls import register_for_packet

# The RFC-4122 namespace UUID this exporter derives every STIX UUIDv5 from. STIX
# 2.1 ids are `<type>--<UUID>`; using a fixed namespace + a stable per-object
# content string makes every id a deterministic, byte-stable function of the
# incident, never uuid4(). The namespace itself is a fixed UUIDv5 under the DNS
# namespace over a Deadline Room identifier, so it is stable and self-documenting.
STIX_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "deadline-room.stix.export")

# The OASIS-published STIX 2.1 core incident extension-definition id. Adding this
# extension to the Incident SDO turns the spec's deliberately-minimal Incident
# object into a real, aggregatable incident record (the extension carries status,
# determination, and investigation properties). This is the published id, not
# invented.
INCIDENT_CORE_EXTENSION = (
    "extension-definition--ef765651-680c-498d-9894-99799f2fa126")

STIX_SPEC_VERSION = "2.1"

# A fixed derived `created` / `modified` instant for the bundle's SDOs that are not
# anchored to a specific fact-record timestamp. It is NOT now(): it is the
# canonical incident T0 fallback, so the bundle stays byte-stable. The incident
# SDO's own timing comes from the fact-record (incident_start_utc) directly.
_FALLBACK_INSTANT = "2026-06-16T02:14:00.000Z"


class StixExportError(ValueError):
    """The packet does not carry the incident facts a STIX bundle needs (no
    fact-record). Raised so a missing input surfaces structurally rather than
    producing a silently empty bundle."""


def _stix_id(stix_type: str, *parts: str) -> str:
    """A STIX-2.1-conformant deterministic id `<type>--<UUIDv5>`.

    The UUIDv5 is computed over a stable content string (the object kind plus the
    supplied discriminators, e.g. the incident id and the object label), so the
    same incident always yields the same id. This is the spec-conformant id format
    (a lowercase type, two hyphens, an RFC-4122 UUID) and it is byte-stable, never
    uuid4()."""
    content = "|".join([stix_type, *(str(p) for p in parts)])
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, content)}"


def _to_stix_timestamp(value: str) -> str:
    """Normalize an ISO-8601 instant from the fact-record to a STIX 2.1 timestamp
    (UTC, `Z`-suffixed, with millisecond precision). STIX requires a `Z` zone and
    accepts millisecond fractional seconds. A `+00:00` offset is rewritten to `Z`;
    a value already `Z`-suffixed is kept. Empty / unparseable input falls back to
    the canonical incident instant so the bundle is never malformed.

    Pure string normalization; no now(), so the output is a deterministic function
    of the input."""
    s = str(value or "").strip()
    if not s:
        return _FALLBACK_INSTANT
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    elif s.endswith("+0000"):
        s = s[:-5] + "Z"
    if not s.endswith("Z"):
        # A bare instant with no zone: treat as UTC and append Z (the fact-record
        # instants are UTC by construction).
        s = s + "Z"
    # Add a millisecond fraction if absent, so every timestamp has uniform
    # precision (STIX accepts either, but a uniform shape is byte-stable).
    head = s[:-1]
    if "." not in head and "T" in head:
        head = head + ".000"
    return head + "Z"


def _fact_record(packet: dict) -> dict:
    """The incident fact-record from the packet. Raises StixExportError when it is
    absent (no incident to model)."""
    fact = (packet.get("incident", {}) or {}).get("fact_record", {}) or {}
    if not fact:
        raise StixExportError(
            "no incident fact-record in the packet; a STIX 2.1 bundle needs the "
            "canonical incident facts (attacker, entity, systems, timing)")
    return fact


def _final_claims(packet: dict) -> dict:
    """The per-branch reconciled claims the diff produced (records_affected etc.),
    used to enrich the incident SDO description. Empty dict when absent."""
    return (packet.get("diff", {}) or {}).get("final_claims", {}) or {}


def _confirmed_findings(packet: dict) -> list[dict]:
    """The control / contradiction findings that justify a course-of-action SDO.

    Two sources, both already in the packet and both deterministic:
      - the control-evidence register (E4.4): every control that OPERATED is a
        relevant control of the incident; an auditor / responder records the
        course of action it represents. Derived from the packet via the same
        register the OSCAL export uses.
      - the adversarial review (the Challenger objections the deterministic
        grounding oracle CONFIRMED): each confirmed objection is a finding about
        the filing set that maps to a remediating course of action.

    Returns a list of {key, kind, title, description} dicts in a stable order, so
    the bundle's course-of-action set is byte-stable."""
    findings: list[dict] = []

    register = register_for_packet(packet)
    for control in register.controls:
        if not control.operated:
            continue
        findings.append({
            "key": f"control:{control.id}",
            "kind": "control",
            "title": f"{control.id}: {control.title}",
            "description": (
                f"{control.objective} Control {control.id} OPERATED in this "
                f"incident; named-framework references: {control.framework_refs}. "
                f"Evidence: {control.evidence.detail}."),
        })

    review = packet.get("adversarial_review", {}) or {}
    for r in review.get("reviews", []) or []:
        if str(r.get("disposition", "")).upper() != "CONCEDE":
            # Only filings whose Challenger objections the oracle CONFIRMED (the
            # drafter CONCEDEs) are recorded as a remediating course of action; a
            # filing the oracle fully OVERTURNED (a REBUT) raised no confirmed
            # control gap.
            continue
        regime = str(r.get("regime", "") or r.get("branch", ""))
        for i, obj in enumerate(r.get("objections", []) or []):
            target = str(obj.get("target", "")).strip()
            reason = str(obj.get("reason", "")).strip()
            findings.append({
                "key": f"finding:{r.get('branch', '')}:{i}",
                "kind": "finding",
                "title": (f"Confirmed finding on the {regime} filing: "
                          f"{target or 'unsupported claim'}"),
                "description": (
                    f"The adversarial Challenger objected to the {regime} filing "
                    f"({target or 'an unsupported claim'}) and the deterministic "
                    f"grounding oracle CONFIRMED it: "
                    f"{reason or 'unsupported by the fact-record'}. Course of "
                    f"action: correct the filing to the grounded fact-record "
                    f"value."),
            })

    return findings


def _malware_name(attacker: str) -> str | None:
    """The malware-family name for an attacker label, when the attacker names a
    known ransomware family. LockBit 3.0 is both a threat-actor label and a
    malware family, so it is modeled as both. Returns None when the attacker is
    not a recognized malware family (then only the threat-actor SDO is emitted)."""
    a = str(attacker or "").strip()
    if a.lower().startswith("lockbit"):
        return a
    return None


def to_stix_bundle(packet: dict) -> dict:
    """Build a valid STIX 2.1 bundle modeling the incident from the packet.

    Pure and deterministic: every value is read from the packet (the fact-record,
    the diff, the control register), every id is a STIX-conformant UUIDv5 over
    stable content, every timestamp is a fact-record instant. No LLM, no now(), no
    uuid4(); the same packet renders a byte-identical bundle.
    """
    fact = _fact_record(packet)
    incident_id = (packet.get("incident", {}) or {}).get("incident_id", "") \
        or fact.get("incident_id", "") or "incident"
    attacker = str(fact.get("attacker", "")).strip()
    entity = str(fact.get("regulated_entity", "")).strip()
    systems = [str(s) for s in (fact.get("systems") or [])]
    data_categories = [str(d) for d in (fact.get("data_categories") or [])]
    start_ts = _to_stix_timestamp(fact.get("incident_start_utc", ""))

    claims = _final_claims(packet)
    records_affected = None
    for branch_claim in claims.values():
        rec = branch_claim.get("records_affected")
        if rec is not None:
            records_affected = rec
            break
    if records_affected is None:
        records_affected = fact.get("records_affected")

    objects: list[dict] = []
    relationships: list[dict] = []

    # --- threat-actor (the attacker as an actor label) ---
    actor_id = _stix_id("threat-actor", incident_id, "actor", attacker)
    objects.append({
        "type": "threat-actor",
        "spec_version": STIX_SPEC_VERSION,
        "id": actor_id,
        "created": start_ts,
        "modified": start_ts,
        "name": attacker or "Unknown threat actor",
        "threat_actor_types": ["crime-syndicate"],
        "description": (
            f"The threat actor attributed to incident {incident_id} against "
            f"{entity or 'the regulated entity'}."),
    })

    # --- malware (LockBit 3.0 as a named ransomware family) ---
    malware_id = None
    malware_name = _malware_name(attacker)
    if malware_name:
        malware_id = _stix_id("malware", incident_id, "malware", malware_name)
        objects.append({
            "type": "malware",
            "spec_version": STIX_SPEC_VERSION,
            "id": malware_id,
            "created": start_ts,
            "modified": start_ts,
            "name": malware_name,
            "is_family": True,
            "malware_types": ["ransomware"],
            "description": (
                f"{malware_name} ransomware family, the malware associated with "
                f"incident {incident_id}."),
        })

    # --- identity (the regulated entity / victim organization) ---
    entity_id = _stix_id("identity", incident_id, "victim", entity)
    objects.append({
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": entity_id,
        "created": start_ts,
        "modified": start_ts,
        "name": entity or "Regulated entity",
        "identity_class": "organization",
        "sectors": ["financial-services"],
        "description": (
            f"The regulated entity affected by incident {incident_id}."),
    })

    # --- observed-data (affected systems + data-subject categories) ---
    affected_summary = []
    if systems:
        affected_summary.append("systems: " + ", ".join(systems))
    if data_categories:
        affected_summary.append(
            "data-subject categories: " + ", ".join(data_categories))
    observed_id = _stix_id("observed-data", incident_id, "observed")
    objects.append({
        "type": "observed-data",
        "spec_version": STIX_SPEC_VERSION,
        "id": observed_id,
        "created": start_ts,
        "modified": start_ts,
        "first_observed": start_ts,
        "last_observed": start_ts,
        "number_observed": 1,
        # The affected systems and personal-data categories the incident touched.
        # STIX observed-data carries object refs to SCOs in a full deployment; here
        # the deterministic summary is carried as a description so the bundle stays
        # self-contained and byte-stable without inventing SCO ids.
        "description": (
            "; ".join(affected_summary)
            or f"Resources affected by incident {incident_id}."),
    })

    # --- incident (the incident SDO with the core incident extension) ---
    incident_sdo_id = _stix_id("incident", incident_id, "incident")
    records_txt = (f"{records_affected:,}" if isinstance(records_affected, int)
                   else str(records_affected))
    incident_desc = (
        f"Regulated breach-reporting incident {incident_id}: {entity} affected by "
        f"{attacker}, approximately {records_txt} records, containment "
        f"{fact.get('containment', 'unknown')}, beginning "
        f"{fact.get('incident_start_utc', '')}.")
    objects.append({
        "type": "incident",
        "spec_version": STIX_SPEC_VERSION,
        "id": incident_sdo_id,
        "created": start_ts,
        "modified": start_ts,
        "name": f"Incident {incident_id}",
        "description": incident_desc,
        # The recommended core incident extension turns the stub Incident SDO into
        # a real incident record. The extension key is the OASIS-published
        # extension-definition id; extension_type names it a property-extension.
        "extensions": {
            INCIDENT_CORE_EXTENSION: {
                "extension_type": "property-extension",
                "determination": "confirmed",
                "investigation_status": "closed",
                "first_seen": start_ts,
            }
        },
    })

    # --- relationships: actor uses malware, incident attributed-to actor,
    #     incident targets victim, incident related-to observed data ---
    def _rel(rel_type: str, source: str, target: str) -> dict:
        rid = _stix_id("relationship", incident_id, rel_type, source, target)
        return {
            "type": "relationship",
            "spec_version": STIX_SPEC_VERSION,
            "id": rid,
            "created": start_ts,
            "modified": start_ts,
            "relationship_type": rel_type,
            "source_ref": source,
            "target_ref": target,
        }

    if malware_id:
        relationships.append(_rel("uses", actor_id, malware_id))
    relationships.append(_rel("attributed-to", incident_sdo_id, actor_id))
    relationships.append(_rel("targets", incident_sdo_id, entity_id))
    relationships.append(_rel("related-to", incident_sdo_id, observed_id))

    # --- course-of-action per oracle-CONFIRMED control / finding ---
    for finding in _confirmed_findings(packet):
        coa_id = _stix_id("course-of-action", incident_id, "coa", finding["key"])
        objects.append({
            "type": "course-of-action",
            "spec_version": STIX_SPEC_VERSION,
            "id": coa_id,
            "created": start_ts,
            "modified": start_ts,
            "name": finding["title"],
            "description": finding["description"],
        })
        relationships.append(_rel("related-to", incident_sdo_id, coa_id))

    objects.extend(relationships)

    bundle_id = _stix_id("bundle", incident_id, "bundle")
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
