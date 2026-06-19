"""SIEM ingest adapter: pull a detection/incident finding from a SIEM and MAP it
to the canonical fact-record, which then flows through the input integrity gate
(`floor.fact_record.validate_fact_record`) BEFORE any drafting prompt.

This is the LEFT edge of the system. In the hackathon the breach alert was an
honest in-process `[STUB]`: the canonical fact-record was hand-authored. Production
ingests the alert from a real SIEM (Splunk, Microsoft Sentinel, Elastic Security),
which speak OCSF (the Open Cybersecurity Schema Framework) for findings. This module
turns "hand-authored fact-record" into "ask a SiemConnector for a finding and map
it", behind a clean interface, so a deployment points the connector at its SIEM
while the build DEFAULTS to the in-process stub and stays offline and deterministic.

WHY A CONNECTOR, NOT A DIRECT CALL. A SIEM exposes a query/finding API behind an
access policy; it never hands the floor a ready-made fact-record. Modeling ingest as
a connector with `fetch_finding() -> dict` (the raw OCSF finding) plus a pure
`map_finding_to_fact_record(finding) -> dict` (the SIEM-shape -> canonical-shape
mapping) is the faithful seam: the in-process stub and a live Splunk connector are
interchangeable through it, and the MAPPING is pure Python a test can pin exactly.

WHAT IS PRESERVED. The stub maps to the SAME canonical fact-record the floor already
uses (`run_floor.CANONICAL_FACTS`), so ingesting through the stub yields the exact
input the sealed runs were driven from: the fact-record hash, the sealed run-log
shas, and byte-identical replay are untouched. The validator the finding flows
through is additive (it rejects malformed input, it never rewrites a valid record),
so a record that ingests cleanly hashes exactly as before.

THE LIVE PATH IS A DOCUMENTED SEAM. A real HTTP connector
(`HttpSiemConnector`/`SplunkConnector`) raises `NotImplementedError` with the exact
wiring a deployer fills in, so a reproducible offline build never makes a network
call on the default/test path. The mapping itself is real and tested against a
representative OCSF Security Finding shape.
"""

from __future__ import annotations

from dataclasses import dataclass

from floor.fact_record import validate_fact_record


class SiemIngestError(ValueError):
    """A SIEM finding could not be mapped to a well-formed fact-record: a required
    field is absent from the finding, or the mapped record fails the input integrity
    gate. Raised so a malformed or poisoned upstream alert is QUARANTINED at the
    edge rather than flowing into a drafting prompt."""


class SiemConnector:
    """The ingest seam: an object that can FETCH one detection/incident finding from
    a SIEM. One operation, the surface a SIEM finding API offers:

      * `fetch_finding() -> dict` : return one raw finding as the SIEM emits it
        (an OCSF Security Finding object, or the SIEM's native finding JSON). On a
        live connector this is a network/API call against the SIEM; on the stub it
        is an in-process fixture.

    The MAPPING from a finding to the canonical fact-record is NOT on the connector:
    it is the pure module-level `map_finding_to_fact_record`, so every connector
    (stub, Splunk, Sentinel, Elastic) shares one deterministic, testable mapping and
    connectors differ only in WHERE the finding comes from."""

    def fetch_finding(self) -> dict:
        raise NotImplementedError


# --- The OCSF -> canonical-fact-record mapping (pure, deterministic) -----------
# OCSF (Open Cybersecurity Schema Framework) is the inbound schema Splunk, Sentinel,
# and Elastic findings normalize to. A Security Finding (OCSF class_uid 2001) carries
# the fields below. The mapping reads them defensively and produces the canonical
# fact-record shape the floor and the validator expect. It does NOT invent values: a
# missing required source field raises rather than guessing.


def _require(finding: dict, path: tuple[str, ...]) -> object:
    """Walk a dotted path into the OCSF finding, raising SiemIngestError naming the
    missing key rather than returning a silent None that would map to garbage."""
    node: object = finding
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise SiemIngestError(
                f"OCSF finding missing required field {'.'.join(path)!r}")
        node = node[key]
    return node


def _optional(finding: dict, path: tuple[str, ...], default: object) -> object:
    node: object = finding
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def map_finding_to_fact_record(finding: dict) -> dict:
    """Map one OCSF Security Finding to the canonical fact-record, then validate it.

    Pure and deterministic: the same finding always yields the same fact-record. The
    field mapping (OCSF source on the left, canonical fact-record key on the right):

      finding.uid                         -> incident_id
      finding.time_dt / first_seen_time   -> incident_start_utc (ISO-8601)
      finding.count / affected_records    -> records_affected
      finding.malware[0].name / actor     -> attacker
      finding.status                       -> containment
      affected resources (type.name list) -> systems
      data_classifications                 -> data_categories
      resources[0].owner.org.name          -> regulated_entity

    The mapped record flows through `validate_fact_record`, so a malformed or
    poisoned finding (a negative count, a control-envelope token smuggled into the
    attacker name) is quarantined HERE, before any prompt sees it. A finding that
    maps cleanly produces a record that hashes exactly as a hand-authored one would,
    so the sealed shas and replay are untouched."""
    if not isinstance(finding, dict):
        raise SiemIngestError(
            f"OCSF finding must be a dict, got {type(finding).__name__}")

    incident_id = str(_require(finding, ("finding_info", "uid")))
    incident_start = str(_require(finding, ("finding_info", "first_seen_time_dt")))

    # records_affected: OCSF carries the impacted record count as a metric. Coerce a
    # numeric string to int; leave any other type to the validator to reject.
    raw_count = _require(finding, ("count",))
    if isinstance(raw_count, bool):
        raise SiemIngestError("OCSF finding 'count' must be a number, got a bool")
    if isinstance(raw_count, str) and raw_count.strip().lstrip("-").isdigit():
        records_affected: object = int(raw_count)
    else:
        records_affected = raw_count

    malware = _optional(finding, ("malware",), [])
    if isinstance(malware, list) and malware and isinstance(malware[0], dict):
        attacker = str(malware[0].get("name", "unknown"))
    else:
        attacker = str(_optional(finding, ("threat_actor", "name"), "unknown"))

    # OCSF status_id: 1=New ... we render the SIEM's textual status as containment
    # posture. The stub finding carries an explicit containment string.
    containment = str(_optional(finding, ("status",), "unknown"))

    resources = _optional(finding, ("resources",), [])
    systems: list[str] = []
    regulated_entity = "unknown"
    if isinstance(resources, list):
        for res in resources:
            if not isinstance(res, dict):
                continue
            name = res.get("name") or res.get("type")
            if isinstance(name, str) and name:
                systems.append(name)
            org = (res.get("owner") or {}).get("org") if isinstance(
                res.get("owner"), dict) else None
            if isinstance(org, dict) and isinstance(org.get("name"), str):
                regulated_entity = org["name"]

    data_categories = _optional(finding, ("data_classifications",), [])
    if not isinstance(data_categories, list):
        data_categories = []

    fact_record = {
        "incident_id": incident_id,
        "incident_start_utc": incident_start,
        "records_affected": records_affected,
        "attacker": attacker,
        "containment": containment,
        "systems": [str(s) for s in systems],
        "data_categories": [str(d) for d in data_categories],
        "regulated_entity": regulated_entity,
    }
    # The INPUT INTEGRITY GATE: the mapped record flows through the E2.2 validator
    # before it is returned to the floor, so nothing malformed reaches a prompt.
    try:
        return validate_fact_record(fact_record)
    except Exception as exc:  # FactRecordError; re-raised as an ingest failure.
        raise SiemIngestError(
            f"OCSF finding {incident_id!r} mapped to an invalid fact-record: {exc}"
        ) from exc


def ingest_finding(connector: SiemConnector) -> dict:
    """Fetch one finding from `connector`, map it to the canonical fact-record, and
    return the validated record. This is the one call the floor makes to ingest from
    a SIEM: it works identically for the stub and a live connector, because the
    mapping and the validation are shared and only the fetch differs."""
    finding = connector.fetch_finding()
    return map_finding_to_fact_record(finding)


# --- The DEFAULT stub connector (offline, deterministic) ----------------------


def _canonical_stub_finding() -> dict:
    """An in-process OCSF Security Finding whose mapping reproduces the canonical
    fact-record the floor runs on (`run_floor.CANONICAL_FACTS`). Built from the
    canonical facts so the stub and the floor never drift: ingesting through the stub
    yields the exact input the sealed runs were driven from, which keeps the
    fact-record hash, the sealed shas, and replay untouched. Imported lazily to
    avoid an import cycle (run_floor imports floor.fact_record, which this module
    also imports)."""
    from floor.run_floor import CANONICAL_FACTS

    facts = CANONICAL_FACTS
    # One OCSF resource per affected system. The regulated entity rides as the
    # owning org on the FIRST resource (not a separate duplicate resource), so the
    # mapped `systems` list reproduces the canonical systems exactly with no repeat.
    resources = [{"name": name, "type": "system"} for name in facts["systems"]]
    if resources:
        resources[0]["owner"] = {"org": {"name": facts["regulated_entity"]}}
    else:
        resources = [{"name": "primary", "type": "system",
                      "owner": {"org": {"name": facts["regulated_entity"]}}}]
    return {
        "class_uid": 2001,  # OCSF Security Finding.
        "finding_info": {
            "uid": facts["incident_id"],
            "first_seen_time_dt": facts["incident_start_utc"],
            "title": "Data exfiltration detected",
        },
        "count": facts["records_affected"],
        "status": facts["containment"],
        "malware": [{"name": facts["attacker"]}],
        "resources": resources,
        "data_classifications": list(facts["data_categories"]),
    }


class StubSiemConnector(SiemConnector):
    """The DEFAULT connector: returns an in-process OCSF finding that maps to the
    canonical fact-record. This is the hackathon's honest `[STUB]` behavior, now
    behind the seam, so CI ingests offline and deterministically and the sealed runs
    are byte-identical. A custom finding can be supplied to exercise the mapping or
    the validator's rejection path."""

    def __init__(self, finding: dict | None = None) -> None:
        self._finding = finding

    def fetch_finding(self) -> dict:
        return self._finding if self._finding is not None else _canonical_stub_finding()


@dataclass
class HttpSiemConnector(SiemConnector):
    """Production ingest from a real SIEM over HTTP. SHIPPED AS A CLEAN INTERFACE,
    not a live call: the network call is left to a deployer to wire to its SIEM,
    because a reproducible offline build must not depend on a live SIEM round-trip.
    This is the seam, documented, that a deployment fills in.

    Wiring (Splunk, Microsoft Sentinel, Elastic Security all follow this shape):

      * Authenticate to the SIEM API (Splunk HEC/REST token, Sentinel Azure AD app,
        Elastic API key) against `base_url`.
      * `fetch_finding()` runs the configured detection search / incident query and
        returns ONE finding normalized to OCSF (Splunk's `| ocsf` pipeline, Sentinel
        OCSF export, Elastic's OCSF integration). Splunk: POST the saved search to
        `/services/search/jobs`, poll, read the first event. Sentinel: GET the
        incident from the Security Insights API. Elastic: query the
        `.alerts-security.alerts-*` index.

    The returned finding then flows through the SAME `map_finding_to_fact_record`
    and validator as the stub, so only WHERE the finding comes from changes."""

    base_url: str
    detection_id: str
    api_token: str = ""

    def fetch_finding(self) -> dict:
        raise NotImplementedError(
            "HttpSiemConnector.fetch_finding is the production seam: authenticate to "
            f"the SIEM at {self.base_url!r}, run detection {self.detection_id!r}, and "
            "return one OCSF Security Finding (Splunk '| ocsf' / Sentinel OCSF export "
            "/ Elastic OCSF integration). The finding then flows through "
            "map_finding_to_fact_record unchanged.")


# A named alias so a deployment reads as targeting its specific SIEM. The wiring is
# identical; only the saved-search/query semantics differ, documented above.
SplunkConnector = HttpSiemConnector


def siem_connector() -> SiemConnector:
    """The connector the floor ingests through. DEFAULT: the in-process stub, so the
    build runs offline and the sealed runs are byte-identical. A deployment returns
    an `HttpSiemConnector`/`SplunkConnector` pointed at its SIEM here instead."""
    return StubSiemConnector()
