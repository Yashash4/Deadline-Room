"""OASIS STIX 2.1 bundle export of the incident (E4.7 / POV 15 S1).

The incident is produced as a valid STIX 2.1 bundle the threat-intel ecosystem
ingests: the attacker LockBit 3.0 as a threat-actor + malware, the regulated entity
as an identity, the incident as an incident SDO with the recommended core incident
extension, the affected systems / data categories as observed-data, and a
course-of-action per oracle-CONFIRMED control finding, all tied by relationship
SROs. These tests pin:

  (a) the bundle is well-formed STIX 2.1: a bundle skeleton, every SDO with
      spec_version 2.1 + a spec-conformant <type>--<UUID> id + created/modified,
      every SRO with relationship_type/source_ref/target_ref resolving to objects
      in the bundle;
  (b) the required SDO set is present (threat-actor, malware, identity, incident,
      course-of-action) and the incident carries the core incident extension;
  (c) the SDOs carry the real fact-record values (LockBit 3.0, the entity, the
      systems, the timing);
  (d) the ids are deterministic UUIDv5 (a second build is byte-identical; no
      uuid4(), no now());
  (e) the export is DERIVED at render time and changes NOTHING in the hashed log:
      the run-log sha is byte-identical with the export present, and the four
      default sealed captures + their shas are unchanged.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from floor.exports_stix import (
    INCIDENT_CORE_EXTENSION,
    STIX_SPEC_VERSION,
    StixExportError,
    to_stix_bundle,
)
from floor.run_floor import CANONICAL_FACTS, DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.replay import RunLog, replay

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

# The four default sealed captures and the run-log sha256 prefix each must
# reproduce. The STIX work is export-only and must not move a single one of them.
SEALED_SHAS = {
    "normal": "89dae1455e3719996036ff4f",
    "inject_contradiction": "f1f2223aa57b4bace83bf3fc",
    "chaos": "303c437140df55fc6694780d",
    "amendment": "0ca07fb0a1f975a84de67966",
}

REQUIRED_SDO_TYPES = (
    "threat-actor", "malware", "identity", "incident", "course-of-action")


def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return room, clients


def _stub_draft_fns():
    fns = {}

    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    for r in DRAFTER_ROLES:
        fns[r.branch] = make(r.regime)

    def sec_characterize(counterpart_text):
        return "approximately 2.1 million affected records, data categories bounded"

    def nis2_characterize(counterpart_text):
        return counterpart_text

    fns["sec:characterize"] = sec_characterize
    fns["nis2:characterize"] = nis2_characterize
    return fns


def _run(mode, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                     draft_fns=_stub_draft_fns())


def _valid_stix_id(obj_id: str) -> bool:
    parts = str(obj_id).split("--", 1)
    if len(parts) != 2:
        return False
    try:
        uuid.UUID(parts[1])
    except ValueError:
        return False
    return True


# ---- 1. The bundle skeleton + required SDO set -----------------------------

def test_bundle_skeleton_and_required_sdos(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    assert bundle["type"] == "bundle"
    assert _valid_stix_id(bundle["id"]) and bundle["id"].startswith("bundle--")

    by_type = {}
    for o in bundle["objects"]:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    for t in REQUIRED_SDO_TYPES:
        assert by_type.get(t, 0) >= 1, f"missing required SDO type {t}: {by_type}"


def test_threat_actor_and_malware_for_lockbit(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
    malware = [o for o in bundle["objects"] if o["type"] == "malware"]
    assert any(o["name"] == "LockBit 3.0" for o in actors)
    assert any(o["name"] == "LockBit 3.0" and o["is_family"] for o in malware)
    assert malware[0]["malware_types"] == ["ransomware"]


def test_identity_is_the_regulated_entity(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    ids = [o for o in bundle["objects"] if o["type"] == "identity"]
    assert any(o["name"] == "Meridian Trust Bank N.V."
               and o["identity_class"] == "organization" for o in ids)


def test_incident_sdo_has_core_incident_extension(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    incident = next(o for o in bundle["objects"] if o["type"] == "incident")
    assert INCIDENT_CORE_EXTENSION in incident["extensions"]
    ext = incident["extensions"][INCIDENT_CORE_EXTENSION]
    assert ext["extension_type"] == "property-extension"


def test_course_of_action_per_confirmed_control(tmp_path):
    # The normal run exercises four controls (SOD/AVL/INT/TML), each a relevant
    # control of the incident, so there is at least one course-of-action.
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    coas = [o for o in bundle["objects"] if o["type"] == "course-of-action"]
    assert coas, "expected at least one course-of-action for the operated controls"


def test_inject_contradiction_adds_a_finding_course_of_action(tmp_path):
    # The contradiction run additionally OPERATES the VAL-01 veto, so it carries
    # more courses of action than the clean run.
    normal = to_stix_bundle(_run("normal", tmp_path / "n"))
    contra = to_stix_bundle(_run("inject_contradiction", tmp_path / "c"))
    n = sum(1 for o in normal["objects"] if o["type"] == "course-of-action")
    c = sum(1 for o in contra["objects"] if o["type"] == "course-of-action")
    assert c > n


# ---- 2. STIX 2.1 conformance of every object -------------------------------

def test_every_sdo_has_required_properties_and_valid_id(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    for o in bundle["objects"]:
        assert _valid_stix_id(o["id"]), f"bad id: {o['id']}"
        if o["type"] == "relationship":
            assert o["relationship_type"]
            assert o["source_ref"] and o["target_ref"]
        else:
            assert o["spec_version"] == STIX_SPEC_VERSION
            assert o["created"] and o["modified"]


def test_relationships_resolve_to_objects_in_the_bundle(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    ids = {o["id"] for o in bundle["objects"]}
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels
    for r in rels:
        assert r["source_ref"] in ids
        assert r["target_ref"] in ids


def test_timestamps_are_stix_z_form(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    for o in bundle["objects"]:
        if o["type"] != "relationship":
            assert o["created"].endswith("Z")
            assert "+00:00" not in o["created"]


# ---- 3. Grounded in the real facts -----------------------------------------

def test_incident_description_carries_the_real_facts(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    incident = next(o for o in bundle["objects"] if o["type"] == "incident")
    assert "Meridian Trust Bank N.V." in incident["description"]
    assert "LockBit 3.0" in incident["description"]


def test_observed_data_lists_systems_and_data_categories(tmp_path):
    packet = _run("normal", tmp_path)
    bundle = to_stix_bundle(packet)
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    for system in CANONICAL_FACTS["systems"]:
        assert system in observed["description"]
    for cat in CANONICAL_FACTS["data_categories"]:
        assert cat in observed["description"]


def test_export_omitted_structurally_when_no_fact_record(tmp_path):
    packet = _run("normal", tmp_path)
    packet["incident"]["fact_record"] = {}
    try:
        to_stix_bundle(packet)
    except StixExportError:
        return
    raise AssertionError("expected StixExportError when the fact-record is absent")


# ---- 4. Deterministic + render-only (nothing in the hashed log moves) -------

def test_bundle_is_deterministic_byte_for_byte(tmp_path):
    p1 = _run("normal", tmp_path / "a")
    p2 = _run("normal", tmp_path / "b")
    b1 = to_stix_bundle(p1)
    b2 = to_stix_bundle(p2)
    assert json.dumps(b1, sort_keys=True) == json.dumps(b2, sort_keys=True)


def test_run_log_sha_byte_identical_with_export(tmp_path):
    packet = _run("normal", tmp_path)
    assert "ecosystem_exports" in packet
    assert "stix" in packet["ecosystem_exports"]
    assert packet["replay"]["byte_identical"] is True
    run_log_path = Path(packet["_paths"]["json"]).parent / "run-inc-8842-normal.jsonl"
    loaded = RunLog.load(run_log_path)
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]
    assert loaded.sha256() == packet["replay"]["original_sha256"]


def test_sealed_capture_shas_unchanged():
    for mode, expected_prefix in SEALED_SHAS.items():
        log = RunLog.load(DATA / f"run-inc-8842-{mode}.jsonl")
        sha = log.sha256()
        assert sha.startswith(expected_prefix), (
            f"sealed {mode} sha moved: {sha[:24]} != {expected_prefix}")
        assert replay(log).sha256() == sha


def test_sealed_packets_export_a_conformant_stix_bundle():
    for mode in SEALED_SHAS:
        packet = json.loads(
            (DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))
        bundle = to_stix_bundle(packet)
        assert bundle["type"] == "bundle"
        by_type = {o["type"] for o in bundle["objects"]}
        for t in REQUIRED_SDO_TYPES:
            assert t in by_type


def test_sealed_packets_carry_the_ecosystem_exports_block():
    # The regenerated captures carry the STIX / OSCAL / MISP exports in the packet
    # JSON, so the web viewer and the casefile see them.
    for mode in SEALED_SHAS:
        packet = json.loads(
            (DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))
        ex = packet.get("ecosystem_exports", {})
        assert set(ex.keys()) == {"stix", "oscal", "misp"}, mode


# ---- 5. The packet HTML renders the ecosystem-exports reference ------------

def test_packet_html_renders_the_ecosystem_exports_section(tmp_path):
    from floor.packet import _render_html
    packet = _run("normal", tmp_path)
    html = _render_html(packet)
    assert "Ecosystem exports (STIX 2.1 / OSCAL / MISP)" in html
    assert "STIX 2.1 bundle (OASIS)" in html
    assert "OSCAL assessment-results (NIST)" in html
    assert "MISP event (core format)" in html
    # honest coverage labelling carries the BUILT vs STUB note
    assert "BUILT" in html and "STUB" in html
