"""MISP-core-format event export of the incident (E4.7 / POV 15 S5).

The incident is produced as a well-formed MISP event a CERT / ISAC analyst can
share: typed Attribute objects for the attacker (threat-actor), the malware family
(malware-type), the victim (target-org), the affected systems / data categories,
and the incident timing, plus a galaxy tag for the named ransomware family. Riding
on the STIX export's deterministic id scheme, it is byte-stable. These tests pin:

  (a) the MISP core event shape: a top-level Event with
      uuid/info/date/threat_level_id/analysis and an Attribute list, each attribute
      carrying a real MISP type/category/value and a valid uuid;
  (b) the load-bearing indicators are present (attacker, malware, victim, timing)
      with the right MISP types;
  (c) the named ransomware family carries a MISP galaxy + a ransomware galaxy tag;
  (d) it is deterministic (a second build is byte-identical; no uuid4(), no now());
  (e) it is DERIVED at render time and changes NOTHING in the hashed log: the four
      default sealed captures + their shas are unchanged.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from floor.exports_misp import MispExportError, to_misp_event
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.replay import RunLog, replay

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

SEALED_SHAS = {
    "normal": "89dae1455e3719996036ff4f",
    "inject_contradiction": "f1f2223aa57b4bace83bf3fc",
    "chaos": "303c437140df55fc6694780d",
    "amendment": "0ca07fb0a1f975a84de67966",
}


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


def _valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


# ---- 1. The MISP core event shape ------------------------------------------

def test_event_skeleton(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    for k in ("uuid", "info", "date", "threat_level_id", "analysis", "Attribute"):
        assert k in event, f"missing event field {k}"
    assert _valid_uuid(event["uuid"])
    assert event["threat_level_id"] == "1"  # high
    assert event["Orgc"]["name"] == "Deadline Room"


def test_attributes_are_well_formed(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    assert event["Attribute"]
    for a in event["Attribute"]:
        assert a["type"] and a["category"] and a["value"]
        assert _valid_uuid(a["uuid"])


# ---- 2. The load-bearing indicators ----------------------------------------

def test_attacker_is_a_threat_actor_attribute(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    actor = next(a for a in event["Attribute"] if a["type"] == "threat-actor")
    assert actor["value"] == "LockBit 3.0"


def test_malware_family_attribute(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    malware = next(a for a in event["Attribute"] if a["type"] == "malware-type")
    assert malware["value"] == "LockBit 3.0"


def test_victim_is_a_target_org_attribute(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    victim = next(a for a in event["Attribute"] if a["type"] == "target-org")
    assert victim["value"] == "Meridian Trust Bank N.V."


def test_incident_timing_is_a_datetime_attribute(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    dt = next(a for a in event["Attribute"] if a["type"] == "datetime")
    assert dt["value"].endswith("Z")


# ---- 3. The galaxy / tag structure -----------------------------------------

def test_named_ransomware_family_has_a_galaxy_and_tag(tmp_path):
    packet = _run("normal", tmp_path)
    event = to_misp_event(packet)["Event"]
    assert event["Galaxy"]
    galaxy = event["Galaxy"][0]
    assert galaxy["type"] == "ransomware"
    assert galaxy["GalaxyCluster"][0]["value"] == "LockBit 3.0"
    tags = {t["name"] for t in event["Tag"]}
    assert any("ransomware=" in t and "LockBit 3.0" in t for t in tags)
    assert "tlp:amber" in tags


def test_export_omitted_structurally_when_no_fact_record(tmp_path):
    packet = _run("normal", tmp_path)
    packet["incident"]["fact_record"] = {}
    try:
        to_misp_event(packet)
    except MispExportError:
        return
    raise AssertionError("expected MispExportError when the fact-record is absent")


# ---- 4. Deterministic + render-only ----------------------------------------

def test_event_is_deterministic_byte_for_byte(tmp_path):
    p1 = _run("normal", tmp_path / "a")
    p2 = _run("normal", tmp_path / "b")
    e1 = to_misp_event(p1)
    e2 = to_misp_event(p2)
    assert json.dumps(e1, sort_keys=True) == json.dumps(e2, sort_keys=True)


def test_run_log_sha_byte_identical_with_export(tmp_path):
    packet = _run("normal", tmp_path)
    assert "misp" in packet["ecosystem_exports"]
    assert packet["replay"]["byte_identical"] is True
    run_log_path = Path(packet["_paths"]["json"]).parent / "run-inc-8842-normal.jsonl"
    loaded = RunLog.load(run_log_path)
    assert loaded.sha256() == packet["replay"]["original_sha256"]


def test_sealed_capture_shas_unchanged():
    for mode, expected_prefix in SEALED_SHAS.items():
        log = RunLog.load(DATA / f"run-inc-8842-{mode}.jsonl")
        sha = log.sha256()
        assert sha.startswith(expected_prefix), (
            f"sealed {mode} sha moved: {sha[:24]} != {expected_prefix}")
        assert replay(log).sha256() == sha


def test_sealed_packets_export_a_well_formed_misp_event():
    for mode in SEALED_SHAS:
        packet = json.loads(
            (DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))
        event = to_misp_event(packet)["Event"]
        assert _valid_uuid(event["uuid"])
        types = {a["type"] for a in event["Attribute"]}
        assert "threat-actor" in types and "target-org" in types
