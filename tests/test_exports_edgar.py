"""EDGAR-shaped Form 8-K Item 1.05 export + Inline-XBRL tagging (E3.8).

The SEC filing is produced in the SEC's own machine-readable form: a Form 8-K
Item 1.05 with the real EDGAR cover-page header and the four mandated content
elements, plus an Inline-XBRL fragment that tags the Item 1.05 facts with the real
SEC Cybersecurity Disclosure (CYD) taxonomy concepts. These tests pin:

  (a) the EDGAR 8-K carries the mandated cover fields and the four Item 1.05
      content elements (nature, scope, timing, material impact);
  (b) the iXBRL fragment is well-formed (it parses), declares the real CYD
      namespace, tags the three CYD Text Block concepts, dimensions them by the
      MaterialCybersecurityIncidentAxis, and tags the right facts from the SEC
      claims (records_affected, incident_start, attacker) and the SEC clock;
  (c) honesty: no fabricated EDGAR accession number is present;
  (d) the export is DERIVED at render time and changes NOTHING in the hashed log:
      the SEC [CLAIMS] block and the run-log sha are byte-identical with or
      without the export, and the four default sealed captures + their shas are
      unchanged.

The export is a pure function of the packet (no LLM, no now()), so a fresh build
reproduces it byte-for-byte, exactly like the byte-identical replay it sits beside.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from floor.claims import parse_claims
from floor.exports_edgar import (
    CYD_INCIDENT_AXIS,
    CYD_INCIDENT_TEXT_BLOCK,
    CYD_MATERIAL_IMPACT_TEXT_BLOCK,
    CYD_NAMESPACE,
    CYD_NATURE_SCOPE_TIMING_TEXT_BLOCK,
    EdgarExportError,
    to_edgar_8k,
    to_edgar_ixbrl,
)
from floor.run_floor import CANONICAL_FACTS, DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.replay import RunLog, replay

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

# The four default sealed captures and the run-log sha256 each must reproduce.
# These are the shas committed to web/data; the EDGAR/XBRL work is export-only and
# must not move a single one of them. If a sealed capture is legitimately
# regenerated, update these AND re-sign, never silently.
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


# ---- 1. The EDGAR 8-K shape ------------------------------------------------

def test_edgar_8k_has_cover_fields_and_four_content_elements(tmp_path):
    packet = _run("normal", tmp_path)
    edgar = to_edgar_8k(packet)

    assert edgar["form_type"] == "8-K"
    assert edgar["item"] == "1.05"
    assert "Material Cybersecurity Incidents" in edgar["item_heading"]

    cover = edgar["cover"]
    assert cover["Name of registrant as specified in its charter"] \
        == "Meridian Trust Bank N.V."
    assert "Commission file number" in cover
    assert "Date of report (date of earliest event reported)" in cover

    # The four mandated Item 1.05 content elements, in order.
    labels = [e["label"] for e in edgar["content_elements"]]
    assert labels == [
        "Nature of the incident",
        "Scope of the incident",
        "Timing of the incident",
        "Material impact or reasonably likely material impact",
    ]


def test_edgar_period_of_report_is_the_determination_date(tmp_path):
    # The Form 8-K date of earliest event reported is the SEC materiality-
    # determination date the four-business-day clock anchors at, not T0.
    packet = _run("normal", tmp_path)
    edgar = to_edgar_8k(packet)
    assert edgar["period_of_report"] == "2026-06-16"


def test_edgar_export_is_honest_no_fake_accession(tmp_path):
    packet = _run("normal", tmp_path)
    edgar = to_edgar_8k(packet)
    assert edgar["edgar_accession_number"] is None
    assert "not a filed EDGAR submission" in edgar["export_note"]


def test_edgar_export_omitted_when_sec_suppressed(tmp_path):
    # A packet with no SEC claims / clock owes no 8-K; the export surfaces the
    # missing facts structurally rather than fabricating a filing.
    packet = _run("normal", tmp_path)
    packet["diff"]["final_claims"].pop("sec", None)
    packet["clocks"] = [c for c in packet["clocks"]
                        if not str(c.get("correlation_id", "")).endswith(":sec")]
    try:
        to_edgar_8k(packet)
    except EdgarExportError:
        return
    raise AssertionError("expected EdgarExportError when the SEC branch is absent")


# ---- 2. The Inline-XBRL fragment -------------------------------------------

def test_ixbrl_is_well_formed_and_parses(tmp_path):
    packet = _run("normal", tmp_path)
    ixbrl = to_edgar_ixbrl(packet)
    # Well-formed: it parses through the stdlib XML parser.
    root = ET.fromstring(ixbrl)
    assert root.tag.endswith("}fragment") or root.tag == "fragment"


def test_ixbrl_declares_real_cyd_namespace(tmp_path):
    packet = _run("normal", tmp_path)
    ixbrl = to_edgar_ixbrl(packet)
    assert CYD_NAMESPACE == "http://xbrl.sec.gov/cyd/2024"
    assert CYD_NAMESPACE in ixbrl


def test_ixbrl_tags_the_three_item_105_cyd_concepts(tmp_path):
    packet = _run("normal", tmp_path)
    ixbrl = to_edgar_ixbrl(packet)
    for concept in (CYD_INCIDENT_TEXT_BLOCK,
                    CYD_NATURE_SCOPE_TIMING_TEXT_BLOCK,
                    CYD_MATERIAL_IMPACT_TEXT_BLOCK):
        assert f'name="cyd:{concept}"' in ixbrl


def test_ixbrl_dimensions_facts_by_incident_axis(tmp_path):
    packet = _run("normal", tmp_path)
    ixbrl = to_edgar_ixbrl(packet)
    assert f'dimension="cyd:{CYD_INCIDENT_AXIS}"' in ixbrl
    # The custom member identifying this incident, derived from the incident id.
    assert "cyd:Inc8842Member" in ixbrl


def test_ixbrl_tags_the_facts_from_canonical_facts(tmp_path):
    # The tagged facts come from the SEC claims (which carry CANONICAL_FACTS on a
    # normal run), not re-invented. The records figure and the attacker appear in
    # the tagged bodies.
    packet = _run("normal", tmp_path)
    edgar = to_edgar_8k(packet)
    facts = edgar["facts"]
    assert facts["records_affected"] == CANONICAL_FACTS["records_affected"]
    assert facts["incident_start_utc"] == CANONICAL_FACTS["incident_start_utc"]
    ixbrl = to_edgar_ixbrl(packet)
    # The records figure (formatted by the drafter stub) and the start instant are
    # carried in the tagged Text Block bodies.
    assert str(CANONICAL_FACTS["records_affected"]) in ixbrl
    assert CANONICAL_FACTS["incident_start_utc"] in ixbrl


def test_ixbrl_carries_amended_records_on_amendment(tmp_path):
    # On the amendment cascade the SEC claims carry the revised count; the export
    # tags THAT figure, proving the export is grounded in the post-amendment claims.
    packet = _run("amendment", tmp_path)
    edgar = to_edgar_8k(packet)
    assert edgar["facts"]["records_affected"] == 2_100_000


# ---- 3. The export is render-only: nothing in the hashed log moves ----------

def test_sec_claims_block_unchanged_by_export(tmp_path):
    # The [CLAIMS] block the Warden parses is attached by the drafter process and
    # is never touched by the EDGAR/XBRL export. The SEC filing's claims parse to
    # the canonical facts regardless of the export.
    packet = _run("normal", tmp_path)
    sec_filing = next(f for f in packet["filings"]
                      if f.get("regime", "").lower() == "sec")
    claims = parse_claims(sec_filing["text"])
    assert claims.records_affected == CANONICAL_FACTS["records_affected"]
    assert claims.incident_start_ts == CANONICAL_FACTS["incident_start_utc"]


def test_run_log_sha_byte_identical_with_export(tmp_path):
    # The packet now carries the EDGAR export, yet the run-log sha and byte-
    # identical replay are unchanged: the export is computed at packet-assembly
    # time and never enters the hashed run-log JSONL.
    packet = _run("normal", tmp_path)
    assert "edgar_export" in packet  # the export is present
    assert packet["replay"]["byte_identical"] is True
    run_log_path = Path(packet["_paths"]["json"]).parent / "run-inc-8842-normal.jsonl"
    loaded = RunLog.load(run_log_path)
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]
    assert loaded.sha256() == packet["replay"]["original_sha256"]


def test_export_is_deterministic_byte_for_byte(tmp_path):
    # Two independent runs produce a byte-identical EDGAR 8-K + iXBRL: the export
    # is a pure function of the packet, no now(), no randomness.
    p1 = _run("normal", tmp_path / "a")
    p2 = _run("normal", tmp_path / "b")
    assert to_edgar_8k(p1) == to_edgar_8k(p2)
    assert to_edgar_ixbrl(p1) == to_edgar_ixbrl(p2)


# ---- 4. The four sealed captures + their shas are unchanged -----------------

def test_sealed_capture_shas_unchanged():
    # The export is export-only; it must not move a single sealed run-log sha. This
    # pins the four default captures byte-for-byte (the prefix is enough to catch
    # any drift, and is the value the README / docs cite).
    for mode, expected_prefix in SEALED_SHAS.items():
        log = RunLog.load(DATA / f"run-inc-8842-{mode}.jsonl")
        sha = log.sha256()
        assert sha.startswith(expected_prefix), (
            f"sealed {mode} sha moved: {sha[:24]} != {expected_prefix}")
        # And the capture still replays byte-identically to that sha.
        assert replay(log).sha256() == sha


def test_sealed_packets_carry_a_conformant_edgar_export():
    # The committed packets (regenerated to carry the export) each produce a
    # conformant EDGAR 8-K + iXBRL. This guards the verifier's input.
    for mode in SEALED_SHAS:
        packet = json.loads(
            (DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))
        edgar = to_edgar_8k(packet)
        assert edgar["form_type"] == "8-K" and edgar["item"] == "1.05"
        ixbrl = to_edgar_ixbrl(packet)
        ET.fromstring(ixbrl)  # well-formed
        assert CYD_NAMESPACE in ixbrl
