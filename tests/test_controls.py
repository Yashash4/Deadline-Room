"""test_controls.py -- the control-evidence register with named-framework mapping (E4.4).

The CONTROL-EVIDENCE REGISTER turns the Warden's existing mechanisms into the
audit-committee artifact an auditor accepts: per control, the named-framework
controls the mechanism satisfies (SOC 2 / ISO/IEC 27001:2022 / NIST CSF 2.0), the
EVIDENCE that the control OPERATED in a given run (the run-log event type(s) found
+ the chain head that seals them), and an OPERATED / NOT-EXERCISED status. It is a
pure derived render over the assembled packet, generated from the declarative
floor/controls.yaml catalog, exactly like the completeness screen (E4.2) and the
consistency sheet (E4.3).

Layers:

  Catalog layer over floor/controls.yaml: every catalogued control names a real
  framework control id and a Warden mechanism; the mapping is honest and complete
  (the six core mechanisms each have a row).

  Unit layer over floor/controls.py: each mechanism maps to its named controls and
  the register marks it OPERATED when the proving run-log event is present in the
  run, NOT-EXERCISED when absent; the evidence points at the real run-log event(s)
  and the run's chain head; the contradiction veto operates only when a
  contradiction is planted.

  Render layer over the packet HTML: the control -> framework -> evidence table is
  rendered with the status badge and the sealing chain head.

  Derived layer: no LLM surface, no run-log mutation, deterministic across runs.

  Guard layer: the four DEFAULT sealed captures and their run-log shas are
  byte-for-byte unchanged by this render/derive-only feature.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.controls as controls_mod
from floor.controls import (
    STATUS_NOT_EXERCISED,
    STATUS_OPERATED,
    ControlEvidenceRegister,
    controls_record,
    load_catalog,
    register_for_packet,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "web" / "data"

# The six core mechanisms the register must cover, by control id, and the
# mechanism word the catalog row must name (a smoke check that the mapping is the
# real Warden component, not a placeholder).
CORE_CONTROLS = {
    "SOD-01": "release_gate",
    "VAL-01": "diff",
    "AVL-01": "ledger",
    "INT-01": "chain",
    "TML-01": "clocks",
    "DEC-01": "reportability",
}


# ---- helpers ----------------------------------------------------------------

def _packet(mode: str) -> dict:
    return json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))


def _by_id(register: ControlEvidenceRegister) -> dict:
    return {c.id: c for c in register.controls}


# ---- catalog layer: the mapping is honest, real, and complete ----------------

def test_catalog_covers_the_six_core_mechanisms():
    specs = {s.id: s for s in load_catalog()}
    for cid in CORE_CONTROLS:
        assert cid in specs, f"control {cid} missing from the catalog"


def test_each_control_maps_to_real_named_framework_ids():
    # Every control names at least the three core frameworks, each with a real,
    # non-empty control id and a one-line criterion. No invented or blank id.
    for spec in load_catalog():
        standards = {f.standard for f in spec.frameworks}
        assert {"SOC 2", "ISO/IEC 27001:2022", "NIST CSF 2.0"} <= standards, (
            f"{spec.id} must map to SOC 2, ISO 27001, and NIST CSF")
        for f in spec.frameworks:
            assert f.ref, f"{spec.id}/{f.standard} has an empty control id"
            assert f.criterion, f"{spec.id}/{f.standard} {f.ref} has no criterion"


def test_specific_named_control_ids_are_the_expected_real_identifiers():
    # Pin the headline mappings to the exact real framework ids, so a future edit
    # that swaps in a wrong id (or invents one) fails here.
    specs = {s.id: s for s in load_catalog()}
    sod = {f.standard: f.ref for f in specs["SOD-01"].frameworks}
    assert sod["SOC 2"] == "CC1.3"
    assert sod["ISO/IEC 27001:2022"] == "A.5.3"
    assert sod["NIST CSF 2.0"] == "PR.AA-05"
    intg = {f.standard: f.ref for f in specs["INT-01"].frameworks}
    assert intg["SOC 2"] == "CC7.3"
    assert intg["ISO/IEC 27001:2022"] == "A.8.15"
    assert intg["NIST CSF 2.0"] == "PR.DS-06"


def test_each_control_names_its_real_warden_mechanism():
    specs = {s.id: s for s in load_catalog()}
    for cid, mech_word in CORE_CONTROLS.items():
        assert mech_word in specs[cid].mechanism.lower(), (
            f"{cid} must name the {mech_word} mechanism")


# ---- unit layer: OPERATED when the proving event is present ------------------

def test_always_on_controls_operate_on_a_clean_run():
    # The normal capture reaches release, runs the clocks, the ledger, and seals a
    # signed chain, so the four always-on controls OPERATED.
    register = register_for_packet(_packet("normal"))
    by_id = _by_id(register)
    for cid in ("SOD-01", "AVL-01", "INT-01", "TML-01"):
        assert by_id[cid].status == STATUS_OPERATED, f"{cid} should be OPERATED"
        assert by_id[cid].operated is True
        assert by_id[cid].evidence.found_events, (
            f"{cid} OPERATED must carry the proving event(s)")


def test_contradiction_veto_operates_only_when_a_contradiction_is_planted():
    # VAL-01 (the veto) is NOT-EXERCISED on a clean run (no diff_blocked), and
    # OPERATED on the inject_contradiction run (diff_blocked is present).
    clean = _by_id(register_for_packet(_packet("normal")))["VAL-01"]
    assert clean.status == STATUS_NOT_EXERCISED
    assert clean.operated is False
    assert clean.evidence.found_events == ()

    injected = _by_id(register_for_packet(_packet("inject_contradiction")))["VAL-01"]
    assert injected.status == STATUS_OPERATED
    assert "protocol_event:diff_blocked" in injected.evidence.found_events


def test_decision_gate_is_not_exercised_on_the_core_captures():
    # The four default captures do not run the reportability beat, so DEC-01 is
    # honestly NOT-EXERCISED (not a failure, just an unexercised control path).
    for mode in ("normal", "inject_contradiction", "chaos", "amendment"):
        dec = _by_id(register_for_packet(_packet(mode)))["DEC-01"]
        assert dec.status == STATUS_NOT_EXERCISED


def test_decision_gate_operates_when_reportability_is_present():
    # A synthetic packet carrying a reportability section exercises DEC-01.
    packet = {
        "replay": {"chain_head": "a" * 64,
                   "signature": {"pubkey_fingerprint": "fp-1"}},
        "reportability": {"regimes": [{"regime": "NIS2", "reportable": False}]},
    }
    dec = _by_id(register_for_packet(packet))["DEC-01"]
    assert dec.status == STATUS_OPERATED
    assert dec.evidence.found_events  # the reportability event token is recorded


# ---- unit layer: the evidence points at the real run-log event + chain hash --

def test_operated_evidence_points_at_the_real_run_log_event_and_chain_head():
    packet = _packet("inject_contradiction")
    register = register_for_packet(packet)
    by_id = _by_id(register)
    head = packet["replay"]["chain_head"]
    fp = packet["replay"]["signature"]["pubkey_fingerprint"]

    sod = by_id["SOD-01"]
    # the named run-log event types behind the two-key release
    assert "release_signoff" in sod.evidence.found_events
    assert "protocol_event:human_released" in sod.evidence.found_events
    # the evidence is sealed at THIS run's chain head and signed
    assert sod.evidence.chain_head == head
    assert sod.evidence.signature_fp == fp
    assert len(head) == 64

    veto = by_id["VAL-01"]
    assert "protocol_event:diff_blocked" in veto.evidence.found_events
    assert veto.evidence.chain_head == head


def test_not_exercised_control_carries_no_seal():
    # A NOT-EXERCISED control did not operate in this run, so it carries no chain
    # head / signature (there is no operating event to seal).
    veto = _by_id(register_for_packet(_packet("normal")))["VAL-01"]
    assert veto.status == STATUS_NOT_EXERCISED
    assert veto.evidence.chain_head == ""
    assert veto.evidence.signature_fp == ""


def test_only_admitted_transitions_count_as_evidence():
    # A rejected (illegal) transition is not evidence the control's path ran. A
    # packet whose human_released transition was REJECTED does not credit SOD-01
    # via that event token (it still has the release_signoff section, but the
    # protocol_event token must come from an admitted transition).
    packet = {
        "replay": {"chain_head": "b" * 64, "signature": {"pubkey_fingerprint": "fp"}},
        "release": {"signoffs": [{"role": "general_counsel"}, {"role": "head_of_ir"}]},
        "state_transitions": [
            {"event": "human_released", "admitted": False, "reason": "blocked"},
            {"event": "signoff_opened", "admitted": True},
        ],
    }
    sod = _by_id(register_for_packet(packet))["SOD-01"]
    # release_signoff (from the present signoffs section) and the ADMITTED
    # signoff_opened are evidence; the REJECTED human_released is not.
    assert "release_signoff" in sod.evidence.found_events
    assert "protocol_event:signoff_opened" in sod.evidence.found_events
    assert "protocol_event:human_released" not in sod.evidence.found_events
    assert sod.status == STATUS_OPERATED  # it still operated via the other events


# ---- unit layer: the register verdict and counts -----------------------------

def test_register_verdict_counts_operated_and_not_exercised():
    register = register_for_packet(_packet("inject_contradiction"))
    assert register.total == len(load_catalog())
    assert register.operated_count == 5  # all but the reportability gate
    assert register.not_exercised_count == 1
    assert "5 of 6" in register.verdict
    assert "was not exercised" in register.verdict


# ---- packet-level record -----------------------------------------------------

def test_controls_record_over_packet():
    rec = controls_record(_packet("normal"))
    assert rec["total"] == len(load_catalog())
    assert rec["operated_count"] >= 4
    ids = {c["id"] for c in rec["controls"]}
    assert set(CORE_CONTROLS) <= ids
    for c in rec["controls"]:
        assert c["status"] in (STATUS_OPERATED, STATUS_NOT_EXERCISED)
        assert c["framework_refs"]  # the compact "SOC 2 CC1.3; ..." string


def test_controls_record_empty_only_when_catalog_empty(monkeypatch):
    # With the real catalog the record is always non-empty (a run that exercises
    # no control still yields a full NOT-EXERCISED register). It returns {} only
    # when the catalog itself is empty.
    assert controls_record({}) != {}
    monkeypatch.setattr(controls_mod, "load_catalog", lambda: [])
    assert controls_record(_packet("normal")) == {}


# ---- derived: no LLM surface, no run-log mutation ----------------------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    src = inspect.getsource(controls_mod)
    # No LLM call, no wall-clock / RNG, no run-log WRITER. ("run_log_events" is a
    # read-only catalog field name, not a writer, so the writer tokens below are
    # the precise check: a mutation would have to call one of these.)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", ".save("):
        assert token not in src, f"controls module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    packet = _packet("inject_contradiction")
    before = json.dumps(packet, sort_keys=True)
    register_for_packet(packet)
    controls_record(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_register_is_deterministic_across_two_derivations():
    packet = _packet("inject_contradiction")
    a = controls_record(packet)
    b = controls_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---- render layer: the control -> framework -> evidence table ----------------

def test_packet_html_renders_the_control_register():
    from floor.packet import _render_html
    packet = _packet("inject_contradiction")
    packet["controls"] = controls_record(packet)
    html = _render_html(packet)
    assert "Control-evidence register" in html
    # the headline control row, its named framework ids, and the OPERATED badge
    assert "SOD-01" in html
    assert "CC1.3" in html
    assert "A.5.3" in html
    assert "PR.AA-05" in html
    assert "OPERATED" in html
    # the veto row renders OPERATED with its run-log evidence on this run
    assert "VAL-01" in html
    assert "diff_blocked" in html
    # the sealing chain head is shown
    assert packet["replay"]["chain_head"] in html


def test_packet_html_renders_not_exercised_on_a_clean_run():
    from floor.packet import _render_html
    packet = _packet("normal")
    packet["controls"] = controls_record(packet)
    html = _render_html(packet)
    assert "NOT-EXERCISED" in html  # the veto on a clean run


# ---- guard: the four DEFAULT sealed captures and shas are untouched ----------

def test_default_sealed_captures_and_shas_unchanged():
    """The control register is a render/derive-only feature; the four committed
    sealed captures (normal, inject_contradiction, chaos, amendment) and their
    run-log shas must be byte-for-byte unchanged. This pins them so a regression
    that perturbs a sealed capture fails here."""
    from warden.replay import RunLog
    for mode in ("normal", "inject_contradiction", "chaos", "amendment"):
        log_path = DATA / f"run-inc-8842-{mode}.jsonl"
        assert log_path.exists(), f"sealed capture missing: {log_path}"
        sha = hashlib.sha256(log_path.read_bytes()).hexdigest()
        assert len(sha) == 64
        packet_path = DATA / f"packet-{mode}.json"
        if packet_path.exists():
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            recorded = packet.get("replay", {}).get("original_sha256")
            loaded = RunLog.load(log_path)
            assert loaded.sha256() == recorded, (
                f"{mode}: run-log sha drifted from the committed packet")


def test_control_register_receipt_over_a_committed_capture():
    # The receipt script derives the register from a committed capture and exits 0
    # (at least one control operated and is evidenced).
    packet = DATA / "packet-inject_contradiction.json"
    if not packet.exists():
        return  # capture not present in this checkout; the unit layer covers it
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import control_register
    rc = control_register.main([str(packet)])
    assert rc == 0
