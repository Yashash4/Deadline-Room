"""test_assertion.py -- the signed management assertion / SOC-2-style letter (E4.8).

The MANAGEMENT ASSERTION is the one-page letter an audit engagement is anchored on:
management asserts the relevant controls operated effectively over the reporting
period, the control-evidence register (E4.4) is the supporting evidence, and the
assertion is signed. This module is a PURE DERIVED summary over the SAME register
the packet's controls block is built from, rendered as a formal attestation letter,
with its digest signed by a SEPARATE, DETACHED Ed25519 signature.

Layers:

  Derivation layer over floor/assertion.py: the assertion lists the asserted
  controls (id, framework refs, OPERATED / NOT-EXERCISED, evidence) exactly from
  the register, the period (the run window from the packet's clocks), and the
  one-line verdict.

  Signature layer: the assertion document's canonical digest is signed and
  verifies; tampering any asserted field breaks the signature; the signature is
  separate from and never folded into the run-log bound signature.

  Render layer over the packet HTML: the attestation letter renders with the
  controls, the period, and the digest.

  Derived layer: no LLM surface, no run-log mutation, deterministic across runs.

  Guard layer: the four DEFAULT sealed captures, their run-log shas, and the
  run-log .sig.json sidecars are byte-for-byte unchanged by this derive/sign-only
  feature; the emitted assertion sidecar is a SEPARATE artifact.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.assertion as assertion_mod
from floor.assertion import (
    ASSERTION_SIGNER,
    assertion_digest,
    assertion_record,
    build_assertion,
    canonical_assertion_bytes,
    render_letter,
    sign_assertion,
    verify_assertion_signature,
)
from floor.controls import STATUS_NOT_EXERCISED, STATUS_OPERATED, register_for_packet

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "web" / "data"

CORE_CONTROLS = ("SOD-01", "VAL-01", "AVL-01", "INT-01", "TML-01", "DEC-01")


def _packet(mode: str) -> dict:
    return json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))


# ---- derivation layer: the assertion mirrors the register --------------------

def test_assertion_lists_the_register_controls_with_status():
    # Every catalogued control appears in the assertion with the SAME status the
    # register derives for the same run.
    packet = _packet("inject_contradiction")
    register = register_for_packet(packet)
    assertion = build_assertion(packet)
    reg_status = {c.id: c.status for c in register.controls}
    assert assertion.total == register.total
    assert {c.id for c in assertion.controls} == set(reg_status)
    for c in assertion.controls:
        assert c.status == reg_status[c.id]
        assert c.status in (STATUS_OPERATED, STATUS_NOT_EXERCISED)
        assert c.framework_refs  # the compact "SOC 2 CC1.3; ..." string
    assert set(CORE_CONTROLS) <= {c.id for c in assertion.controls}


def test_assertion_counts_match_the_register():
    packet = _packet("inject_contradiction")
    register = register_for_packet(packet)
    assertion = build_assertion(packet)
    assert assertion.operated_count == register.operated_count
    assert assertion.not_exercised_count == register.not_exercised_count
    # The inject_contradiction run exercises 5 of 6 (the veto fires; the decision
    # gate is not exercised on this capture).
    assert assertion.operated_count == 5
    assert assertion.not_exercised_count == 1


def test_assertion_verdict_states_operated_over_total():
    assertion = build_assertion(_packet("inject_contradiction"))
    assert "5 of 6" in assertion.verdict
    assert "OPERATED" in assertion.verdict
    assert "was not exercised" in assertion.verdict


def test_assertion_period_is_the_run_window_from_the_clocks():
    # The period start is the earliest clock start, the end the latest deadline,
    # both verbatim from the packet's clock rows (a deterministic run window).
    packet = _packet("inject_contradiction")
    assertion = build_assertion(packet)
    starts = [c.get("started") for c in packet["clocks"] if c.get("started")]
    deadlines = [c.get("deadline") for c in packet["clocks"] if c.get("deadline")]
    assert assertion.period.start in starts
    assert assertion.period.end in deadlines
    # the start is no later than every clock start; the end no earlier than every
    # deadline (it is the window that covers them all).
    assert all(assertion.period.start <= s for s in starts)
    assert all(assertion.period.end >= d for d in deadlines)


def test_assertion_carries_incident_reference_and_entity():
    packet = _packet("inject_contradiction")
    assertion = build_assertion(packet)
    assert assertion.incident_id == packet["incident"]["incident_id"]
    assert assertion.regulated_entity == (
        packet["incident"]["fact_record"]["regulated_entity"])


def test_assertion_references_the_same_seal_as_the_register():
    packet = _packet("inject_contradiction")
    assertion = build_assertion(packet)
    assert assertion.chain_head == packet["replay"]["chain_head"]
    assert assertion.signature_fp == (
        packet["replay"]["signature"]["pubkey_fingerprint"])


# ---- the letter renders the assertion ----------------------------------------

def test_letter_states_preamble_controls_period_and_verdict():
    assertion = build_assertion(_packet("inject_contradiction"))
    letter = render_letter(assertion)
    assert "MANAGEMENT ASSERTION" in letter
    assert assertion.preamble in letter
    # every control id appears in the letter with its status
    for c in assertion.controls:
        assert c.id in letter
        assert c.status in letter
    assert assertion.period.start in letter
    assert assertion.period.end in letter
    assert assertion.verdict in letter
    assert ASSERTION_SIGNER in letter


# ---- signature layer: the digest + signature verify --------------------------

def test_digest_and_signature_verify_over_the_assertion():
    document = build_assertion(_packet("inject_contradiction")).as_document()
    record = sign_assertion(document)
    assert record["assertion_digest"] == assertion_digest(document)
    assert verify_assertion_signature(document, record) is True


def test_signature_is_detached_and_separate_from_the_run_log_signature():
    document = build_assertion(_packet("normal")).as_document()
    record = sign_assertion(document)
    assert record["detached"] is True
    assert record["separate_from_run_log_signature"] is True
    assert record["signed_payload"] == "canonical_json(management_assertion)"
    # the demo-key caveat travels with it
    assert record["demo_key"] is True
    assert "Demo key" in record["caveat"]


def test_tampering_any_asserted_field_breaks_the_signature():
    document = build_assertion(_packet("inject_contradiction")).as_document()
    record = sign_assertion(document)
    # a single edited asserted field moves the recomputed digest and fails
    for mutate in (
        lambda d: d.__setitem__("operated_count", d["operated_count"] + 1),
        lambda d: d["controls"][0].__setitem__("status", "TAMPERED"),
        lambda d: d["period"].__setitem__("end", "2099-01-01T00:00:00+00:00"),
        lambda d: d.__setitem__("verdict", "Management asserts nothing."),
    ):
        tampered = json.loads(json.dumps(document))
        mutate(tampered)
        assert verify_assertion_signature(tampered, record) is False


def test_verify_returns_false_on_malformed_record():
    document = build_assertion(_packet("normal")).as_document()
    assert verify_assertion_signature(document, {}) is False
    assert verify_assertion_signature(
        document, {"assertion_digest": assertion_digest(document),
                   "signature": "zz", "public_key": "00"}) is False


def test_signature_is_deterministic():
    # Ed25519 is deterministic, so the same assertion always yields the same
    # signature (the captured sidecar is reproducible byte for byte).
    document = build_assertion(_packet("chaos")).as_document()
    a = sign_assertion(document)
    b = sign_assertion(document)
    assert a["signature"] == b["signature"]
    assert a["assertion_digest"] == b["assertion_digest"]


# ---- packet-level record + render --------------------------------------------

def test_assertion_record_over_packet():
    rec = assertion_record(_packet("normal"))
    assert rec["total"] == build_assertion(_packet("normal")).total
    assert rec["digest"] == assertion_digest(rec["document"])
    assert "MANAGEMENT ASSERTION" in rec["letter"]
    assert rec["operated_count"] >= 4


def test_assertion_record_empty_only_when_no_control(monkeypatch):
    # With the real register the record is always non-empty (a run that exercises
    # no control still yields a full NOT-EXERCISED assertion). It returns {} only
    # when the register carries no control at all.
    assert assertion_record(_packet("normal")) != {}

    class _Empty:
        total = 0
        controls = ()
    monkeypatch.setattr(assertion_mod, "register_for_packet", lambda p: _Empty())
    assert assertion_record(_packet("normal")) == {}


def test_packet_html_renders_the_assertion_letter():
    from floor.packet import _render_html
    packet = _packet("inject_contradiction")
    packet["assertion"] = assertion_record(packet)
    html = _render_html(packet)
    assert "Management assertion" in html
    assert "attestation letter" in html
    # the digest the signature is taken over, and a headline control, appear
    assert packet["assertion"]["digest"] in html
    assert "SOD-01" in html
    assert "Period asserted" in html


# ---- derived: no LLM surface, deterministic, no run-log mutation -------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    src = inspect.getsource(assertion_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", ".save("):
        assert token not in src, f"assertion module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    packet = _packet("inject_contradiction")
    before = json.dumps(packet, sort_keys=True)
    build_assertion(packet)
    assertion_record(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_assertion_is_deterministic_across_two_derivations():
    packet = _packet("inject_contradiction")
    a = assertion_record(packet)
    b = assertion_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_canonical_bytes_use_the_sorted_compact_recipe():
    document = build_assertion(_packet("normal")).as_document()
    raw = canonical_assertion_bytes(document)
    # the same recipe the run log and the bound signing payload use: sorted keys,
    # no whitespace.
    assert raw == json.dumps(
        document, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---- guard: the four DEFAULT sealed captures and shas are untouched ----------

def test_default_sealed_run_log_shas_unchanged():
    """The signed assertion is a derive/sign-only feature; the four committed
    sealed run-logs and their recorded shas must be byte-for-byte unchanged, and
    the run-log .sig.json sidecars (the run-log signature) must be untouched: the
    assertion signature is a SEPARATE sidecar."""
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
        # the run-log signature sidecar still names the run-log bound payload, not
        # the assertion (the assertion signature is a separate file).
        sig_path = log_path.with_suffix(log_path.suffix + ".sig.json")
        if sig_path.exists():
            sig = json.loads(sig_path.read_text(encoding="utf-8"))
            assert sig.get("signed_payload", "").startswith("canonical_json{")
            assert "assertion" not in sig.get("signed_payload", "")


def test_emitted_assertion_sidecar_verifies_against_the_packet():
    # The committed assertion sidecar (web/data/assertion-<mode>.json) verifies
    # against the assertion re-derived from the committed packet.
    for mode in ("normal", "inject_contradiction", "chaos", "amendment"):
        sidecar_path = DATA / f"assertion-{mode}.json"
        if not sidecar_path.exists():
            continue
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        document = build_assertion(_packet(mode)).as_document()
        assert verify_assertion_signature(document, sidecar) is True


def test_verify_assertion_receipt_over_a_committed_capture():
    # The receipt script verifies the committed sidecar against the committed
    # packet and exits 0.
    sidecar = DATA / "assertion-inject_contradiction.json"
    if not sidecar.exists():
        return
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import verify_assertion
    rc = verify_assertion.main(["inject_contradiction"])
    assert rc == 0
