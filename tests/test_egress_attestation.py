"""E5.8 signed egress attestation + sovereign (air-gapped) pre-flight.

These tests pin the real guarantees:

  * the sovereign pre-flight REFUSES to start (raises, the CLI exits nonzero) when
    any role resolves to a closed hosted model, and PASSES when every role is
    open / self-hosted. Default off: a run without --sovereign is unaffected.
  * the signed egress attestation verifies under the committed key, and a tampered
    copy (any edited field) is INVALID.
  * CRITICALLY: the egress signature is a SEPARATE detached sidecar under a
    DISTINCT label. Producing it does NOT change the per-run 4-field bound payload,
    the four sealed run-log shas, or the four committed .sig.json signatures.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from floor import roster
from floor.egress_attestation import (
    EGRESS_SIGNED_PAYLOAD,
    SovereigntyError,
    assert_sovereign,
    build_egress_attestation,
    canonical_egress_bytes,
    egress_digest,
    egress_record,
    sign_egress,
    verify_egress_signature,
)
from warden.signing import DEMO_KEY_CAVEAT, verify_run_log_jsonl

DATA = Path(__file__).resolve().parents[1] / "web" / "data"
SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


# --- the sovereign pre-flight ------------------------------------------------

def test_dev_provider_set_is_fully_sovereign():
    att = build_egress_attestation(roster.PROVIDER_DEV)
    assert att.sovereign is True
    assert att.self_hosted_count == att.total
    assert att.hosted_roles == ()
    # Every resolved role is on the open, self-hostable Featherless family.
    for r in att.roles:
        assert r.provider == roster.FEATHERLESS
        assert r.self_hosted is True


def test_sovereign_preflight_passes_when_every_role_is_open():
    att = assert_sovereign(roster.PROVIDER_DEV)
    assert att.sovereign is True
    assert "zero breach facts left the perimeter" in att.verdict


def test_prod_provider_set_routes_some_roles_to_a_closed_hosted_model():
    att = build_egress_attestation(roster.PROVIDER_PROD)
    # prod moves the racing drafters onto the closed AI/ML gateway, so at least one
    # role is NOT self-hosted: the run is not sovereign.
    assert att.sovereign is False
    assert len(att.hosted_roles) >= 1
    for r in att.hosted_roles:
        assert r.provider == roster.AIMLAPI
        assert r.self_hosted is False
    assert "NOT sovereign" in att.verdict


def test_sovereign_preflight_refuses_a_closed_role():
    with pytest.raises(SovereigntyError) as exc:
        assert_sovereign(roster.PROVIDER_PROD)
    # The refusal names the offending roles and is specific, not a bare flag.
    offenders = exc.value.offenders
    assert offenders
    for o in offenders:
        assert o.provider == roster.AIMLAPI
        assert o.role_label in str(exc.value)
    assert "refuses to start" in str(exc.value)


def test_unknown_provider_set_is_rejected_not_silently_empty():
    with pytest.raises(ValueError):
        build_egress_attestation("bogus")


# --- the signed attestation --------------------------------------------------

def test_egress_attestation_verifies_under_the_committed_key():
    att = build_egress_attestation(roster.PROVIDER_DEV)
    document = att.as_document()
    sig = sign_egress(document)
    assert sig["signed_payload"] == EGRESS_SIGNED_PAYLOAD
    assert sig["detached"] is True
    assert sig["separate_from_run_log_signature"] is True
    assert verify_egress_signature(document, sig) is True


def test_tampered_egress_document_is_invalid():
    att = build_egress_attestation(roster.PROVIDER_DEV)
    document = att.as_document()
    sig = sign_egress(document)
    tampered = copy.deepcopy(document)
    tampered["sovereign"] = not tampered["sovereign"]
    assert verify_egress_signature(tampered, sig) is False


def test_tampering_a_single_role_field_breaks_the_signature():
    att = build_egress_attestation(roster.PROVIDER_DEV)
    document = att.as_document()
    sig = sign_egress(document)
    tampered = copy.deepcopy(document)
    tampered["roles"][0]["model"] = "attacker/closed-model"
    tampered["roles"][0]["self_hosted"] = False
    assert verify_egress_signature(tampered, sig) is False


def test_egress_signature_is_deterministic_with_the_demo_key():
    document = build_egress_attestation(roster.PROVIDER_DEV).as_document()
    assert sign_egress(document)["signature"] == sign_egress(document)["signature"]


def test_egress_record_carries_the_honest_demo_caveat():
    block = egress_record(roster.PROVIDER_DEV)
    assert block["signature"]["caveat"] == DEMO_KEY_CAVEAT
    assert block["signature"]["demo_key"] is True


def test_canonical_bytes_are_sorted_key_no_whitespace_json():
    document = build_egress_attestation(roster.PROVIDER_DEV).as_document()
    raw = canonical_egress_bytes(document)
    # The canonical recipe: sorted keys, no separator whitespace. (Value strings
    # may contain spaces; the STRUCTURE must not.) Round-trip byte-identical with
    # the same recipe the run log, the bound payload, and the assertion use.
    assert raw == json.dumps(
        document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # Keys are emitted in sorted order with no whitespace around the colon.
    assert raw.startswith(b'{"claim":')
    # The digest is the sha256 over exactly these bytes.
    assert egress_digest(document) == hashlib.sha256(raw).hexdigest()


def test_egress_label_is_distinct_from_run_log_and_assertion_labels():
    # The distinct label is what stops an egress signature being replayed as a
    # per-run or assertion receipt: the signed bytes differ.
    assert EGRESS_SIGNED_PAYLOAD == "canonical_json(egress_attestation)"
    assert EGRESS_SIGNED_PAYLOAD != (
        "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}")
    assert EGRESS_SIGNED_PAYLOAD != "canonical_json(management_assertion)"


def test_unsigned_egress_record_omits_the_signature():
    block = egress_record(roster.PROVIDER_DEV, sign=False)
    assert "signature" not in block
    assert block["document"] and block["digest"]


# --- the sealed run-log seals are UNCHANGED ----------------------------------

def _sha_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_producing_egress_does_not_touch_the_four_sealed_shas_or_signatures():
    # Snapshot the four sealed run-log byte shas and their committed .sig.json
    # bound signatures BEFORE producing any egress artifact.
    before_shas = {m: _sha_of(DATA / f"run-inc-8842-{m}.jsonl") for m in SEALED_MODES}
    before_sigs = {
        m: json.loads(
            (DATA / f"run-inc-8842-{m}.jsonl.sig.json").read_text(encoding="utf-8"))
        for m in SEALED_MODES
    }

    # Produce a SIGNED egress attestation (the E5.8 artifact). This must not write
    # to or re-sign any sealed run-log or its sidecar.
    block = egress_record(roster.PROVIDER_DEV)
    assert block["sovereign"] is True
    assert verify_egress_signature(block["document"], block["signature"]) is True

    # The four sealed run-log byte shas are byte-frozen.
    after_shas = {m: _sha_of(DATA / f"run-inc-8842-{m}.jsonl") for m in SEALED_MODES}
    assert after_shas == before_shas

    # The four committed .sig.json bound signatures are unchanged, still carry the
    # per-run 4-field label, and still verify against their sealed log bytes.
    for m in SEALED_MODES:
        after_sig = json.loads(
            (DATA / f"run-inc-8842-{m}.jsonl.sig.json").read_text(encoding="utf-8"))
        assert after_sig["signature"] == before_sigs[m]["signature"]
        assert after_sig["signed_payload"] == (
            "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}")
        jsonl = (DATA / f"run-inc-8842-{m}.jsonl").read_text(encoding="utf-8")
        assert verify_run_log_jsonl(jsonl, after_sig) is True


def test_egress_label_never_appears_in_the_sealed_run_log_signatures():
    # The egress label must not have leaked into any sealed per-run signature: the
    # egress signature lives only in its own separate sidecar.
    for m in SEALED_MODES:
        sig = json.loads(
            (DATA / f"run-inc-8842-{m}.jsonl.sig.json").read_text(encoding="utf-8"))
        assert sig["signed_payload"] != EGRESS_SIGNED_PAYLOAD
