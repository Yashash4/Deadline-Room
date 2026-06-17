"""in-toto Statement + DSSE envelope (warden/intoto.py): name our signed
provenance in the recognized supply-chain standard, as a STRICTLY ADDITIVE
sidecar over bytes already on disk.

These tests pin the real guarantees and the strict-additivity constraint:

  * the DSSE envelope's Ed25519 signature verifies over the PAE of its payload
    under the committed key (so the provenance is a valid in-toto / SLSA
    attestation, not a bespoke blob).
  * the in-toto subject digest equals the run-log sha256 the seal was taken over,
    for every captured scenario and its committed `.intoto.json` sidecar.
  * a one-byte tamper of the payload, the subject digest, or the predicate makes
    the envelope INVALID (PAE binds all of it).
  * the PAE encoding matches the canonical DSSE v1 spec vector exactly.
  * critically: building the attestation does NOT change the run-log bytes, the
    run-log sha256, the chain head, the existing detached signature, or the
    byte-identical replay. The in-toto envelope is derived read-only; it never
    enters the hashed JSONL.
"""

import base64
import copy
import hashlib
import json
from pathlib import Path

from warden.chain import chain_head
from warden.intoto import (
    INTOTO_PAYLOAD_TYPE,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    attestation_for_capture,
    build_dsse_envelope,
    build_statement,
    canonical_statement_bytes,
    pae,
    sidecar_path_for,
    statement_of_envelope,
    verify_dsse_envelope,
)
from warden.replay import RunLog, replay
from warden.signing import (
    load_public_key_hex,
    sign_run_log_jsonl,
    verify_run_log_jsonl,
)

DATA = Path(__file__).resolve().parents[1] / "web" / "data"

# Each captured run log paired with the packet it was sealed beside.
CAPTURES = [
    ("run-inc-8842-normal.jsonl", "packet-normal.json"),
    ("run-inc-8842-inject_contradiction.jsonl", "packet-inject_contradiction.json"),
    ("run-inc-8842-chaos.jsonl", "packet-chaos.json"),
    ("run-inc-8842-amendment.jsonl", "packet-amendment.json"),
]


def _canon_sha(jsonl: str) -> str:
    """The run-log integrity sha over the canonical UTF-8 text, the same value
    the seal, the chain, and verify_signature use."""
    return hashlib.sha256(jsonl.encode("utf-8")).hexdigest()


def _read_capture(log_name: str, packet_name: str) -> tuple[str, dict]:
    jsonl = (DATA / log_name).read_text(encoding="utf-8")
    packet = json.loads((DATA / packet_name).read_text(encoding="utf-8"))
    return jsonl, packet


# ---------------------------------------------------------------------------
# PAE: the DSSE Pre-Authentication Encoding matches the published spec vector.
# ---------------------------------------------------------------------------


def test_pae_matches_canonical_dsse_spec_vector():
    # The canonical DSSE protocol.md vector:
    #   PAE(UTF8("application/example"), UTF8("test"))
    #     == "DSSEv1 19 application/example 4 test"
    got = pae("application/example", b"test")
    assert got == b"DSSEv1 19 application/example 4 test"


def test_pae_lengths_are_byte_lengths_not_char_counts():
    # A multibyte payload: the length field must be the BYTE length, per spec.
    payload = "abé".encode("utf-8")  # 'é' is two UTF-8 bytes -> 4 bytes total
    assert len(payload) == 4
    out = pae("t", payload)
    assert out == b"DSSEv1 1 t 4 " + payload


def test_pae_is_deterministic():
    a = pae(INTOTO_PAYLOAD_TYPE, b"some payload bytes")
    b = pae(INTOTO_PAYLOAD_TYPE, b"some payload bytes")
    assert a == b


# ---------------------------------------------------------------------------
# DSSE envelope verifies; in-toto subject digest equals the run-log sha.
# ---------------------------------------------------------------------------


def test_envelope_verifies_and_subject_digest_matches_for_every_capture():
    for log_name, packet_name in CAPTURES:
        jsonl, packet = _read_capture(log_name, packet_name)
        env = attestation_for_capture(jsonl, packet, subject_name=log_name)

        # The DSSE envelope signature verifies over the PAE.
        assert verify_dsse_envelope(env), log_name

        statement = statement_of_envelope(env)
        # in-toto Statement shape per the v1 spec.
        assert statement["_type"] == STATEMENT_TYPE
        assert statement["predicateType"] == PREDICATE_TYPE
        subject = statement["subject"][0]
        assert subject["name"] == log_name

        # The subject digest is the run-log sha the seal was taken over.
        assert subject["digest"]["sha256"] == _canon_sha(jsonl), log_name

        # The predicate carries the run facts from the packet, all present.
        pred = statement["predicate"]
        assert pred["chain_head"]
        assert isinstance(pred["filed_frameworks"], list) and pred["filed_frameworks"]
        assert "sec_deadline" in pred
        assert pred["signer_fingerprint"]
        # The two bound digests are named in the predicate, mirroring the sealed
        # detached signature, so the standards envelope reflects the full custody.
        sealed_sig = (packet.get("replay") or {}).get("signature") or {}
        assert pred["attestation_sha"] == sealed_sig["attestation_sha"]
        assert pred["fact_record_hash"] == sealed_sig["fact_record_hash"]


def test_committed_sidecar_matches_freshly_built_and_sealed_sig():
    # The committed .intoto.json sidecars must equal a fresh build (byte-stable,
    # Ed25519 deterministic) AND agree with the sealed sig.json sha + chain head.
    for log_name, packet_name in CAPTURES:
        jsonl, packet = _read_capture(log_name, packet_name)
        fresh = attestation_for_capture(jsonl, packet, subject_name=log_name)

        sidecar = sidecar_path_for(DATA / log_name)
        assert sidecar.exists(), f"missing committed sidecar for {log_name}"
        committed = json.loads(sidecar.read_text(encoding="utf-8"))
        assert committed == fresh, log_name
        assert verify_dsse_envelope(committed), log_name

        # Cross-check against the sealed detached signature record.
        sealed = json.loads(
            (DATA / (log_name + ".sig.json")).read_text(encoding="utf-8")
        )
        statement = statement_of_envelope(committed)
        assert statement["subject"][0]["digest"]["sha256"] == sealed["sha256"]
        assert statement["predicate"]["chain_head"] == sealed["chain_head"]


def test_attestation_is_byte_stable_across_two_builds():
    jsonl, packet = _read_capture(*CAPTURES[0])
    a = attestation_for_capture(jsonl, packet, subject_name="x")
    b = attestation_for_capture(jsonl, packet, subject_name="x")
    assert a == b


# ---------------------------------------------------------------------------
# Tamper detection: a flipped payload / subject / predicate fails verification.
# ---------------------------------------------------------------------------


def test_tampered_subject_digest_fails_verification():
    jsonl, packet = _read_capture(*CAPTURES[0])
    env = attestation_for_capture(jsonl, packet, subject_name="x")
    statement = statement_of_envelope(env)
    # Flip one hex char of the subject digest, then re-embed WITHOUT re-signing:
    # the payload no longer matches the PAE the signature covers.
    digest = statement["subject"][0]["digest"]["sha256"]
    statement["subject"][0]["digest"]["sha256"] = ("f" if digest[0] != "f" else "0") + digest[1:]
    tampered = dict(env)
    tampered["payload"] = base64.standard_b64encode(
        canonical_statement_bytes(statement)
    ).decode("ascii")
    assert verify_dsse_envelope(tampered) is False


def test_tampered_predicate_fails_verification():
    jsonl, packet = _read_capture(*CAPTURES[0])
    env = attestation_for_capture(jsonl, packet, subject_name="x")
    statement = statement_of_envelope(env)
    statement["predicate"]["chain_head"] = "0" * 64
    tampered = dict(env)
    tampered["payload"] = base64.standard_b64encode(
        canonical_statement_bytes(statement)
    ).decode("ascii")
    assert verify_dsse_envelope(tampered) is False


def test_flipped_payload_byte_fails_verification():
    jsonl, packet = _read_capture(*CAPTURES[0])
    env = attestation_for_capture(jsonl, packet, subject_name="x")
    payload = env["payload"]
    tampered = dict(env)
    tampered["payload"] = ("B" if payload[0] != "B" else "C") + payload[1:]
    assert verify_dsse_envelope(tampered) is False


def test_swapped_payload_type_fails_verification():
    # The payloadType is bound into the PAE, so changing it must break the sig.
    jsonl, packet = _read_capture(*CAPTURES[0])
    env = attestation_for_capture(jsonl, packet, subject_name="x")
    tampered = dict(env)
    tampered["payloadType"] = "application/vnd.other+json"
    assert verify_dsse_envelope(tampered) is False


def test_wrong_public_key_fails_verification():
    jsonl, packet = _read_capture(*CAPTURES[0])
    env = attestation_for_capture(jsonl, packet, subject_name="x")
    # A different but well-formed Ed25519 public key (all zeros) must not verify.
    assert verify_dsse_envelope(env, public_key_hex="00" * 32) is False


# ---------------------------------------------------------------------------
# STRICT ADDITIVITY: the in-toto layer changes nothing about the existing seal.
# ---------------------------------------------------------------------------


def test_building_attestation_does_not_change_run_log_bytes_or_sha():
    log_name, packet_name = CAPTURES[0]
    path = DATA / log_name
    before_text = path.read_text(encoding="utf-8")
    before_bytes = path.read_bytes()
    jsonl, packet = _read_capture(log_name, packet_name)

    # Build the attestation (the operation under test).
    attestation_for_capture(jsonl, packet, subject_name=log_name)

    # The run-log file on disk is untouched, byte for byte.
    assert path.read_text(encoding="utf-8") == before_text
    assert path.read_bytes() == before_bytes


def test_existing_detached_signature_unchanged_by_intoto_layer():
    # The native signing path must still produce and verify the SAME bound-payload
    # signature; the in-toto sidecar rides beside it, never replacing it. The two
    # derived digests are read from the sealed record (they are bound into the
    # payload but cannot be recomputed from the run-log bytes), so re-signing with
    # them reproduces the committed signature exactly.
    jsonl, _ = _read_capture(*CAPTURES[0])
    sealed = json.loads(
        (DATA / (CAPTURES[0][0] + ".sig.json")).read_text(encoding="utf-8")
    )
    record = sign_run_log_jsonl(
        jsonl, sealed["attestation_sha"], sealed["fact_record_hash"])
    assert record["signature"] == sealed["signature"]
    assert record["sha256"] == sealed["sha256"]
    assert record["chain_head"] == sealed["chain_head"]
    assert record["attestation_sha"] == sealed["attestation_sha"]
    assert record["fact_record_hash"] == sealed["fact_record_hash"]
    assert verify_run_log_jsonl(jsonl, sealed) is True


def test_chain_head_and_sha_unchanged_for_capture():
    # The two values the native signature binds are still exactly the sealed ones,
    # recomputed from the bytes on disk. The in-toto layer derives, never mutates.
    for log_name, _ in CAPTURES:
        jsonl = (DATA / log_name).read_text(encoding="utf-8")
        entries = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
        sealed = json.loads(
            (DATA / (log_name + ".sig.json")).read_text(encoding="utf-8")
        )
        assert _canon_sha(jsonl) == sealed["sha256"]
        assert chain_head(entries) == sealed["chain_head"]


def test_byte_identical_replay_holds_with_intoto_present():
    # The replay guarantee is independent of the in-toto sidecar: a saved log
    # replays byte-for-byte regardless. Pinned here as the key strict-additivity
    # property, mirroring the chain/signing tests.
    for log_name, _ in CAPTURES:
        saved = RunLog.load(DATA / log_name)
        again = replay(saved)
        assert again.to_jsonl() == saved.to_jsonl()
        assert again.sha256() == saved.sha256()


# ---------------------------------------------------------------------------
# build_statement / build_dsse_envelope direct unit checks.
# ---------------------------------------------------------------------------


def test_build_statement_pins_passed_values():
    jsonl, _ = _read_capture(*CAPTURES[0])
    statement = build_statement(
        jsonl,
        subject_name="my-run.jsonl",
        filed_frameworks=["NIS2", "DORA"],
        sec_deadline="2026-06-23T23:59:59+00:00",
        signer_fingerprint="46e30f5bff8c221d",
    )
    assert statement["subject"][0]["name"] == "my-run.jsonl"
    assert statement["subject"][0]["digest"]["sha256"] == _canon_sha(jsonl)
    assert statement["predicate"]["filed_frameworks"] == ["NIS2", "DORA"]
    assert statement["predicate"]["sec_deadline"] == "2026-06-23T23:59:59+00:00"
    assert statement["predicate"]["demo_key"] is True


def test_build_dsse_envelope_signs_with_committed_key():
    jsonl, _ = _read_capture(*CAPTURES[0])
    statement = build_statement(
        jsonl,
        subject_name="x",
        filed_frameworks=["NIS2"],
        sec_deadline=None,
        signer_fingerprint="fp",
    )
    env = build_dsse_envelope(statement)
    assert env["payloadType"] == INTOTO_PAYLOAD_TYPE
    assert env["public_key"] == load_public_key_hex()
    assert verify_dsse_envelope(env) is True
    # The envelope round-trips back to the exact Statement.
    assert statement_of_envelope(env) == statement


def test_deepcopy_of_envelope_still_verifies():
    # Guard against accidental mutable-state coupling in the verify path.
    jsonl, packet = _read_capture(*CAPTURES[0])
    env = attestation_for_capture(jsonl, packet, subject_name="x")
    assert verify_dsse_envelope(copy.deepcopy(env)) is True
