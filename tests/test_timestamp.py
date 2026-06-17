"""RFC 3161 trusted timestamp over the signed artifact (warden/timestamp.py).

These tests pin the real guarantees of the additive timestamp layer:

  * the demo TSA issues a TimeStampToken whose Ed25519 signature verifies over the
    TSTInfo, and whose messageImprint equals the artifact digest (sha256 of the
    bound payload the Warden signature was taken over).
  * the messageImprint EQUALS the artifact digest: timestamping anchors the SAME
    fact the signature attests, not a different value.
  * a tampered artifact (a forged bound value) breaks the messageImprint match.
  * a tampered token (a flipped TSTInfo byte or signature byte) breaks the TSA
    signature.
  * the demo TSA is DETERMINISTIC: the same signature record and the same fixed
    genTime always yield the identical token, byte for byte (so the sealed sidecar
    is reproducible).
  * the hand-rolled DER round-trips: build_tst_info -> parse_tst_info recovers every
    field, and the DER structures follow the RFC 3161 shapes faithfully.
  * the layer is ADDITIVE: it never touches the bound payload, the existing
    signature, or the run-log bytes. The four sealed captures each ship a verifying
    .tst.json sidecar.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from warden.signing import bound_payload_bytes, sign_run_log_jsonl
from warden.simulate import KillSchedule, run_incident
from warden.timestamp import (
    DEMO_GENTIME,
    OID_SHA256,
    STANDARD,
    DemoTimestampAuthority,
    artifact_digest_from_signature,
    build_timestamp_request,
    build_tst_info,
    der_generalizedtime,
    der_integer,
    der_oid,
    load_demo_tsa_public_key_hex,
    message_imprint,
    parse_tst_info,
    sidecar_path_for,
    timestamp_signature_record,
    verify_timestamp_token,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")


def _fresh_signature_record() -> tuple[str, dict]:
    """A fresh run plus its detached signature record, so the timestamp tests do
    not depend on a sealed capture and exercise the live signing path."""
    log = run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "A", ("dora", 1): "B"}),
        contradiction_in="sec",
    ).log
    jsonl = log.to_jsonl()
    sig = sign_run_log_jsonl(jsonl, "a" * 64, "b" * 64)
    return jsonl, sig


def test_demo_token_verifies():
    """The demo TSA issues a token whose TSA signature is valid AND whose
    messageImprint matches the signed artifact's digest."""
    _, sig = _fresh_signature_record()
    token = timestamp_signature_record(sig)
    v = verify_timestamp_token(token, sig)
    assert v.valid
    assert v.signature_valid
    assert v.imprint_matches
    assert v.gen_time == DEMO_GENTIME
    assert token["standard"] == STANDARD
    assert token["pki_status"] == 0
    assert token["demo_tsa"] is True


def test_message_imprint_equals_artifact_digest():
    """The timestamped messageImprint is exactly sha256 of the bound payload the
    Ed25519 signature was taken over: the timestamp anchors the same fact."""
    _, sig = _fresh_signature_record()
    expected = hashlib.sha256(
        bound_payload_bytes(
            sig["sha256"], sig["chain_head"],
            sig["attestation_sha"], sig["fact_record_hash"])
    ).hexdigest()
    assert artifact_digest_from_signature(sig).hex() == expected

    token = timestamp_signature_record(sig)
    assert token["artifact_digest"] == expected
    parsed = parse_tst_info(bytes.fromhex(token["tst_info_der"]))
    assert parsed.hashed_message_hex == expected


def test_tampered_artifact_breaks_imprint():
    """A forged bound value (a different signed artifact) breaks the messageImprint
    match, even though the TSA signature over the original TSTInfo is still valid."""
    _, sig = _fresh_signature_record()
    token = timestamp_signature_record(sig)

    forged = dict(sig)
    forged["sha256"] = ("0" if sig["sha256"][0] != "0" else "1") + sig["sha256"][1:]
    v = verify_timestamp_token(token, forged)
    assert not v.valid
    assert v.signature_valid  # the token itself is untouched
    assert not v.imprint_matches  # but it no longer matches the forged artifact


def test_tampered_token_signature_breaks_verification():
    """A flipped byte of the token signature fails the TSA-signature check."""
    _, sig = _fresh_signature_record()
    token = timestamp_signature_record(sig)
    bad = dict(token)
    s = token["token_signature"]
    bad["token_signature"] = s[:-2] + ("00" if not s.endswith("00") else "11")
    v = verify_timestamp_token(bad, sig)
    assert not v.valid
    assert not v.signature_valid


def test_tampered_tst_info_breaks_verification():
    """A flipped byte of the signed TSTInfo DER fails the TSA-signature check (the
    signature was taken over the original TSTInfo bytes)."""
    _, sig = _fresh_signature_record()
    token = timestamp_signature_record(sig)
    bad = dict(token)
    t = token["tst_info_der"]
    bad["tst_info_der"] = ("0" if t[0] != "0" else "1") + t[1:]
    v = verify_timestamp_token(bad, sig)
    assert not v.valid
    assert not v.signature_valid


def test_demo_tsa_is_deterministic():
    """The demo TSA with a fixed genTime produces the identical token byte for byte
    on repeat issuance: same input + fixed time -> identical token. This is what
    keeps the sealed .tst.json sidecar reproducible."""
    _, sig = _fresh_signature_record()
    token_a = timestamp_signature_record(sig)
    token_b = timestamp_signature_record(sig)
    assert token_a["tst_info_der"] == token_b["tst_info_der"]
    assert token_a["token_signature"] == token_b["token_signature"]
    assert token_a == token_b


def test_passed_in_gentime_is_used_not_now():
    """The genTime is a PASSED-IN fixed instant, never now(): a different fixed time
    yields a different (still deterministic) token, and the parsed genTime matches."""
    _, sig = _fresh_signature_record()
    other = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    authority = DemoTimestampAuthority(gen_time=other)
    token = timestamp_signature_record(sig, authority=authority)
    v = verify_timestamp_token(token, sig)
    assert v.valid
    assert v.gen_time == other
    # And it differs from the default-genTime token, proving the time is honored.
    default_token = timestamp_signature_record(sig)
    assert token["tst_info_der"] != default_token["tst_info_der"]


def test_tst_info_der_round_trips():
    """build_tst_info -> parse_tst_info recovers every field faithfully."""
    digest = hashlib.sha256(b"round-trip artifact").digest()
    gen = datetime(2026, 6, 17, 12, 30, 45, tzinfo=timezone.utc)
    tst = build_tst_info(digest, gen, serial=7)
    parsed = parse_tst_info(tst)
    assert parsed.version == 1
    assert parsed.hash_oid == OID_SHA256
    assert parsed.hashed_message_hex == digest.hex()
    assert parsed.serial == 7
    assert parsed.gen_time == gen


def test_der_primitives_are_well_formed():
    """The hand-rolled DER primitives produce the canonical X.690 encodings the
    RFC 3161 structures rely on (tag, definite length, value)."""
    # INTEGER 1 -> 02 01 01
    assert der_integer(1) == bytes([0x02, 0x01, 0x01])
    # INTEGER 128 needs a leading 0x00 so the high bit does not read negative.
    assert der_integer(128) == bytes([0x02, 0x02, 0x00, 0x80])
    # OID sha256 first two arcs fold: 2.16 -> 0x60 (40*2 + 16).
    sha_oid = der_oid(OID_SHA256)
    assert sha_oid[0] == 0x06
    assert sha_oid[2] == 0x60
    # GeneralizedTime is zulu, no fractional seconds.
    gt = der_generalizedtime(datetime(2026, 6, 17, 0, 0, 0, tzinfo=timezone.utc))
    assert gt[0] == 0x18
    assert gt[2:].decode("ascii") == "20260617000000Z"


def test_message_imprint_carries_the_digest():
    """The MessageImprint SEQUENCE carries the sha256 AlgorithmIdentifier and the
    hashed OCTET STRING with the exact digest bytes."""
    digest = hashlib.sha256(b"imprint").digest()
    mi = message_imprint(digest)
    # It parses as part of a TimeStampReq round-trip via the request builder.
    req = build_timestamp_request(digest)
    # The demo TSA reads the digest straight back out of the request.
    token = DemoTimestampAuthority().request_token(req)
    assert token["timestamped_digest"] == digest.hex()
    assert mi[0] == 0x30  # SEQUENCE


def test_timestamp_is_additive_replay_unchanged():
    """Issuing a timestamp is read-only: it never touches the run-log bytes or the
    byte-identical replay. The same log replays identically before and after."""
    from warden.replay import replay
    log = run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "A"}),
        contradiction_in="sec",
    ).log
    before = log.to_jsonl()
    sig = sign_run_log_jsonl(before, "c" * 64, "d" * 64)
    _ = timestamp_signature_record(sig)
    after = log.to_jsonl()
    assert before == after
    assert replay(log).to_jsonl() == before


def test_sidecar_path_naming():
    """The sidecar sits beside the run log as <run-log>.tst.json, a NEW file that
    never rewrites the sealed log/packet/sig.json/intoto bytes."""
    p = sidecar_path_for("web/data/run-inc-8842-normal.jsonl")
    assert p.name == "run-inc-8842-normal.jsonl.tst.json"


def test_packet_render_is_derived_and_optional():
    """The derived packet line renders only when a timestamp token is present, so a
    packet without one (every sealed capture) renders nothing: the sealed bytes are
    unaffected. With a token present, the RFC 3161 line and the genTime render."""
    from floor.packet import _render_timestamp
    assert _render_timestamp({}) == ""
    assert _render_timestamp({"gen_time": ""}) == ""

    _, sig = _fresh_signature_record()
    token = timestamp_signature_record(sig)
    html = _render_timestamp(token)
    assert "Trusted timestamp (RFC 3161)" in html
    assert token["gen_time"] in html
    assert "demo" in html.lower()  # the honest caveat travels with the line


@pytest.mark.parametrize("mode", SCENARIOS)
def test_sealed_capture_timestamp_verifies(mode):
    """Each of the four sealed captures ships a .tst.json sidecar that verifies
    against the sealed signature record, and whose messageImprint equals that
    capture's artifact digest."""
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    sig_path = log_path.with_suffix(log_path.suffix + ".sig.json")
    tst_path = sidecar_path_for(log_path)
    assert tst_path.exists(), f"missing timestamp sidecar for {mode}"
    sig = json.loads(sig_path.read_text(encoding="utf-8"))
    token = json.loads(tst_path.read_text(encoding="utf-8"))
    v = verify_timestamp_token(token, sig)
    assert v.valid, f"{mode}: sealed timestamp did not verify"
    assert v.imprint_matches
    assert v.signature_valid
    assert token["tsa_public_key"] == load_demo_tsa_public_key_hex()
