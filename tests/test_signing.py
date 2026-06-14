"""Detached Ed25519 signed provenance (warden/signing.py): integrity becomes
authenticity. These tests pin the real guarantees:

  * a valid signature over the run-log bytes verifies under the committed key.
  * a one-byte change to the signed bytes makes the signature INVALID.
  * sign + verify is deterministic with the demo key (Ed25519 is deterministic).
  * critically: signing is ADDITIVE and DETACHED. It does NOT change the run-log
    bytes or the replay sha. Byte-identical replay still holds with signing
    present, exactly as the chain tests prove for the hash chain.
"""

import copy

from warden.replay import RunLog, replay
from warden.signing import (
    DEMO_KEY_CAVEAT,
    canonical_signing_bytes,
    fingerprint,
    load_demo_private_key,
    load_public_key_hex,
    public_key_hex_of,
    sign_bytes,
    sign_run_log_jsonl,
    verify_bytes,
    verify_run_log_jsonl,
)
from warden.simulate import KillSchedule, run_incident


def _fresh_log() -> RunLog:
    return run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "A", ("dora", 1): "B"}),
        contradiction_in="sec",
    ).log


# --- a valid signature verifies ----------------------------------------

def test_valid_signature_verifies_over_the_run_log_bytes():
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)
    assert record["algorithm"] == "ed25519"
    assert record["detached"] is True
    assert verify_run_log_jsonl(jsonl, record) is True


def test_committed_public_key_matches_the_demo_private_key():
    # The committed pubkey is exactly the public half of the committed demo seed.
    sk = load_demo_private_key()
    assert public_key_hex_of(sk) == load_public_key_hex()
    record = sign_run_log_jsonl(_fresh_log().to_jsonl())
    assert record["public_key"] == load_public_key_hex()
    assert record["pubkey_fingerprint"] == fingerprint(load_public_key_hex())


# --- a one-byte change makes it INVALID --------------------------------

def test_one_byte_change_to_the_signed_bytes_makes_it_invalid():
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)

    # Flip a single character of the signed payload, like a field edit.
    assert '"admitted":true' in jsonl
    tampered = jsonl.replace('"admitted":true', '"admitted":false', 1)
    assert tampered != jsonl
    assert verify_run_log_jsonl(tampered, record) is False
    # And the honest baseline still verifies, proving the failure is the edit.
    assert verify_run_log_jsonl(jsonl, record) is True


def test_wrong_signature_does_not_verify():
    log = _fresh_log()
    payload = canonical_signing_bytes(log.to_jsonl())
    other_payload = canonical_signing_bytes(log.to_jsonl() + "x")
    sig = sign_bytes(payload)
    assert verify_bytes(payload, sig) is True
    # The same signature does not verify a different payload.
    assert verify_bytes(other_payload, sig) is False
    # A malformed signature hex returns False rather than raising.
    assert verify_bytes(payload, "not-hex") is False
    assert verify_bytes(payload, "00" * 64) is False


# --- determinism with the demo key -------------------------------------

def test_sign_is_deterministic_with_the_demo_key():
    log = _fresh_log()
    payload = canonical_signing_bytes(log.to_jsonl())
    # Ed25519 is deterministic: the same payload and key always yield the same
    # signature, so captured artifacts are reproducible byte for byte.
    assert sign_bytes(payload) == sign_bytes(payload)
    a = sign_run_log_jsonl(log.to_jsonl())
    b = sign_run_log_jsonl(log.to_jsonl())
    assert a["signature"] == b["signature"]
    assert a["public_key"] == b["public_key"]


def test_signature_record_carries_the_honest_demo_caveat():
    record = sign_run_log_jsonl(_fresh_log().to_jsonl())
    assert record["demo_key"] is True
    assert record["caveat"] == DEMO_KEY_CAVEAT
    # The caveat states plainly that the key ships with the repo (not HSM/KMS).
    assert "ships with the repo" in record["caveat"]


# --- THE LOAD-BEARING GUARD: signing is detached, replay untouched -----

def test_signing_does_not_change_the_run_log_bytes_or_the_replay_sha():
    log = _fresh_log()
    before_jsonl = log.to_jsonl()
    before_sha = log.sha256()

    # Sign in every way the module offers.
    sign_run_log_jsonl(log.to_jsonl())
    sign_bytes(canonical_signing_bytes(log.to_jsonl()))

    # The run-log bytes and its sha are byte-identical afterwards: the signature
    # is computed FROM the bytes, never written INTO them.
    assert log.to_jsonl() == before_jsonl
    assert log.sha256() == before_sha


def test_byte_identical_replay_still_holds_with_signing_present():
    log = _fresh_log()
    original_sha = log.sha256()

    # Produce a signature, then assert replay is still byte-identical and the sha
    # the signature was taken over is unchanged.
    record = sign_run_log_jsonl(log.to_jsonl())
    assert verify_run_log_jsonl(log.to_jsonl(), record) is True

    replayed = replay(log)
    assert replayed.to_jsonl() == log.to_jsonl()
    assert replayed.sha256() == original_sha
    # The signature verifies against the replayed bytes too: replay reproduces
    # the exact bytes the signature is bound to.
    assert verify_run_log_jsonl(replayed.to_jsonl(), record) is True


def test_signature_lives_outside_the_hashed_payload():
    # A captured-style flow: sign the log, attach the record to a replay_info
    # dict, and confirm the signed JSONL never contained the signature. This is
    # the detached property the packet relies on.
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)
    replay_info = {"original_sha256": log.sha256(), "signature": record}
    # The signature hex is not in the bytes it signs (no self-reference loop).
    assert record["signature"] not in jsonl
    # And re-signing the unchanged bytes gives the same signature stored above.
    assert sign_run_log_jsonl(copy.copy(jsonl))["signature"] == \
        replay_info["signature"]["signature"]
