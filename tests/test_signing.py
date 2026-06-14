"""Detached Ed25519 signed provenance (warden/signing.py): integrity becomes
authenticity, and the signature now BINDS the order. These tests pin the real
guarantees:

  * a valid signature over the bound payload (sha256 + chain head) verifies under
    the committed key.
  * a one-byte field edit makes the signature INVALID (the sha moves).
  * a REORDER now makes the signature INVALID too (the chain head moves, and the
    head is bound into the signed payload). This is the new guarantee: before,
    a reorder could slip past a signature over the bare bytes of a re-sealed log.
  * sign + verify is deterministic with the demo key (Ed25519 is deterministic).
  * critically: binding is ADDITIVE and DERIVED. It does NOT change the run-log
    bytes or the replay sha. Byte-identical replay still holds with signing
    present, exactly as the chain tests prove for the hash chain.
"""

import copy

from warden.chain import chain_head
from warden.replay import RunLog, replay
from warden.signing import (
    DEMO_KEY_CAVEAT,
    bound_payload_bytes,
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


def _entries_of(jsonl: str) -> list[dict]:
    import json
    return [json.loads(line) for line in jsonl.splitlines() if line.strip()]


def _reorder_first_two_protocol_events(jsonl: str) -> str:
    """Swap the first two protocol_event entries in a run log's JSONL, leaving
    every field untouched: only the ORDER changes. This is the reorder a bare
    byte-stream signature, taken over a re-sealed log, would miss but a chain-head
    binding catches."""
    import json
    entries = _entries_of(jsonl)
    idxs = [k for k, e in enumerate(entries) if e["type"] == "protocol_event"]
    assert len(idxs) >= 2, "fixture needs two protocol events to reorder"
    a, b = idxs[0], idxs[1]
    entries[a], entries[b] = entries[b], entries[a]
    return "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":"))
                     for e in entries) + "\n"


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


# --- THE BINDING: the signed payload includes the chain head -----------

def test_signed_payload_binds_both_the_sha_and_the_chain_head():
    # The record names the bound payload and carries BOTH attested values, and
    # they equal what the log itself produces: the byte sha and the chain head.
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)

    assert record["signed_payload"] == "canonical_json{sha256,chain_head}"
    assert record["sha256"] == log.sha256()
    assert record["chain_head"] == chain_head(_entries_of(jsonl))


def test_bound_payload_is_canonical_sorted_key_json():
    # The exact bytes the signature covers: sorted keys, no whitespace, mirroring
    # the run log's own canonicalization. chain_head sorts before sha256. Pinning
    # this is what lets the browser rebuild identical bytes.
    payload = bound_payload_bytes("aa", "bb")
    assert payload == b'{"chain_head":"bb","sha256":"aa"}'


def test_a_field_edit_breaks_the_bound_signature():
    # A flipped field moves the sha (and the entry's chain hash), so the bound
    # payload changes and the signature is INVALID. The honest baseline verifies.
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)
    assert verify_run_log_jsonl(jsonl, record) is True

    assert '"admitted":true' in jsonl
    tampered = jsonl.replace('"admitted":true', '"admitted":false', 1)
    assert tampered != jsonl
    assert verify_run_log_jsonl(tampered, record) is False


def test_a_reorder_now_breaks_the_signature_the_key_new_guarantee():
    # The load-bearing new assertion. A REORDER changes no field, so the bare
    # byte sha of a re-sealed log could be forged to match; but the chain head
    # moves, and because the head is BOUND into the signature, the reorder makes
    # the signature INVALID. Before this binding, a reorder slipped past a
    # signature taken over the bare run-log bytes.
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)
    assert verify_run_log_jsonl(jsonl, record) is True

    reordered = _reorder_first_two_protocol_events(jsonl)
    assert reordered != jsonl
    # The chain head genuinely moved (that is what the signature now binds).
    assert chain_head(_entries_of(reordered)) != chain_head(_entries_of(jsonl))
    # So the signature over the bound payload no longer verifies.
    assert verify_run_log_jsonl(reordered, record) is False


def test_bound_verify_is_deterministic():
    # Verifying the same record against the same bytes is stable across calls, and
    # signing the same bytes twice yields the same signature (Ed25519 determinism
    # carried through the bound payload).
    log = _fresh_log()
    jsonl = log.to_jsonl()
    record = sign_run_log_jsonl(jsonl)
    assert verify_run_log_jsonl(jsonl, record) is True
    assert verify_run_log_jsonl(jsonl, record) is True
    assert sign_run_log_jsonl(jsonl)["signature"] == record["signature"]


# --- the captured web/data scenarios carry the bound signature ---------

def test_captured_scenarios_carry_chain_head_and_a_bound_signature():
    import json
    from pathlib import Path

    data = Path(__file__).resolve().parents[1] / "web" / "data"
    for mode in ("normal", "inject_contradiction", "chaos", "amendment"):
        packet = json.loads((data / f"packet-{mode}.json").read_text(encoding="utf-8"))
        log = RunLog.load(data / f"run-inc-8842-{mode}.jsonl")
        jsonl = log.to_jsonl()

        replay_block = packet["replay"]
        sig = replay_block["signature"]
        # The packet replay block persists the chain head, and it matches the log.
        assert replay_block["chain_head"] == chain_head(_entries_of(jsonl))
        # The signature record binds sha + head and verifies against the bundled
        # log over the bound payload.
        assert sig["signed_payload"] == "canonical_json{sha256,chain_head}"
        assert sig["sha256"] == log.sha256() == replay_block["original_sha256"]
        assert sig["chain_head"] == replay_block["chain_head"]
        assert verify_run_log_jsonl(jsonl, sig) is True

        # The sibling sidecar carries the same bound signature.
        sidecar = json.loads(
            (data / f"run-inc-8842-{mode}.jsonl.sig.json").read_text(encoding="utf-8"))
        assert sidecar["signature"] == sig["signature"]
        assert sidecar["chain_head"] == sig["chain_head"]
        assert verify_run_log_jsonl(jsonl, sidecar) is True

        # And a reorder of that captured log breaks its captured signature.
        reordered = _reorder_first_two_protocol_events(jsonl)
        assert verify_run_log_jsonl(reordered, sig) is False


def test_binding_does_not_change_the_run_log_bytes_or_replay_sha():
    # The whole point: binding the chain head into the signature is derived and
    # read-only. The run-log bytes, its sha, and byte-identical replay are
    # untouched by producing the bound signature.
    log = _fresh_log()
    before_jsonl = log.to_jsonl()
    before_sha = log.sha256()

    record = sign_run_log_jsonl(log.to_jsonl())
    assert "chain_head" in record

    assert log.to_jsonl() == before_jsonl
    assert log.sha256() == before_sha
    replayed = replay(log)
    assert replayed.to_jsonl() == before_jsonl
    assert replayed.sha256() == before_sha
