"""Detached Ed25519 signatures over the run-log sha: integrity becomes authenticity.

The flat `RunLog.sha256()` and the per-entry hash chain (`warden/chain.py`) both
catch tampering, but neither binds the evidence to an IDENTITY. A skeptic who
distrusts us can recompute the hash and get a match on a log we forged wholesale,
because nothing ties the seal to a key only the Warden holds. A detached Ed25519
signature closes that gap: the Warden attests the run-log bytes with a private
key, and anyone holding the committed public key can verify, in Python or in a
browser, that these exact bytes were signed by the holder of that key, and that
one flipped byte makes the signature INVALID.

DETACHED, by design. The signature is computed FROM the canonical run-log bytes
(the same bytes `RunLog.sha256()` hashes and replay reproduces). It is stored
BESIDE the log, in the packet sidecar / replay_info, NEVER inside the hashed
JSONL. So the run-log sha and the byte-identical replay are completely
unaffected: this module reads the bytes, it never writes them.

BINDS THE ORDER, not just the byte stream. The signature is taken over a small
canonical object that names BOTH the run-log sha256 AND the per-entry hash
chain head (warden/chain.py). A bare sha attests "these bytes"; the chain head
is the single value that summarizes the ORDERED, COMPLETE run (reorder or omit
an entry and the head moves). Signing them together means "signature VALID"
reads as "this exact ordered, complete run, attested by this key", which is the
sentence a regulator writes down. The chain head is a DERIVED value computed
read-only from the same canonical bytes, so it is still never written into the
hashed JSONL: the run-log sha and byte-identical replay remain untouched.

Honest key-handling caveat (stated plainly, no security theater): the private
key shipped with this repo is a DEMONSTRATION key, generated once and committed
so signatures are reproducible. The signature MECHANISM is fully real: it
cryptographically binds the bytes to the public key, and a single flipped byte
invalidates it. What is NOT production-grade is the key's SECRECY. Anyone with
the repo holds the demo private key, so the signature proves "signed by whoever
holds this demo key", not "signed by a key only a trusted Warden could ever
hold". In production the private key lives in an HSM or KMS, never in the repo,
with rotation, a published key directory, and RFC-3161 timestamping. Those are
Phase 2; the integrity and authenticity-relative-to-this-keypair claims are real
and independently checkable today.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# The committed demo keypair lives beside this module in warden/keys/. The seed
# (the 32-byte Ed25519 private seed, hex) is the DEMO private key: clearly named
# .demo. so no one mistakes it for a protected production key. The public key
# (32 bytes, hex) is what a verifier checks against.
_KEYS_DIR = Path(__file__).resolve().parent / "keys"
DEMO_SEED_PATH = _KEYS_DIR / "warden_seed.demo.ed25519"
PUBKEY_PATH = _KEYS_DIR / "warden_pubkey.ed25519"

# The one honest line that travels with every verification output. The mechanism
# is real; the key's secrecy is not production-grade, and we say so.
DEMO_KEY_CAVEAT = (
    "Demo key: the signature mechanism is fully real (one flipped byte makes it "
    "INVALID), but this private key ships with the repo, so it proves 'signed by "
    "whoever holds this demo key', not HSM/KMS-grade secrecy. Key rotation, a "
    "published key directory, and RFC-3161 timestamping are Phase 2."
)


def canonical_signing_bytes(run_log_jsonl: str) -> bytes:
    """The exact bytes the run-log INTEGRITY hash is taken over: the canonical
    run-log JSONL, UTF-8 encoded. These are the SAME bytes `RunLog.sha256()`
    hashes and replay reproduces. This is the raw byte stream; the SIGNATURE is
    taken over the bound payload below, which folds in this stream's sha256 plus
    the chain head so the signature attests ORDER and COMPLETENESS, not just
    bytes. Kept public because `sign_bytes`/`verify_bytes` still operate at this
    byte level and the tests exercise it directly."""
    return run_log_jsonl.encode("utf-8")


def bound_payload_bytes(sha256_hex: str, chain_head_hex: str,
                        attestation_sha_hex: str,
                        fact_record_hash_hex: str) -> bytes:
    """The exact bytes the SIGNATURE is taken over: a small canonical JSON object
    that BINDS four values into one attested fact.

      * sha256          : the run-log integrity hash (the bytes are intact).
      * chain_head      : the per-entry hash chain head (the run is in the proven
                          order with nothing dropped).
      * attestation_sha : the digest of the deadline-compliance attestation (the
                          per-regime met/margin verdict), so the timeliness verdict
                          is itself signed.
      * fact_record_hash: the digest of the canonical input fact-record, so the
                          signature attests the INPUT the run was driven from, not
                          just the output.

    The encoding mirrors the run log's own canonicalization
    (`json.dumps(..., sort_keys=True, separators=(",",":"))`), so sorted keys
    render as `{"attestation_sha":"...","chain_head":"...","fact_record_hash":"...",
    "sha256":"..."}` with no whitespace. Pinning the recipe lets the browser
    (web/app.js) rebuild the identical bytes and verify the same signature
    client-side.

    A valid signature over this object reads as "this exact ordered, complete run,
    driven from this exact fact-record, met these statutory deadlines, attested by
    this key": reorder or omit an entry and the chain head moves; edit a field and
    the sha moves; tamper a margin and the attestation digest moves; change the
    input and the fact-record hash moves. Any of those changes the bound payload
    and the signature no longer verifies."""
    obj = {
        "sha256": sha256_hex,
        "chain_head": chain_head_hex,
        "attestation_sha": attestation_sha_hex,
        "fact_record_hash": fact_record_hash_hex,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(public_key_hex: str) -> str:
    """A short, stable fingerprint of a public key for display: the first 16 hex
    chars of sha256(pubkey bytes). Lets the packet and the verify output name the
    signer without printing the full 64-char key everywhere."""
    raw = bytes.fromhex(public_key_hex)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_demo_private_key() -> Ed25519PrivateKey:
    """Load the committed DEMO Ed25519 private key from its hex seed. Raises if
    the seed file is missing or malformed: a signing path must never silently
    fall back to an unsigned artifact."""
    seed_hex = DEMO_SEED_PATH.read_text(encoding="utf-8").strip()
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError(
            f"demo Ed25519 seed must be 32 bytes (64 hex chars); got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_public_key_hex() -> str:
    """Load the committed public key as a 64-char hex string. This is what a
    verifier checks a signature against."""
    return PUBKEY_PATH.read_text(encoding="utf-8").strip()


def load_public_key(public_key_hex: str | None = None) -> Ed25519PublicKey:
    """Build an Ed25519 public key object from hex (the committed key by default)."""
    if public_key_hex is None:
        public_key_hex = load_public_key_hex()
    raw = bytes.fromhex(public_key_hex)
    if len(raw) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes (64 hex chars); got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_hex_of(private_key: Ed25519PrivateKey) -> str:
    """The hex public key derived from a private key, for pairing checks."""
    from cryptography.hazmat.primitives import serialization
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def sign_bytes(payload: bytes, private_key: Ed25519PrivateKey | None = None) -> str:
    """Detached Ed25519 signature over `payload`, returned as 128-char hex (the
    64-byte signature). Uses the committed demo key unless one is supplied.

    Ed25519 is deterministic: the same payload and key always yield the same
    signature, so the captured artifacts are reproducible byte for byte."""
    if private_key is None:
        private_key = load_demo_private_key()
    return private_key.sign(payload).hex()


def verify_bytes(payload: bytes, signature_hex: str,
                 public_key_hex: str | None = None) -> bool:
    """True iff `signature_hex` is a valid Ed25519 signature over `payload` under
    the given public key (the committed key by default). Returns False on any
    invalid signature or malformed input rather than raising, so a verifier can
    print INVALID and exit nonzero without a stack trace on tampered evidence."""
    try:
        public_key = load_public_key(public_key_hex)
        public_key.verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def _sha256_of_jsonl(run_log_jsonl: str) -> str:
    """The run-log integrity sha: sha256 of the canonical JSONL bytes. Equal to
    `RunLog.sha256()` for the same bytes, recomputed here so signing depends only
    on the JSONL string it is handed."""
    return hashlib.sha256(run_log_jsonl.encode("utf-8")).hexdigest()


def _chain_head_of_jsonl(run_log_jsonl: str) -> str:
    """The per-entry hash chain head over the run log's entries (warden/chain.py).

    Parses the canonical JSONL back into entries and folds the chain read-only,
    using the SAME canonicalization replay and the chain sidecar use. Nothing is
    written back into the log; this is a derived summarizing value. The import is
    local to keep this module free of an import cycle (chain -> replay)."""
    from .chain import chain_head

    entries = [json.loads(line) for line in run_log_jsonl.splitlines() if line.strip()]
    return chain_head(entries)


def sign_run_log_jsonl(run_log_jsonl: str,
                       attestation_sha_hex: str,
                       fact_record_hash_hex: str,
                       private_key: Ed25519PrivateKey | None = None) -> dict:
    """Sign a run log and return the detached signature record that lands in the
    packet sidecar / replay_info.

    The signature is taken over the BOUND payload (`bound_payload_bytes`): the
    run-log sha256 AND the chain head AND the deadline-compliance attestation
    digest AND the input fact-record hash, so a valid signature attests the exact
    ordered, complete run, driven from this exact fact-record, that met these
    statutory deadlines, not just a byte stream.

    `attestation_sha_hex` and `fact_record_hash_hex` are DERIVED values the caller
    computes from data outside the hashed JSONL (the deadline-compliance
    attestation in `floor/attestation.py`, the input fact-record in
    `floor/fact_record.py`). They are bound into the signature and recorded in the
    returned dict; a verifier recomputes the sha and chain head from the bytes and
    reads these two digests from the record, so editing either digest in the record
    changes the bound payload and breaks the signature.

    The record carries everything a verifier needs and nothing the hashed log
    covers: the algorithm, the detached signature, all four attested values, the
    public key, its fingerprint, and the honest demo-key caveat. It is metadata
    stored BESIDE the log; it never enters the hashed JSONL, so the run-log sha and
    replay are untouched (the chain head, the attestation digest, and the
    fact-record hash are all derived read-only)."""
    if private_key is None:
        private_key = load_demo_private_key()
    sha256_hex = _sha256_of_jsonl(run_log_jsonl)
    chain_head_hex = _chain_head_of_jsonl(run_log_jsonl)
    payload = bound_payload_bytes(
        sha256_hex, chain_head_hex, attestation_sha_hex, fact_record_hash_hex)
    pub_hex = public_key_hex_of(private_key)
    return {
        "algorithm": "ed25519",
        "detached": True,
        "signed_payload": "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}",
        "sha256": sha256_hex,
        "chain_head": chain_head_hex,
        "attestation_sha": attestation_sha_hex,
        "fact_record_hash": fact_record_hash_hex,
        "signature": sign_bytes(payload, private_key),
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": "Deadline Warden",
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_run_log_jsonl(run_log_jsonl: str, signature_record: dict) -> bool:
    """Verify a signature record (as produced by `sign_run_log_jsonl`) against a
    run log's canonical JSONL. True only when the detached signature is valid over
    the BOUND payload (sha256 + chain head + attestation digest + fact-record hash)
    rebuilt from these exact bytes and the record's derived digests.

    The sha256 and chain head are recomputed from the run log handed in, NOT read
    from the record, so a tamper that edits a field (sha moves), reorders, or omits
    an entry (chain head moves) changes the bound payload and the signature fails.
    The attestation digest and the fact-record hash are DERIVED from data outside
    the hashed JSONL, so they are read from the record; because they are part of the
    signed payload, editing either one in the record also changes the bound payload
    and the signature fails. Binding the head is what makes a REORDER, which leaves
    the byte sha of a re-sealed log free to be forged, break the signature too."""
    sha256_hex = _sha256_of_jsonl(run_log_jsonl)
    chain_head_hex = _chain_head_of_jsonl(run_log_jsonl)
    payload = bound_payload_bytes(
        sha256_hex, chain_head_hex,
        signature_record.get("attestation_sha", ""),
        signature_record.get("fact_record_hash", ""),
    )
    return verify_bytes(
        payload,
        signature_record.get("signature", ""),
        signature_record.get("public_key"),
    )
