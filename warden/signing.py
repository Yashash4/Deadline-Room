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
    """The exact bytes a signature is taken over: the canonical run-log JSONL,
    UTF-8 encoded. These are the SAME bytes `RunLog.sha256()` hashes and replay
    reproduces, so signing reads them without touching them."""
    return run_log_jsonl.encode("utf-8")


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


def sign_run_log_jsonl(run_log_jsonl: str,
                       private_key: Ed25519PrivateKey | None = None) -> dict:
    """Sign a run log's canonical JSONL and return the detached signature record
    that lands in the packet sidecar / replay_info.

    The record carries everything a verifier needs and nothing the hashed log
    covers: the algorithm, the detached signature, the public key, its
    fingerprint, and the honest demo-key caveat. It is metadata stored BESIDE the
    log; it never enters the hashed JSONL, so the run-log sha and replay are
    untouched."""
    if private_key is None:
        private_key = load_demo_private_key()
    payload = canonical_signing_bytes(run_log_jsonl)
    pub_hex = public_key_hex_of(private_key)
    return {
        "algorithm": "ed25519",
        "detached": True,
        "signed_payload": "run_log_jsonl_utf8",
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
    these exact bytes under the record's public key."""
    payload = canonical_signing_bytes(run_log_jsonl)
    return verify_bytes(
        payload,
        signature_record.get("signature", ""),
        signature_record.get("public_key"),
    )
