"""Detached Ed25519 signature over a PORTFOLIO manifest, under a distinct label.

The per-run signing path (warden/signing.py) attests one run: it signs the bound
`{sha256, chain_head, attestation_sha, fact_record_hash}` payload for a single
sealed run-log. A PORTFOLIO receipt is a different claim entirely: it attests a
Merkle root over the chain-heads of a whole FLEET of sealed runs, proving in one
verification that the set is untampered and complete (floor/portfolio.py).

Two rules keep the two receipts from ever being confused.

  1. SAME key, DISTINCT label. The portfolio signature uses the same committed
     demo Ed25519 key (so a verifier checks one published key), but it is taken
     over a payload carrying a different `signed_payload` label,
     `canonical_json{portfolio_root,run_count}`, not the per-run label. A verifier
     reading the label knows immediately which kind of receipt it holds, and a
     per-run signature can never be replayed as a portfolio signature (or vice
     versa) because the signed bytes differ.
  2. REUSE, do not re-implement. This module does not touch the per-run signing
     path and re-implements no crypto. It imports the Ed25519 primitives and the
     custody seam from warden/signing.py, so the key loading, signing, and
     fingerprinting are byte-identical to the per-run path.

The same honest demo-key caveat applies: the mechanism is fully real (one flipped
byte of the root or run count makes the signature INVALID), but the private key
ships with the repo, so it proves "signed by whoever holds this demo key", not
HSM/KMS-grade secrecy.
"""

from __future__ import annotations

import json

from .signing import (
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
    sign_bytes,
    verify_bytes,
)

# The distinct portfolio label. A per-run receipt carries
# "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}"; a
# portfolio receipt carries this, so the two can never be confused. The label
# names the insights digest too, so a verifier reading it knows the cross-incident
# finding is part of what the signature covers.
PORTFOLIO_SIGNED_PAYLOAD = (
    "canonical_json{insights_sha256,portfolio_root,run_count}")


def portfolio_payload_bytes(portfolio_root: str, run_count: int,
                            insights_sha256: str) -> bytes:
    """The exact bytes the PORTFOLIO signature is taken over: a small canonical
    JSON object binding the Merkle root over the fleet's chain heads, the count of
    attested runs, AND the digest of the cross-incident insights.

      * portfolio_root  : the Merkle root over the SORTED per-run chain heads. Edit
                          one byte of any run and its chain head moves, which moves
                          the root.
      * run_count       : the number of attested runs. Drop a run and the count
                          falls (and the root is folded over a smaller set), so a
                          silently dropped run breaks the signature here.
      * insights_sha256 : the digest of the canonical cross-incident findings (the
                          repeat-offender flag, the field-level veto recurrence,
                          the suppress-by-regime and per-entity groupings). Edit
                          any finding and this digest moves, so the signature no
                          longer verifies: the attestation attests the FINDINGS,
                          not just the fleet integrity.

    The encoding mirrors the run log's own canonicalization
    (`json.dumps(..., sort_keys=True, separators=(",",":"))`), so the object
    renders as
    `{"insights_sha256":"...","portfolio_root":"...","run_count":N}` with no
    whitespace. A valid signature over these bytes reads as "this exact Merkle
    root over exactly this many sealed runs, with exactly these cross-incident
    findings, attested by this key"."""
    obj = {
        "portfolio_root": portfolio_root,
        "run_count": run_count,
        "insights_sha256": insights_sha256,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_portfolio(portfolio_root: str, run_count: int,
                   manifest_sha256: str, insights_sha256: str) -> dict:
    """Sign a portfolio roll-up and return the detached signature record.

    The signature is taken over the portfolio payload (the Merkle root, the
    attested run count, AND the cross-incident insights digest) under the DISTINCT
    portfolio label, using the committed demo key. The record also carries the
    manifest digest (so a verifier can confirm the canonical manifest it holds is
    the one signed) and the honest demo-key caveat. Like the per-run path, this
    record is metadata stored BESIDE the manifest; it covers no hashed run-log and
    changes no sealed byte."""
    payload = portfolio_payload_bytes(portfolio_root, run_count, insights_sha256)
    pub_hex = load_public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "signed_payload": PORTFOLIO_SIGNED_PAYLOAD,
        "portfolio_root": portfolio_root,
        "run_count": run_count,
        "insights_sha256": insights_sha256,
        "manifest_sha256": manifest_sha256,
        "signature": sign_bytes(payload),
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": "Deadline Warden",
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_portfolio(portfolio_root: str, run_count: int,
                     insights_sha256: str, signature_record: dict) -> bool:
    """Verify a portfolio signature record against a root, run count, and insights.

    True only when the detached signature is valid over the portfolio payload (the
    Merkle root, the run count, AND the insights digest) rebuilt from the values
    passed in, under the record's public key. All three are passed by the caller
    (who recomputed them from the sealed runs and the findings), NOT read from the
    record, so a tamper that edits the root, the count, or any finding breaks the
    signature. Returns False on any invalid signature or malformed input rather
    than raising, so a verifier prints INVALID and exits nonzero without a stack
    trace on tampered evidence."""
    payload = portfolio_payload_bytes(portfolio_root, run_count, insights_sha256)
    return verify_bytes(
        payload,
        signature_record.get("signature", ""),
        signature_record.get("public_key"),
    )
