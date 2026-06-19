"""Detached Ed25519 signature over a COUNTERFACTUAL outcome, under a distinct label.

The per-run signing path (warden/signing.py) attests one ACTUAL run: it signs the
bound `{sha256, chain_head, attestation_sha, fact_record_hash}` payload for a
single sealed run-log that really happened. A COUNTERFACTUAL receipt is a
different claim entirely. It does not attest a run that happened; it attests, "had
this one DETERMINISTIC input been different, here is the consequence the same
no-LLM substrate computes," and binds together the actual run it was derived from,
the perturbation applied, and the hypothetical outcome.

Two rules keep the counterfactual receipt from ever being confused with a real
run receipt (the same two rules floor/portfolio.py + warden/portfolio_signing.py
use for the portfolio receipt).

  1. SAME key, DISTINCT label. The counterfactual signature uses the same
     committed demo Ed25519 key (so a verifier checks one published key), but it
     is taken over a payload carrying a different `signed_payload` label,
     `canonical_json{counterfactual,actual_chain_head,counterfactual_outcome_sha}`,
     not the per-run label and not the portfolio label. A verifier reading the
     label knows immediately which kind of receipt it holds, and a per-run
     signature can never be replayed as a counterfactual signature (or vice versa)
     because the signed bytes differ.
  2. REUSE, do not re-implement. This module does not touch the per-run signing
     path and re-implements no crypto. It imports the Ed25519 primitives and the
     custody seam from warden/signing.py, so the key loading, signing, and
     fingerprinting are byte-identical to the per-run path.

The same honest demo-key caveat applies: the mechanism is fully real (one flipped
byte of the actual chain head, the perturbation, or the outcome digest makes the
signature INVALID), but the private key ships with the repo, so it proves "signed
by whoever holds this demo key", not HSM/KMS-grade secrecy.

CRITICAL FENCE. Nothing in this module writes a canonical run log or mutates a
gate. It signs a SEPARATE hypothetical outcome under the counterfactual namespace.
The four sealed per-run captures and their signatures are completely untouched by
this module: it computes new bytes (a counterfactual) and signs THOSE.
"""

from __future__ import annotations

import hashlib
import json

from .signing import (
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
    sign_bytes,
    verify_bytes,
)

# The distinct counterfactual label. A per-run receipt carries
# "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}"; a
# portfolio receipt carries "canonical_json{portfolio_root,run_count}"; a
# counterfactual receipt carries this, so none of the three can ever be confused.
COUNTERFACTUAL_SIGNED_PAYLOAD = (
    "canonical_json{counterfactual,actual_chain_head,counterfactual_outcome_sha}")


def outcome_sha(outcome: dict) -> str:
    """The sha256 of a counterfactual OUTCOME object, canonicalized the same way
    the run log canonicalizes (`json.dumps(..., sort_keys=True,
    separators=(",",":"))`). The outcome is the hypothetical result the
    deterministic engine computed (the recomputed deadline, the divergent claim
    set, the re-file decision); folding its digest into the signature means a
    tampered outcome breaks the signature. Pure function of the outcome dict."""
    canon = json.dumps(outcome, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def counterfactual_payload_bytes(name: str, actual_chain_head: str,
                                 counterfactual_outcome_sha: str) -> bytes:
    """The exact bytes the COUNTERFACTUAL signature is taken over: a small
    canonical JSON object binding three values into one attested fact.

      * counterfactual            : the stable id of the perturbation applied
                                    (e.g. "sec_materiality_6h_later"), so the
                                    receipt names WHICH what-if it attests.
      * actual_chain_head         : the per-entry chain head of the REAL run the
                                    counterfactual was derived from, so the receipt
                                    is anchored to the exact actual run (change the
                                    actual run and this moves).
      * counterfactual_outcome_sha: the digest of the hypothetical OUTCOME the
                                    engine computed, so the receipt binds the
                                    consequence (tamper the outcome and this moves).

    The encoding mirrors the run log's own canonicalization, so sorted keys render
    as `{"actual_chain_head":"...","counterfactual":"...",
    "counterfactual_outcome_sha":"..."}` with no whitespace. Pinning the recipe
    lets the browser (web/app.js) rebuild the identical bytes and verify the same
    signature client-side. A valid signature over this object reads as "this exact
    what-if, derived from this exact actual run, yields this exact hypothetical
    outcome, attested by this key": change any of the three and the signature no
    longer verifies."""
    obj = {
        "counterfactual": name,
        "actual_chain_head": actual_chain_head,
        "counterfactual_outcome_sha": counterfactual_outcome_sha,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_counterfactual(name: str, actual_chain_head: str, outcome: dict) -> dict:
    """Sign a counterfactual outcome and return the detached signature record.

    The signature is taken over the counterfactual payload (the perturbation id,
    the ACTUAL run's chain head, and the digest of the hypothetical outcome) under
    the DISTINCT counterfactual label, using the committed demo key. The record
    also carries the full outcome (so a verifier can recompute its digest and
    confirm what was signed) and the honest demo-key caveat. Like the per-run and
    portfolio paths, this record is metadata stored BESIDE the captures; it covers
    no hashed run-log and changes no sealed byte. The outcome it signs is a
    SEPARATE hypothetical computed by floor/whatif.py, never a canonical run."""
    o_sha = outcome_sha(outcome)
    payload = counterfactual_payload_bytes(name, actual_chain_head, o_sha)
    pub_hex = load_public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "namespace": "counterfactual",
        "signed_payload": COUNTERFACTUAL_SIGNED_PAYLOAD,
        "counterfactual": name,
        "actual_chain_head": actual_chain_head,
        "counterfactual_outcome_sha": o_sha,
        "signature": sign_bytes(payload),
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": "Deadline Warden (counterfactual)",
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_counterfactual(name: str, actual_chain_head: str, outcome: dict,
                          signature_record: dict) -> bool:
    """Verify a counterfactual signature record against a perturbation id, the
    actual run's chain head, and the hypothetical outcome.

    True only when the detached signature is valid over the counterfactual payload
    (the perturbation id, the actual chain head, and the digest RECOMPUTED from the
    outcome passed in) under the record's public key. The name, the actual chain
    head, and the outcome are passed by the caller (who recomputed them), NOT read
    from the record, so a tamper that edits the perturbation id, the anchoring
    actual run, or the outcome breaks the signature. Returns False on any invalid
    signature or malformed input rather than raising, so a verifier prints INVALID
    and exits nonzero without a stack trace on tampered evidence."""
    o_sha = outcome_sha(outcome)
    payload = counterfactual_payload_bytes(name, actual_chain_head, o_sha)
    return verify_bytes(
        payload,
        signature_record.get("signature", ""),
        signature_record.get("public_key"),
    )
