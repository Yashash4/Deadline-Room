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
# names the insights digest AND the fleet SLA digest too, so a verifier reading it
# knows the cross-incident findings and the SLA / throughput rollup are both part
# of what the signature covers.
PORTFOLIO_SIGNED_PAYLOAD = (
    "canonical_json{insights_sha256,portfolio_root,run_count,sla_sha256}")


def portfolio_payload_bytes(portfolio_root: str, run_count: int,
                            insights_sha256: str, sla_sha256: str) -> bytes:
    """The exact bytes the PORTFOLIO signature is taken over: a small canonical
    JSON object binding the Merkle root over the fleet's chain heads, the count of
    attested runs, the digest of the cross-incident insights, AND the digest of the
    fleet SLA / throughput rollup.

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
      * sla_sha256      : the digest of the canonical fleet SLA / throughput rollup
                          (worst-case and median statutory margin, near-breach and
                          breach counts, the nearest fleet deadline, and the
                          aggregated throughput). Edit any rollup number and this
                          digest moves, so the signature attests the SLA verdict
                          itself, not only the fleet integrity.

    The encoding mirrors the run log's own canonicalization
    (`json.dumps(..., sort_keys=True, separators=(",",":"))`), so the object
    renders as
    `{"insights_sha256":"...","portfolio_root":"...","run_count":N,"sla_sha256":"..."}`
    with no whitespace. A valid signature over these bytes reads as "this exact
    Merkle root over exactly this many sealed runs, with exactly these
    cross-incident findings and exactly this SLA verdict, attested by this key"."""
    obj = {
        "portfolio_root": portfolio_root,
        "run_count": run_count,
        "insights_sha256": insights_sha256,
        "sla_sha256": sla_sha256,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_portfolio(portfolio_root: str, run_count: int,
                   manifest_sha256: str, insights_sha256: str,
                   sla_sha256: str) -> dict:
    """Sign a portfolio roll-up and return the detached signature record.

    The signature is taken over the portfolio payload (the Merkle root, the
    attested run count, the cross-incident insights digest, AND the fleet SLA /
    throughput rollup digest) under the DISTINCT portfolio label, using the
    committed demo key. The record also carries the manifest digest (so a verifier
    can confirm the canonical manifest it holds is the one signed) and the honest
    demo-key caveat. Like the per-run path, this record is metadata stored BESIDE
    the manifest; it covers no hashed run-log and changes no sealed byte."""
    payload = portfolio_payload_bytes(
        portfolio_root, run_count, insights_sha256, sla_sha256)
    pub_hex = load_public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "signed_payload": PORTFOLIO_SIGNED_PAYLOAD,
        "portfolio_root": portfolio_root,
        "run_count": run_count,
        "insights_sha256": insights_sha256,
        "sla_sha256": sla_sha256,
        "manifest_sha256": manifest_sha256,
        "signature": sign_bytes(payload),
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": "Deadline Warden",
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_portfolio(portfolio_root: str, run_count: int,
                     insights_sha256: str, sla_sha256: str,
                     signature_record: dict) -> bool:
    """Verify a portfolio signature record against a root, run count, insights, and
    SLA rollup.

    True only when the detached signature is valid over the portfolio payload (the
    Merkle root, the run count, the insights digest, AND the SLA rollup digest)
    rebuilt from the values passed in, under the record's public key. All four are
    passed by the caller (who recomputed them from the sealed runs, the findings,
    and the SLA rollup), NOT read from the record, so a tamper that edits the root,
    the count, any finding, or any rollup number breaks the signature. Returns
    False on any invalid signature or malformed input rather than raising, so a
    verifier prints INVALID and exits nonzero without a stack trace on tampered
    evidence."""
    payload = portfolio_payload_bytes(
        portfolio_root, run_count, insights_sha256, sla_sha256)
    return verify_bytes(
        payload,
        signature_record.get("signature", ""),
        signature_record.get("public_key"),
    )


# A standing operations center serves a GROUP with subsidiaries (E6.5). The board
# wants the fleet segmented by regulated entity, AND a per-subsidiary signed
# sub-attestation a subsidiary GC can hand to its own regulator without exposing
# the rest of the group. The two-level tree is: a per-entity Merkle SUB-ROOT (over
# that entity's chain heads) is signed with this DISTINCT sub-attestation label,
# and the per-entity sub-roots combine into the group portfolio root. A third
# label keeps a sub-attestation from ever being confused with a group portfolio
# receipt OR a per-run receipt: the three carry three different `signed_payload`
# strings, so a verifier reading the label knows exactly which claim it holds and
# none can be replayed as another.
PORTFOLIO_SUBATTESTATION_PAYLOAD = (
    "canonical_json{entity,run_count,sub_root}")


def subattestation_payload_bytes(entity: str, sub_root: str,
                                 run_count: int) -> bytes:
    """The exact bytes a per-ENTITY sub-attestation signature is taken over: a
    small canonical JSON object binding the regulated entity name, the Merkle
    sub-root over THAT entity's sorted chain heads, and the count of that entity's
    attested runs.

      * entity     : the regulated entity (the subsidiary) the sub-attestation is
                     scoped to. Binding the name means a sub-attestation for entity
                     A can never be presented as entity B's, even at the same root.
      * sub_root   : the Merkle root over the SORTED chain heads of only this
                     entity's runs. Edit one byte of any of this entity's runs and
                     its chain head moves, which moves the sub-root.
      * run_count  : the number of this entity's attested runs. Drop one and the
                     count falls and the sub-root folds over a smaller set, so a
                     silently dropped run breaks this signature.

    The encoding mirrors the run log's canonicalization, so the object renders as
    `{"entity":"...","run_count":N,"sub_root":"..."}` with no whitespace. A valid
    signature reads as "this exact set of runs, all filed by this exact entity,
    attested by this key": the scoped receipt a subsidiary hands its regulator."""
    obj = {
        "entity": entity,
        "sub_root": sub_root,
        "run_count": run_count,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_subattestation(entity: str, sub_root: str, run_count: int,
                        sub_manifest_sha256: str,
                        provider: object | None = None) -> dict:
    """Sign one entity's sub-attestation and return the detached signature record.

    The signature is taken over the sub-attestation payload (the entity name, its
    Merkle sub-root, and its attested run count) under the DISTINCT sub-attestation
    label. The signing key is a `provider` (a `warden/custody.SigningProvider`): the
    DEFAULT is the committed demo Warden key, so the signature is byte-identical to
    today; a per-tenant deployment passes the tenant's OWN provider, so one
    subsidiary's group never signs as another's. The record also carries the
    sub-manifest digest (so a verifier can confirm the scoped manifest it holds is
    the one signed) and the honest demo-key caveat. Like every signing path here, it
    is metadata stored BESIDE the scoped manifest; it covers no hashed run-log and
    changes no sealed byte."""
    if provider is None:
        from .custody import warden_signing_provider as _warden_provider
        provider = _warden_provider()
    payload = subattestation_payload_bytes(entity, sub_root, run_count)
    pub_hex = provider.public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "signed_payload": PORTFOLIO_SUBATTESTATION_PAYLOAD,
        "entity": entity,
        "sub_root": sub_root,
        "run_count": run_count,
        "sub_manifest_sha256": sub_manifest_sha256,
        "signature": provider.sign(payload),
        "public_key": pub_hex,
        "pubkey_fingerprint": provider.fingerprint(),
        "signer": "Deadline Warden",
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_subattestation(entity: str, sub_root: str, run_count: int,
                          signature_record: dict) -> bool:
    """Verify an entity sub-attestation record against an entity, sub-root, and run
    count.

    True only when the detached signature is valid over the sub-attestation payload
    (the entity name, the sub-root, and the run count) rebuilt from the values
    passed in, under the record's public key. All three are passed by the caller
    (recomputed from that entity's sealed runs), NOT read from the record, so a
    tamper that edits the entity, the sub-root, or the count breaks the signature.
    Because each tenant signs with its OWN key, a sub-attestation signed by one
    tenant's key fails verification under another tenant's public key, which is the
    cross-tenant isolation proof. Returns False on any invalid signature or
    malformed input rather than raising."""
    payload = subattestation_payload_bytes(entity, sub_root, run_count)
    return verify_bytes(
        payload,
        signature_record.get("signature", ""),
        signature_record.get("public_key"),
    )
