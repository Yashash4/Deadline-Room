"""The signed egress attestation: zero breach facts left the perimeter (E5.8).

A regulated bank can be required to keep breach facts INSIDE its own perimeter:
no incident detail may be handed to a closed, third-party hosted model. The
roster already carries the seam that decides where every role's drafting runs:
`floor/roster.resolve(role, provider_set)` returns each role's (provider, model),
and a provider is either an OPEN, self-hostable family on Featherless
(`roster.FEATHERLESS`) or a CLOSED hosted gateway (`roster.AIMLAPI`). A
"sovereign" run is one in which EVERY role resolves to an open, self-hostable
model, so no breach fact is ever sent to a closed hosted API.

This module turns that property into a signed, independently checkable
attestation. It is a PURE DERIVED function of the provider set and the roster:

  * It walks the same roles `run_floor` walks under the active provider set and
    records, per role, the resolved (provider, model) and whether that provider
    is self-hosted (open) or hosted (closed).
  * It states the one-line sovereign verdict: every role is self-hosted, so zero
    breach facts left the perimeter, OR (when not sovereign) names the roles that
    would route to a closed hosted model.
  * It canonicalizes that record (sorted keys, no whitespace, the SAME recipe the
    run log, the bound signing payload, and the management assertion use, with no
    now() and no RNG) and signs its digest with a SEPARATE, DETACHED Ed25519
    signature under a DISTINCT signed_payload label.

CRITICAL: this is a SEPARATE detached signature in its OWN sidecar, exactly like
the management assertion (floor/assertion.py) and the portfolio receipt
(warden/portfolio_signing.py). The egress digest is NOT folded into the run-log
4-field bound payload {sha256, chain_head, attestation_sha, fact_record_hash}.
Folding it would force re-signing every sealed capture and break their committed
signatures. Instead the egress attestation rests beside the sealed run: it never
enters the hashed run-log, so the run-log sha, the chain head, the four sealed
.sig.json bound signatures, and byte-identical replay are all untouched.

Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The
same provider set always derives the byte-identical egress record and therefore
the same digest and the same signature (Ed25519 is deterministic). It reads only
the roster config; it never gates a Warden transition, never clocks or counts
anything inside the core. The Warden stays no-LLM.

Honest demo-key caveat: the private key shipped with this repo is a DEMONSTRATION
key (warden/signing.py). The signature MECHANISM is fully real (one flipped byte
of the egress record makes it INVALID), but the key's SECRECY is not
production-grade because anyone with the repo holds it. The same caveat that
travels with the run-log signature travels with this one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from floor import roster
from warden.signing import (
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
    sign_bytes,
    verify_bytes,
)

# The distinct egress label. A per-run receipt carries
# "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}"; the
# management assertion carries "canonical_json(management_assertion)"; the egress
# attestation carries THIS, so the three can never be confused and an egress
# signature can never be replayed as a per-run or assertion signature (the signed
# bytes differ).
EGRESS_SIGNED_PAYLOAD = "canonical_json(egress_attestation)"

# The signer's stated role on the attestation. The same identity the run-log
# signature attributes the seal to, so one attesting party names the run and the
# egress claim.
EGRESS_SIGNER = "Deadline Warden"

# The roles the egress attestation walks: the same identities run_floor resolves
# under the active provider set. The Warden itself makes NO LLM call (model ""),
# so it is not an egress surface; it is omitted. Triage and the four drafters are
# the roles that actually send incident text to a model, plus the runtime-recruit
# drafters (UK ICO, NYDFS) and the Challenger, so the attestation covers every
# role that could route a breach fact to a provider.
EGRESS_ROLES = (
    roster.TRIAGE,
    roster.NIS2_DRAFTER,
    roster.SEC_DRAFTER,
    roster.DORA_DRAFTER,
    roster.UK_DRAFTER,
    roster.NYDFS_DRAFTER,
    roster.CHALLENGER,
)

# Which providers are self-hosted / open (no breach fact leaves the perimeter) and
# which are closed hosted gateways (a breach fact would be sent to a third party).
# Featherless models are open weights a bank can self-host; AI/ML API is a closed
# hosted multi-model gateway.
_SELF_HOSTED_PROVIDERS = frozenset({roster.FEATHERLESS})
_HOSTED_PROVIDERS = frozenset({roster.AIMLAPI})


def _self_hosted(provider: str) -> bool:
    """True iff a provider is an open, self-hostable family (a breach fact drafted
    on it never leaves the bank's perimeter). An unknown provider is treated as
    HOSTED (the conservative call: refuse to claim sovereignty for a provider this
    module does not positively know to be self-hostable)."""
    return provider in _SELF_HOSTED_PROVIDERS


class SovereigntyError(RuntimeError):
    """Raised by the sovereign pre-flight when a role resolves to a closed hosted
    model under the active provider set. Carries the offending roles so the caller
    can print a clear, specific refusal and exit nonzero."""

    def __init__(self, offenders: list["RoleEgress"]) -> None:
        self.offenders = offenders
        names = ", ".join(f"{o.role_label} ({o.provider}:{o.model})"
                          for o in offenders)
        super().__init__(
            "sovereign mode refuses to start: these roles route breach facts to a "
            f"closed hosted model: {names}. Run without --sovereign, or move every "
            "role to a self-hosted open model (provider dev is all-Featherless).")


@dataclass(frozen=True)
class RoleEgress:
    """One role's egress posture under the active provider set: the role label, its
    resolved (provider, model), and whether that provider is self-hosted. Derived
    1:1 from roster.resolve(role, provider_set)."""
    role_label: str
    branch: str
    regime: str
    provider: str
    model: str
    self_hosted: bool

    def as_dict(self) -> dict:
        return {
            "role_label": self.role_label,
            "branch": self.branch,
            "regime": self.regime,
            "provider": self.provider,
            "model": self.model,
            "self_hosted": self.self_hosted,
        }


@dataclass(frozen=True)
class EgressAttestation:
    """The full egress attestation over one provider set: the resolved roles, the
    sovereign verdict, and the counts. A pure derived view of the roster under the
    active provider set, signed separately."""
    provider_set: str
    roles: tuple[RoleEgress, ...]

    @property
    def total(self) -> int:
        return len(self.roles)

    @property
    def self_hosted_count(self) -> int:
        return sum(1 for r in self.roles if r.self_hosted)

    @property
    def hosted_roles(self) -> tuple[RoleEgress, ...]:
        """The roles that route to a closed hosted model. Empty iff sovereign."""
        return tuple(r for r in self.roles if not r.self_hosted)

    @property
    def sovereign(self) -> bool:
        """True iff every role resolves to a self-hosted open model: zero breach
        facts leave the perimeter."""
        return all(r.self_hosted for r in self.roles)

    @property
    def verdict(self) -> str:
        """The one-line verdict a compliance officer reads first."""
        if self.sovereign:
            return (
                f"Sovereign: all {self.total} drafting roles resolve to a "
                "self-hosted open model under provider set "
                f"'{self.provider_set}', so zero breach facts left the perimeter.")
        n = len(self.hosted_roles)
        names = ", ".join(r.role_label for r in self.hosted_roles)
        roles_word = "role" if n == 1 else "roles"
        return (
            f"NOT sovereign: {n} of {self.total} {roles_word} route breach facts "
            f"to a closed hosted model under provider set '{self.provider_set}' "
            f"({names}).")

    def as_document(self) -> dict:
        """The canonical egress DOCUMENT: the exact JSON the digest is taken over
        and the signature attests. Stable key order so the digest is byte-stable.
        This is the signed object; the rendered packet block and the verifier
        rebuild it identically."""
        return {
            "claim": "zero_breach_facts_left_perimeter",
            "provider_set": self.provider_set,
            "signer": EGRESS_SIGNER,
            "sovereign": self.sovereign,
            "verdict": self.verdict,
            "total": self.total,
            "self_hosted_count": self.self_hosted_count,
            "roles": [r.as_dict() for r in self.roles],
        }


def build_egress_attestation(provider_set: str) -> EgressAttestation:
    """Build the egress attestation for a provider set from the SAME roster seam
    run_floor resolves roles through.

    Pure derived: it walks EGRESS_ROLES, resolves each under the provider set, and
    records its open/closed posture. No LLM, no now(); the same provider set
    derives the byte-identical attestation. It never enters the hashed run-log and
    gates nothing. Raises ValueError on an unknown provider set (mirroring
    roster.resolve), so a typo never silently produces an empty attestation."""
    roles: list[RoleEgress] = []
    for role in EGRESS_ROLES:
        provider, model = roster.resolve(role, provider_set)
        roles.append(RoleEgress(
            role_label=role.name,
            branch=role.branch,
            regime=role.regime,
            provider=provider,
            model=model,
            self_hosted=_self_hosted(provider)))
    return EgressAttestation(provider_set=provider_set, roles=tuple(roles))


def assert_sovereign(provider_set: str) -> EgressAttestation:
    """The sovereign PRE-FLIGHT: build the egress attestation and REFUSE (raise
    SovereigntyError) if any role routes to a closed hosted model. Returns the
    attestation when every role is self-hosted, so a caller can sign it.

    This is the gate behind run_floor's --sovereign flag: it is DEFAULT OFF (the
    caller only invokes it when --sovereign is set), so a run without it behaves
    exactly as before."""
    attestation = build_egress_attestation(provider_set)
    if not attestation.sovereign:
        raise SovereigntyError(list(attestation.hosted_roles))
    return attestation


def canonical_egress_bytes(document: dict) -> bytes:
    """The egress document serialized to canonical JSON bytes.

    Uses the SAME canonicalization recipe as the run log, the bound signing
    payload, the management assertion, and the portfolio receipt
    (`json.dumps(..., sort_keys=True, separators=(",",":"))`), with no now() and
    no RNG, so the same attestation always yields the same bytes and therefore the
    same digest. A verifier rebuilds these exact bytes from the re-derived
    attestation to check the signature."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def egress_digest(document: dict) -> str:
    """The sha256 over the canonical egress bytes. This is the digest the detached
    Ed25519 signature is taken over, so a single edited field in the egress record
    moves it and breaks the signature."""
    return hashlib.sha256(canonical_egress_bytes(document)).hexdigest()


def sign_egress(document: dict, private_key=None) -> dict:
    """Sign the egress DOCUMENT with a SEPARATE, DETACHED Ed25519 signature and
    return the signature record that lands in the egress sidecar.

    The signature is taken over the egress document's canonical bytes (the same
    bytes `egress_digest` hashes), with the committed demo key by default, under
    the DISTINCT egress label. It is DETACHED and SEPARATE from the run-log bound
    signature: it attests the egress document only, it is never folded into the
    run-log bound payload, and it never enters the hashed run-log. So the run-log
    sha, the chain head, the four sealed run-log signatures, and byte-identical
    replay are all untouched.

    The record carries the digest, the detached signature, the public key, its
    fingerprint, and the honest demo-key caveat, so a verifier re-derives the
    attestation, recomputes the digest, rebuilds the signed bytes, and checks the
    signature with no private key."""
    digest = egress_digest(document)
    signed_bytes = canonical_egress_bytes(document)
    signature_hex = sign_bytes(signed_bytes, private_key)
    pub_hex = load_public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "separate_from_run_log_signature": True,
        "signed_payload": EGRESS_SIGNED_PAYLOAD,
        "egress_digest": digest,
        "signature": signature_hex,
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": EGRESS_SIGNER,
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_egress_signature(document: dict, signature_record: dict) -> bool:
    """Verify a detached egress signature against a re-derived egress document.
    True only when the digest the record carries matches the digest of the
    canonical bytes of THIS document AND the Ed25519 signature is valid over those
    bytes under the record's public key.

    The digest is recomputed from the document handed in, not trusted from the
    record, so an edit to any field (the digest moves) breaks the check. Returns
    False on any mismatch or malformed input rather than raising, so a verifier
    prints INVALID and exits nonzero without a stack trace on a tampered
    attestation."""
    recomputed = egress_digest(document)
    if recomputed != str(signature_record.get("egress_digest", "")):
        return False
    return verify_bytes(
        canonical_egress_bytes(document),
        signature_record.get("signature", ""),
        signature_record.get("public_key"))


def egress_record(provider_set: str, *, sign: bool = True) -> dict:
    """The packet-ready egress block for the Examiner Packet: the egress document,
    its digest, and (by default) the detached signature record, JSON-serializable.

    Pure derived from the provider set: the same provider set yields the
    byte-identical block. No LLM, no now(); it never enters the hashed run-log and
    gates nothing. When `sign` is False the block carries only the document and
    digest (the unsigned view a render uses), so the signature is an explicit,
    auditable step a verifier checks on its own."""
    attestation = build_egress_attestation(provider_set)
    document = attestation.as_document()
    block = {
        "document": document,
        "digest": egress_digest(document),
        "sovereign": attestation.sovereign,
        "verdict": attestation.verdict,
        "self_hosted_count": attestation.self_hosted_count,
        "total": attestation.total,
    }
    if sign:
        block["signature"] = sign_egress(document)
    return block
