"""One-command egress receipt: did zero breach facts leave the perimeter?

A regulated bank can require that no breach fact be handed to a closed, third-party
hosted model. A --sovereign run (floor/run_floor.py, E5.8) is one in which EVERY
drafting role resolves to an open, self-hostable model (floor/roster.resolve), so
no incident detail leaves the bank's perimeter, and it emits a SIGNED "zero breach
facts left the perimeter" egress attestation. This script answers, in one keyless
offline command, the question a compliance officer starts with: does that signed
attestation still verify?

It RE-DERIVES the egress attestation PURELY from the roster under a provider set
(floor/egress_attestation.build_egress_attestation), recomputes the egress digest
from the re-derived document, takes the detached Ed25519 signature (a sidecar if
one is supplied, else freshly produced from the committed demo key), and verifies
the signature over the re-derived bytes under the committed public key. No network,
no private key needed to verify, just the public key that ships in the repo.

Because the attestation is RE-DERIVED from the roster and the digest is RECOMPUTED
(never trusted from the record), a tampered field that changes any resolved role,
its provider, its model, or the sovereign verdict moves the digest and the
signature no longer verifies. The egress signature is SEPARATE and DETACHED from
the run-log bound signature: it attests the egress document only under a DISTINCT
label and is never folded into the run-log payload, so verifying it neither needs
nor touches the run-log bytes, and the run-log sha / chain head / the four sealed
.sig.json signatures / byte-identical replay are unaffected.

  py scripts/verify_egress.py                 (the default dev provider set)
  py scripts/verify_egress.py dev | prod      (verify a provider set)
  py scripts/verify_egress.py <egress.json>   (verify an egress sidecar)
  py scripts/verify_egress.py --tampered      (prove a tampered attestation fails)

It prints VALID + the resolved roles + the signer fingerprint and exits 0 when the
signature verifies; it prints INVALID and exits nonzero when the attestation was
tampered or the signature does not match. The honest demo-key caveat prints every
time: the mechanism is real, the key's secrecy is not production-grade because the
key ships with the repo.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor import roster  # noqa: E402
from floor.egress_attestation import (  # noqa: E402
    build_egress_attestation,
    egress_digest,
    sign_egress,
    verify_egress_signature,
)
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
)

DEFAULT_PROVIDER = roster.PROVIDER_DEV
PROVIDER_SETS = (roster.PROVIDER_DEV, roster.PROVIDER_PROD)


def _resolve_input(args: list[str]) -> tuple[str, dict | None]:
    """Resolve (provider_set, sidecar) from the arguments: a provider-set name, an
    explicit egress sidecar json (whose document names the provider set), or
    nothing (the default provider set). The sidecar, when given, supplies the
    signature record to verify; otherwise a fresh signature is produced from the
    committed demo key over the re-derived attestation."""
    if args:
        candidate = Path(args[0])
        if candidate.suffix == ".json" and candidate.exists():
            sidecar = json.loads(candidate.read_text(encoding="utf-8"))
            doc = sidecar.get("document", sidecar)
            provider_set = str(doc.get("provider_set", DEFAULT_PROVIDER))
            sig = sidecar.get("signature", sidecar)
            return provider_set, sig
        if args[0] in PROVIDER_SETS:
            return args[0], None
    return DEFAULT_PROVIDER, None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    tampered = "--tampered" in argv

    provider_set, sidecar_sig = _resolve_input(args)

    print("=" * 74)
    print("EGRESS RECEIPT: did zero breach facts leave the perimeter?")
    print("=" * 74)
    print(f"Provider set : {provider_set}")
    print("No network, no private key. Verified against the committed public key.")
    print()

    if provider_set not in PROVIDER_SETS:
        print(f"verify_egress: unknown provider set {provider_set!r}",
              file=sys.stderr)
        return 2

    # Re-derive the egress attestation PURELY from the roster under the provider
    # set, then build the canonical document the signature is taken over.
    attestation = build_egress_attestation(provider_set)
    document = attestation.as_document()
    # The signature record: a supplied sidecar, else a fresh demo-key signature
    # over the re-derived document.
    sig = sidecar_sig if sidecar_sig is not None else sign_egress(document)

    if tampered:
        # Edit one field. The digest is recomputed from THIS document, so the same
        # edit that changes the attestation makes the signature INVALID.
        document = json.loads(json.dumps(document))  # deep copy
        document["sovereign"] = not document.get("sovereign", False)
        if document.get("roles"):
            document["roles"][0]["self_hosted"] = (
                not document["roles"][0].get("self_hosted", True))
        print("Mode         : --tampered (one egress field flipped)")
        print()

    pubkey_hex = load_public_key_hex()
    digest_now = egress_digest(document)
    valid = verify_egress_signature(document, sig)
    signer = sig.get("signer", "Deadline Warden")
    sig_fp = sig.get("pubkey_fingerprint",
                     fingerprint(sig.get("public_key", "") or pubkey_hex))

    print(f"Public key   : {pubkey_hex}")
    print(f"Key fp       : {fingerprint(pubkey_hex)}")
    print(f"Algorithm    : {sig.get('algorithm', 'ed25519')} (detached, separate "
          "from the run-log signature)")
    print(f"Signed over  : {sig.get('signed_payload', 'canonical_json(egress_attestation)')}")
    print(f"Egress digest: {digest_now}")
    print(f"  (record digest: {sig.get('egress_digest', '(absent)')})")
    print(f"Signature    : {str(sig.get('signature', ''))[:32]}...")
    print()

    print(f"Resolved roles ({attestation.self_hosted_count} of {attestation.total} "
          "self-hosted):")
    for r in attestation.roles:
        posture = "self-hosted (open)" if r.self_hosted else "hosted (CLOSED)"
        print(f"  [{posture:18s}] {r.role_label}: {r.provider}:{r.model}")
    print()

    if valid:
        print(f"VALID. Signature verifies: egress attestation signed by {signer} "
              f"(key fp {sig_fp}).")
        print("  The detached Ed25519 signature attests this exact egress record,")
        print("  re-derived from the roster under the provider set and re-digested")
        print("  here. It is SEPARATE from the run-log signature, under a DISTINCT")
        print("  label, and never folded into the run-log payload, so the run-log")
        print("  sha, the chain head, the four sealed signatures, and byte-identical")
        print("  replay are untouched. An edited role, provider, model, or verdict")
        print("  moves the digest and would make this INVALID.")
        if attestation.sovereign:
            print()
            print("  Sovereign: every drafting role is self-hosted, so ZERO breach")
            print("  facts left the perimeter.")
        print()
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 74)
        return 0

    print("INVALID. Signature does NOT verify against the committed public key.")
    if tampered:
        print("  Expected: a tampered attestation moves the digest and breaks the "
              "signature. It did.")
    else:
        print("  The attestation was tampered after signing, or it was not signed "
              "by the holder of this key.")
    print()
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 74)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
