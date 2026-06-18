"""One-command management-assertion receipt: is this signed assertion VALID?

An audit engagement is anchored on a MANAGEMENT ASSERTION plus its supporting
evidence: management asserts the relevant controls operated effectively over the
reporting period, and the auditor tests that assertion against the evidence. The
control-evidence register (E4.4) is the evidence; the signed assertion (E4.8) is
the letter on top of it. This script answers, in one keyless offline command, the
question the auditor starts with: does the signed assertion still verify?

It re-derives the management assertion PURELY from the captured packet's
control-evidence register (floor/assertion.build_assertion over the same register
the packet's controls block is built from), recomputes the assertion digest from
the re-derived document, loads the detached assertion signature sidecar
(web/data/assertion-<scenario>.json), and verifies the Ed25519 signature over the
re-derived assertion bytes under the committed public key. No network, no private
key needed to verify, just the public key that ships in the repo.

Because the assertion is RE-DERIVED from the register and the digest is RECOMPUTED
(never trusted from the sidecar), a tampered packet field that changes any asserted
control, the status, the period, or the verdict moves the digest and the signature
no longer verifies. The assertion signature is SEPARATE and DETACHED from the
run-log bound signature: it attests the assertion document only and is never folded
into the run-log payload, so verifying it neither needs nor touches the run-log
bytes, and the run-log sha / chain head / byte-identical replay are unaffected.

  py scripts/verify_assertion.py                 (the default sealed scenario)
  py scripts/verify_assertion.py <scenario>      (normal | inject_contradiction |
                                                  chaos | amendment)
  py scripts/verify_assertion.py <packet.json> <assertion.json>
  py scripts/verify_assertion.py --tampered      (prove a tampered assertion fails)

It prints VALID + the asserted controls + the signer fingerprint and exits 0 when
the signature verifies; it prints INVALID and exits nonzero when the assertion was
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

from floor.assertion import (  # noqa: E402
    assertion_digest,
    build_assertion,
    verify_assertion_signature,
)
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
)

DATA = REPO_ROOT / "web" / "data"
DEFAULT_SCENARIO = "inject_contradiction"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment", "submit")


def _resolve_paths(args: list[str]) -> tuple[Path, Path]:
    """Resolve the (packet, assertion-sidecar) pair from the arguments: a scenario
    name, an explicit packet + assertion pair, or nothing (the default scenario)."""
    if len(args) >= 2:
        return Path(args[0]).resolve(), Path(args[1]).resolve()
    scenario = args[0] if args else DEFAULT_SCENARIO
    # An explicit packet path with the sidecar found by convention beside it.
    candidate = Path(scenario)
    if candidate.suffix == ".json" and candidate.exists():
        # Derive the sidecar name from a packet-<mode>.json convention if possible.
        name = candidate.name
        if name.startswith("packet-"):
            mode = name[len("packet-"):-len(".json")]
            return candidate.resolve(), (DATA / f"assertion-{mode}.json")
        return candidate.resolve(), (DATA / f"assertion-{DEFAULT_SCENARIO}.json")
    return (DATA / f"packet-{scenario}.json", DATA / f"assertion-{scenario}.json")


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    tampered = "--tampered" in argv

    packet_path, sidecar_path = _resolve_paths(args)

    print("=" * 74)
    print("MANAGEMENT-ASSERTION RECEIPT: is this signed assertion VALID?")
    print("=" * 74)
    print(f"Packet    : {packet_path}")
    print(f"Assertion : {sidecar_path}")
    print("No network, no private key. Verified against the committed public key.")
    print()

    if not packet_path.exists():
        print(f"verify_assertion: packet not found at {packet_path}",
              file=sys.stderr)
        return 2
    if not sidecar_path.exists():
        print(f"verify_assertion: assertion sidecar not found at {sidecar_path}",
              file=sys.stderr)
        return 2

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))

    # Re-derive the assertion PURELY from the packet's control-evidence register,
    # then build the canonical document the signature is taken over.
    assertion = build_assertion(packet)
    document = assertion.as_document()

    if tampered:
        # Edit one asserted field. The digest is recomputed from THIS document, so
        # the same edit that changes the assertion makes the signature INVALID.
        document = json.loads(json.dumps(document))  # deep copy
        document["operated_count"] = document.get("operated_count", 0) + 1
        if document.get("controls"):
            document["controls"][0]["status"] = "TAMPERED"
        print("Mode      : --tampered (one asserted field flipped)")
        print()

    if assertion.total == 0:
        print("EMPTY: this packet carries no catalogued control to assert.")
        print("=" * 74)
        return 2

    pubkey_hex = load_public_key_hex()
    digest_now = assertion_digest(document)
    valid = verify_assertion_signature(document, sidecar)
    signer = sidecar.get("signer", "Deadline Warden, on behalf of management")
    sig_fp = sidecar.get("pubkey_fingerprint",
                         fingerprint(sidecar.get("public_key", "") or pubkey_hex))

    print(f"Public key       : {pubkey_hex}")
    print(f"Key fp           : {fingerprint(pubkey_hex)}")
    print(f"Algorithm        : {sidecar.get('algorithm', 'ed25519')} (detached, "
          "separate from the run-log signature)")
    print(f"Signed over      : {sidecar.get('signed_payload', 'canonical_json(management_assertion)')}")
    print(f"Assertion digest : {digest_now}")
    print(f"  (sidecar digest: {sidecar.get('assertion_digest', '(absent)')})")
    print(f"Signature        : {str(sidecar.get('signature', ''))[:32]}...")
    print()

    period = assertion.period
    if period.start or period.end:
        print(f"Period asserted  : {period.start or '(open)'} through "
              f"{period.end or '(open)'} (UTC)")
    print(f"Asserted controls ({assertion.operated_count} of {assertion.total} "
          "OPERATED):")
    for c in assertion.controls:
        print(f"  [{c.status:13s}] {c.id}: {c.title}")
        print(f"                  {c.framework_refs}")
    print()

    if valid:
        print(f"VALID. Signature verifies: assertion signed by {signer} "
              f"(key fp {sig_fp}).")
        print("  The detached Ed25519 signature attests this exact management")
        print("  assertion, re-derived from the control-evidence register and")
        print("  re-digested here. It is SEPARATE from the run-log signature and")
        print("  never folded into the run-log payload, so the run-log sha, the")
        print("  chain head, and byte-identical replay are untouched. An edited")
        print("  asserted control, status, period, or verdict moves the digest and")
        print("  would make this INVALID.")
        print()
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 74)
        return 0

    print("INVALID. Signature does NOT verify against the committed public key.")
    if tampered:
        print("  Expected: a tampered assertion moves the digest and breaks the "
              "signature. It did.")
    else:
        print("  The assertion was tampered after signing, or it was not signed by "
              "the holder of this key.")
    print()
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 74)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
