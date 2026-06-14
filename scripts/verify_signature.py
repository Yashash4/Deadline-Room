"""One-command signature receipt: is this run log signed by the Warden's key?

The flat sha and the hash chain prove INTEGRITY (the bytes were not edited). They
do not prove AUTHENTICITY (who attests them). This script closes that: it loads a
captured run log and its detached Ed25519 signature, and verifies the signature
against the committed Warden public key. No network, no private key needed to
verify, just the public key that ships in the repo.

The signature is taken over a BOUND payload: the run-log sha256 AND the per-entry
chain head together. So VALID means "this exact ordered, complete run, attested
by this key", not merely "these bytes". Both bound values are recomputed here
from the bytes on disk and printed, so a field edit (sha moves) or a
reorder/omission (chain head moves) both turn the signature INVALID.

  py scripts/verify_signature.py                          (a clean captured run)
  py scripts/verify_signature.py <run-log.jsonl>          (verify any run log)
  py scripts/verify_signature.py <run-log.jsonl> <packet.json>
  py scripts/verify_signature.py --tampered               (prove tamper => INVALID)

It prints VALID + the signer fingerprint and exits 0 when the signature verifies;
it prints INVALID and exits nonzero when the bytes were tampered or the signature
does not match. The honest demo-key caveat is printed every time: the mechanism
is real, the key's secrecy is not production-grade.

How the signature is located: a captured packet's replay block carries the
signature record (algorithm, signature hex, public key, fingerprint). When a
packet path is given (or a sibling <run-log>.sig.json exists), its signature is
verified against the run-log bytes. With no signature on hand the script reports
that plainly rather than guessing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.chain import chain_head  # noqa: E402
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
    verify_run_log_jsonl,
)


def _sha_and_head(jsonl: str) -> tuple[str, str]:
    """Recompute the two values the signature binds, straight from the bytes on
    disk: the run-log sha256 and the per-entry chain head. A verifier derives
    these itself rather than trusting the record, so a field edit (sha moves) or
    a reorder/omission (chain head moves) is caught."""
    import hashlib
    import json

    sha = hashlib.sha256(jsonl.encode("utf-8")).hexdigest()
    entries = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
    return sha, chain_head(entries)

DEFAULT_LOG = REPO_ROOT / "web" / "data" / "run-inc-8842-normal.jsonl"
DEFAULT_PACKET = REPO_ROOT / "web" / "data" / "packet-normal.json"


def _sidecar_for(log_path: Path) -> Path:
    """The detached signature sidecar that sits beside a run log."""
    return log_path.with_suffix(log_path.suffix + ".sig.json")


def _load_signature_record(log_path: Path, packet_path: Path | None) -> dict | None:
    """Find the signature record for a run log. Order of preference: an explicit
    packet's replay.signature, a sibling <log>.sig.json sidecar, else the
    default captured packet if it pairs with this log."""
    if packet_path and packet_path.exists():
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        sig = (packet.get("replay") or {}).get("signature")
        if sig:
            return sig
    sidecar = _sidecar_for(log_path)
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    if log_path == DEFAULT_LOG and DEFAULT_PACKET.exists():
        packet = json.loads(DEFAULT_PACKET.read_text(encoding="utf-8"))
        sig = (packet.get("replay") or {}).get("signature")
        if sig:
            return sig
    return None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    tampered = "--tampered" in argv

    log_path = Path(args[0]).resolve() if len(args) >= 1 else DEFAULT_LOG
    packet_path = Path(args[1]).resolve() if len(args) >= 2 else None

    print("=" * 72)
    print("SIGNATURE RECEIPT: is this run log signed by the Warden's key?")
    print("=" * 72)
    print(f"Run log    : {log_path}")
    print("No network, no private key. Verified against the committed public key.")
    print()

    if not log_path.exists():
        print(f"verify_signature: run log not found at {log_path}", file=sys.stderr)
        return 2

    jsonl = log_path.read_text(encoding="utf-8")
    if tampered:
        # Flip one byte of the signed payload: prove the same edit that breaks the
        # hash and the chain ALSO makes the signature INVALID. We change a single
        # character so the bytes the signature covers no longer match.
        original = jsonl
        jsonl = jsonl.replace('"admitted":true', '"admitted":false', 1)
        if jsonl == original:
            jsonl = original[:-2] + ("X" + original[-1:] if original else "X")
        print("Mode       : --tampered (one byte of the signed payload flipped)")
        print()

    sig = _load_signature_record(log_path, packet_path)
    pubkey_hex = load_public_key_hex()
    print(f"Public key : {pubkey_hex}")
    print(f"Key fp     : {fingerprint(pubkey_hex)}")
    print()

    if not sig:
        print("INVALID: no detached signature found for this run log.")
        print("  Provide a packet with replay.signature, or a <log>.sig.json "
              "sidecar.")
        print()
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 72)
        return 4

    signer = sig.get("signer", "Deadline Warden")
    sig_fp = sig.get("pubkey_fingerprint", fingerprint(sig.get("public_key", "")
                                                        or pubkey_hex))
    valid = verify_run_log_jsonl(jsonl, sig)

    # Recompute the two bound values from the bytes on disk so the receipt shows
    # exactly what the signature attests: the byte sha AND the ordered-run head.
    sha_now, head_now = _sha_and_head(jsonl)

    print(f"Algorithm  : {sig.get('algorithm', 'ed25519')} (detached)")
    print(f"Signed over: {sig.get('signed_payload', 'canonical_json{sha256,chain_head}')}")
    print(f"  sha256     : {sha_now}")
    print(f"  chain_head : {head_now}")
    print(f"Signature  : {str(sig.get('signature', ''))[:32]}...")
    print(f"Signer     : {signer}")
    print()

    if valid:
        print(f"VALID. Signature verifies: signed by {signer} (key fp {sig_fp}).")
        print("  The signature binds BOTH the run-log sha256 and the chain head, so")
        print("  it attests this exact ORDERED, COMPLETE run, not just the bytes. A")
        print("  flipped field (sha moves) or a reorder/omission (chain head moves)")
        print("  would make this INVALID.")
        print()
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 72)
        return 0

    print("INVALID. Signature does NOT verify against the committed public key.")
    if tampered:
        print("  Expected: a one-byte tamper of the signed payload breaks the "
              "signature. It did.")
    else:
        print("  These bytes were not signed by the holder of this key, or they "
              "were tampered after signing.")
    print()
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
