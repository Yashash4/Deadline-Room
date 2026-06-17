"""One-command in-toto / DSSE receipt: does our provenance verify as the standard?

`scripts/verify_signature.py` verifies our NATIVE detached signature over the
bound `{sha256, chain_head}` payload. THIS script answers the supply-chain
ecosystem's version of the same question: is the run's provenance also a valid
in-toto Statement wrapped in a signed DSSE (Dead Simple Signing Envelope)? It
loads the `.intoto.json` sidecar beside a captured run log, re-encodes the DSSE
PAE and verifies the Ed25519 signature against the committed public key, then
checks that the in-toto subject digest equals the sealed run-log sha256 on disk.

This NAMES our provenance in the recognized in-toto / SLSA standard. The existing
native signature, audit_run, tamper_sweep, and byte-identical replay are
untouched: the DSSE envelope is a strictly ADDITIVE sidecar, derived read-only
from the same bytes.

  py scripts/verify_intoto.py                       (the normal captured run)
  py scripts/verify_intoto.py <run-log.jsonl>       (verify any run's sidecar)
  py scripts/verify_intoto.py <run-log.jsonl> <envelope.intoto.json>
  py scripts/verify_intoto.py --tampered            (prove tamper => INVALID)

It prints VALID + the standard names (in-toto Statement v1, DSSE v1) and the
signer fingerprint, and exits 0 when both the envelope signature verifies AND the
subject digest matches the run-log on disk. It prints INVALID and exits nonzero
when the envelope was tampered, the signature does not match, or the subject
digest no longer equals the sealed bytes. The honest demo-key caveat prints every
time: the PAE/signature mechanism is fully real, the key's secrecy is not
production-grade because the key ships with the repo.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.intoto import (  # noqa: E402
    INTOTO_PAYLOAD_TYPE,
    STATEMENT_TYPE,
    sidecar_path_for,
    statement_of_envelope,
    verify_dsse_envelope,
)
from warden.signing import DEMO_KEY_CAVEAT, fingerprint, load_public_key_hex  # noqa: E402

DEFAULT_LOG = REPO_ROOT / "web" / "data" / "run-inc-8842-normal.jsonl"


def _sha256_of(path: Path) -> str:
    """The run-log integrity sha, computed the SAME way the sealed pipeline does:
    over the canonical UTF-8 text (`read_text` then `.encode("utf-8")`), which is
    exactly what `RunLog.sha256()`, the chain, the detached signature, and
    `verify_signature.py` hash. Reading as text normalizes platform line endings
    to the canonical LF form the seal was taken over, so this matches the in-toto
    subject digest and the sealed sig.json sha byte for byte."""
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def _load_envelope(log_path: Path, env_path: Path | None) -> dict | None:
    """Find the DSSE envelope for a run log: an explicit path, else the sibling
    `<log>.intoto.json` sidecar. None when neither is present, so the receipt
    reports that plainly rather than guessing."""
    if env_path and env_path.exists():
        return json.loads(env_path.read_text(encoding="utf-8"))
    sidecar = sidecar_path_for(log_path)
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    tampered = "--tampered" in argv

    log_path = Path(args[0]).resolve() if len(args) >= 1 else DEFAULT_LOG
    env_path = Path(args[1]).resolve() if len(args) >= 2 else None

    print("=" * 72)
    print("in-toto / DSSE RECEIPT: does our provenance verify as the standard?")
    print("=" * 72)
    print(f"Run log    : {log_path}")
    print(f"Standards  : in-toto Statement v1 ({STATEMENT_TYPE})")
    print(f"             DSSE v1 envelope, payloadType {INTOTO_PAYLOAD_TYPE}")
    print("No network, no private key. Verified against the committed public key.")
    print()

    if not log_path.exists():
        print(f"verify_intoto: run log not found at {log_path}", file=sys.stderr)
        return 2

    envelope = _load_envelope(log_path, env_path)
    pubkey_hex = load_public_key_hex()
    print(f"Public key : {pubkey_hex}")
    print(f"Key fp     : {fingerprint(pubkey_hex)}")
    print()

    if not envelope:
        print("INVALID: no in-toto/DSSE sidecar found for this run log.")
        print("  Expected a sibling <log>.intoto.json, or pass one explicitly.")
        print()
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 72)
        return 4

    if tampered:
        # Flip one byte of the DSSE payload: prove the same edit that breaks our
        # native signature ALSO breaks the standard envelope. Mutating the base64
        # payload changes the PAE the signature was taken over, so it must fail.
        payload = envelope.get("payload", "")
        if payload:
            flipped = ("B" if payload[0] != "B" else "C") + payload[1:]
            envelope = {**envelope, "payload": flipped}
        print("Mode       : --tampered (one byte of the DSSE payload flipped)")
        print()

    sig_valid = verify_dsse_envelope(envelope)

    # Decode the Statement so the receipt can show exactly what it attests. On a
    # tamper the base64 may not decode to JSON; guard so the receipt still prints.
    try:
        statement = statement_of_envelope(envelope)
    except (ValueError, json.JSONDecodeError):
        statement = None

    sha_on_disk = _sha256_of(log_path)
    subject_digest = ""
    subject_name = ""
    keyid = ""
    predicate_type = ""
    if statement:
        subjects = statement.get("subject") or [{}]
        subject_name = subjects[0].get("name", "")
        subject_digest = (subjects[0].get("digest") or {}).get("sha256", "")
        predicate_type = statement.get("predicateType", "")
    sigs = envelope.get("signatures") or [{}]
    keyid = sigs[0].get("keyid", "")

    digest_matches = bool(subject_digest) and subject_digest == sha_on_disk

    print(f"Envelope   : DSSE v1, 1 signature, keyid {keyid}")
    if statement:
        print(f"Statement  : {statement.get('_type', '')}")
        print(f"predicate  : {predicate_type}")
        print(f"subject    : {subject_name}")
        print(f"  subject sha256 : {subject_digest}")
    print(f"  run-log sha256 : {sha_on_disk}")
    print()

    valid = sig_valid and digest_matches

    if valid:
        print("VALID. DSSE envelope signature verifies over the PAE, and the")
        print("  in-toto subject digest equals the sealed run-log sha256.")
        print("  Our signed provenance is a conformant in-toto / SLSA attestation:")
        print("  in-toto Statement v1 inside a DSSE v1 envelope, Ed25519 over the")
        print("  Pre-Authentication Encoding. A flipped byte makes it INVALID.")
        print()
        print(f"Note: {DEMO_KEY_CAVEAT}")
        print("=" * 72)
        return 0

    print("INVALID. The in-toto / DSSE attestation does NOT verify.")
    if not sig_valid:
        if tampered:
            print("  Expected: a one-byte payload tamper breaks the DSSE signature. "
                  "It did.")
        else:
            print("  The DSSE signature does not verify over the PAE under this key.")
    elif not digest_matches:
        print("  The in-toto subject digest does NOT equal the run-log sha256 on "
              "disk;")
        print("  the attested bytes are not the bytes present.")
    print()
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
