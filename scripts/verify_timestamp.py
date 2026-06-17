"""One-command RFC 3161 timestamp receipt: WHEN was this signed artifact sealed?

`scripts/verify_signature.py` proves WHO signed the run (the holder of the Warden
key); `scripts/verify_intoto.py` re-expresses that as the in-toto / DSSE standard.
THIS script answers WHEN. It loads the `.tst.json` RFC 3161 timestamp sidecar beside
a captured run log, verifies the Time-Stamping Authority's signature over the
TSTInfo, and checks that the timestamped messageImprint equals the signed artifact's
digest (the sha256 of the bound-payload bytes the Ed25519 signature was taken over).

  py scripts/verify_timestamp.py                       (the normal captured run)
  py scripts/verify_timestamp.py <run-log.jsonl>       (verify any run's sidecar)
  py scripts/verify_timestamp.py <run-log.jsonl> <token.tst.json>
  py scripts/verify_timestamp.py --tampered            (prove tamper => INVALID)

It prints VALID + the timestamp (genTime), the standard (RFC 3161), the serial and
policy, and the honest demo-TSA caveat, and exits 0 when BOTH the TSA signature
verifies AND the messageImprint matches the artifact digest. It prints INVALID and
exits nonzero when the token was tampered, the TSA signature does not match, or the
messageImprint no longer equals the signed artifact. The demo-TSA caveat prints
every time: the RFC 3161 mechanism is fully real, but the AUTHORITY is a local demo,
not a qualified third-party TSA, which is a deployment configuration.

How the timestamp and the signature are located: the signature record is read the
same way verify_signature.py reads it (a packet's replay.signature, else a sibling
<log>.sig.json sidecar). The timestamp token is the sibling <log>.tst.json sidecar
(or an explicit path). The artifact digest is recomputed from the signature record's
bound values, so a forged digest in the token is caught by the messageImprint check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.signing import fingerprint, load_public_key_hex  # noqa: E402
from warden.timestamp import (  # noqa: E402
    DEMO_TSA_CAVEAT,
    STANDARD,
    sidecar_path_for,
    verify_timestamp_token,
)

DEFAULT_LOG = REPO_ROOT / "web" / "data" / "run-inc-8842-normal.jsonl"
DEFAULT_PACKET = REPO_ROOT / "web" / "data" / "packet-normal.json"


def _sig_sidecar_for(log_path: Path) -> Path:
    return log_path.with_suffix(log_path.suffix + ".sig.json")


def _default_packet_for(log_path: Path) -> Path | None:
    name = log_path.name
    prefix, suffix = "run-inc-8842-", ".jsonl"
    if name.startswith(prefix) and name.endswith(suffix):
        mode = name[len(prefix):-len(suffix)]
        candidate = REPO_ROOT / "web" / "data" / f"packet-{mode}.json"
        if candidate.exists():
            return candidate
    return None


def _load_signature_record(log_path: Path) -> dict | None:
    """The sealed signature record whose bound payload the timestamp anchors: a
    sibling <log>.sig.json sidecar, else the paired packet's replay.signature."""
    sidecar = _sig_sidecar_for(log_path)
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    packet_path = _default_packet_for(log_path)
    if packet_path and packet_path.exists():
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        sig = (packet.get("replay") or {}).get("signature")
        if sig:
            return sig
    return None


def _load_token(log_path: Path, token_path: Path | None) -> dict | None:
    """The RFC 3161 timestamp token: an explicit path, else the sibling
    <log>.tst.json sidecar."""
    if token_path and token_path.exists():
        return json.loads(token_path.read_text(encoding="utf-8"))
    sidecar = sidecar_path_for(log_path)
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    tampered = "--tampered" in argv

    log_path = Path(args[0]).resolve() if len(args) >= 1 else DEFAULT_LOG
    token_path = Path(args[1]).resolve() if len(args) >= 2 else None

    print("=" * 72)
    print("RFC 3161 TIMESTAMP RECEIPT: when was this signed artifact sealed?")
    print("=" * 72)
    print(f"Run log    : {log_path}")
    print(f"Standard   : {STANDARD}")
    print("No network, no private key. Verified against the committed TSA public key.")
    print()

    if not log_path.exists():
        print(f"verify_timestamp: run log not found at {log_path}", file=sys.stderr)
        return 2

    signature_record = _load_signature_record(log_path)
    if signature_record is None:
        print("INVALID: no signature record found for this run log.")
        print("  The timestamp anchors the signed artifact, so a <log>.sig.json or a")
        print("  packet with replay.signature must be present.")
        print()
        print(f"Note: {DEMO_TSA_CAVEAT}")
        print("=" * 72)
        return 4

    token = _load_token(log_path, token_path)
    if token is None:
        print("INVALID: no RFC 3161 timestamp sidecar found for this run log.")
        print("  Expected a sibling <log>.tst.json, or pass one explicitly.")
        print()
        print(f"Note: {DEMO_TSA_CAVEAT}")
        print("=" * 72)
        return 4

    if tampered:
        # Flip one byte of the signed TSTInfo: prove the same edit that breaks our
        # native signature ALSO breaks the timestamp. Mutating the TSTInfo DER
        # changes the bytes the TSA signature was taken over, so it must fail.
        tst_hex = token.get("tst_info_der", "")
        if tst_hex:
            flipped = ("0" if tst_hex[0] != "0" else "1") + tst_hex[1:]
            token = {**token, "tst_info_der": flipped}
        print("Mode       : --tampered (one byte of the signed TSTInfo flipped)")
        print()

    warden_pub = load_public_key_hex()
    print(f"Warden key : {warden_pub}  (fp {fingerprint(warden_pub)})")
    print(f"TSA key    : {token.get('tsa_public_key', '(absent)')}  "
          f"(fp {token.get('tsa_pubkey_fingerprint', '?')})")
    print(f"TSA        : {token.get('tsa', 'demo TSA')}")
    print()

    verification = verify_timestamp_token(token, signature_record)

    print(f"PKI status : {token.get('pki_status_string', '?')} "
          f"({token.get('pki_status', '?')})")
    print(f"Policy OID : {verification.policy_oid or token.get('policy_oid', '?')}")
    print(f"Serial     : {verification.serial if verification.serial is not None else token.get('serial_number', '?')}")
    print(f"Hash alg   : {token.get('hash_algorithm', 'sha256')} "
          f"({token.get('hash_oid', '?')})")
    print(f"Artifact   : sha256(bound payload) = {token.get('artifact_digest', '?')}")
    print(f"  TSA signature over TSTInfo : "
          f"{'VALID' if verification.signature_valid else 'INVALID'}")
    print(f"  messageImprint == artifact : "
          f"{'MATCH' if verification.imprint_matches else 'MISMATCH'}")
    print()

    if verification.valid:
        gen = verification.gen_time.isoformat() if verification.gen_time else "?"
        print(f"VALID. RFC 3161 timestamp verifies. Timestamped at: {gen}")
        print("  The TSA signed a TSTInfo binding the artifact digest to this")
        print("  genTime, and the timestamped messageImprint equals the sha256 of")
        print("  the bound payload the Warden signature was taken over. So the")
        print("  signed run is anchored to a point in time: a flipped TSTInfo byte")
        print("  (TSA signature fails) or a different artifact (messageImprint")
        print("  mismatch) would make this INVALID.")
        print()
        print(f"Note: {DEMO_TSA_CAVEAT}")
        print("=" * 72)
        return 0

    print("INVALID. The RFC 3161 timestamp does NOT verify.")
    print(f"  {verification.detail}")
    if tampered:
        print("  Expected: a one-byte TSTInfo tamper breaks the TSA signature. "
              "It did.")
    print()
    print(f"Note: {DEMO_TSA_CAVEAT}")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
