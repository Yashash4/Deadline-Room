"""Re-sign the committed web/data captured scenarios over the BOUND payload.

The captured replay viewer ships four scenarios (normal, contradiction, chaos,
amendment), each a packet JSON plus a bundled run-log JSONL. This script re-signs
each over the BOUND payload: the canonical {sha256, chain_head, attestation_sha,
fact_record_hash} object, so a valid signature attests the exact ORDERED, COMPLETE
run, driven from this exact fact-record, that met these statutory deadlines, not
just the byte stream. It persists the chain head, the attestation digest, and the
input fact-record hash into each packet's replay block so the browser can rebuild
and verify the same bound payload client-side, and it regenerates the sibling
<log>.intoto.json DSSE/in-toto sidecar over the new predicate.

The attestation digest is derived from the packet's clock rows (deadline minus
filed-at per regime) and the fact-record hash from the packet's input fact-record,
so the two derived digests recomputed here are exactly the ones a fresh run would
produce. The deadline-compliance attestation object is refreshed into the packet at
the same time so the rendered table matches the signed digest.

It is DERIVED and read-only over the run-log bytes: the .jsonl files are never
rewritten (only the packet replay block, the packet attestation, the <log>.sig.json
sidecar, and the <log>.intoto.json sidecar move), so every packet's original_sha256
and the in-browser byte-identical replay are unchanged. The chain head is computed
from the same canonical entries replay reproduces.

Run from code/:  py scripts/resign_captures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.attestation import attestation_sha, build_attestation  # noqa: E402
from floor.fact_record import fact_record_hash  # noqa: E402
from warden.chain import head_for_log  # noqa: E402
from warden.intoto import attestation_for_capture, sidecar_path_for  # noqa: E402
from warden.replay import RunLog  # noqa: E402
from warden.signing import sign_run_log_jsonl, verify_run_log_jsonl  # noqa: E402
from warden.timestamp import (  # noqa: E402
    sidecar_path_for as tst_sidecar_path_for,
)
from warden.timestamp import (  # noqa: E402
    timestamp_signature_record,
    verify_timestamp_token,
)

DATA = REPO_ROOT / "web" / "data"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")


def _resign(mode: str) -> str:
    packet_path = DATA / f"packet-{mode}.json"
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    sidecar_path = log_path.with_suffix(log_path.suffix + ".sig.json")

    before_bytes = log_path.read_bytes()

    log = RunLog.load(log_path)
    jsonl = log.to_jsonl()
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    # The bytes the signature binds are exactly the bytes whose sha the packet
    # already records. If these diverge the capture is broken; fail loudly.
    if log.sha256() != packet["replay"]["original_sha256"]:
        raise SystemExit(
            f"{mode}: bundled log hash does not match packet replay hash; "
            "the capture is inconsistent, not re-signing.")

    # The two DERIVED digests folded into the bound payload, recomputed from the
    # packet's own clock rows and input fact-record so they equal what a fresh run
    # produces. The attestation object is refreshed into the packet too, so the
    # rendered table and the signed digest agree.
    attestation = build_attestation(packet.get("clocks", []))
    attestation_sha_hex = attestation_sha(attestation)
    fact_record_hash_hex = fact_record_hash(
        packet.get("incident", {}).get("fact_record", {}))

    chain_head_hex = head_for_log(log)
    signature = sign_run_log_jsonl(
        jsonl, attestation_sha_hex, fact_record_hash_hex)
    if signature["chain_head"] != chain_head_hex:
        raise SystemExit(f"{mode}: signature chain_head disagrees with the log head")
    if signature["sha256"] != packet["replay"]["original_sha256"]:
        raise SystemExit(f"{mode}: signature sha256 disagrees with the packet sha")
    if not verify_run_log_jsonl(jsonl, signature):
        raise SystemExit(f"{mode}: freshly produced signature does not verify")

    packet["replay"]["chain_head"] = chain_head_hex
    packet["replay"]["attestation_sha"] = attestation_sha_hex
    packet["replay"]["fact_record_hash"] = fact_record_hash_hex
    packet["replay"]["signature"] = signature
    packet["attestation"] = attestation
    packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
    sidecar_path.write_text(json.dumps(signature, indent=2) + "\n", encoding="utf-8")

    # Regenerate the in-toto / DSSE sidecar over the new predicate (it names the
    # same two bound digests). It reads the freshly written packet so the digests
    # in its predicate match the just-sealed signature.
    intoto_path = sidecar_path_for(log_path)
    envelope = attestation_for_capture(jsonl, packet, subject_name=log_path.name)
    intoto_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")

    # Regenerate the RFC 3161 timestamp sidecar over the freshly sealed signature.
    # The demo TSA stamps a FIXED genTime (never now()), so the token is byte-stable
    # and reproducible. It is an additive sidecar derived read-only from the
    # signature record; the run-log/packet/sig.json/intoto bytes are never touched.
    tst_path = tst_sidecar_path_for(log_path)
    token = timestamp_signature_record(signature)
    if not verify_timestamp_token(token, signature).valid:
        raise SystemExit(f"{mode}: freshly issued RFC 3161 timestamp does not verify")
    tst_path.write_text(json.dumps(token, indent=2) + "\n", encoding="utf-8")

    # The run-log bytes must be untouched: this script is derived/read-only.
    if log_path.read_bytes() != before_bytes:
        raise SystemExit(f"{mode}: run-log bytes changed; that must never happen")

    return chain_head_hex


def main() -> int:
    for mode in SCENARIOS:
        head = _resign(mode)
        print(f"  {mode:22s} re-signed over sha256 + chain_head + attestation_sha + "
              f"fact_record_hash (head {head[:16]}...)")
    print("Re-signed every captured scenario over the 4-field bound payload and "
          "regenerated the in-toto and RFC 3161 timestamp sidecars. Run-log bytes "
          "unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
