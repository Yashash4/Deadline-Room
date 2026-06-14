"""Re-sign the committed web/data captured scenarios over the BOUND payload.

The captured replay viewer ships four scenarios (normal, contradiction, chaos,
amendment), each a packet JSON plus a bundled run-log JSONL. The signature over
each run log used to cover the bare run-log bytes. This script re-signs each over
the BOUND payload instead: the canonical {sha256, chain_head} object, so a valid
signature attests the exact ORDERED, COMPLETE run, not just the byte stream. It
also persists the chain head into each packet's replay block so the browser can
rebuild and verify the same bound payload client-side.

It is DERIVED and read-only over the run-log bytes: the .jsonl files are never
rewritten (only the packet replay.signature, replay.chain_head, and the sibling
<log>.sig.json sidecar move), so every packet's original_sha256 and the in-browser
byte-identical replay are unchanged. The chain head is computed from the same
canonical entries replay reproduces.

Run from code/:  py scripts/resign_captures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.chain import head_for_log  # noqa: E402
from warden.replay import RunLog  # noqa: E402
from warden.signing import sign_run_log_jsonl, verify_run_log_jsonl  # noqa: E402

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

    chain_head_hex = head_for_log(log)
    signature = sign_run_log_jsonl(jsonl)
    if signature["chain_head"] != chain_head_hex:
        raise SystemExit(f"{mode}: signature chain_head disagrees with the log head")
    if signature["sha256"] != packet["replay"]["original_sha256"]:
        raise SystemExit(f"{mode}: signature sha256 disagrees with the packet sha")
    if not verify_run_log_jsonl(jsonl, signature):
        raise SystemExit(f"{mode}: freshly produced signature does not verify")

    packet["replay"]["chain_head"] = chain_head_hex
    packet["replay"]["signature"] = signature
    packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
    sidecar_path.write_text(json.dumps(signature, indent=2) + "\n", encoding="utf-8")

    # The run-log bytes must be untouched: this script is derived/read-only.
    if log_path.read_bytes() != before_bytes:
        raise SystemExit(f"{mode}: run-log bytes changed; that must never happen")

    return chain_head_hex


def main() -> int:
    for mode in SCENARIOS:
        head = _resign(mode)
        print(f"  {mode:22s} re-signed over sha256 + chain_head {head[:16]}...")
    print("Re-signed every captured scenario over the bound payload. Run-log bytes "
          "unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
