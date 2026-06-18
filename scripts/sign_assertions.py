"""Emit the detached, signed management-assertion sidecars for the sealed scenarios.

For each committed sealed scenario this re-derives the management assertion PURELY
from the captured packet's control-evidence register (floor/assertion), signs the
assertion document's canonical bytes with a SEPARATE, DETACHED Ed25519 signature,
and writes the signed assertion sidecar to web/data/assertion-<scenario>.json.

It is DERIVED and read-only over the sealed run: it reads the packet only and writes
ONLY the new assertion sidecar. It never rewrites the run-log JSONL, the run-log
.sig.json, the packet, or any other sealed byte. The assertion signature is separate
from the run-log bound signature and is never folded into the run-log payload, so the
run-log sha, the chain head, the run-log signature, and byte-identical replay are all
untouched. The script asserts the run-log bytes and the run-log .sig.json bytes are
byte-for-byte unchanged before and after, and fails loudly if either moves.

Run from code/:  py scripts/sign_assertions.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.assertion import (  # noqa: E402
    build_assertion,
    sign_assertion,
    verify_assertion_signature,
)

DATA = REPO_ROOT / "web" / "data"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")


def _emit(mode: str) -> str:
    packet_path = DATA / f"packet-{mode}.json"
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    sig_path = log_path.with_suffix(log_path.suffix + ".sig.json")
    sidecar_path = DATA / f"assertion-{mode}.json"

    if not packet_path.exists():
        raise SystemExit(f"{mode}: packet missing at {packet_path}")

    # Snapshot the sealed bytes this script must never touch.
    log_before = log_path.read_bytes() if log_path.exists() else None
    sig_before = sig_path.read_bytes() if sig_path.exists() else None

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assertion = build_assertion(packet)
    if assertion.total == 0:
        raise SystemExit(
            f"{mode}: packet carries no catalogued control to assert; "
            "cannot emit an assertion sidecar")
    document = assertion.as_document()
    signature = sign_assertion(document)
    if not verify_assertion_signature(document, signature):
        raise SystemExit(f"{mode}: freshly produced assertion signature does not verify")

    sidecar_path.write_text(json.dumps(signature, indent=2) + "\n", encoding="utf-8")

    # The sealed run-log and the run-log signature must be untouched.
    if log_before is not None and log_path.read_bytes() != log_before:
        raise SystemExit(f"{mode}: run-log bytes changed; that must never happen")
    if sig_before is not None and sig_path.read_bytes() != sig_before:
        raise SystemExit(f"{mode}: run-log .sig.json bytes changed; that must never happen")

    return signature["assertion_digest"]


def main() -> int:
    for mode in SCENARIOS:
        digest = _emit(mode)
        print(f"  {mode:22s} assertion signed (digest {digest[:16]}...) -> "
              f"web/data/assertion-{mode}.json")
    print("Emitted a detached, signed management-assertion sidecar per scenario. "
          "The run-log JSONL and the run-log .sig.json bytes are unchanged; the "
          "assertion signature is separate from the run-log signature.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
