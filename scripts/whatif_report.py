"""What-If Console report: compute three deterministic counterfactuals, sign each
under the counterfactual namespace, and print the actual-vs-counterfactual outcome.

The same deterministic substrate that makes the PAST byte-identically replayable
makes the COUNTERFACTUAL computable. This script runs the three shipped what-ifs
(floor/whatif.py), each a pure no-LLM perturbation over a DETERMINISTIC input of a
sealed run:

  1. SEC materiality determined 6h later  (re-anchor the SEC clock; the
     holiday-aware four-business-day count is shown to be load-bearing).
  2. The contradiction had NOT been caught (the diff BLOCK edge removed; a
     divergent filing set with a different chain head).
  3. The amended count stayed 48K, not 2.1M (no fact delta; the SEC would NOT
     have re-filed).

Each counterfactual outcome is signed with the committed demo Ed25519 key under a
DISTINCT "counterfactual" namespace label (warden/counterfactual_signing.py), so a
what-if receipt can never be confused with a real-run receipt. The script verifies
each signature it produces and prints the receipt, and (unless --no-write) writes
the three artifacts to web/data/whatif-*.json for the browser panel to load and
re-verify client-side.

  py scripts/whatif_report.py              (compute, sign, print, write artifacts)
  py scripts/whatif_report.py --no-write   (compute, sign, print only)
  py scripts/whatif_report.py --check      (recompute and re-verify the committed
                                            artifacts; exit nonzero on any mismatch)

CRITICAL FENCE. This script reads the four sealed captures and writes only NEW
web/data/whatif-*.json artifacts. It NEVER writes a canonical run-log, NEVER
re-signs a per-run capture, and NEVER mutates a gate. The real-run shas are
untouched (scripts/audit_run.py still passes 4/4 with this script present).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.counterfactual_signing import (  # noqa: E402
    COUNTERFACTUAL_SIGNED_PAYLOAD,
    sign_counterfactual,
    verify_counterfactual,
)
from warden.signing import DEMO_KEY_CAVEAT  # noqa: E402

from floor.whatif import Counterfactual, all_counterfactuals  # noqa: E402

DATA = REPO_ROOT / "web" / "data"


def _artifact_path(name: str) -> Path:
    return DATA / f"whatif-{name}.json"


def build_artifact(cf: Counterfactual) -> dict:
    """The full signed artifact for one counterfactual: the outcome plus the
    anchoring actual chain head plus a detached signature record under the
    counterfactual namespace. Verified before it is returned, so a malformed
    signature never ships."""
    artifact = cf.as_dict()
    sig = sign_counterfactual(cf.name, cf.actual_chain_head, cf.outcome())
    if not verify_counterfactual(cf.name, cf.actual_chain_head, cf.outcome(), sig):
        raise SystemExit(
            f"whatif_report: signature for {cf.name} failed self-verification")
    artifact["signature"] = sig
    return artifact


def _canon(obj: dict) -> str:
    """Canonical JSON, matching the run log's recipe, so a committed artifact is
    byte-stable across builds and --check can compare exactly."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _print_counterfactual(cf: Counterfactual, artifact: dict) -> None:
    sig = artifact["signature"]
    print("=" * 78)
    print(f"WHAT IF: {cf.title}")
    print("=" * 78)
    print(f"Question      : {cf.question}")
    print(f"Perturbation  : {json.dumps(cf.perturbation)}")
    print()
    print("ACTUAL:")
    for k, v in cf.actual.items():
        print(f"  {k:42s}: {v}")
    print()
    print("COUNTERFACTUAL:")
    for k, v in cf.counterfactual.items():
        print(f"  {k:42s}: {v}")
    print()
    print(f"DIVERGENCE    : {cf.divergence}")
    print(f"WHY IT MATTERS: {cf.load_bearing}")
    print()
    print("SIGNED MINI-RECEIPT (counterfactual namespace):")
    print(f"  namespace                  : {sig['namespace']}")
    print(f"  signed_payload             : {sig['signed_payload']}")
    print(f"  counterfactual             : {sig['counterfactual']}")
    print(f"  actual_chain_head          : {sig['actual_chain_head']}")
    print(f"  counterfactual_outcome_sha : {sig['counterfactual_outcome_sha']}")
    print(f"  signature                  : {sig['signature'][:48]}...")
    print(f"  signer                     : {sig['signer']}")
    print(f"  pubkey_fingerprint         : {sig['pubkey_fingerprint']}")
    reverified = verify_counterfactual(
        cf.name, cf.actual_chain_head, cf.outcome(), sig)
    print(f"  re-verifies                : {'YES' if reverified else 'NO'}")
    print()


def run(write: bool) -> int:
    counterfactuals = all_counterfactuals()
    labels_seen: set[str] = set()
    for cf in counterfactuals:
        artifact = build_artifact(cf)
        labels_seen.add(artifact["signature"]["signed_payload"])
        _print_counterfactual(cf, artifact)
        if write:
            _artifact_path(cf.name).write_text(
                json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

    # Prove every receipt rode the DISTINCT counterfactual label, never the per-run
    # or portfolio label: the one thing that keeps the namespaces from mixing.
    assert labels_seen == {COUNTERFACTUAL_SIGNED_PAYLOAD}, (
        f"unexpected signed_payload labels: {labels_seen}")

    print("=" * 78)
    print(f"{len(counterfactuals)} counterfactuals computed and signed under the "
          "DISTINCT counterfactual")
    print(f"namespace label: {COUNTERFACTUAL_SIGNED_PAYLOAD}")
    print("Each re-verifies against the committed public key. None is a real run; "
          "none touches")
    print("a sealed run-log or its per-run signature.")
    if write:
        print()
        print("Artifacts written for the browser panel:")
        for cf in counterfactuals:
            print(f"  {_artifact_path(cf.name).relative_to(REPO_ROOT)}")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0


def check() -> int:
    """Recompute every counterfactual and compare against the committed artifact
    byte-for-byte (outcome) and re-verify the committed signature. Exit nonzero on
    any drift, so CI / a judge can prove the committed artifacts are exactly what
    the engine produces from the sealed captures."""
    failures: list[str] = []
    for cf in all_counterfactuals():
        path = _artifact_path(cf.name)
        if not path.exists():
            failures.append(f"{cf.name}: committed artifact missing at {path}")
            continue
        committed = json.loads(path.read_text(encoding="utf-8"))
        committed_outcome = {k: committed[k] for k in cf.outcome()}
        if _canon(committed_outcome) != _canon(cf.outcome()):
            failures.append(f"{cf.name}: committed outcome differs from recomputed")
            continue
        if committed.get("actual_chain_head") != cf.actual_chain_head:
            failures.append(f"{cf.name}: committed actual_chain_head differs")
            continue
        sig = committed.get("signature") or {}
        if not verify_counterfactual(cf.name, cf.actual_chain_head, cf.outcome(), sig):
            failures.append(f"{cf.name}: committed signature does not verify")
            continue
        if sig.get("signed_payload") != COUNTERFACTUAL_SIGNED_PAYLOAD:
            failures.append(f"{cf.name}: committed signature is not under the "
                            "counterfactual namespace label")

    print("=" * 78)
    print("WHAT-IF ARTIFACT CHECK")
    print("=" * 78)
    if not failures:
        print("All committed whatif-*.json artifacts match the engine and re-verify "
              "under the")
        print("counterfactual namespace. PASS.")
        print("=" * 78)
        return 0
    for f in failures:
        print(f"  FAIL: {f}")
    print("=" * 78)
    return 1


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return check()
    write = "--no-write" not in argv
    return run(write)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
