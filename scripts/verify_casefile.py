"""One-command case file receipt: does this bundle re-verify, whole, offline?

An examiner is handed a case file (web/data/casefile-<scenario>.json): the run-log,
the packet, the signature, the in-toto / DSSE envelope and RFC 3161 timestamp (when
present), the EDGAR-shaped 8-K export, the relevant statutory corpus citations, a
manifest of every file's sha256, a bundle-level Merkle root, and a signature over the
manifest. This script answers, in one keyless offline command, the only question that
matters: does the whole bundle still verify?

It composes the FROZEN verifiers already in the repo (it reimplements no crypto and
no replay). In order:

  1. MANIFEST. RE-HASH every sealed file off disk and RE-RENDER every derived
     artifact from the sealed packet, rebuild the manifest, and confirm every file
     sha and the bundle Merkle digest match what the bundle stores. A tampered sealed
     byte, a swapped derived artifact, or an edited manifest is caught here.
  2. BUNDLE SIGNATURE. Verify the detached Ed25519 signature over the canonical
     manifest bytes under the bundle's public key. The bundle itself is sealed.
  3. RUN AUDIT. Run scripts/audit_run.py over the run-log the bundle indexes: the run
     replays byte-identical, the chain head matches, the run signature verifies, and
     exactly-once, two-key release, and clock monotonicity all hold from the sealed
     bytes.

Every step prints PASS or FAIL with a one-line locus; the exit code is 0 only when
EVERY step passes. The manifest is printed so the output reads like a chain-of-custody
receipt, and the honest demo-key caveat prints every time: the signing mechanism is
real, the key's secrecy is not production-grade because the key ships with the repo.

  py scripts/verify_casefile.py                  (the default sealed scenario)
  py scripts/verify_casefile.py <scenario>       (verify a named scenario's bundle)
  py scripts/verify_casefile.py <bundle.json>    (verify a specific bundle file)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.casefile import (  # noqa: E402
    CaseFileError,
    DEFAULT_DATA_DIR,
    recompute_manifest,
    run_log_path_for,
    verify_bundle_signature,
)
from scripts.audit_run import audit_run  # noqa: E402
from warden.signing import DEMO_KEY_CAVEAT  # noqa: E402

DEFAULT_SCENARIO = "submit"


@dataclass(frozen=True)
class Step:
    """One verification step's verdict: a stable name, ok True/False, and a one-line
    detail that names the locus on failure (and summarizes on success)."""
    name: str
    ok: bool
    detail: str


def _resolve_bundle_path(arg: str | None) -> Path | None:
    """Resolve the bundle file from an argument that may be a scenario name, a bundle
    file path, or nothing (the default scenario)."""
    if arg is None:
        return DEFAULT_DATA_DIR / f"casefile-{DEFAULT_SCENARIO}.json"
    candidate = Path(arg)
    if candidate.suffix == ".json" and candidate.exists():
        return candidate.resolve()
    # Treat the argument as a scenario name.
    return DEFAULT_DATA_DIR / f"casefile-{arg}.json"


def _check_manifest(bundle: dict) -> Step:
    """MANIFEST: the recomputed manifest (every sealed file re-hashed off disk, every
    derived artifact re-rendered) matches the bundle's stored manifest, file sha by
    file sha and on the bundle digest."""
    stored = bundle.get("manifest", {}) or {}
    try:
        recomputed = recompute_manifest(bundle)
    except CaseFileError as exc:
        return Step("MANIFEST", False, str(exc))

    stored_files = {f["name"]: f for f in stored.get("files", [])}
    recomputed_files = {f["name"]: f for f in recomputed.get("files", [])}
    if set(stored_files) != set(recomputed_files):
        only_stored = sorted(set(stored_files) - set(recomputed_files))
        only_disk = sorted(set(recomputed_files) - set(stored_files))
        return Step("MANIFEST", False,
                    f"file set differs (bundle-only: {only_stored}, "
                    f"disk-only: {only_disk})")
    for name, want in stored_files.items():
        got = recomputed_files[name]
        if got["sha256"] != want["sha256"]:
            return Step("MANIFEST", False,
                        f"{name}: sha256 on disk {got['sha256'][:16]} != "
                        f"manifest {want['sha256'][:16]}")
        if got["bytes"] != want["bytes"]:
            return Step("MANIFEST", False,
                        f"{name}: byte length on disk {got['bytes']} != "
                        f"manifest {want['bytes']}")
    if recomputed.get("bundle_digest") != stored.get("bundle_digest"):
        return Step("MANIFEST", False,
                    f"bundle Merkle digest mismatch: recomputed "
                    f"{recomputed.get('bundle_digest', '')[:16]} != stored "
                    f"{stored.get('bundle_digest', '')[:16]}")
    return Step("MANIFEST", True,
                f"{recomputed.get('file_count', 0)} file(s), every sha and the bundle "
                "Merkle digest match")


def _check_bundle_signature(bundle: dict) -> Step:
    """BUNDLE-SIGNATURE: the detached Ed25519 signature over the canonical manifest
    bytes verifies under the bundle's public key."""
    if verify_bundle_signature(bundle):
        sig = bundle.get("signature", {}) or {}
        return Step("BUNDLE-SIGNATURE", True,
                    f"valid Ed25519 over the manifest, signer fp "
                    f"{sig.get('pubkey_fingerprint', '')}")
    return Step("BUNDLE-SIGNATURE", False,
                "manifest signature does NOT verify against the bundle public key")


def _check_run_audit(bundle: dict) -> tuple[Step, list]:
    """RUN-AUDIT: scripts/audit_run.py over the run-log the bundle indexes passes
    every in-log invariant (replay, chain, signature, exactly-once, two-key release,
    clock monotonicity). Returns the summary step and the per-invariant checks so the
    receipt can list them."""
    scenario = bundle.get("scenario", "")
    log_path = run_log_path_for(scenario)
    if not log_path.exists():
        return (Step("RUN-AUDIT", False,
                     f"run-log absent on disk at {log_path}"), [])
    result = audit_run(log_path)
    failing = [c for c in result.checks if not c.ok]
    if result.ok:
        return (Step("RUN-AUDIT", True,
                     f"{len(result.checks)} in-log invariant(s) hold over the sealed "
                     "run"), result.checks)
    locus = "; ".join(f"{c.name}: {c.detail}" for c in failing)
    return (Step("RUN-AUDIT", False, f"audit FAILED: {locus}"), result.checks)


def _print_manifest(bundle: dict) -> None:
    manifest = bundle.get("manifest", {}) or {}
    print("Manifest (every file sealed at its sha256):")
    name_w = max((len(f["name"]) for f in manifest.get("files", [])), default=4)
    role_w = max((len(f["role"]) for f in manifest.get("files", [])), default=4)
    for f in manifest.get("files", []):
        print(f"  [{f['origin']:>7}] {f['role'].ljust(role_w)}  "
              f"{f['name'].ljust(name_w)}  {f['bytes']:>7} B  {f['sha256']}")
    print(f"  bundle Merkle digest : {manifest.get('bundle_digest', '')}")
    print()


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    bundle_path = _resolve_bundle_path(args[0] if args else None)

    print("=" * 78)
    print("CASE FILE RECEIPT: does this bundle re-verify, whole, offline?")
    print("=" * 78)

    if bundle_path is None or not bundle_path.exists():
        print(f"verify_casefile: no case file bundle found at {bundle_path}. "
              "Run `py scripts/build_casefile.py` first.", file=sys.stderr)
        return 2
    print(f"Bundle : {bundle_path}")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    print(f"Scenario : {bundle.get('scenario', '')} "
          f"(incident {bundle.get('incident_id', '')})")
    print(f"Version  : {bundle.get('bundle_version', '')}")
    print("No network, no private key. Re-verified against the committed public key.")
    print()

    _print_manifest(bundle)

    manifest_step = _check_manifest(bundle)
    signature_step = _check_bundle_signature(bundle)
    run_step, run_checks = _check_run_audit(bundle)
    steps = [manifest_step, signature_step, run_step]

    name_width = max(len(s.name) for s in steps)
    for s in steps:
        status = "PASS" if s.ok else "FAIL"
        print(f"  [{status}] {s.name.ljust(name_width)}  {s.detail}")
    if run_checks:
        print("    run-audit invariants:")
        inv_width = max(len(c.name) for c in run_checks)
        for c in run_checks:
            status = "PASS" if c.ok else "FAIL"
            print(f"      [{status}] {c.name.ljust(inv_width)}  {c.detail}")
    print()

    all_ok = all(s.ok for s in steps)
    print("=" * 78)
    if all_ok:
        print("VALID. The case file re-verifies offline: every manifest sha and the")
        print("bundle Merkle digest match the files on disk, the manifest signature")
        print("verifies, and the indexed run replays byte-identical with its chain,")
        print("signature, exactly-once, two-key release, and clocks all holding.")
    else:
        print("INVALID. At least one step FAILED. See the named locus above.")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
