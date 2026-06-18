"""Build the immutable case file bundle for a sealed scenario.

Assembles the single self-contained, hash-manifested artifact an examiner pulls to
get the WHOLE case and re-verify it offline: the run-log, the packet, the detached
signature, the in-toto / DSSE envelope and the RFC 3161 timestamp (when captured),
the EDGAR-shaped 8-K export, and the relevant statutory corpus citations, all listed
in a manifest with their sha256, sealed by a bundle-level Merkle root, and signed with
the committed Ed25519 key.

The build is strictly ADDITIVE: it reads the sealed captures byte-for-byte, derives
the EDGAR export and the corpus citations read-only from the packet, and writes ONE
new file (web/data/casefile-<scenario>.json) beside the captures it indexes. No sealed
run-log / packet / sidecar byte is touched, no Warden gate is touched, and the build
is deterministic (sorted, no now()), so a re-build produces a byte-identical bundle.

  py scripts/build_casefile.py                  (build the default sealed scenario)
  py scripts/build_casefile.py <scenario>       (build a named scenario: normal,
                                                 inject_contradiction, chaos,
                                                 amendment, submit, ...)
  py scripts/build_casefile.py <scenario> --print   (print the bundle JSON, no write)

It prints the manifest (every file, its role, its byte length, its sha256) and the
bundle digest + signer fingerprint, writes the bundle, and exits 0. The honest
demo-key caveat prints with the seal.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.casefile import (  # noqa: E402
    CaseFileError,
    DEFAULT_DATA_DIR,
    build_casefile,
    bundle_json,
)
from warden.signing import DEMO_KEY_CAVEAT  # noqa: E402

# The default scenario to bundle when none is named. The submit run is the richest
# (it carries the EDGAR export and the submission receipts), so it is the most
# complete single case file; any of the captured scenarios builds the same way.
DEFAULT_SCENARIO = "submit"


def _bundle_path(scenario: str) -> Path:
    return DEFAULT_DATA_DIR / f"casefile-{scenario}.json"


def _print_manifest(bundle: dict) -> None:
    manifest = bundle.get("manifest", {})
    signature = bundle.get("signature", {})
    print("=" * 78)
    print(f"CASE FILE BUNDLE: {bundle.get('scenario', '')} "
          f"(incident {bundle.get('incident_id', '')})")
    print("=" * 78)
    print(f"  bundle version : {bundle.get('bundle_version', '')}")
    print(f"  files          : {manifest.get('file_count', 0)}")
    print(f"  merkle rule    : {manifest.get('merkle', '')}")
    print()
    name_w = max((len(f["name"]) for f in manifest.get("files", [])), default=4)
    role_w = max((len(f["role"]) for f in manifest.get("files", [])), default=4)
    for f in manifest.get("files", []):
        print(f"  [{f['origin']:>7}] {f['role'].ljust(role_w)}  "
              f"{f['name'].ljust(name_w)}  {f['bytes']:>7} B  {f['sha256']}")
    print()
    print(f"  bundle digest  : {manifest.get('bundle_digest', '')}")
    print(f"  signed by      : {signature.get('signer', '')} "
          f"(key fp {signature.get('pubkey_fingerprint', '')})")
    print()


def main(argv: list[str]) -> int:
    flags = [a for a in argv if a.startswith("--")]
    args = [a for a in argv if not a.startswith("--")]
    scenario = args[0] if args else DEFAULT_SCENARIO
    print_only = "--print" in flags

    try:
        bundle = build_casefile(scenario)
    except CaseFileError as exc:
        print(f"build_casefile: {exc}", file=sys.stderr)
        return 2

    if print_only:
        sys.stdout.write(bundle_json(bundle))
        return 0

    _print_manifest(bundle)

    out_path = _bundle_path(scenario)
    out_path.write_text(bundle_json(bundle), encoding="utf-8")
    print(f"  wrote          : {out_path}")
    print()
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
