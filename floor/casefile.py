"""Immutable case file: the single bundle an examiner pulls to re-verify a run offline.

An examiner, an auditor, or a court does not subpoena "a packet". They subpoena THE
case file and expect a chain of custody: the whole sealed run, every receipt that
attests it, the rules that governed it, and one top-level manifest that lets them
re-derive every digest and re-verify the cryptography without trusting us and without
a network. This module assembles that bundle, deterministically, as a strictly ADDITIVE
read over the already-sealed artifacts.

WHAT GOES IN. For a sealed scenario (normal, inject_contradiction, chaos, amendment,
submit, ...) the bundle gathers, by role:

  * run_log     : the append-only run-log JSONL (the hashed evidence itself).
  * packet      : the assembled Examiner Packet for the run.
  * signature   : the detached Ed25519 signature sidecar over the bound payload.
  * intoto      : the in-toto Statement / DSSE envelope sidecar (when captured).
  * timestamp   : the RFC 3161 timestamp token sidecar (when captured).
  * edgar_8k    : the EDGAR-shaped Form 8-K Item 1.05 export, DERIVED read-only from
                  the packet (rendered into the bundle, no SEC clock -> omitted).
  * corpus      : the relevant statutory corpus chunks (the real cited legal text) for
                  exactly the regimes that have a clock in this run, DERIVED read-only
                  from floor/corpus/index.json + the catalog corpus_tags.

The first five are SEALED files read byte-for-byte off disk; their bytes are never
re-rendered, so a case file can never silently disagree with the sealed capture. The
last two are DERIVED artifacts the bundle renders deterministically (no LLM, no now())
and embeds inline; each still carries its own sha256 so the manifest seals it the same
way.

THE MANIFEST AND THE SEAL. Every included item is listed with its name, role, byte
length, and sha256. A bundle-level digest is the Merkle-style ROOT over the SORTED
per-file shas (sha256 of the newline-joined "<sha>  <name>" lines, in sorted order):
one value that summarizes the whole bundle, so adding, dropping, or editing any file
moves it. The whole manifest object is then signed with the SAME committed Ed25519 key
the run-log signature uses, so the bundle itself is sealed: a verifier recomputes every
file sha, recomputes the bundle digest, and checks the bundle signature, all offline.

DETERMINISM. The build sorts every list, reads sealed bytes verbatim, and renders the
derived artifacts purely from the packet and the committed corpus index. There is no
now() and no randomness, so two builds over the same sealed inputs produce a
byte-identical bundle (and therefore an identical bundle digest and signature). The
build is a pure READ of the sealed artifacts: it writes nothing back into any run-log,
moves no sealed sha, and touches no Warden gate. The bundle is an additive artifact
that sits BESIDE the captures it indexes.

HONEST KEY CAVEAT. The bundle is sealed with the same DEMO key as the run-log
signature: the signing mechanism is fully real (one flipped byte makes the bundle
signature INVALID), but the private key ships with the repo, so it proves "sealed by
whoever holds this demo key", not HSM/KMS-grade secrecy. The same caveat that travels
with every signature travels with the bundle.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from floor.exports_edgar import EdgarExportError, to_edgar_8k
from floor.regcorpus import load_index
from floor.regimes import load_catalog
from warden.signing import (
    DEMO_KEY_CAVEAT,
    sign_bytes,
    fingerprint,
    load_demo_private_key,
    public_key_hex_of,
)

# The bundle format version. Pinned so a verifier can reject a bundle built by an
# incompatible builder rather than silently mis-reading it.
BUNDLE_VERSION = "deadline-room/casefile/v1"

# The repo's sealed-capture directory. The default scenarios live here; a caller may
# point the builder at another directory holding the same naming convention.
_REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = _REPO_ROOT / "web" / "data"

# The sealed sidecar roles and their filename suffixes relative to the run-log path.
# A role whose file is absent for a scenario (e.g. submit has no .intoto.json) is
# simply omitted from the bundle; the manifest lists exactly what is present.
_SIDECAR_ROLES = (
    ("signature", ".sig.json"),
    ("intoto", ".intoto.json"),
    ("timestamp", ".tst.json"),
)


class CaseFileError(ValueError):
    """A case file could not be assembled: the run-log for the scenario is missing,
    or a required sealed artifact is absent. Raised so a missing input surfaces
    structurally rather than producing a partial or silently empty bundle."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj: object) -> bytes:
    """The canonical JSON encoding used for every derived artifact and for the
    signed manifest: sorted keys, compact separators, UTF-8. The SAME recipe the
    run log and the bound signature payload use, so a verifier rebuilds identical
    bytes and the sha256 / signature match."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def run_log_path_for(scenario: str, data_dir: Path | None = None) -> Path:
    """The sealed run-log path for a scenario, by the committed naming convention."""
    base = data_dir if data_dir is not None else DEFAULT_DATA_DIR
    return base / f"run-inc-8842-{scenario}.jsonl"


def packet_path_for(scenario: str, data_dir: Path | None = None) -> Path:
    """The sealed packet path for a scenario, by the committed naming convention."""
    base = data_dir if data_dir is not None else DEFAULT_DATA_DIR
    return base / f"packet-{scenario}.json"


def _clocked_regime_keys(packet: dict) -> list[str]:
    """The catalog regime keys that actually have a clock in this run, derived from
    the packet's clock correlation ids.

    A clock correlation id is `<incident>:<regime-branch>` (e.g. `inc-8842:nis2`,
    `inc-8842:sec`, `inc-8842:uk`). The branch token is matched against each catalog
    regime's `branch`, so the corpus citations bundled are exactly those for the
    regimes that produced a filing in this scenario (not the whole catalog). Returned
    sorted and de-duplicated for determinism."""
    branches: set[str] = set()
    for clock in packet.get("clocks", []) or []:
        corr = str(clock.get("correlation_id", ""))
        if ":" in corr:
            branches.add(corr.rsplit(":", 1)[1])
    keys: set[str] = set()
    for regime in load_catalog():
        if regime.branch in branches:
            keys.add(regime.key)
    return sorted(keys)


def relevant_corpus_citations(packet: dict) -> dict:
    """The statutory corpus chunks relevant to this run: the real cited legal text for
    exactly the regimes that have a clock here.

    Walks the clocked regimes (from the packet), collects their catalog `corpus_tags`,
    resolves each tag against the committed corpus index, and returns a sorted,
    de-duplicated list of the resolved chunks (id, citation, title, regime_family,
    verbatim flag, and the statutory text) plus the list of any tags that did NOT
    resolve to a chunk. Deterministic: sorted regimes, sorted tags, sorted output, no
    now(). An examiner can trace each filing back to the clause it satisfies, in the
    same bundle, offline.

    Raises CaseFileError if a clocked regime cites a corpus tag that has no chunk in
    the index: a dangling citation is a real corpus defect, surfaced loudly rather
    than dropped."""
    index = load_index()
    catalog = {r.key: r for r in load_catalog()}
    tags: set[str] = set()
    for key in _clocked_regime_keys(packet):
        regime = catalog.get(key)
        if regime is None:
            continue
        tags.update(regime.corpus_tags)

    resolved: list[dict] = []
    unresolved: list[str] = []
    for tag in sorted(tags):
        chunk = index.get(tag)
        if chunk is None:
            unresolved.append(tag)
            continue
        resolved.append({
            "id": tag,
            "citation": chunk.get("citation", ""),
            "title": chunk.get("title", ""),
            "regime_family": chunk.get("regime_family", ""),
            "verbatim": bool(chunk.get("verbatim", False)),
            "text": chunk.get("text", ""),
        })
    if unresolved:
        raise CaseFileError(
            "case file corpus citations reference chunk id(s) absent from the "
            f"corpus index: {', '.join(sorted(unresolved))}. Rebuild the corpus "
            "(scripts/build_corpus.py) or fix the regime corpus_tags.")
    return {
        "regimes": _clocked_regime_keys(packet),
        "chunk_count": len(resolved),
        "chunks": resolved,
    }


def _edgar_artifact(packet: dict) -> dict | None:
    """The EDGAR-shaped Form 8-K Item 1.05 export derived from the packet, or None
    when this run has no SEC clock (the SEC branch was suppressed and no 8-K is
    owed). Pure derived render; the EdgarExportError signals 'no SEC facts', which
    for the bundle means 'no EDGAR artifact', not a failure."""
    try:
        return to_edgar_8k(packet)
    except EdgarExportError:
        return None


@dataclass(frozen=True)
class BundleFile:
    """One item in the case file: a role (run_log / packet / signature / intoto /
    timestamp / edgar_8k / corpus), the item name, its byte length, its sha256, and
    where it came from (`sealed` for a file read off disk, `derived` for an artifact
    rendered into the bundle). The bytes themselves live in the bundle's `sealed`
    (verbatim text) or `derived` (inline object) section, keyed by name."""
    role: str
    name: str
    bytes: int
    sha256: str
    origin: str


def _manifest(files: list[BundleFile]) -> dict:
    """The manifest object: the sorted file list plus the bundle-level Merkle root
    over the per-file shas. The root is sha256 over the newline-joined
    "<sha>  <name>" lines in name-sorted order, so it summarizes every file and its
    identity; adding, dropping, reordering (it is re-sorted, so a reorder cannot
    hide), or editing any file moves the root."""
    ordered = sorted(files, key=lambda f: f.name)
    file_rows = [
        {
            "name": f.name,
            "role": f.role,
            "origin": f.origin,
            "bytes": f.bytes,
            "sha256": f.sha256,
        }
        for f in ordered
    ]
    digest_material = "\n".join(f"{f.sha256}  {f.name}" for f in ordered)
    bundle_digest = _sha256_hex(digest_material.encode("utf-8"))
    return {
        "algorithm": "sha256",
        "merkle": "sha256 over sorted '<sha>  <name>' lines",
        "file_count": len(file_rows),
        "bundle_digest": bundle_digest,
        "files": file_rows,
    }


def _sign_manifest(manifest: dict) -> dict:
    """Sign the canonical manifest bytes with the committed demo Ed25519 key. The
    signature seals the WHOLE bundle (the file list + the bundle digest), so a
    verifier recomputes the manifest from the files on disk and checks this one
    signature. Byte-identical to the run-log signing recipe: same key, same
    canonical JSON encoding, same honest demo-key caveat."""
    private_key = load_demo_private_key()
    payload = _canonical_json_bytes(manifest)
    pub_hex = public_key_hex_of(private_key)
    return {
        "algorithm": "ed25519",
        "detached": True,
        "signed_payload": "canonical_json(manifest)",
        "signature": sign_bytes(payload, private_key),
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": "Deadline Warden",
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def build_casefile(scenario: str, data_dir: Path | None = None) -> dict:
    """Assemble the immutable case file bundle for a sealed scenario.

    Reads the sealed run-log, packet, and every present sidecar (signature, in-toto,
    timestamp) byte-for-byte off disk; derives the EDGAR-shaped 8-K export and the
    relevant statutory corpus citations from the packet; lists every item with its
    sha256 in a manifest sealed by a bundle-level Merkle root; and signs the manifest
    with the committed Ed25519 key.

    Deterministic and pure: sorted lists, verbatim sealed bytes, derived artifacts
    rendered with no LLM and no now(). Two builds over the same sealed inputs produce
    a byte-identical bundle. Raises CaseFileError if the run-log or packet for the
    scenario is missing."""
    base = data_dir if data_dir is not None else DEFAULT_DATA_DIR
    log_path = run_log_path_for(scenario, base)
    packet_path = packet_path_for(scenario, base)
    if not log_path.exists():
        raise CaseFileError(f"no sealed run-log for scenario '{scenario}' at {log_path}")
    if not packet_path.exists():
        raise CaseFileError(f"no sealed packet for scenario '{scenario}' at {packet_path}")

    files: list[BundleFile] = []
    sealed: dict[str, str] = {}

    # The two mandatory sealed files, read verbatim. The sha256 is taken over the
    # exact bytes on disk (read as text, encoded UTF-8) so it matches the run-log
    # integrity sha and the sidecar shas byte for byte.
    for role, path in (("run_log", log_path), ("packet", packet_path)):
        text = path.read_text(encoding="utf-8")
        raw = text.encode("utf-8")
        sealed[path.name] = text
        files.append(BundleFile(role, path.name, len(raw), _sha256_hex(raw), "sealed"))

    # The present sidecars (signature is required; in-toto and timestamp are bundled
    # when the scenario captured them).
    for role, suffix in _SIDECAR_ROLES:
        sidecar = log_path.with_suffix(log_path.suffix + suffix)
        if not sidecar.exists():
            if role == "signature":
                raise CaseFileError(
                    f"scenario '{scenario}' has no detached signature sidecar at "
                    f"{sidecar}; a case file must carry the seal it re-verifies")
            continue
        text = sidecar.read_text(encoding="utf-8")
        raw = text.encode("utf-8")
        sealed[sidecar.name] = text
        files.append(BundleFile(role, sidecar.name, len(raw), _sha256_hex(raw), "sealed"))

    packet = json.loads(sealed[packet_path.name])

    # The derived artifacts: rendered deterministically, embedded inline, each sealed
    # by its own canonical-bytes sha in the manifest.
    derived: dict[str, object] = {}
    edgar = _edgar_artifact(packet)
    if edgar is not None:
        raw = _canonical_json_bytes(edgar)
        name = f"edgar-8k-{scenario}.json"
        derived[name] = edgar
        files.append(BundleFile("edgar_8k", name, len(raw), _sha256_hex(raw), "derived"))

    corpus = relevant_corpus_citations(packet)
    raw = _canonical_json_bytes(corpus)
    corpus_name = f"corpus-citations-{scenario}.json"
    derived[corpus_name] = corpus
    files.append(
        BundleFile("corpus", corpus_name, len(raw), _sha256_hex(raw), "derived"))

    manifest = _manifest(files)
    signature = _sign_manifest(manifest)

    incident = packet.get("incident", {}) or {}
    return {
        "bundle_version": BUNDLE_VERSION,
        "scenario": scenario,
        "incident_id": incident.get("incident_id", ""),
        "manifest": manifest,
        "signature": signature,
        "sealed": sealed,
        "derived": derived,
        "caveat": DEMO_KEY_CAVEAT,
    }


def bundle_json(bundle: dict) -> str:
    """Serialize a case file bundle to the exact, byte-stable JSON the builder writes
    to web/data/casefile-<scenario>.json: sorted keys, a fixed indent, a trailing
    newline. Deterministic and diff-friendly, so the committed bundle is
    reproducible and a re-build produces an identical file."""
    return json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def recompute_manifest(bundle: dict, data_dir: Path | None = None) -> dict:
    """Recompute the manifest a case file CLAIMS, straight from the sealed files on
    disk and the derived artifacts re-rendered from the sealed packet.

    This is the verifier's core: it does not trust the bundle's embedded `sealed`
    bytes or `derived` objects. For every sealed file it RE-READS the bytes off disk
    and re-hashes; for every derived artifact it RE-RENDERS from the freshly read
    packet and re-hashes. It then rebuilds the manifest (file rows + bundle digest)
    the same way build does. A verifier compares this against the bundle's stored
    manifest and signature: any divergence (a tampered sealed byte, a swapped derived
    artifact, an edited manifest) shows up as a sha or bundle-digest mismatch.

    Raises CaseFileError if a sealed file named in the bundle is missing on disk."""
    scenario = bundle.get("scenario", "")
    base = data_dir if data_dir is not None else DEFAULT_DATA_DIR
    stored_files = (bundle.get("manifest", {}) or {}).get("files", [])

    log_path = run_log_path_for(scenario, base)
    packet_path = packet_path_for(scenario, base)
    if not packet_path.exists():
        raise CaseFileError(
            f"case file references packet {packet_path.name} but it is absent on disk")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    files: list[BundleFile] = []
    for row in stored_files:
        name = row.get("name", "")
        role = row.get("role", "")
        origin = row.get("origin", "")
        if origin == "sealed":
            disk_path = base / name
            if not disk_path.exists():
                raise CaseFileError(
                    f"case file lists sealed file {name} but it is absent on disk at "
                    f"{disk_path}")
            raw = disk_path.read_text(encoding="utf-8").encode("utf-8")
            files.append(BundleFile(role, name, len(raw), _sha256_hex(raw), "sealed"))
        elif origin == "derived":
            if role == "edgar_8k":
                artifact = _edgar_artifact(packet)
                if artifact is None:
                    raise CaseFileError(
                        "case file lists an EDGAR export but the packet now carries "
                        "no SEC clock to derive it from")
                raw = _canonical_json_bytes(artifact)
            elif role == "corpus":
                raw = _canonical_json_bytes(relevant_corpus_citations(packet))
            else:
                raise CaseFileError(f"unknown derived role '{role}' in case file")
            files.append(BundleFile(role, name, len(raw), _sha256_hex(raw), "derived"))
        else:
            raise CaseFileError(f"unknown file origin '{origin}' for {name} in case file")
    # The run-log path is referenced indirectly; assert it exists so a verifier on a
    # bundle whose run-log was deleted fails loudly rather than passing on the
    # in-bundle copy alone.
    if not log_path.exists():
        raise CaseFileError(
            f"case file scenario '{scenario}' has no run-log on disk at {log_path}")
    return _manifest(files)


def verify_bundle_signature(bundle: dict) -> bool:
    """True iff the bundle's manifest signature verifies under its public key over the
    canonical manifest bytes. Reads the manifest the bundle stores and checks the
    detached Ed25519 signature; a tampered manifest field moves the canonical bytes
    and the signature fails. Returns False (never raises) on any malformed input so a
    verifier can print INVALID and exit nonzero without a stack trace."""
    from warden.signing import verify_bytes

    manifest = bundle.get("manifest")
    signature = bundle.get("signature") or {}
    if not manifest:
        return False
    payload = _canonical_json_bytes(manifest)
    return verify_bytes(
        payload,
        signature.get("signature", ""),
        signature.get("public_key"),
    )
