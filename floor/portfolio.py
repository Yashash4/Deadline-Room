"""Signed portfolio attestation: one receipt over a whole fleet of sealed runs.

A per-run signature proves a SINGLE incident's run-log was not tampered with.
It says nothing about the fleet: an operator standing up a breach-reporting
operations center runs many incidents, and the question an auditor then asks is
not "is run X intact" but "is the WHOLE set of runs intact, and was no run
silently dropped from the record". A bare folder of per-run signatures cannot
answer the second half: delete one run's files and every surviving signature
still verifies, so the absence is invisible.

This module closes that gap with a Merkle root over the chain-heads of every
sealed run. Each run already carries a per-entry chain head (warden/chain.py)
that summarizes its exact ordered, complete sequence. Folding the SORTED set of
those heads into one Merkle root yields a single value that summarizes the whole
fleet: edit one byte of any run and that run's chain head moves, which moves the
root; drop a run and the root is computed over a smaller set, which also moves
it. A signature over that root (warden/portfolio_signing.py, under a DISTINCT
label so it is never confused with a per-run receipt) therefore proves, in one
verification, that the entire fleet is untampered and complete.

READ-ONLY over the sealed captures. This module discovers, re-verifies, and
folds; it never writes a run log or a per-run signature. The per-run sealed bytes
and their signatures stay byte-frozen. A run that fails its own per-run signature
is FLAGGED and excluded from the attested set, never silently folded in, so the
root only ever attests runs that independently verify.

CANONICAL-LF read recipe. The per-run seal is taken over
`path.read_text(encoding="utf-8").encode("utf-8")` (LF-canonical), NOT the raw
on-disk bytes, which on Windows may carry CRLF. Every read here uses that exact
recipe so the recomputed sha and chain head match the sealed signature on every
platform.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from warden.chain import chain_head
from warden.signing import verify_run_log_jsonl


def _canonical_jsonl(path: Path) -> str:
    """The LF-canonical run-log string the per-run seal is taken over.

    The seal is computed from `read_text(encoding="utf-8").encode("utf-8")`, so a
    verifier must read with the SAME recipe (utf-8 decode) rather than the raw
    on-disk bytes, which on Windows may carry CRLF line endings that the sealed
    sha never saw. Returning the decoded string lets the caller both re-verify the
    signature and recompute the chain head from one canonical source."""
    return path.read_text(encoding="utf-8")


def _sha256_of(jsonl: str) -> str:
    """The run-log integrity sha over the LF-canonical bytes, matching the seal."""
    return hashlib.sha256(jsonl.encode("utf-8")).hexdigest()


def _chain_head_of(jsonl: str) -> str:
    """The per-entry chain head over the run log's entries, recomputed read-only
    from the canonical bytes (the same value warden/chain.head_for_log produces
    for a loaded RunLog, derived here straight from the canonical string)."""
    entries = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
    return chain_head(entries)


@dataclass(frozen=True)
class SealedRun:
    """One discovered run and the verdict of re-verifying it.

    `name` is the run-log file name (a stable identifier in the manifest);
    `sha256` and `chain_head` are recomputed from the LF-canonical bytes;
    `signature_valid` records whether the sibling per-run signature verified over
    those recomputed values; `flag` names why a run was excluded when it did not
    verify (empty string when the run is sound). Only runs with
    `signature_valid is True` are folded into the Merkle root."""
    name: str
    log_path: Path
    sig_path: Path
    sha256: str
    chain_head: str
    signature_valid: bool
    flag: str


def _sidecar_for(log_path: Path) -> Path:
    """The detached per-run signature sidecar that sits beside a run log."""
    return log_path.with_suffix(log_path.suffix + ".sig.json")


def load_portfolio(data_dir: str | Path) -> list[SealedRun]:
    """Discover every sealed run under `data_dir` and re-verify each one.

    A run is any `run-*.jsonl` that has a sibling `<name>.sig.json`. For each, the
    LF-canonical bytes are read, the sha256 and chain head are recomputed from
    them, and the sibling per-run signature is re-verified over those recomputed
    values via warden.signing.verify_run_log_jsonl. A run whose signature does NOT
    verify (or whose sidecar is missing or malformed) is returned with
    `signature_valid=False` and a populated `flag`; it is discovered but will be
    excluded from the attested set by `attest_portfolio`. The list is sorted by
    file name so discovery is deterministic regardless of filesystem order."""
    data_path = Path(data_dir)
    runs: list[SealedRun] = []
    for log_path in sorted(data_path.glob("run-*.jsonl")):
        sig_path = _sidecar_for(log_path)
        jsonl = _canonical_jsonl(log_path)
        sha = _sha256_of(jsonl)
        head = _chain_head_of(jsonl)
        if not sig_path.exists():
            runs.append(SealedRun(
                name=log_path.name, log_path=log_path, sig_path=sig_path,
                sha256=sha, chain_head=head, signature_valid=False,
                flag="no per-run signature sidecar found"))
            continue
        try:
            record = json.loads(sig_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            runs.append(SealedRun(
                name=log_path.name, log_path=log_path, sig_path=sig_path,
                sha256=sha, chain_head=head, signature_valid=False,
                flag=f"per-run signature sidecar unreadable: {exc}"))
            continue
        valid = verify_run_log_jsonl(jsonl, record)
        flag = "" if valid else "per-run signature does not verify"
        runs.append(SealedRun(
            name=log_path.name, log_path=log_path, sig_path=sig_path,
            sha256=sha, chain_head=head, signature_valid=valid, flag=flag))
    return runs


def merkle_root(leaves: list[str]) -> str:
    """Fold a list of hex leaf digests into one Merkle root.

    Each leaf is first hashed with a domain-separating `leaf:` prefix; interior
    nodes hash the concatenation of their two children with a `node:` prefix. An
    odd node at any level is promoted (duplicated) rather than hashed against a
    sibling, the standard odd-leaf rule. An empty leaf set folds to the hash of
    the empty string, a stable sentinel. The leaf-vs-node domain separation makes
    a second-preimage collision (passing an interior digest off as a leaf)
    infeasible. Callers pass the leaves already SORTED so the root is a pure
    function of the SET of chain heads, independent of discovery order."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [
        hashlib.sha256(f"leaf:{leaf}".encode("utf-8")).hexdigest()
        for leaf in leaves
    ]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(
                hashlib.sha256(
                    f"node:{left}{right}".encode("utf-8")).hexdigest())
        level = nxt
    return level[0]


def _canonical_manifest(runs: list[SealedRun]) -> dict:
    """The canonical, sorted manifest the portfolio signature is taken over.

    Lists every attested run by name with its recomputed sha256 and chain head,
    plus the Merkle root over the SORTED chain heads and the run count. Built only
    from runs that passed their per-run signature; flagged runs are excluded so
    the root never attests an unverified run. The dict carries sorted-key data so
    `canonical_manifest_bytes` renders it deterministically."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    heads = sorted(r.chain_head for r in attested)
    return {
        "portfolio_version": "1",
        "run_count": len(attested),
        "portfolio_root": merkle_root(heads),
        "runs": [
            {"name": r.name, "sha256": r.sha256, "chain_head": r.chain_head}
            for r in attested
        ],
    }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """The exact bytes the canonical manifest renders to: sorted keys, no
    whitespace, UTF-8. Mirrors the run log's own canonicalization so a verifier
    (in Python or a browser) rebuilds identical bytes and recomputes the same
    digest."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(manifest: dict) -> str:
    """The sha256 of the canonical manifest bytes: the value the portfolio
    signature ultimately commits to, alongside the root and run count."""
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


@dataclass(frozen=True)
class PortfolioAttestation:
    """The signed roll-up over a fleet of sealed runs.

    `manifest` is the canonical sorted manifest (run count, Merkle root, per-run
    name/sha/head); `root` is its Merkle root over the sorted chain heads;
    `run_count` is the number of ATTESTED runs; `manifest_sha256` is the digest of
    the canonical manifest bytes; `flagged` carries any discovered runs that
    failed their per-run signature and were therefore excluded, so the exclusion
    is visible rather than silent. The detached portfolio signature is added by
    warden/portfolio_signing.py and stored beside this attestation."""
    manifest: dict
    root: str
    run_count: int
    manifest_sha256: str
    attested: list[SealedRun]
    flagged: list[SealedRun]


def attest_portfolio(runs: list[SealedRun]) -> PortfolioAttestation:
    """Build the portfolio attestation over the verified runs.

    Folds a Merkle root over the SORTED chain heads of every run that passed its
    per-run signature, alongside a canonical sorted manifest. Runs that failed
    verification are recorded in `flagged` and excluded from the root, never
    silently included. Pure and deterministic: the same set of sealed runs yields
    the same root and manifest digest on every build and platform."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    flagged = sorted(
        (r for r in runs if not r.signature_valid), key=lambda r: r.name)
    manifest = _canonical_manifest(runs)
    return PortfolioAttestation(
        manifest=manifest,
        root=manifest["portfolio_root"],
        run_count=manifest["run_count"],
        manifest_sha256=manifest_digest(manifest),
        attested=attested,
        flagged=flagged,
    )
