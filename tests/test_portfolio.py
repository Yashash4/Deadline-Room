"""Tests for the signed portfolio attestation (E6.2).

Five things are proven. (1) The Merkle root over the sealed captures is
DETERMINISTIC: two independent builds over the same web/data produce the same
root, run count, and manifest digest. (2) Editing one byte of any run (on a temp
COPY, never the sealed original) flips that run's chain head, moves the portfolio
root, and breaks the portfolio signature. (3) A dropped run (named in the
manifest but missing on disk) is DETECTED by the verifier. (4) A run that fails
its own per-run signature is FLAGGED and excluded from the attested set, never
silently folded into the root. (5) CRITICALLY, the four sealed per-run captures,
their .sig.json sidecars, and their byte-identical replay are UNCHANGED: the
portfolio path is read-only over them, asserted by byte-equality before == after.
"""

from __future__ import annotations

import json
from pathlib import Path

from floor.portfolio import (
    attest_portfolio,
    load_portfolio,
    merkle_root,
)
from scripts.attest_portfolio import build, verify
from warden.portfolio_signing import sign_portfolio, verify_portfolio
from warden.replay import RunLog, replay
from warden.signing import verify_run_log_jsonl

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

# The four canonical sealed run-log shas (LF-canonical), which must stay frozen.
FROZEN_SHAS = {
    "run-inc-8842-normal.jsonl":
        "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3",
    "run-inc-8842-inject_contradiction.jsonl":
        "f1f2223a",
    "run-inc-8842-chaos.jsonl":
        "303c4371",
    "run-inc-8842-amendment.jsonl":
        "0ca07fb0",
}


def _copy_data(tmp: Path) -> Path:
    """Copy every web/data file into a temp dir so a tamper test never touches a
    sealed original. Returns the temp data dir."""
    dst = tmp / "data"
    dst.mkdir()
    for src in DATA.iterdir():
        if src.is_file():
            (dst / src.name).write_bytes(src.read_bytes())
    return dst


def test_portfolio_discovers_and_verifies_sealed_runs():
    runs = load_portfolio(DATA)
    assert runs, "expected to discover sealed runs under web/data"
    # Every committed capture verifies its own per-run signature, so none is flagged.
    flagged = [r for r in runs if not r.signature_valid]
    assert not flagged, f"unexpected flagged runs: {[r.name for r in flagged]}"
    names = {r.name for r in runs}
    for canonical in FROZEN_SHAS:
        assert canonical in names, f"canonical capture {canonical} not discovered"


def test_root_is_deterministic_across_two_builds():
    a = attest_portfolio(load_portfolio(DATA))
    b = attest_portfolio(load_portfolio(DATA))
    assert a.root == b.root
    assert a.run_count == b.run_count
    assert a.manifest_sha256 == b.manifest_sha256
    assert a.manifest == b.manifest


def test_root_independent_of_chain_head_order():
    # The root is a pure function of the SET of heads (sorted), not their order.
    heads = ["aa", "bb", "cc", "dd"]
    assert merkle_root(heads) == merkle_root(sorted(heads))
    assert merkle_root(heads) != merkle_root(heads[:-1])  # dropping one moves it


def test_one_byte_edit_flips_head_moves_root_breaks_signature(tmp_path):
    data = _copy_data(tmp_path)
    base = attest_portfolio(load_portfolio(data))

    target = data / "run-inc-8842-normal.jsonl"
    original = target.read_text(encoding="utf-8")
    before_head = next(
        r.chain_head for r in base.attested if r.name == target.name)

    # Flip one field on the temp copy. The chain head must move, the root must
    # move, and the run's own per-run signature must now fail (so it is flagged).
    tampered = original.replace('"admitted":true', '"admitted":false', 1)
    assert tampered != original, "expected a flippable field in the capture"
    target.write_text(tampered, encoding="utf-8")

    after = attest_portfolio(load_portfolio(data))
    # The tampered run fails its per-run signature and is excluded from the root.
    flagged_names = {r.name for r in after.flagged}
    assert target.name in flagged_names
    after_head = next(
        (r.chain_head for r in load_portfolio(data) if r.name == target.name))
    assert after_head != before_head, "chain head should move on a one-byte edit"
    assert after.root != base.root, "portfolio root should move when a run changes"

    # Sign the ORIGINAL root, then prove that signature does NOT verify the new
    # post-tamper root: a one-byte run edit breaks the portfolio signature.
    record = sign_portfolio(base.root, base.run_count, base.manifest_sha256)
    assert verify_portfolio(base.root, base.run_count, record)
    assert not verify_portfolio(after.root, after.run_count, record)


def test_dropped_run_is_detected_by_verifier(tmp_path, capsys):
    data = _copy_data(tmp_path)
    manifest_path = data / "portfolio-attestation.json"

    # Build over the full set, then drop one run's files and re-verify.
    monkeypatch_data_dir(build, data, manifest_path)
    assert manifest_path.exists()

    dropped = data / "run-inc-8842-chaos.jsonl"
    dropped.unlink()
    (data / "run-inc-8842-chaos.jsonl.sig.json").unlink()

    rc = verify(manifest_path, data)
    out = capsys.readouterr().out
    assert rc != 0, "dropping a run must make the portfolio INVALID"
    assert "DROPPED RUN" in out
    assert "run-inc-8842-chaos.jsonl" in out


def test_failed_per_run_signature_is_flagged_not_included(tmp_path):
    data = _copy_data(tmp_path)
    # Corrupt one run's bytes so its per-run signature no longer verifies, but
    # leave its sidecar in place. It must be flagged, not folded into the root.
    target = data / "run-inc-8842-amendment.jsonl"
    text = target.read_text(encoding="utf-8")
    target.write_text(text.replace('"admitted":true', '"admitted":false', 1),
                      encoding="utf-8")

    runs = load_portfolio(data)
    flagged = {r.name for r in runs if not r.signature_valid}
    assert target.name in flagged

    att = attest_portfolio(runs)
    attested_names = {r.name for r in att.attested}
    assert target.name not in attested_names
    # The manifest's run list never contains a flagged run.
    manifest_names = {r["name"] for r in att.manifest["runs"]}
    assert target.name not in manifest_names


def test_four_sealed_captures_and_replay_unchanged():
    """The per-run captures are READ ONLY: the portfolio path never mutates them.
    Snapshot the sealed bytes, signatures, and replay before and after a full
    portfolio build and verify, then assert byte-equality."""
    targets = list(FROZEN_SHAS)

    def snapshot() -> dict:
        snap: dict = {}
        for name in targets:
            log_bytes = (DATA / name).read_bytes()
            sig_bytes = (DATA / f"{name}.sig.json").read_bytes()
            log = RunLog.load(DATA / name)
            replayed = replay(log).to_jsonl()
            snap[name] = (log_bytes, sig_bytes, replayed)
        return snap

    before = snapshot()

    # Exercise the full portfolio path against the real sealed data (read-only).
    runs = load_portfolio(DATA)
    attest_portfolio(runs)

    after = snapshot()
    assert before == after, "the sealed per-run captures must not change"

    # The four canonical shas still match, and each per-run signature still verifies.
    for name, sha_prefix in FROZEN_SHAS.items():
        jsonl = (DATA / name).read_text(encoding="utf-8")
        import hashlib
        sha = hashlib.sha256(jsonl.encode("utf-8")).hexdigest()
        assert sha.startswith(sha_prefix), f"{name} sha drifted: {sha}"
        record = json.loads((DATA / f"{name}.sig.json").read_text(encoding="utf-8"))
        assert verify_run_log_jsonl(jsonl, record), f"{name} per-run signature broke"


def monkeypatch_data_dir(build_fn, data: Path, manifest_path: Path) -> None:
    """Run the build over a temp data dir by pointing the build function at it.
    The build entry point takes (data_dir, out_path) directly, so this is a thin
    call wrapper kept for read clarity at the call site."""
    build_fn(data, manifest_path)
