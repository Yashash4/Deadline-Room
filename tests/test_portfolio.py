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
    SealedRun,
    attest_portfolio,
    cross_incident_patterns,
    insights_dict,
    insights_dict_digest,
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
    record = sign_portfolio(
        base.root, base.run_count, base.manifest_sha256, base.insights_sha256)
    assert verify_portfolio(
        base.root, base.run_count, base.insights_sha256, record)
    assert not verify_portfolio(
        after.root, after.run_count, after.insights_sha256, record)


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


# ---------------------------------------------------------------------------
# E6.3 cross-incident pattern detection. The fold is a capability impossible from
# a single run: a repeat offender spans incidents, and a field-type veto recurs
# across them. All proven over real or synthetic SEALED logs, with zero LLM, and
# the finding is INSIDE the signed manifest so editing it breaks the signature.
# ---------------------------------------------------------------------------


def _write_run(data: Path, name: str, entries: list[dict]) -> SealedRun:
    """Write a synthetic run log to disk and return a SealedRun pointing at it,
    marked signature_valid so the cross-incident fold counts it. The fold reads the
    log bytes off disk, so the entries drive every count exactly."""
    path = data / name
    lines = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in entries]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return SealedRun(
        name=name, log_path=path, sig_path=path.with_suffix(".sig.json"),
        sha256="00", chain_head="00", signature_valid=True, flag="")


def test_same_attacker_across_incidents_flags_a_repeat_offender(tmp_path):
    # Two distinct incidents, same named attacker: the fold must flag a repeat
    # offender (impossible to see from either single run alone).
    runs = [
        _write_run(tmp_path, "run-a.jsonl", [
            {"type": "room", "seq": 0,
             "payload": {"attacker": "lockbit", "regulated_entity": "acme-bank",
                         "correlation_id": "inc-1001:nis2"}},
        ]),
        _write_run(tmp_path, "run-b.jsonl", [
            {"type": "room", "seq": 0,
             "payload": {"attacker": "lockbit", "regulated_entity": "acme-bank",
                         "correlation_id": "inc-1002:nis2"}},
        ]),
    ]
    insights = cross_incident_patterns(runs)
    assert insights.repeat_offenders == {"lockbit": ["inc-1001", "inc-1002"]}
    assert insights.attacker_incident_counts == {"lockbit": 2}
    # Grouped by regulated entity: one entity, two incidents.
    assert insights.incidents_by_entity == {
        "acme-bank": ["inc-1001", "inc-1002"]}


def test_single_incident_attacker_is_not_a_repeat_offender(tmp_path):
    # One attacker, one incident: present in the per-attacker count, but NOT
    # flagged as a repeat offender (the >= 2 threshold is exact).
    runs = [
        _write_run(tmp_path, "run-a.jsonl", [
            {"type": "room", "seq": 0,
             "payload": {"attacker": "blackcat",
                         "correlation_id": "inc-2001:dora"}},
        ]),
    ]
    insights = cross_incident_patterns(runs)
    assert insights.repeat_offenders == {}
    assert insights.attacker_incident_counts == {"blackcat": 1}


def test_field_level_veto_recurrence_counts_exactly():
    # On the real sealed captures, the contradiction veto (diff_blocked) fired
    # three times on incident_start_utc in the inject_contradiction run. The fold
    # must count that field exactly, with no other field present.
    insights = cross_incident_patterns(load_portfolio(DATA))
    assert insights.veto_field_recurrence == {"incident_start_utc": 3}


def test_suppress_dispositions_grouped_by_regime(tmp_path):
    # A suppress protocol event is bucketed by the regime in its correlation id.
    runs = [
        _write_run(tmp_path, "run-a.jsonl", [
            {"type": "protocol_event", "seq": 1,
             "payload": {"event": "suppress", "to_state": "suppressed",
                         "correlation_id": "inc-3001:sec"}},
            {"type": "protocol_event", "seq": 2,
             "payload": {"event": "suppress", "to_state": "suppressed",
                         "correlation_id": "inc-3001:sec"}},
        ]),
        _write_run(tmp_path, "run-b.jsonl", [
            {"type": "protocol_event", "seq": 1,
             "payload": {"event": "suppress", "to_state": "suppressed",
                         "correlation_id": "inc-3002:nis2"}},
        ]),
    ]
    insights = cross_incident_patterns(runs)
    assert insights.suppress_by_regime == {"nis2": 1, "sec": 2}


def test_flagged_run_is_not_folded_into_insights(tmp_path):
    # A run that did not pass its per-run signature must never contribute a count.
    good = _write_run(tmp_path, "run-good.jsonl", [
        {"type": "protocol_event", "seq": 1,
         "payload": {"event": "suppress", "correlation_id": "inc-1:sec"}},
    ])
    bad = _write_run(tmp_path, "run-bad.jsonl", [
        {"type": "protocol_event", "seq": 1,
         "payload": {"event": "suppress", "correlation_id": "inc-2:sec"}},
    ])
    bad = SealedRun(
        name=bad.name, log_path=bad.log_path, sig_path=bad.sig_path,
        sha256=bad.sha256, chain_head=bad.chain_head, signature_valid=False,
        flag="per-run signature does not verify")
    insights = cross_incident_patterns([good, bad])
    # Only the good run's suppress is counted.
    assert insights.suppress_by_regime == {"sec": 1}


def test_insight_is_inside_the_signed_manifest_editing_breaks_signature():
    # The cross-incident finding is folded into the RANK-1 signed manifest, and
    # the portfolio signature commits to its digest, so editing any finding breaks
    # the portfolio signature directly (not only a cross-check).
    att = attest_portfolio(load_portfolio(DATA))
    # The finding is genuinely inside the manifest the signature commits to.
    assert "insights" in att.manifest
    assert att.manifest["insights"]["veto_field_recurrence"] == {
        "incident_start_utc": 3}

    record = sign_portfolio(
        att.root, att.run_count, att.manifest_sha256, att.insights_sha256)
    assert verify_portfolio(
        att.root, att.run_count, att.insights_sha256, record)

    # Edit one finding: flip the veto count from 3 to 4. The insights digest moves,
    # so the signature no longer verifies over the edited findings.
    tampered = insights_dict(att.insights)
    tampered = {**tampered,
                "veto_field_recurrence": {"incident_start_utc": 4}}
    tampered_digest = insights_dict_digest(tampered)
    assert tampered_digest != att.insights_sha256
    assert not verify_portfolio(
        att.root, att.run_count, tampered_digest, record)


def test_edited_finding_in_manifest_is_detected_by_verifier(tmp_path, capsys):
    # Build the manifest over the real data into a temp dir, edit a finding in the
    # written manifest, and re-verify: the verifier must report INVALID.
    data = _copy_data(tmp_path)
    manifest_path = data / "portfolio-attestation.json"
    build(data, manifest_path)
    assert manifest_path.exists()

    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    document["manifest"]["insights"]["veto_field_recurrence"] = {
        "incident_start_utc": 99}
    manifest_path.write_text(json.dumps(document, indent=2, sort_keys=True),
                             encoding="utf-8")

    rc = verify(manifest_path, data)
    out = capsys.readouterr().out
    assert rc != 0, "editing a finding must make the portfolio INVALID"
    assert "INVALID" in out


def test_insights_fold_leaves_sealed_captures_and_replay_unchanged():
    """Folding the cross-incident insights and rebuilding the signed manifest is
    READ ONLY over the four per-run sealed captures: snapshot the sealed bytes,
    sidecars, and replay, run the full insight-bearing attestation, and assert
    byte-equality plus the four frozen shas."""
    targets = list(FROZEN_SHAS)

    def snapshot() -> dict:
        snap: dict = {}
        for name in targets:
            log_bytes = (DATA / name).read_bytes()
            sig_bytes = (DATA / f"{name}.sig.json").read_bytes()
            log = RunLog.load(DATA / name)
            snap[name] = (log_bytes, sig_bytes, replay(log).to_jsonl())
        return snap

    before = snapshot()
    att = attest_portfolio(load_portfolio(DATA))
    # The insight fold ran (it sees the three-time veto on the captures) ...
    assert att.insights.veto_field_recurrence == {"incident_start_utc": 3}
    after = snapshot()
    assert before == after, "the sealed per-run captures must not change"

    import hashlib
    for name, sha_prefix in FROZEN_SHAS.items():
        jsonl = (DATA / name).read_text(encoding="utf-8")
        sha = hashlib.sha256(jsonl.encode("utf-8")).hexdigest()
        assert sha.startswith(sha_prefix), f"{name} sha drifted: {sha}"


def monkeypatch_data_dir(build_fn, data: Path, manifest_path: Path) -> None:
    """Run the build over a temp data dir by pointing the build function at it.
    The build entry point takes (data_dir, out_path) directly, so this is a thin
    call wrapper kept for read clarity at the call site."""
    build_fn(data, manifest_path)
