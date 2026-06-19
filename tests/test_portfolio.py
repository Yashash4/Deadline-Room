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
    NEAR_BREACH_HOURS,
    QUEUE_STAGES,
    SealedRun,
    attest_portfolio,
    cross_incident_patterns,
    insights_dict,
    insights_dict_digest,
    load_portfolio,
    merkle_root,
    portfolio_sla,
    queue_dict,
    queue_view,
    sla_dict,
    sla_dict_digest,
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
        base.root, base.run_count, base.manifest_sha256, base.insights_sha256,
        base.sla_sha256)
    assert verify_portfolio(
        base.root, base.run_count, base.insights_sha256, base.sla_sha256, record)
    assert not verify_portfolio(
        after.root, after.run_count, after.insights_sha256, after.sla_sha256,
        record)


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
        att.root, att.run_count, att.manifest_sha256, att.insights_sha256,
        att.sla_sha256)
    assert verify_portfolio(
        att.root, att.run_count, att.insights_sha256, att.sla_sha256, record)

    # Edit one finding: flip the veto count from 3 to 4. The insights digest moves,
    # so the signature no longer verifies over the edited findings.
    tampered = insights_dict(att.insights)
    tampered = {**tampered,
                "veto_field_recurrence": {"incident_start_utc": 4}}
    tampered_digest = insights_dict_digest(tampered)
    assert tampered_digest != att.insights_sha256
    assert not verify_portfolio(
        att.root, att.run_count, tampered_digest, att.sla_sha256, record)


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


# ---------------------------------------------------------------------------
# E6.4 portfolio SLA / throughput roll-up. The fleet view a standing operations
# center is judged on: across EVERY sealed run, the worst-case and median
# statutory margin, the near-breach and breach counts, the nearest deadline, and
# the aggregated throughput. Every number is a pure read of the clock_started /
# clock_stopped and protocol entries already in the sealed logs, with zero LLM and
# no now(), and the rollup is INSIDE the signed manifest so editing a number breaks
# the portfolio signature.
# ---------------------------------------------------------------------------


def test_sla_rollup_is_deterministic_over_the_captures():
    # Two independent folds over the same sealed data produce identical rollups.
    a = portfolio_sla(load_portfolio(DATA))
    b = portfolio_sla(load_portfolio(DATA))
    assert sla_dict(a) == sla_dict(b)
    assert sla_dict_digest(sla_dict(a)) == sla_dict_digest(sla_dict(b))


def test_sla_margins_match_the_per_run_packet_telemetry():
    """The fleet rollup margins are derived from the sealed clock_started /
    clock_stopped entries; they must equal the per-run packet operability
    deadline_margins, the SAME deadline-minus-filed math the packet renders. This
    proves the cross-run rollup does not drift from the per-run telemetry."""
    sla = portfolio_sla(load_portfolio(DATA))
    by_run = {r.name: r for r in sla.per_run}
    for scenario in json.loads(
            (DATA / "manifest.json").read_text(encoding="utf-8"))["scenarios"]:
        run_name = Path(scenario["run_log"]).name
        if run_name not in by_run:
            continue
        packet = json.loads(
            (DATA / Path(scenario["packet"]).name).read_text(encoding="utf-8"))
        packet_margins = {
            m["correlation_id"]: m["margin_hours"]
            for m in packet["operability"]["deadline_margins"]
            if m["filed"]
        }
        rollup_margins = {
            m.correlation_id: m.margin_hours
            for m in by_run[run_name].margins
        }
        assert rollup_margins == packet_margins, (
            f"{run_name} rollup margins drifted from the packet telemetry")
        # The tightest filed margin and breach verdict match the packet too.
        assert by_run[run_name].min_margin_hours == \
            packet["operability"]["min_filed_margin_hours"]
        assert (by_run[run_name].breaches > 0) == \
            packet["operability"]["any_breached"]


def test_sla_throughput_matches_the_per_run_packet_throughput():
    """The per-run drafted / released / suppressed counts the rollup folds from the
    sealed protocol events equal the packet operability throughput block."""
    sla = portfolio_sla(load_portfolio(DATA))
    by_run = {r.name: r for r in sla.per_run}
    for scenario in json.loads(
            (DATA / "manifest.json").read_text(encoding="utf-8"))["scenarios"]:
        run_name = Path(scenario["run_log"]).name
        if run_name not in by_run:
            continue
        packet = json.loads(
            (DATA / Path(scenario["packet"]).name).read_text(encoding="utf-8"))
        pkt = packet["operability"]["throughput"]
        tp = by_run[run_name].throughput
        for key in ("drafted", "filings", "released", "suppressed"):
            assert tp[key] == pkt[key], (
                f"{run_name} throughput {key} drifted from the packet")


def test_sla_aggregates_are_exact_on_the_captures():
    # The clean captures file every clock on time, so the fleet never breaches and
    # the worst-case margin equals the tightest filed margin across all runs.
    sla = portfolio_sla(load_portfolio(DATA))
    assert sla.total_filings == sum(r.filings_landed for r in sla.per_run)
    assert sla.total_breaches == 0
    assert sla.ever_breached is False
    assert sla.near_breach_count == 0
    assert sla.near_breach_hours == NEAR_BREACH_HOURS
    # The worst-case margin is the minimum filed margin across every run, and it
    # names the run and clock that owns it.
    all_filed = [m for r in sla.per_run for m in r.margins]
    assert sla.worst_margin_hours == min(m.margin_hours for m in all_filed)
    assert sla.worst_margin_run
    assert sla.worst_margin_clock
    # The fleet nearest deadline is the earliest deadline any clock started on.
    assert sla.nearest_deadline_utc == min(
        r.nearest_deadline_utc for r in sla.per_run
        if r.nearest_deadline_utc is not None)


def test_synthetic_breached_run_is_counted(tmp_path):
    # A run that files PAST its deadline is a breach: the rollup counts it, flips
    # ever_breached, and the negative margin becomes the worst-case.
    breached = _write_run(tmp_path, "run-breach.jsonl", [
        {"type": "clock_started", "seq": 0,
         "payload": {"clock": "NIS2 full notification (72h)",
                     "correlation_id": "inc-9001:nis2",
                     "deadline": "2026-06-19T02:14:00+00:00"}},
        # Filed 10 hours AFTER the deadline: a breach.
        {"type": "clock_stopped", "seq": 1,
         "payload": {"correlation_id": "inc-9001:nis2",
                     "ts": "2026-06-19T12:14:00+00:00"}},
        {"type": "protocol_event", "seq": 2,
         "payload": {"event": "draft_started", "correlation_id": "inc-9001:nis2"}},
        {"type": "protocol_event", "seq": 3,
         "payload": {"event": "human_released",
                     "correlation_id": "inc-9001:nis2"}},
    ])
    ontime = _write_run(tmp_path, "run-ontime.jsonl", [
        {"type": "clock_started", "seq": 0,
         "payload": {"clock": "DORA major-incident (72h)",
                     "correlation_id": "inc-9002:dora",
                     "deadline": "2026-06-19T02:14:00+00:00"}},
        {"type": "clock_stopped", "seq": 1,
         "payload": {"correlation_id": "inc-9002:dora",
                     "ts": "2026-06-16T02:14:00+00:00"}},
        {"type": "protocol_event", "seq": 2,
         "payload": {"event": "draft_started", "correlation_id": "inc-9002:dora"}},
        {"type": "protocol_event", "seq": 3,
         "payload": {"event": "human_released",
                     "correlation_id": "inc-9002:dora"}},
    ])
    sla = portfolio_sla([breached, ontime])
    assert sla.total_filings == 2
    assert sla.total_breaches == 1
    assert sla.ever_breached is True
    # The breached filing landed 10h past the deadline: margin -10.0h, the worst.
    assert sla.worst_margin_hours == -10.0
    assert sla.worst_margin_run == "run-breach.jsonl"
    # Both filings are within the near-breach window? No: the breached one is past
    # the deadline (counted as a breach, not a near-breach); the on-time one landed
    # 72h early. So near_breach_count stays 0 here.
    assert sla.near_breach_count == 0


def test_near_breach_window_counts_a_tight_but_on_time_filing(tmp_path):
    # A filing that lands inside the near-breach window but before the deadline is a
    # near-breach (not a breach): it is counted in near_breach_count.
    tight = _write_run(tmp_path, "run-tight.jsonl", [
        {"type": "clock_started", "seq": 0,
         "payload": {"clock": "NIS2 early warning (24h)",
                     "correlation_id": "inc-9100:nis2-early",
                     "deadline": "2026-06-17T02:14:00+00:00"}},
        # Filed 1 hour before the deadline: 1.0h of margin, inside the 24h window.
        {"type": "clock_stopped", "seq": 1,
         "payload": {"correlation_id": "inc-9100:nis2-early",
                     "ts": "2026-06-17T01:14:00+00:00"}},
        {"type": "protocol_event", "seq": 2,
         "payload": {"event": "draft_started",
                     "correlation_id": "inc-9100:nis2-early"}},
        {"type": "protocol_event", "seq": 3,
         "payload": {"event": "human_released",
                     "correlation_id": "inc-9100:nis2-early"}},
    ])
    sla = portfolio_sla([tight])
    assert sla.total_breaches == 0
    assert sla.near_breach_count == 1
    assert sla.worst_margin_hours == 1.0


def test_unfiled_clock_contributes_no_margin(tmp_path):
    # A clock that started but never stopped never filed: it contributes no margin
    # and no breach (never a fabricated zero), mirroring the packet operability.
    run = _write_run(tmp_path, "run-open.jsonl", [
        {"type": "clock_started", "seq": 0,
         "payload": {"clock": "SEC 8-K (4 business days)",
                     "correlation_id": "inc-9200:sec",
                     "deadline": "2026-06-23T23:59:59+00:00"}},
    ])
    sla = portfolio_sla([run])
    assert sla.total_filings == 0
    assert sla.per_run[0].min_margin_hours is None
    assert sla.total_breaches == 0
    # The nearest deadline still reflects the started clock even though it is unfiled.
    assert sla.nearest_deadline_utc == "2026-06-23T23:59:59+00:00"


def test_flagged_run_is_not_folded_into_sla(tmp_path):
    # A run that did not pass its per-run signature must never contribute an SLA
    # number, exactly as the insights fold excludes it.
    good = _write_run(tmp_path, "run-good.jsonl", [
        {"type": "clock_started", "seq": 0,
         "payload": {"clock": "NIS2 full notification (72h)",
                     "correlation_id": "inc-1:nis2",
                     "deadline": "2026-06-19T02:14:00+00:00"}},
        {"type": "clock_stopped", "seq": 1,
         "payload": {"correlation_id": "inc-1:nis2",
                     "ts": "2026-06-16T02:14:00+00:00"}},
        {"type": "protocol_event", "seq": 2,
         "payload": {"event": "human_released", "correlation_id": "inc-1:nis2"}},
    ])
    bad = _write_run(tmp_path, "run-bad.jsonl", [
        {"type": "clock_started", "seq": 0,
         "payload": {"clock": "DORA major-incident (72h)",
                     "correlation_id": "inc-2:dora",
                     "deadline": "2026-06-19T02:14:00+00:00"}},
        {"type": "clock_stopped", "seq": 1,
         "payload": {"correlation_id": "inc-2:dora",
                     "ts": "2026-06-19T20:14:00+00:00"}},
    ])
    bad = SealedRun(
        name=bad.name, log_path=bad.log_path, sig_path=bad.sig_path,
        sha256=bad.sha256, chain_head=bad.chain_head, signature_valid=False,
        flag="per-run signature does not verify")
    sla = portfolio_sla([good, bad])
    # Only the good run is folded: one filing, no breach (the bad run's late filing
    # never enters the rollup).
    assert sla.total_filings == 1
    assert sla.total_breaches == 0
    assert sla.ever_breached is False
    assert [r.name for r in sla.per_run] == ["run-good.jsonl"]


def test_sla_is_inside_the_signed_manifest_editing_breaks_signature():
    # The fleet SLA rollup is folded into the signed manifest, and the portfolio
    # signature commits to its digest, so editing any rollup number breaks the
    # signature directly (not only a cross-check).
    att = attest_portfolio(load_portfolio(DATA))
    assert "sla" in att.manifest
    assert att.manifest["sla"]["total_breaches"] == 0

    record = sign_portfolio(
        att.root, att.run_count, att.manifest_sha256, att.insights_sha256,
        att.sla_sha256)
    assert verify_portfolio(
        att.root, att.run_count, att.insights_sha256, att.sla_sha256, record)

    # Edit one rollup number: claim zero breaches became one. The SLA digest moves,
    # so the signature no longer verifies over the edited rollup.
    tampered = sla_dict(att.sla)
    tampered = {**tampered, "total_breaches": 1, "ever_breached": True}
    tampered_digest = sla_dict_digest(tampered)
    assert tampered_digest != att.sla_sha256
    assert not verify_portfolio(
        att.root, att.run_count, att.insights_sha256, tampered_digest, record)


def test_edited_sla_in_manifest_is_detected_by_verifier(tmp_path, capsys):
    # Build the manifest over the real data into a temp dir, edit an SLA number in
    # the written manifest, and re-verify: the verifier must report INVALID.
    data = _copy_data(tmp_path)
    manifest_path = data / "portfolio-attestation.json"
    build(data, manifest_path)
    assert manifest_path.exists()

    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    document["manifest"]["sla"]["total_breaches"] = 99
    manifest_path.write_text(json.dumps(document, indent=2, sort_keys=True),
                             encoding="utf-8")

    rc = verify(manifest_path, data)
    out = capsys.readouterr().out
    assert rc != 0, "editing an SLA number must make the portfolio INVALID"
    assert "INVALID" in out


def test_sla_fold_leaves_sealed_captures_and_replay_unchanged():
    """Folding the fleet SLA rollup and rebuilding the signed manifest is READ ONLY
    over the four per-run sealed captures: snapshot the sealed bytes, sidecars, and
    replay, run the full SLA-bearing attestation, and assert byte-equality plus the
    four frozen shas."""
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
    # The SLA fold ran (it sees no breach on the clean captures) ...
    assert att.sla.ever_breached is False
    assert att.sla.total_breaches == 0
    after = snapshot()
    assert before == after, "the sealed per-run captures must not change"

    import hashlib
    for name, sha_prefix in FROZEN_SHAS.items():
        jsonl = (DATA / name).read_text(encoding="utf-8")
        sha = hashlib.sha256(jsonl.encode("utf-8")).hexdigest()
        assert sha.startswith(sha_prefix), f"{name} sha drifted: {sha}"


# ---------------------------------------------------------------------------
# E6.6 deterministic incident intake queue + status board. The queue reads each
# running incident's status from its sealed log (a released run shows released,
# never a status the log does not support), the pending intake records sit in the
# queued lane, the board sorts by nearest deadline, and the whole path leaves the
# sealed captures and replay byte-unchanged.
# ---------------------------------------------------------------------------


def test_queue_reads_real_terminal_status_from_the_sealed_captures():
    # Every committed capture released all four filings, so each running incident
    # on the board must read `released`, never an unsupported status. No item is
    # green-washed: the status comes straight from the branch transitions.
    board = queue_view(load_portfolio(DATA))
    run_items = [it for it in board.items if it.kind == "run"]
    assert run_items, "expected the sealed runs to populate the board"
    for it in run_items:
        assert it.status == "released", f"{it.key} read as {it.status}"
        # The status is supported by the branches: every branch terminal state is
        # `released`, so the rolled-up run status is honest.
        assert set(it.branches.values()) == {"released"}, it.branches
    # The released lane counts exactly the sealed runs; nothing is closed (closure
    # is an operator disposition the sealed log never asserts).
    assert board.released == len(run_items)
    assert board.closed == 0


def test_queued_intake_record_shows_queued_not_released():
    # A declarative pending record has NOT run, so the board must place it in the
    # queued lane and never assert a run status (released) for it.
    pending = [{
        "id": "intake-inc-7000-nis2",
        "incident_id": "inc-7000",
        "regime": "nis2",
        "nearest_deadline_utc": "2026-06-16T12:00:00+00:00",
        "label": "inc-7000 fresh intake",
    }]
    board = queue_view(load_portfolio(DATA), pending=pending)
    queued = [it for it in board.items if it.kind == "pending"]
    assert len(queued) == 1
    item = queued[0]
    assert item.status == "queued"
    assert item.status != "released"
    assert item.incident_id == "inc-7000"
    assert item.branches == {}
    assert board.queued == 1


def test_queue_sorts_by_nearest_deadline():
    # The board is total-ordered by nearest statutory deadline. A pending record
    # due BEFORE the sealed runs sorts ahead of them; one due AFTER sorts behind.
    pending = [
        {"id": "early", "incident_id": "inc-e", "regime": "nis2",
         "nearest_deadline_utc": "2026-06-16T00:00:00+00:00", "label": "early"},
        {"id": "late", "incident_id": "inc-l", "regime": "sec",
         "nearest_deadline_utc": "2026-12-01T00:00:00+00:00", "label": "late"},
    ]
    board = queue_view(load_portfolio(DATA), pending=pending)
    deadlines = [
        it.nearest_deadline_utc for it in board.items
        if it.nearest_deadline_utc is not None]
    assert deadlines == sorted(deadlines), "board not sorted by nearest deadline"
    # The earliest pending record owns the head of the board and the nearest
    # deadline; the late one is strictly behind the sealed runs.
    assert board.items[0].key == "early"
    assert board.nearest_deadline_key == "early"
    keys = [it.key for it in board.items]
    assert keys.index("early") < keys.index("late")
    sealed_positions = [
        i for i, it in enumerate(board.items) if it.kind == "run"]
    assert all(keys.index("early") < p for p in sealed_positions)
    assert all(keys.index("late") > p for p in sealed_positions)


def test_queue_flags_the_fleet_worst_case_margin():
    # The board surfaces the SLA worst-case margin so the tightest filing on
    # record is flagged. On the clean captures nothing breached.
    board = queue_view(load_portfolio(DATA))
    sla = portfolio_sla(load_portfolio(DATA))
    assert board.worst_case_margin_hours == sla.worst_margin_hours
    assert board.worst_case_run == sla.worst_margin_run
    assert board.worst_case_clock == sla.worst_margin_clock
    assert board.ever_breached is False


def test_an_in_flight_branch_keeps_a_run_active_never_released(tmp_path):
    # A run with a branch still drafting (not settled) must read `active`, never a
    # terminal status the log does not support. Green-washing is impossible.
    run = _write_run(tmp_path, "run-active.jsonl", [
        {"type": "protocol_event", "seq": 0, "payload": {
            "correlation_id": "inc-1:nis2", "event": "human_released",
            "admitted": True, "to_state": "released"}},
        {"type": "protocol_event", "seq": 1, "payload": {
            "correlation_id": "inc-1:sec", "event": "draft_started",
            "admitted": True, "to_state": "drafting"}},
    ])
    board = queue_view([run])
    item = board.items[0]
    assert item.status == "active", item.branches
    assert item.status != "released"
    assert board.active == 1
    assert board.released == 0


def test_a_suppressed_branch_reads_suppressed_not_released(tmp_path):
    # A run whose branches all settled and one was suppressed reads `suppressed`,
    # the real disposition, never `released`.
    run = _write_run(tmp_path, "run-suppressed.jsonl", [
        {"type": "protocol_event", "seq": 0, "payload": {
            "correlation_id": "inc-2:nis2", "event": "human_released",
            "admitted": True, "to_state": "released"}},
        {"type": "protocol_event", "seq": 1, "payload": {
            "correlation_id": "inc-2:sec", "event": "suppress",
            "admitted": True, "to_state": "suppressed"}},
    ])
    board = queue_view([run])
    item = board.items[0]
    assert item.status == "suppressed"
    assert item.status != "released"
    assert board.suppressed == 1


def test_flagged_run_is_not_placed_on_the_board(tmp_path):
    # A run that failed its per-run signature is excluded from the board, matching
    # the rest of the portfolio path (never silently folded in).
    flagged = SealedRun(
        name="run-bad.jsonl", log_path=tmp_path / "run-bad.jsonl",
        sig_path=tmp_path / "run-bad.jsonl.sig.json",
        sha256="00", chain_head="00", signature_valid=False,
        flag="per-run signature does not verify")
    board = queue_view([flagged])
    assert board.items == []
    assert board.released == 0


def test_queue_is_deterministic_across_two_builds():
    pending = [{
        "id": "intake-inc-7777", "incident_id": "inc-7777", "regime": "dora",
        "nearest_deadline_utc": "2026-06-20T00:00:00+00:00", "label": "x"}]
    a = queue_dict(queue_view(load_portfolio(DATA), pending=pending))
    b = queue_dict(queue_view(load_portfolio(DATA), pending=pending))
    assert a == b
    # Stages are a closed, known set.
    for it in a["items"]:
        assert it["status"] in QUEUE_STAGES


def test_intake_json_fixture_loads_and_queues():
    # The shipped declarative intake set loads and every record sits in queued.
    doc = json.loads((DATA / "intake.json").read_text(encoding="utf-8"))
    pending = doc["pending"]
    assert pending, "expected shipped pending intake records"
    board = queue_view(load_portfolio(DATA), pending=pending)
    pend_items = [it for it in board.items if it.kind == "pending"]
    assert len(pend_items) == len(pending)
    assert all(it.status == "queued" for it in pend_items)
    assert board.queued == len(pending)


def test_queue_view_leaves_sealed_captures_and_replay_unchanged():
    # The queue path is a pure read: the four sealed captures and their replay are
    # byte-identical before and after building the board.
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
    doc = json.loads((DATA / "intake.json").read_text(encoding="utf-8"))
    queue_view(load_portfolio(DATA), pending=doc["pending"])
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
