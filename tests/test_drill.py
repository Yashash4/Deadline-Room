"""Tests for the Examiner Drill and the deadline-pressure worst-case walk (E9.4).

Four things are proven here.

  1. The drill manifest EXTRACTS the correct ground-truth verdict per gate from a
     sealed run: the answer key is DERIVED from the cryptographically-fixed bytes,
     never hand-asserted. The contradiction veto reads BLOCK when the diff carries
     conflicts and RELEASE when it is clean; the two-key gate reads BLOCK on the
     first single key and RELEASE once both distinct keys are present.
  2. The certification receipt VERIFIES against the committed public key, and a
     tampered copy (any edited field) FAILS. It is a SEPARATE detached signature
     under a DISTINCT label, so it can never be confused with the per-run signature.
  3. The deadline-pressure sweep is DETERMINISTIC (the same sweep twice is
     byte-identical) and surfaces the KNOWN worst-case window (the Christmas /
     New Year cluster, where the SEC clock is pushed a full 96h past the naive
     reading).
  4. The four per-run sealed shas are UNCHANGED: building the drill and signing the
     certification never touch a sealed run-log byte or its committed .sig.json.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.deadline_pressure import (
    NAIVE_HOURS,
    SEC_BUSINESS_DAYS,
    build_report,
    sweep,
    worst_window,
)
from scripts.drill_manifest import (
    BLOCK,
    CERTIFICATION_SIGNED_PAYLOAD,
    RELEASE,
    SCENARIOS,
    answer_key_digest,
    build_drill_manifest,
    extract_decision_points,
    sign_certification,
    verify_certification,
)
from warden.chain import chain_head
from warden.replay import RunLog
from warden.signing import verify_run_log_jsonl

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

# The four per-run sealed canonical shas, frozen and read-only. The drill and the
# pressure walk read these bytes; they must never move.
SEALED_SHAS = {
    "normal": "89dae145",
    "inject_contradiction": "f1f2223a",
    "chaos": "303c4371",
    "amendment": "0ca07fb0",
}


def _log_path(mode: str) -> Path:
    return DATA / f"run-inc-8842-{mode}.jsonl"


# --- 1. The answer key is DERIVED from the sealed run -------------------------

@pytest.mark.parametrize("mode", SCENARIOS)
def test_drill_extracts_decision_points(mode):
    """Every sealed run yields at least one gate, and every decision point's
    ground truth is one of RELEASE / BLOCK, derived from the bytes."""
    entries = RunLog.load(_log_path(mode)).entries()
    points = extract_decision_points(entries)
    assert points, f"{mode}: expected at least one decision point"
    for p in points:
        assert p.ground_truth in (RELEASE, BLOCK)
        assert p.kind in ("contradiction_diff", "two_key_release")
        # The seq it rests on is a real entry in the sealed log.
        assert any(e.get("seq") == p.seq for e in entries), (
            f"{mode}: decision point seq {p.seq} not in the sealed log")


def test_clean_diff_is_release_blocked_diff_is_block():
    """The contradiction veto ground truth is read straight from the diff: the
    normal run's clean round-1 diff is RELEASE; the inject_contradiction run's
    round-1 diff (two conflicts) is BLOCK, then its round-2 clean diff is RELEASE.
    This is the answer key derived from the cryptographically-fixed bytes."""
    normal = extract_decision_points(RunLog.load(_log_path("normal")).entries())
    normal_diffs = [p for p in normal if p.kind == "contradiction_diff"]
    assert len(normal_diffs) == 1
    assert normal_diffs[0].ground_truth == RELEASE

    inj = extract_decision_points(
        RunLog.load(_log_path("inject_contradiction")).entries())
    inj_diffs = [p for p in inj if p.kind == "contradiction_diff"]
    assert len(inj_diffs) == 2, "expected a blocked round 1 and a clean round 2"
    assert inj_diffs[0].ground_truth == BLOCK, "round 1 has conflicts -> BLOCK"
    assert inj_diffs[1].ground_truth == RELEASE, "round 2 is clean -> RELEASE"


def test_two_key_gate_first_key_blocks_second_key_releases():
    """The two-key gate ground truth: each branch's first single key is BLOCK
    (release withheld, segregation of duties not met) and the completing second
    distinct key is RELEASE. Derived from the sealed have_roles/released fields."""
    points = extract_decision_points(RunLog.load(_log_path("normal")).entries())
    two_key = [p for p in points if p.kind == "two_key_release"]
    assert two_key, "expected two-key release decision points"
    # They come in (withhold, admit) pairs per branch.
    by_branch: dict[str, list] = {}
    for p in two_key:
        by_branch.setdefault(p.branch, []).append(p)
    for branch, pair in by_branch.items():
        assert pair[0].ground_truth == BLOCK, (
            f"{branch}: first single key must be BLOCK")
        assert pair[-1].ground_truth == RELEASE, (
            f"{branch}: completing second key must be RELEASE")


def test_answer_key_digest_is_order_sensitive():
    """The answer key digest binds the ordered verdicts: reordering or flipping any
    verdict moves the digest, so a tampered answer key cannot pass as the real one.
    """
    points = extract_decision_points(RunLog.load(_log_path("normal")).entries())
    base = answer_key_digest(points)
    # Flip one verdict on a copy: the digest must move.
    flipped = copy.deepcopy(points)
    object.__setattr__(
        flipped[0], "ground_truth",
        BLOCK if flipped[0].ground_truth == RELEASE else RELEASE)
    assert answer_key_digest(flipped) != base
    # Reverse the order: the digest must move (the key is ordered).
    assert answer_key_digest(list(reversed(points))) != base


# --- 2. The certification receipt verifies; a tampered copy fails -------------

@pytest.mark.parametrize("mode", SCENARIOS)
def test_certification_receipt_verifies(mode):
    """The signed certification receipt verifies against the committed public key
    over the certification document for the run."""
    m = build_drill_manifest(_log_path(mode))
    assert m.signature["signed_payload"] == CERTIFICATION_SIGNED_PAYLOAD
    assert m.signature["detached"] is True
    assert m.signature["separate_from_run_log_signature"] is True
    assert verify_certification(m.document, m.signature), (
        f"{mode}: certification receipt should verify")


@pytest.mark.parametrize("mode", SCENARIOS)
def test_tampered_certification_fails(mode):
    """Editing any field of the certification document breaks the receipt: the
    digest moves and the signature no longer verifies. Tested over several fields
    so the binding is shown to cover the whole document, not one field."""
    m = build_drill_manifest(_log_path(mode))
    for field, bad in [
        ("run_sha256", "0" * 64),
        ("run_chain_head", "0" * 64),
        ("answer_key_sha256", "0" * 64),
        ("gate_count", m.document["gate_count"] + 1),
        ("required_score", 0),
        ("mode", "forged"),
    ]:
        tampered = copy.deepcopy(m.document)
        tampered[field] = bad
        assert not verify_certification(tampered, m.signature), (
            f"{mode}: a tampered {field} must fail the receipt")


def test_tampered_signature_bytes_fail():
    """Flipping a byte of the detached signature itself fails verification."""
    m = build_drill_manifest(_log_path("normal"))
    bad = copy.deepcopy(m.signature)
    sig = bad["signature"]
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    bad["signature"] = flipped
    assert not verify_certification(m.document, bad)


def test_certification_is_deterministic():
    """The same sealed run always derives the byte-identical document and the same
    Ed25519 signature (the receipt is reproducible)."""
    a = build_drill_manifest(_log_path("amendment"))
    b = build_drill_manifest(_log_path("amendment"))
    assert a.document == b.document
    assert a.signature["signature"] == b.signature["signature"]
    assert a.signature["certification_digest"] == b.signature["certification_digest"]


def test_certification_label_distinct_from_per_run():
    """The certification label is DISTINCT, so a certification signature can never
    be replayed as a per-run signature: the signed bytes differ. Signing the
    certification document with the per-run payload label would not be this label.
    """
    m = build_drill_manifest(_log_path("normal"))
    assert m.signature["signed_payload"] == "canonical_json(drill_certification)"
    assert m.signature["signed_payload"] != (
        "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}")


def test_sign_certification_accepts_explicit_key_path():
    """The signer entry point round-trips through verify for an arbitrary document
    shape, confirming the sign/verify pair is self-consistent."""
    doc = {"claim": "examiner_drill_passed", "mode": "x", "gate_count": 3}
    sig = sign_certification(doc)
    assert verify_certification(doc, sig)
    doc2 = dict(doc)
    doc2["gate_count"] = 4
    assert not verify_certification(doc2, sig)


# --- 3. The deadline-pressure sweep is deterministic + surfaces the worst case -

def test_pressure_sweep_is_deterministic():
    """The sweep run twice is byte-identical: same start dates, same deadlines,
    same spans. No now(), no randomness."""
    a = [p.as_dict() for p in sweep()]
    b = [p.as_dict() for p in sweep()]
    assert a == b
    assert a, "the sweep should produce probes"


def test_pressure_surfaces_known_worst_case_window():
    """The worst-case window is the Christmas / New Year cluster: a contiguous run
    of determination dates from 2026-12-21 through 2026-12-31, each pushing the SEC
    4-business-day deadline a full 96h past the naive reading. This is the known
    dangerous start window the deterministic walk must surface."""
    report = build_report()
    assert report.days == SEC_BUSINESS_DAYS
    assert report.naive_hours == NAIVE_HOURS
    assert report.max_span_hours == pytest.approx(192.0, abs=0.01)
    assert report.max_slack_hours == pytest.approx(96.0, abs=0.01)

    worst = report.worst
    assert worst, "expected a worst-case window"
    starts = [p.start.date().isoformat() for p in worst]
    assert starts[0] == "2026-12-21"
    assert starts[-1] == "2026-12-31"
    # Every date in the window is at the maximum span and over the naive guess.
    for p in worst:
        assert p.span_hours == pytest.approx(192.0, abs=0.01)
        assert p.slack_hours == pytest.approx(96.0, abs=0.01)
    # The cluster is responsible: Christmas then New Year's Day appear as the
    # named holidays across the run.
    named = {h for p in worst for h in p.skipped_holidays}
    assert "Christmas" in named
    assert "New Year's Day" in named


def test_worst_window_is_the_longest_contiguous_run():
    """worst_window returns the single longest CONTIGUOUS run of max-span starts,
    not every disjoint max-span date. The holiday cluster run is strictly longer
    than any single-holiday week (which is broken by the post-holiday short week)."""
    probes = sweep()
    worst = worst_window(probes)
    max_span = max(p.span_hours for p in probes)
    # All in the returned window are at the maximum span.
    assert all(p.span_hours == max_span for p in worst)
    # It is strictly longer than 4 (a single-holiday week yields at most 4
    # consecutive max-span business-day starts before a short week breaks it).
    assert len(worst) > 4


# --- 4. The four sealed shas are unchanged ------------------------------------

@pytest.mark.parametrize("mode", SCENARIOS)
def test_sealed_sha_unchanged(mode):
    """Building the drill and signing the certification never touch a sealed byte.
    The canonical run-log sha and the chain head are exactly the frozen values."""
    log = RunLog.load(_log_path(mode))
    sha = log.sha256()
    assert sha.startswith(SEALED_SHAS[mode]), (
        f"{mode}: sealed sha moved (got {sha[:8]}, want {SEALED_SHAS[mode]})")
    # Build the drill: it must not perturb the log's sha or chain head.
    m = build_drill_manifest(_log_path(mode))
    assert m.run_sha256 == sha
    assert m.run_chain_head == chain_head(log.entries())
    # Re-read after building: byte-identical.
    assert RunLog.load(_log_path(mode)).sha256() == sha


@pytest.mark.parametrize("mode", SCENARIOS)
def test_per_run_sig_sidecar_still_verifies(mode):
    """The committed per-run .sig.json still verifies over the sealed run-log
    bytes: the drill's separate certification signature did not disturb it."""
    log = RunLog.load(_log_path(mode))
    jsonl = log.to_jsonl()
    sidecar = _log_path(mode).with_suffix(".jsonl.sig.json")
    sig = json.loads(sidecar.read_text(encoding="utf-8"))
    assert verify_run_log_jsonl(jsonl, sig), (
        f"{mode}: committed per-run signature must still verify")
