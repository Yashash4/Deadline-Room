"""Tests for scripts/audit_run.py: the one-command post-run audit.

Two things are proven here. First, the audit PASSES every one of the seven
invariants on all four committed sealed captures (well-formed, byte-identical
replay, chain head, signature, exactly-once, two-key release, clock monotonicity).
The captures were regenerated through the current floor, so they carry the
release_signoff records that prove the segregation of duties, and the audit reads
that two-key evidence straight from the sealed bytes.

Second, the audit is NON-VACUOUS: on a freshly generated floor log that genuinely
contains the two-key release_signoff records (built offline through the same
FakeBand harness the rest of the suite uses), the audit passes every invariant,
and a tampered copy makes the corresponding invariant FAIL. A flipped `admitted`
field breaks REPLAY and SIGNATURE; a removed second release key breaks TWO-KEY
RELEASE. The committed captures are never mutated: every tamper is on a temp copy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from scripts.audit_run import SCENARIOS, audit_run

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

# All seven invariants the audit checks. Every one holds on every committed sealed
# capture, because the captures were regenerated through the current floor and
# carry the release_signoff segregation-of-duties records.
ALL_INVARIANTS = frozenset({
    "WELL-FORMED", "REPLAY", "CHAIN", "SIGNATURE", "EXACTLY-ONCE",
    "TWO-KEY RELEASE", "CLOCK-MONOTONIC",
})
TWO_KEY_RELEASE = "TWO-KEY RELEASE"


def _checks_by_name(result) -> dict:
    return {c.name: c for c in result.checks}


# --- Honest audit of the committed sealed captures ---------------------------

@pytest.mark.parametrize("mode", SCENARIOS)
def test_sealed_capture_passes_every_invariant(mode):
    """Every committed capture satisfies all seven invariants over its own sealed
    bytes: structural soundness, byte-identical replay, the chain head, the bound
    signature, exactly-once, two-key release, and clock monotonicity."""
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    packet_path = DATA / f"packet-{mode}.json"
    result = audit_run(log_path, packet_path)
    checks = _checks_by_name(result)
    assert set(checks) == ALL_INVARIANTS, (
        f"{mode}: audit produced an unexpected invariant set {sorted(checks)}")
    failing = [c for c in result.checks if not c.ok]
    assert result.ok, (
        f"{mode}: sealed capture failed an invariant: "
        + "; ".join(f"{c.name}: {c.detail}" for c in failing))


@pytest.mark.parametrize("mode", SCENARIOS)
def test_sealed_capture_two_key_release_is_proven(mode):
    """The regenerated captures carry release_signoff records, so the audit proves
    two-key release from the sealed bytes: every human release is preceded by a
    passed contradiction diff and two distinct release keys. This pins that the
    segregation of duties is genuinely present, not merely unflagged."""
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    packet_path = DATA / f"packet-{mode}.json"
    result = audit_run(log_path, packet_path)
    two_key = _checks_by_name(result)[TWO_KEY_RELEASE]
    assert two_key.ok, (
        f"{mode}: two-key release unexpectedly FAILED: {two_key.detail}")
    assert "two distinct keys" in two_key.detail


# --- A freshly generated floor log: the audit passes every invariant ----------

def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return room, clients


def _stub_draft_fns():
    def make(branch):
        def fn(claim_facts):
            return (
                f"{branch.upper()} regulatory notification for incident inc-8842. "
                "The affected systems were isolated and the incident is "
                "partially contained.\n"
                "[CLAIMS]\n"
                "incident_start: 2026-06-16T02:14:00+00:00\n"
                "records_affected: 48211\n"
                "attacker: lockbit\n"
                "containment: partially_contained\n"
                "[/CLAIMS]\n")
        return fn
    return {r.branch: make(r.branch) for r in DRAFTER_ROLES}


def _fresh_floor_log(tmp_path: Path, mode: str = "normal") -> tuple[Path, Path]:
    """Generate a passing floor run offline through FakeBand and return its run-log
    and packet paths. The normal mode needs no network and writes release_signoff
    events, so the audit can pass all seven invariants."""
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
              draft_fns=_stub_draft_fns())
    src = tmp_path / "examiner-packet.json"
    packet_path = tmp_path / f"packet-{mode}.json"
    src.rename(packet_path)
    log_path = tmp_path / f"run-inc-8842-{mode}.jsonl"
    return log_path, packet_path


def test_fresh_floor_log_passes_every_invariant(tmp_path):
    """A freshly generated floor log (with release_signoff records) passes all
    seven invariants, including two-key release. This proves the audit's two-key
    check is satisfiable from a run produced independently of the committed
    captures, so the sealed-capture PASS is a real property of the artifact, not a
    quirk of one frozen file."""
    log_path, packet_path = _fresh_floor_log(tmp_path)
    result = audit_run(log_path, packet_path)
    failing = [c for c in result.checks if not c.ok]
    assert result.ok, (
        "fresh floor log should pass every invariant; failing: "
        + "; ".join(f"{c.name}: {c.detail}" for c in failing))
    # And two-key release specifically is satisfied here.
    assert _checks_by_name(result)[TWO_KEY_RELEASE].ok


# --- Non-vacuity: tampering a passing log makes the right invariant FAIL -------

def test_field_flip_fails_replay_and_signature(tmp_path):
    """Flip one admitted field on a passing log: REPLAY re-derives the truth and
    diverges, and the bound-payload signature no longer verifies. The committed
    captures are never touched; this mutates a temp copy."""
    log_path, packet_path = _fresh_floor_log(tmp_path)

    entries = [json.loads(line) for line in
               log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    flipped = False
    for entry in entries:
        if entry["type"] == "protocol_event" and entry["payload"].get("admitted") is True:
            entry["payload"]["admitted"] = False
            entry["payload"]["to_state"] = None
            flipped = True
            break
    assert flipped, "expected at least one admitted protocol_event to flip"

    tampered_path = tmp_path / "run-inc-8842-normal-tampered.jsonl"
    tampered_path.write_text(
        "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":"))
                  for e in entries) + "\n", encoding="utf-8")

    result = audit_run(tampered_path, packet_path)
    checks = _checks_by_name(result)
    assert not checks["REPLAY"].ok, "a flipped admitted field must break REPLAY"
    assert not checks["SIGNATURE"].ok, "a flipped field must break the SIGNATURE"
    assert not result.ok


def test_removed_second_key_fails_two_key_release(tmp_path):
    """Remove the second distinct release key from a passing log's first branch:
    TWO-KEY RELEASE must FAIL and name the under-signed branch. The committed
    captures are never touched; this mutates a temp copy."""
    log_path, packet_path = _fresh_floor_log(tmp_path)

    entries = [json.loads(line) for line in
               log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Identify the branch of the first human_released, then drop the head_of_ir
    # release_signoff for that branch so only one distinct key remains before the
    # release. Removing an entry would break the contiguous seq the chain expects,
    # so instead we DEMOTE the second key to the same role as the first: two
    # signoffs, one distinct role, which is exactly what the gate forbids.
    target_branch = None
    for entry in entries:
        if (entry["type"] == "protocol_event"
                and entry["payload"].get("event") == "human_released"):
            target_branch = entry["payload"]["correlation_id"]
            break
    assert target_branch is not None, "expected a human_released event"

    demoted = False
    for entry in entries:
        if (entry["type"] == "release_signoff"
                and entry["payload"].get("correlation_id") == target_branch
                and entry["payload"].get("role") == "head_of_ir"):
            # Collapse the second key onto the first role: no second DISTINCT key.
            entry["payload"]["role"] = "general_counsel"
            demoted = True
            break
    assert demoted, "expected a head_of_ir release_signoff to demote"

    tampered_path = tmp_path / "run-inc-8842-normal-onekey.jsonl"
    tampered_path.write_text(
        "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":"))
                  for e in entries) + "\n", encoding="utf-8")

    result = audit_run(tampered_path, packet_path)
    two_key = _checks_by_name(result)[TWO_KEY_RELEASE]
    assert not two_key.ok, "a single distinct release key must fail TWO-KEY RELEASE"
    assert target_branch in two_key.detail
    assert not result.ok
