"""test_live_clock.py -- Live Mode (E7.1 + E7.4): the operator's wall-clock board
and the live-vs-sealed isolation guard.

The live board drives the SAME statutory clocks against a caller-supplied
wall-clock anchor, so a deadline genuinely counts down, crosses warn/critical, and
breaches in real time. The load-bearing guard: a live run is the OPERATOR view and
must NEVER move the sealed normal-run sha or break byte-identical replay, because
the live path never touches the hashed log. This file pins both.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from floor.live_clock import LiveClockBoard, relative_stamp
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom

T0 = datetime(2026, 6, 16, 2, 14, 0, tzinfo=timezone.utc)


# ---- the live board -------------------------------------------------------

def test_board_starts_the_four_startup_clocks_at_the_live_anchor():
    board = LiveClockBoard(T0)
    corrs = {c.correlation_id for c in board.clocks}
    assert corrs == {
        "inc-live:nis2-early", "inc-live:nis2", "inc-live:dora", "inc-live:sec"}
    # Every clock is anchored at t0: the 24h NIS2-early deadline is t0 + 24h.
    early = next(c for c in board.clocks if c.correlation_id == "inc-live:nis2-early")
    assert early.deadline == T0 + timedelta(hours=24)


def test_board_counts_down_warns_and_breaches_in_real_time():
    board = LiveClockBoard(T0)
    # 10h in: everything GREEN.
    for s in board.snapshot(T0 + timedelta(hours=10)):
        assert s.tier == "GREEN"
        assert not s.breached
    # 20h in: the 24h early-warning clock is WARN (4h margin), the 72h clocks GREEN.
    snap20 = {s.correlation_id: s for s in board.snapshot(T0 + timedelta(hours=20))}
    assert snap20["inc-live:nis2-early"].tier == "WARN"
    assert snap20["inc-live:nis2-early"].warn is True
    assert snap20["inc-live:nis2"].tier == "GREEN"
    # 25h in: the 24h clock has BREACHED, the rest still running.
    snap25 = {s.correlation_id: s for s in board.snapshot(T0 + timedelta(hours=25))}
    assert snap25["inc-live:nis2-early"].breached is True
    assert snap25["inc-live:nis2-early"].tier == "BREACH"
    assert snap25["inc-live:nis2"].breached is False


def test_board_snapshot_sorted_nearest_deadline_first():
    board = LiveClockBoard(T0)
    snaps = board.snapshot(T0 + timedelta(hours=1))
    deadlines = [s.deadline for s in snaps]
    assert deadlines == sorted(deadlines)
    # The 24h early-warning clock is the nearest deadline.
    assert snaps[0].correlation_id == "inc-live:nis2-early"


def test_board_reuses_clockengine_unchanged_business_day_math():
    # The SEC clock on the live board still uses the business-day engine: a t0 on
    # a Friday lands its 4-business-day deadline past the weekend, proving the live
    # board drives the real ClockEngine, not a cosmetic counter.
    friday = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    board = LiveClockBoard(friday)
    sec = next(c for c in board.clocks if c.correlation_id == "inc-live:sec")
    # 4 business days from Fri Jun 19 2026 (Juneteenth is a holiday Jun 19) skips
    # the weekend and the holiday; the deadline is well past 4 calendar days.
    assert (sec.deadline - friday) > timedelta(days=4)


def test_relative_stamp_renders_t_plus():
    t0 = datetime(2026, 6, 16, 0, 0, 0, tzinfo=timezone.utc)
    assert relative_stamp(t0 + timedelta(hours=2, minutes=30), t0) == "T+02:30:00"
    assert relative_stamp(t0 + timedelta(days=1, hours=1), t0) == "T+1d 01:00:00"
    assert relative_stamp(t0 - timedelta(minutes=5), t0) == "T-00:05:00"


def test_relative_stamp_handles_naive_inputs_as_utc():
    t0 = datetime(2026, 6, 16, 0, 0, 0)
    ev = datetime(2026, 6, 16, 1, 0, 0)
    assert relative_stamp(ev, t0) == "T+01:00:00"


# ---- the sealed-isolation guard (the load-bearing E7.1 invariant) ---------

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
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _run_sealed(tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                     draft_fns=_stub_draft_fns())


def test_building_and_ticking_the_live_board_does_not_touch_the_sealed_sha(tmp_path):
    # Build and tick a live board (the operator view) BETWEEN two sealed runs. The
    # live board owns its own ClockEngine, posts nothing, logs nothing; it must not
    # perturb the sealed run-log sha at all.
    before = _run_sealed(tmp_path / "a")
    board = LiveClockBoard(datetime.now(timezone.utc))
    for _ in range(3):
        board.snapshot(datetime.now(timezone.utc))
    after = _run_sealed(tmp_path / "b")
    assert (before["replay"]["original_sha256"]
            == after["replay"]["original_sha256"])
    assert before["replay"]["byte_identical"] is True
    assert after["replay"]["byte_identical"] is True


def test_live_board_does_not_change_the_committed_sealed_normal_sha(tmp_path):
    # The committed sealed normal capture's sha is the regulator record. A live run
    # is a separate operator view that never writes it; a fresh sealed run still
    # reproduces the committed sha while a live board exists alongside.
    _ = LiveClockBoard(datetime.now(timezone.utc))
    sealed = json.loads(
        (Path(__file__).resolve().parent.parent
         / "web" / "data" / "packet-normal.json").read_text(encoding="utf-8"))
    packet = _run_sealed(tmp_path)
    assert (packet["replay"]["original_sha256"]
            == sealed["replay"]["original_sha256"])
