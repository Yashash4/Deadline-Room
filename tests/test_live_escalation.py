"""test_live_escalation.py -- Escalation-on-approach Warden post (E7.3).

In the --live path ONLY, when a statutory clock crosses a warn/critical/breach
tier the Warden posts a deterministic escalation into the Band room @mentioning the
responsible drafter. These tests drive the live board with an injected, fully
deterministic wall clock (no real sleeping, no real now()), assert the room
contains the WARN and BREACH posts, and pin the load-bearing invariant: the live
escalation is out-of-log, so the sealed sha and byte-identical replay are unchanged.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom

T0 = datetime(2026, 6, 16, 2, 14, 0, tzinfo=timezone.utc)


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


def _deterministic_now_fn(board_instants):
    """A wall-clock now_fn that, at compression == 1.0, walks the board through the
    given instants (the first is the wall-start). Returns a fresh iterator-backed
    function each call. The last instant repeats so the loop's final budget check
    always has a value."""
    # The loop reads now_fn() multiple times per tick (start, board eval, budget
    # check). To keep the board instants exact we map them onto wall instants and
    # let the loop's elapsed = wall_now - wall_start drive board_now at compression
    # 1.0. We pass wall instants that equal the desired board instants offset from
    # the first.
    # The loop reads now_fn() exactly once per iteration (it reuses that reading for
    # the budget check). We return one board instant per call; when the sequence is
    # exhausted we clamp at the last instant, and the loop's stall guard (wall not
    # advancing) then terminates it.
    seq = list(board_instants)
    it = iter(seq)
    last = [seq[-1]]

    def now_fn():
        try:
            last[0] = next(it)
        except StopIteration:
            pass
        return last[0]
    return now_fn


def _run_live(tmp_path, board_instants, duration_s=10_000_000):
    room, clients = _build_clients()
    packet = run_floor(
        out_dir=str(tmp_path), mode="normal", clients=clients,
        draft_fns=_stub_draft_fns(), live_mode=True, live_t0=T0,
        live_duration_s=duration_s, live_tick_s=0, live_compression=1.0,
        live_now_fn=_deterministic_now_fn(board_instants))
    return room, packet


def test_room_contains_warn_critical_and_breach_posts(tmp_path):
    # Walk the nearest clock (24h NIS2-early; warn 6h, critical 1h) through every
    # band: 18h in (6h left, WARN), 23h30m in (30m left, CRITICAL), 25h in (BREACH).
    instants = [
        T0,                              # wall-start (board t0, all GREEN)
        T0 + timedelta(hours=18),        # 6h left -> WARN
        T0 + timedelta(hours=23, minutes=30),  # 30m left -> CRITICAL
        T0 + timedelta(hours=25),        # past deadline -> BREACH
    ]
    room, packet = _run_live(tmp_path, instants)
    contents = [m["content"] for m in room.messages]
    assert sum("WARN margin" in c for c in contents) == 1
    assert sum("CRITICAL margin" in c for c in contents) == 1
    assert sum("DEADLINE BREACHED" in c for c in contents) == 1
    tiers = [e["tier"] for e in packet["live"]["escalations"]
             if e["correlation_id"] == "inc-live:nis2-early"]
    assert tiers == ["WARN", "CRITICAL", "BREACH"]


def test_escalation_mentions_the_responsible_drafter(tmp_path):
    # The NIS2 early-warning clock is owned by the NIS2 drafter; the WARN post must
    # @mention the NIS2 drafter id (never the Warden itself).
    instants = [T0, T0 + timedelta(hours=18)]
    room, _ = _run_live(tmp_path, instants)
    warn = next(m for m in room.messages if "WARN margin" in m["content"])
    assert "nis2-id" in (warn.get("mentions") or [])
    assert "warden-id" not in (warn.get("mentions") or [])


def test_escalation_is_zero_llm_deterministic_template(tmp_path):
    # The escalation text is built purely from the classification; running the same
    # live walk twice yields the identical posts (no model, no randomness).
    instants = [T0, T0 + timedelta(hours=18), T0 + timedelta(hours=25)]
    room_a, _ = _run_live(tmp_path / "a", instants)
    room_b, _ = _run_live(tmp_path / "b", instants)
    a = [m["content"] for m in room_a.messages if "margin on" in m["content"]
         or "BREACHED" in m["content"]]
    b = [m["content"] for m in room_b.messages if "margin on" in m["content"]
         or "BREACHED" in m["content"]]
    assert a == b
    assert a, "expected at least one escalation post"


def test_live_escalation_does_not_change_sealed_sha_or_replay(tmp_path):
    # The load-bearing E7.3 invariant: the live escalation phase is out-of-log. A
    # live run's sealed sha equals the committed sealed normal sha, and replay stays
    # byte-identical.
    sealed = json.loads(
        (Path(__file__).resolve().parent.parent
         / "web" / "data" / "packet-normal.json").read_text(encoding="utf-8"))
    instants = [T0, T0 + timedelta(hours=18), T0 + timedelta(hours=25)]
    _, packet = _run_live(tmp_path, instants)
    assert (packet["replay"]["original_sha256"]
            == sealed["replay"]["original_sha256"])
    assert packet["replay"]["byte_identical"] is True
    # And the live block honestly records the frozen sealed sha.
    assert packet["live"]["sealed_sha256"] == sealed["replay"]["original_sha256"]


def test_no_live_block_when_live_mode_off(tmp_path):
    # Without --live, no live phase runs and the packet carries no live block, so
    # the default sealed path is exactly as before.
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns())
    assert "live" not in packet
    contents = [m["content"] for m in room.messages]
    assert not any("WARN margin" in c or "DEADLINE BREACHED" in c for c in contents)
