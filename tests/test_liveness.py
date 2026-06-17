"""Unit tests for the deterministic liveness watchdog (warden/liveness.py).

The watchdog is the heartbeat -> declared-dead -> recovery detector. These tests
pin its three load-bearing properties in isolation, before the full-floor wiring
tests exercise it end to end:

  1. A stalled agent past the LOGICAL threshold is declared dead, and the
     declaration is deterministic (same tick sequence -> same declaration).
  2. The threshold is logical (counted in ticks the caller advances), never
     wall-clock: the watchdog never reads now(), so two identical tick sequences
     declare at the identical tick.
  3. No false positive: a healthy agent that records a heartbeat every tick is
     never declared dead, no matter how long the run goes.
"""

from warden.liveness import (
    DEFAULT_STALL_THRESHOLD_TICKS, AgentLiveness, LivenessWatchdog)


def test_stalled_agent_declared_dead_past_threshold():
    wd = LivenessWatchdog(threshold_ticks=2)
    wd.register("sec", "SEC")
    wd.progress("sec")          # heartbeat at tick 0
    # Go silent: tick past the threshold without any further heartbeat.
    wd.tick()                   # tick 1: stall 1, within threshold
    assert wd.check("sec", "SEC") is None
    wd.tick()                   # tick 2: stall 2, within threshold (not > 2)
    assert wd.check("sec", "SEC") is None
    wd.tick()                   # tick 3: stall 3 > threshold 2 -> declared dead
    ev = wd.check("sec", "SEC")
    assert ev is not None
    assert ev.state is AgentLiveness.DECLARED_DEAD
    assert ev.branch == "sec"
    assert ev.detection_latency_ticks == 3
    # A second check does not re-declare an already-dead agent.
    assert wd.check("sec", "SEC") is None
    assert len(wd.declared_dead()) == 1


def test_declaration_is_logical_not_wallclock():
    # Two watchdogs driven by the IDENTICAL tick sequence declare at the identical
    # tick. The watchdog reads no now(); only the caller's ticks move it. Run them
    # with a real-time gap between the calls and confirm the declaration tick is
    # the same, proving the threshold is logical, not wall-clock.
    import time

    def drive():
        wd = LivenessWatchdog(threshold_ticks=2)
        wd.register("nis2", "NIS2")
        wd.progress("nis2")
        declared_at = None
        for _ in range(5):
            wd.tick()
            ev = wd.check("nis2", "NIS2")
            if ev is not None and declared_at is None:
                declared_at = ev.tick
        return declared_at

    first = drive()
    time.sleep(0.05)  # real wall-clock time passes between the two runs
    second = drive()
    assert first == second == 3  # declared on the same LOGICAL tick both times


def test_healthy_agent_never_declared_dead():
    # A heartbeat every tick keeps the stall counter at zero, so the agent is
    # never declared dead however long the run runs. No false positive.
    wd = LivenessWatchdog(threshold_ticks=DEFAULT_STALL_THRESHOLD_TICKS)
    wd.register("dora", "DORA")
    for _ in range(50):
        wd.tick()
        wd.progress("dora")     # advances every cycle
        assert wd.check("dora", "DORA") is None
    assert wd.declared_dead() == []
    assert not wd.is_stalled("dora")


def test_recover_only_after_declared_dead():
    wd = LivenessWatchdog(threshold_ticks=1)
    wd.register("sec", "SEC")
    wd.progress("sec")
    # recover on a healthy agent is a clean no-op (no fabricated event).
    assert wd.recover("sec", "SEC") is None
    assert wd.recovered() == []
    # Stall it past the threshold and declare dead, then recover.
    wd.tick()
    wd.tick()
    assert wd.check("sec", "SEC") is not None
    ev = wd.recover("sec", "SEC")
    assert ev is not None
    assert ev.state is AgentLiveness.RECOVERED
    assert len(wd.recovered()) == 1


def test_summary_reports_all_recovered_zero_double_files():
    wd = LivenessWatchdog(threshold_ticks=1)
    wd.register("sec", "SEC")
    wd.progress("sec")
    wd.tick()
    wd.tick()
    wd.check("sec", "SEC")
    wd.recover("sec", "SEC")
    s = wd.summary()
    assert s["time_base"] == "logical_drain_ticks"
    assert s["declared_dead_count"] == 1
    assert s["recovered_count"] == 1
    assert s["all_recovered"] is True
    assert s["double_files"] == 0
    assert s["declared_dead"][0]["branch"] == "sec"
    assert s["declared_dead"][0]["detection_latency_ticks"] >= 1


def test_unrecovered_dead_agent_breaks_all_recovered():
    wd = LivenessWatchdog(threshold_ticks=1)
    wd.register("sec", "SEC")
    wd.progress("sec")
    wd.tick()
    wd.tick()
    wd.check("sec", "SEC")      # declared dead, never recovered
    s = wd.summary()
    assert s["all_recovered"] is False
    assert s["double_files"] is None
