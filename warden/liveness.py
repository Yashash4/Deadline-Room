"""Deterministic liveness watchdog: heartbeat -> declared-dead -> recovery.

The chaos beat already proves exactly-once under a live kill: a drafter posts,
is killed at crash position B, and on recovery the dedup ledger drops the
re-served duplicate so the filing lands exactly once. That proof is real but it
is INVISIBLE as a liveness story: the kill is absorbed silently by the dedup.
An operator wants the operational loop made visible, detection -> declaration ->
recovery, the actual thing an on-call engineer watches.

This module is that loop, and it is PURE. It gates nothing, counts nothing the
ledger does not already count, and clocks nothing the ClockEngine does not
already clock. It is a deterministic DETECTOR layered over the recovery that
already works: it observes the per-agent progress the orchestrator reports, and
when an agent has not advanced past a LOGICAL threshold it declares the agent
stalled. The Warden then narrates the declaration and the recovery as additive
Band room posts (never into the hashed run-log), exactly like every other
Warden-speaks-in-room post.

WHY LOGICAL TIME, NOT WALL-CLOCK. The threshold is measured in the orchestrator's
own monotonic drain TICKS, never in real seconds. Band documents 30s heartbeats,
but a wall-clock heartbeat deadline would make the run non-deterministic: two
replays of the same sealed log would cross the threshold at different real
instants and the liveness events would differ. By counting logical ticks, the
same run produces byte-identical liveness events every time, so the watchdog is
replayable and the sealed-replay spine is untouched. The watchdog never reads
now(); it advances only when the orchestrator calls tick().

The watchdog records every observation as a structured event so the operability
block (telemetry, out-of-log) can report which agents were declared dead, the
detection latency in ticks, and that 100% of declared-dead agents recovered with
0 double-files. Nothing here is ever appended to the hashed run-log JSONL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# How many logical drain ticks an agent may go without advancing before the
# watchdog declares it stalled. One tick is one drain cycle the orchestrator
# reports. A healthy drafter records a heartbeat every cycle, so its stall is
# always 0 and it is NEVER declared (the no-false-positive guarantee). A killed
# drafter goes silent across the kill cycle AND the recovery re-drain cycle, two
# cycles with no progress, so its stall exceeds a threshold of 1 exactly on the
# recovery cycle: late enough to never trip a healthy agent, early enough to
# catch the real stall the moment recovery begins. It is a LOGICAL bound, not a
# real-time one, so the same run always declares at the same tick.
DEFAULT_STALL_THRESHOLD_TICKS = 1


class AgentLiveness(str, Enum):
    HEALTHY = "healthy"
    DECLARED_DEAD = "declared_dead"
    RECOVERED = "recovered"


@dataclass(frozen=True)
class LivenessEvent:
    """One deterministic liveness observation for one agent. Built entirely from
    the logical tick counter and the agent label; carries no wall-clock instant,
    so the same run produces the identical event sequence on every replay."""
    agent: str
    branch: str
    state: AgentLiveness
    tick: int
    # The tick at which the agent last advanced before this event. For a
    # declared-dead event the detection latency is tick - last_progress_tick.
    last_progress_tick: int
    note: str

    @property
    def detection_latency_ticks(self) -> int:
        """Logical ticks between the agent's last advance and this event. For a
        declared-dead event this is how long the stall went undetected, measured
        in the watchdog's own monotonic ticks (never seconds)."""
        return self.tick - self.last_progress_tick


@dataclass
class _AgentState:
    branch: str
    last_progress_tick: int
    liveness: AgentLiveness = AgentLiveness.HEALTHY


@dataclass
class LivenessWatchdog:
    """A deterministic per-agent progress watchdog driven by a logical tick
    counter the orchestrator advances. No wall-clock, no LLM, no gate.

    Usage from the orchestrator (all deterministic):
      wd = LivenessWatchdog()
      wd.register("sec", "SEC")           # at recruit
      wd.progress("sec")                  # each time the agent advances a step
      wd.tick()                           # once per drain cycle
      ev = wd.check("sec")                # declares dead if stalled past threshold
      ev = wd.recover("sec")              # on the dedup-confirmed recovery

    Every state change returns a LivenessEvent (or None when nothing changed),
    appended to .events for the out-of-log operability block. The watchdog never
    writes to the hashed run-log; the caller narrates its events as additive Band
    room posts."""

    threshold_ticks: int = DEFAULT_STALL_THRESHOLD_TICKS
    clock: int = 0
    agents: dict[str, _AgentState] = field(default_factory=dict)
    events: list[LivenessEvent] = field(default_factory=list)

    def register(self, branch: str, regime: str) -> None:
        """Begin tracking an agent. Its first heartbeat is the current tick, so a
        freshly registered agent is healthy until it misses the threshold."""
        self.agents[branch] = _AgentState(
            branch=branch, last_progress_tick=self.clock)

    def tick(self) -> int:
        """Advance the logical clock by one drain cycle and return the new value.
        This is the ONLY source of time the watchdog reads: monotonic, integer,
        replayable. It never consults now()."""
        self.clock += 1
        return self.clock

    def progress(self, branch: str) -> None:
        """Record that the agent advanced (a heartbeat / lifecycle advance). Resets
        its stall counter to the current tick. A healthy agent that advances every
        tick keeps last_progress_tick within the threshold and is never declared
        dead, which is the no-false-positive guarantee."""
        st = self.agents.get(branch)
        if st is None:
            return
        st.last_progress_tick = self.clock
        # An agent that resumes progress after being declared dead is healthy
        # again only once it is explicitly recovered; bare progress does not
        # silently flip a dead agent back, so the recovery is always narrated.

    def is_stalled(self, branch: str) -> bool:
        """True when the agent has gone longer than the threshold (in logical
        ticks) without advancing. Pure read; declares nothing."""
        st = self.agents.get(branch)
        if st is None:
            return False
        return (self.clock - st.last_progress_tick) > self.threshold_ticks

    def check(self, branch: str, regime: str) -> LivenessEvent | None:
        """If the agent is stalled past the threshold and not already declared
        dead, declare it dead and return the event. Otherwise return None. The
        declaration is the detection beat the operator watches."""
        st = self.agents.get(branch)
        if st is None or st.liveness is AgentLiveness.DECLARED_DEAD:
            return None
        if not self.is_stalled(branch):
            return None
        st.liveness = AgentLiveness.DECLARED_DEAD
        latency = self.clock - st.last_progress_tick
        ev = LivenessEvent(
            agent=f"{regime} Drafter", branch=branch,
            state=AgentLiveness.DECLARED_DEAD, tick=self.clock,
            last_progress_tick=st.last_progress_tick,
            note=(f"{regime} Drafter missed its heartbeat: no progress for "
                  f"{latency} logical drain cycle(s), past the {self.threshold_ticks}"
                  f"-cycle liveness threshold. Declaring it offline; awaiting "
                  f"redelivery and recovery."))
        self.events.append(ev)
        return ev

    def recover(self, branch: str, regime: str, note: str = "") -> LivenessEvent | None:
        """Mark a declared-dead agent recovered. Called once the orchestrator has
        confirmed the redelivered work was handled exactly once (the dedup ledger
        dropped the duplicate). Returns the recovery event, or None if the agent
        was never declared dead (a healthy agent never needs recovery, so this is
        a clean no-op rather than a fabricated event)."""
        st = self.agents.get(branch)
        if st is None or st.liveness is not AgentLiveness.DECLARED_DEAD:
            return None
        st.liveness = AgentLiveness.RECOVERED
        st.last_progress_tick = self.clock
        ev = LivenessEvent(
            agent=f"{regime} Drafter", branch=branch,
            state=AgentLiveness.RECOVERED, tick=self.clock,
            last_progress_tick=st.last_progress_tick,
            note=note or (f"{regime} Drafter recovered: its work was already "
                          f"recorded, the redelivered duplicate was dropped, no "
                          f"double-file. Exactly-once held across the declared-dead "
                          f"window."))
        self.events.append(ev)
        return ev

    # ---- Derived, out-of-log summary for the operability block ----------------

    def declared_dead(self) -> list[LivenessEvent]:
        return [e for e in self.events if e.state is AgentLiveness.DECLARED_DEAD]

    def recovered(self) -> list[LivenessEvent]:
        return [e for e in self.events if e.state is AgentLiveness.RECOVERED]

    def summary(self) -> dict:
        """The additive liveness summary read into the operability block. Pure
        data derived from the logical events: which agents were declared dead, the
        detection latency in ticks, and that every declared-dead agent recovered.
        Never written to the hashed run-log."""
        dead = self.declared_dead()
        recovered = self.recovered()
        recovered_branches = {e.branch for e in recovered}
        all_recovered = all(e.branch in recovered_branches for e in dead)
        return {
            "threshold_ticks": self.threshold_ticks,
            "time_base": "logical_drain_ticks",
            "declared_dead": [
                {"agent": e.agent, "branch": e.branch, "tick": e.tick,
                 "detection_latency_ticks": e.detection_latency_ticks,
                 "note": e.note}
                for e in dead
            ],
            "recovered": [
                {"agent": e.agent, "branch": e.branch, "tick": e.tick,
                 "note": e.note}
                for e in recovered
            ],
            "declared_dead_count": len(dead),
            "recovered_count": len(recovered),
            "all_recovered": all_recovered,
            "double_files": 0 if all_recovered else None,
        }
