"""Live Mode (E7.1 + E7.4): the same incident's statutory clocks driven against
real wall-clock time, as the OPERATOR view, strictly separate from the sealed
regulator record.

The sealed run is the regulator's artifact: it is anchored on fixed demo
timestamps, hashed, signed, and replayed byte-identically, and `datetime.now()`
NEVER enters it. This module is the other face: a `LiveClockBoard` built from the
SAME regime catalog and the SAME warden.clocks.ClockEngine, but anchored at a
caller-supplied wall-clock `t0`, so a deadline genuinely counts down, crosses a
warn/critical threshold, and breaches in real time on the operator's screen.

Nothing here writes a run-log, signs a capture, or feeds the verify block. The
board snapshots {name, deadline, remaining(now), breached(now), warn, tier,
margin_seconds} for the live UI and the live escalation beat; the sealed shas and
byte-identical replay are untouched because this code path never touches the
hashed log. The board reuses warden.clocks.ClockEngine UNCHANGED (same
start_hours / start_sec_business_days call sites the sealed floor uses), so the
live clocks are the real statutory clocks, only anchored at a live instant.

`relative_stamp(event_ts, t0)` renders a war-room "T+HH:MM:SS since incident
start" label for the live feed and the --live console (E7.4).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from floor import regimes
from floor.margin import MarginThresholds, classify
from warden.clocks import Clock, ClockEngine


def relative_stamp(event_ts: datetime, t0: datetime) -> str:
    """A war-room relative stamp: "T+HH:MM:SS" (or "T+Nd HH:MM:SS") of elapsed
    wall-clock time since the incident start `t0`. An event before t0 renders with
    a leading minus ("T-..."), so a clock anchored slightly in the past still reads
    honestly. Pure render helper; reads no now() of its own."""
    if event_ts.tzinfo is None:
        event_ts = event_ts.replace(tzinfo=timezone.utc)
    if t0.tzinfo is None:
        t0 = t0.replace(tzinfo=timezone.utc)
    seconds = (event_ts - t0).total_seconds()
    sign = "-" if seconds < 0 else "+"
    s = int(abs(seconds))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    hms = f"{h:02d}:{m:02d}:{s:02d}"
    body = f"{d}d {hms}" if d > 0 else hms
    return f"T{sign}{body}"


@dataclass(frozen=True)
class LiveClockSnapshot:
    """One live clock at one wall-clock instant. Everything is derived from the
    ClockEngine's deterministic Clock math evaluated at the live `now`: this is
    the operator view, never the sealed record."""
    name: str
    correlation_id: str
    deadline: str
    remaining: str
    remaining_seconds: float
    breached: bool
    warn: bool
    tier: str
    margin_seconds: float
    branch: str
    drafter_role: str


class LiveClockBoard:
    """The live statutory-clock board for the operator view (E7.1).

    Built from the regime catalog via the existing clock-start path on a fresh
    ClockEngine, anchored at a caller-supplied wall-clock `t0`. Each startup regime
    that declares live-mode margin thresholds is started here exactly the way the
    sealed floor starts it (start_hours / start_sec_business_days), only against
    the live anchor instead of the fixed demo timestamps. `snapshot(now)` returns
    the per-clock tiered state for the UI and the escalation beat, sorted by
    nearest deadline first.

    This object is the OPERATOR clock set. It owns its own ClockEngine, posts
    nothing, logs nothing, and is never hashed or signed. So building it and
    ticking it cannot move a sealed sha or break replay."""

    def __init__(self, t0: datetime,
                 catalog: list[regimes.RegimeSpec] | None = None,
                 incident_id: str = "inc-live") -> None:
        if t0.tzinfo is None:
            t0 = t0.replace(tzinfo=timezone.utc)
        self.t0 = t0
        self.incident_id = incident_id
        self._engine = ClockEngine()
        self._thresholds: dict[str, MarginThresholds] = {}
        self._meta: dict[str, tuple[str, str]] = {}
        specs = catalog if catalog is not None else regimes.load_catalog()
        t0_ts = t0.isoformat()
        for spec in regimes.startup_regimes(specs):
            # Only startup regimes that declare live-mode margin thresholds drive
            # the live board: a startup regime with no warn/critical configured is
            # not part of the live tiered signal and is skipped rather than guessed.
            if (spec.clock.warn_margin_seconds is None
                    or spec.clock.critical_margin_seconds is None):
                continue
            corr = f"{incident_id}:{spec.branch}"
            # The SAME clock-start call sites the sealed floor uses, only anchored
            # at the live wall-clock t0. warden.clocks.ClockEngine is unchanged.
            if spec.clock.business_days:
                self._engine.start_sec_business_days(
                    corr, t0_ts, days=spec.clock.length,
                    trigger_event=spec.trigger_event,
                    calendar=spec.clock.holiday_calendar,
                    display_tz=spec.clock.display_timezone)
            else:
                self._engine.start_hours(
                    spec.clock.name, corr, t0_ts, spec.clock.length,
                    trigger_event=spec.trigger_event,
                    display_tz=spec.clock.display_timezone)
            self._thresholds[corr] = MarginThresholds(
                warn_seconds=spec.clock.warn_margin_seconds,
                critical_seconds=spec.clock.critical_margin_seconds)
            self._meta[corr] = (spec.branch, spec.regime_label)

    @property
    def clocks(self) -> list[Clock]:
        return self._engine.all()

    def thresholds_for(self, correlation_id: str) -> MarginThresholds:
        return self._thresholds[correlation_id]

    def snapshot(self, now: datetime) -> list[LiveClockSnapshot]:
        """The per-clock tiered state at wall-clock instant `now`, sorted nearest
        deadline first. Pure read over the ClockEngine math and the margin
        classifier; the caller supplies `now` (the live tick), so the same `now`
        always yields the same board."""
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        out: list[LiveClockSnapshot] = []
        for c in self._engine.all():
            thresholds = self._thresholds[c.correlation_id]
            cls = classify(c, now, thresholds)
            branch, regime_label = self._meta[c.correlation_id]
            remaining = c.remaining(now)
            out.append(LiveClockSnapshot(
                name=c.name,
                correlation_id=c.correlation_id,
                deadline=c.deadline.isoformat(),
                remaining=cls.remaining,
                remaining_seconds=round(remaining.total_seconds(), 3),
                breached=cls.tier == "BREACH",
                warn=cls.tier in ("WARN", "CRITICAL"),
                tier=cls.tier,
                margin_seconds=cls.margin_seconds,
                branch=branch,
                drafter_role=regime_label,
            ))
        out.sort(key=lambda s: s.deadline)
        return out
