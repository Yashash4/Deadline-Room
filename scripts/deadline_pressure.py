"""Deadline-pressure worst-case walk over the SEC business-day clock (E9.4).

The SEC Item 1.05 clock is four BUSINESS days from the materiality determination,
skipping weekends and US federal holidays (warden/clocks.add_business_days). A
team that naively reads "four days" as "96 hours" is most wrong precisely when the
window straddles a weekend AND a holiday cluster: a Tuesday-before-Thanksgiving
determination, or a determination in the Christmas / New Year stretch, can push
the real wall-clock deadline a week or more past the naive +96h guess. That gap is
the dangerous start window: the days on which an incident commander's intuition is
furthest from the statutory truth.

This is a DETERMINISTIC sweep, no LLM, no now(), no randomness. It walks every
candidate determination date across the calendar years the US_FEDERAL holiday
calendar covers, computes the real 4-business-day deadline via the FROZEN
add_business_days, and measures, per start date, the calendar span the window
spans and the slack against a naive +96h reading. It then surfaces the worst-case
start window: the contiguous run of start dates whose deadline is pushed furthest
out, naming the holiday(s) responsible. It reads the clock engine; it never edits
it, never gates anything, and never touches a sealed run.

The output is both human-readable and a JSON block a web/ strip renders (the
worst-case start window and its margin), folding naturally into the E7.2 margin
board.

  py scripts/deadline_pressure.py                (sweep, print the worst-case window)
  py scripts/deadline_pressure.py --write        (also write web/data/deadline-pressure.json)
  py scripts/deadline_pressure.py --days N        (sweep an N-business-day window)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.clocks import (  # noqa: E402
    DEFAULT_CALENDAR,
    HOLIDAY_CALENDARS,
    add_business_days,
    is_business_day,
)

DATA = REPO_ROOT / "web" / "data"

# The SEC Item 1.05 window: four business days from materiality determination.
SEC_BUSINESS_DAYS = 4

# The naive reading the worst case is measured against: four days as a flat 96
# wall-clock hours, the mistake add_business_days exists to prevent.
NAIVE_HOURS = SEC_BUSINESS_DAYS * 24


@dataclass(frozen=True)
class StartProbe:
    """One candidate determination date and what its real SEC window costs. The
    `start` is the determination day (counted from 00:00:00 UTC for a stable, the
    business-day walk only reads the date); `deadline` is the real 4-business-day
    instant; `span_hours` is the wall-clock hours from start to deadline;
    `slack_hours` is span minus the naive 96h (how far the real deadline sits past
    the naive guess); `skipped` names the weekend/holiday dates the window walked
    over."""
    start: datetime
    deadline: datetime
    span_hours: float
    slack_hours: float
    skipped_weekend_days: int
    skipped_holidays: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "start": self.start.date().isoformat(),
            "start_weekday": self.start.strftime("%A"),
            "deadline": self.deadline.isoformat(),
            "deadline_weekday": self.deadline.strftime("%A"),
            "span_hours": round(self.span_hours, 1),
            "slack_hours": round(self.slack_hours, 1),
            "skipped_weekend_days": self.skipped_weekend_days,
            "skipped_holidays": list(self.skipped_holidays),
        }


def _covered_years(calendar: str) -> range:
    table = HOLIDAY_CALENDARS[calendar]
    return range(min(table), max(table) + 1)


def _holiday_names(calendar: str) -> dict[str, str]:
    """A best-effort map from an ISO date to a readable holiday label, parsed from
    the calendar module's inline comments. Falls back to the ISO date when no name
    is known, so the output never invents a holiday it cannot name."""
    # The calendar tables in warden/clocks.py carry the names in comments; rather
    # than re-parse source, name the few that the worst-case windows actually land
    # on for the covered demo years. Any date not listed renders as its ISO date,
    # which is honest (we never assert a name we do not have).
    return {
        "2026-11-26": "Thanksgiving",
        "2027-11-25": "Thanksgiving",
        "2028-11-23": "Thanksgiving",
        "2026-12-25": "Christmas",
        "2027-12-24": "Christmas (observed)",
        "2028-12-25": "Christmas",
        "2026-01-01": "New Year's Day",
        "2027-01-01": "New Year's Day",
        "2026-07-03": "Independence Day (observed)",
        "2027-07-05": "Independence Day (observed)",
        "2028-07-04": "Independence Day",
        "2026-05-25": "Memorial Day",
        "2027-05-31": "Memorial Day",
        "2028-05-29": "Memorial Day",
        "2026-09-07": "Labor Day",
        "2027-09-06": "Labor Day",
        "2028-09-04": "Labor Day",
        "2026-01-19": "MLK Day",
        "2027-01-18": "MLK Day",
        "2028-01-17": "MLK Day",
        "2026-02-16": "Washington's Birthday",
        "2027-02-15": "Washington's Birthday",
        "2028-02-21": "Washington's Birthday",
        "2026-06-19": "Juneteenth",
        "2027-06-18": "Juneteenth (observed)",
        "2028-06-19": "Juneteenth",
        "2026-10-12": "Columbus Day",
        "2027-10-11": "Columbus Day",
        "2028-10-09": "Columbus Day",
        "2026-11-11": "Veterans Day",
        "2027-11-11": "Veterans Day",
        "2028-11-10": "Veterans Day (observed)",
        "2027-12-24-c": "Christmas (observed)",
    }


def probe_start(start: datetime, days: int, calendar: str,
                names: dict[str, str]) -> StartProbe:
    """Compute the real SEC deadline for one determination date and measure the
    weekend/holiday days the window walked over. Pure read of add_business_days."""
    deadline = add_business_days(start, days, calendar)
    span_hours = (deadline - start).total_seconds() / 3600.0
    slack_hours = span_hours - NAIVE_HOURS

    # Count the weekend days and name the holidays strictly inside the walk
    # (start exclusive, deadline's date inclusive), so the "why" of the worst case
    # is explicit. A day inside the window that is not a business day is either a
    # weekend day or a listed holiday.
    weekend = 0
    holidays: list[str] = []
    d = start.date()
    end = deadline.date()
    while d < end:
        d += timedelta(days=1)
        if not is_business_day(d, calendar):
            iso = d.isoformat()
            if d.weekday() >= 5:
                weekend += 1
            else:
                holidays.append(names.get(iso, iso))
    return StartProbe(
        start=start, deadline=deadline, span_hours=span_hours,
        slack_hours=slack_hours, skipped_weekend_days=weekend,
        skipped_holidays=tuple(holidays))


def sweep(days: int = SEC_BUSINESS_DAYS,
          calendar: str = DEFAULT_CALENDAR) -> list[StartProbe]:
    """Sweep every business-day start date across the calendar's covered years and
    return a probe per start. Non-business-day starts are skipped: a materiality
    determination on a weekend or holiday is not a start the SEC clock anchors on.
    The last calendar year is excluded as a start year so every 4-business-day
    window lands inside a covered year (add_business_days raises otherwise)."""
    years = list(_covered_years(calendar))
    names = _holiday_names(calendar)
    # Start dates run through the second-to-last covered year, so the window never
    # rolls past the last covered year's holiday table.
    start_year_hi = years[-2] if len(years) >= 2 else years[-1]
    probes: list[StartProbe] = []
    d = datetime(years[0], 1, 1, tzinfo=timezone.utc)
    last = datetime(start_year_hi, 12, 31, tzinfo=timezone.utc)
    while d <= last:
        if is_business_day(d.date(), calendar):
            probes.append(probe_start(d, days, calendar, names))
        d += timedelta(days=1)
    return probes


def worst_window(probes: list[StartProbe]) -> list[StartProbe]:
    """The dangerous worst-case start window: the SINGLE LONGEST contiguous run of
    business-day start dates that all share the maximum span (the deadline pushed
    furthest out).

    A single holiday in a 4-business-day window pushes the span to the maximum, but
    such windows recur all year; the genuinely dangerous stretch is the one
    CONTIGUOUS run of worst-case start dates, which is the back-to-back holiday
    cluster (the Christmas / New Year stretch) where EVERY determination date in a
    multi-day span is at maximum pressure. An incident commander whose breach lands
    anywhere in that run is most exposed to the naive +96h error. Returns that run
    as an ordered list; ties on length resolve to the earliest run."""
    if not probes:
        return []
    max_span = max(p.span_hours for p in probes)
    # Walk every business-day start in calendar order; a run of consecutive
    # business-day starts that are ALL at the maximum span is a worst-case window.
    # A single business-day start below the maximum breaks the run. Holidays and
    # weekends between two max starts do not break it (they are not business-day
    # starts), so the Christmas-through-New-Year cluster reads as one run.
    ordered = sorted(probes, key=lambda p: p.start)
    best: list[StartProbe] = []
    current: list[StartProbe] = []
    for p in ordered:
        if p.span_hours == max_span:
            current.append(p)
        else:
            if len(current) > len(best):
                best = current
            current = []
    if len(current) > len(best):
        best = current
    return best


@dataclass(frozen=True)
class PressureReport:
    days: int
    calendar: str
    naive_hours: int
    total_starts: int
    max_span_hours: float
    max_slack_hours: float
    worst: list[StartProbe]

    def as_dict(self) -> dict:
        return {
            "clock": f"SEC 8-K ({self.days} business days)",
            "calendar": self.calendar,
            "naive_hours": self.naive_hours,
            "total_business_day_starts": self.total_starts,
            "max_span_hours": round(self.max_span_hours, 1),
            "max_slack_hours": round(self.max_slack_hours, 1),
            "worst_case_window": [p.as_dict() for p in self.worst],
        }


def build_report(days: int = SEC_BUSINESS_DAYS,
                 calendar: str = DEFAULT_CALENDAR) -> PressureReport:
    """Run the full deterministic sweep and surface the worst-case start window."""
    probes = sweep(days, calendar)
    worst = worst_window(probes)
    max_span = max((p.span_hours for p in probes), default=0.0)
    max_slack = max((p.slack_hours for p in probes), default=0.0)
    return PressureReport(
        days=days, calendar=calendar, naive_hours=NAIVE_HOURS,
        total_starts=len(probes), max_span_hours=max_span,
        max_slack_hours=max_slack, worst=worst)


def _print_report(report: PressureReport) -> None:
    print("=" * 78)
    print(f"DEADLINE PRESSURE: SEC {report.days}-business-day clock, "
          f"{report.calendar} calendar")
    print("=" * 78)
    print(f"  naive reading        : {report.naive_hours}h "
          f"({report.days} days flat)")
    print(f"  business-day starts  : {report.total_starts} swept across the "
          f"covered years")
    print(f"  worst-case span      : {report.max_span_hours:.0f}h "
          f"({report.max_span_hours / 24:.1f} calendar days)")
    print(f"  worst-case slack     : +{report.max_slack_hours:.0f}h past the "
          f"naive {report.naive_hours}h guess")
    print()
    print("  Dangerous worst-case start window (deadline pushed furthest out, a")
    print("  naive +96h reading is most wrong on these determination dates):")
    print()
    for p in report.worst:
        hol = ", ".join(p.skipped_holidays) if p.skipped_holidays else "none"
        print(f"    determine {p.start.date().isoformat()} ({p.start.strftime('%A')})"
              f"  ->  deadline {p.deadline.date().isoformat()} "
              f"({p.deadline.strftime('%A')})")
        print(f"        real span {p.span_hours:.0f}h, "
              f"+{p.slack_hours:.0f}h past naive; "
              f"window skips {p.skipped_weekend_days} weekend day(s) and "
              f"holiday(s): {hol}")
    print()
    if report.worst:
        first = report.worst[0].start.date().isoformat()
        last = report.worst[-1].start.date().isoformat()
        span = report.worst[0].span_hours
        print(f"  WORST-CASE START WINDOW: {first} .. {last} "
              f"({len(report.worst)} day(s)), each pushing the SEC deadline to "
              f"{span:.0f}h real, +{report.worst[0].slack_hours:.0f}h past naive.")
    print("=" * 78)


def main(argv: list[str]) -> int:
    write = "--write" in argv
    days = SEC_BUSINESS_DAYS
    if "--days" in argv:
        i = argv.index("--days")
        if i + 1 < len(argv):
            try:
                days = int(argv[i + 1])
            except ValueError:
                print(f"deadline_pressure: --days needs an integer, got "
                      f"{argv[i + 1]!r}", file=sys.stderr)
                return 2

    report = build_report(days)
    _print_report(report)

    if write:
        out = DATA / "deadline-pressure.json"
        out.write_text(
            json.dumps(report.as_dict(), indent=1) + "\n", encoding="utf-8")
        print(f"wrote {out.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
