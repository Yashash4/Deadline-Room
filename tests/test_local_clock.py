"""test_local_clock.py (E3.3): local-time + local-public-holiday deadline math.

The clock engine generalizes from a single US-federal holiday set into a NAMED
holiday-calendar registry (US_FEDERAL, UK_BANK, DE_FEDERAL, EU_TARGET), and a
deadline can be RENDERED in the regulator's local IANA wall-clock while the stored
and compared value stays a UTC instant.

The load-bearing constraint pinned here: the existing US/SEC path is BYTE-IDENTICAL
to before this registry existed. The SEC 4-business-day count still lands
2026-06-23, the default-calendar answer equals the explicit US_FEDERAL answer, and
the year-coverage guard still fires beyond coverage. Only the local-wall-clock
RENDERING is additive (render-time, never in the hashed log).
"""

from datetime import datetime, timezone

import pytest

from warden.clocks import (
    DEFAULT_CALENDAR,
    HOLIDAY_CALENDARS,
    Clock,
    ClockEngine,
    HolidayYearNotCovered,
    UnknownHolidayCalendar,
    UnknownTimezone,
    add_business_days,
    is_business_day,
    parse_ts,
    render_local,
)


# --- the SEC / US path must stay byte-identical ------------------------------

def test_sec_path_is_byte_identical_lands_june_23():
    # The single most important pin: the default calendar is US_FEDERAL, so the
    # SEC 4-business-day count from the 2026-06-16 determination still lands
    # exactly 2026-06-23 (Wed 17, Thu 18, Fri 19 Juneteenth skipped, weekend
    # skipped, Mon 22, Tue 23), end of day in UTC.
    d = add_business_days(parse_ts("2026-06-16T02:14:00+00:00"), 4)
    assert d == datetime(2026, 6, 23, 23, 59, 59, tzinfo=timezone.utc)
    assert d.date().isoformat() == "2026-06-23"


def test_default_calendar_equals_explicit_us_federal():
    # Passing US_FEDERAL explicitly must produce the identical instant the default
    # (no-calendar) call produces, across a range of starts, so the refactor moves
    # no existing computed value.
    for start in ("2026-06-16T02:14:00+00:00", "2026-12-30T12:00:00+00:00",
                  "2027-07-01T09:00:00+00:00"):
        s = parse_ts(start)
        assert add_business_days(s, 4) == add_business_days(s, 4, "US_FEDERAL")
    assert DEFAULT_CALENDAR == "US_FEDERAL"


def test_engine_sec_clock_still_lands_june_23_with_us_federal_default():
    eng = ClockEngine()
    c = eng.start_sec_business_days("inc-1:sec", "2026-06-16T02:31:00+00:00")
    assert c.deadline.date().isoformat() == "2026-06-23"
    assert c.holiday_calendar == "US_FEDERAL"


# --- a non-US business-day count skips the LOCAL holidays, not US ones --------

def test_uk_count_skips_a_uk_bank_holiday_not_a_us_one():
    # Early May bank holiday 2026 is Monday 2026-05-04, a UK bank holiday that is
    # NOT a US federal holiday. A UK business-day count starting Friday 2026-05-01
    # must skip it: Fri 1 is the start day; Mon 4 (bank holiday, SKIPPED), Tue 5
    # (1), Wed 6 (2), Thu 7 (3). The same count under US_FEDERAL would NOT skip
    # May 4 (it is a normal US business day), landing a day earlier.
    start = parse_ts("2026-05-01T09:00:00+00:00")
    assert not is_business_day(datetime(2026, 5, 4).date(), "UK_BANK")
    assert is_business_day(datetime(2026, 5, 4).date(), "US_FEDERAL")
    uk = add_business_days(start, 3, "UK_BANK")
    us = add_business_days(start, 3, "US_FEDERAL")
    assert uk.date().isoformat() == "2026-05-07"
    assert us.date().isoformat() == "2026-05-06"
    assert uk != us  # the local calendar genuinely moves the deadline


def test_german_count_skips_german_unity_day_not_a_us_one():
    # German Unity Day 2026 is observed Monday 2026-10-05 (Oct 3 is a Saturday). It
    # is a German federal holiday and NOT a US federal holiday. A German
    # business-day count starting Friday 2026-10-02 must skip it: Mon 5 (German
    # Unity, SKIPPED), Tue 6 (1), Wed 7 (2), Thu 8 (3). Under US_FEDERAL Oct 5 is a
    # normal business day, so the US count lands a day earlier.
    start = parse_ts("2026-10-02T09:00:00+00:00")
    assert not is_business_day(datetime(2026, 10, 5).date(), "DE_FEDERAL")
    assert is_business_day(datetime(2026, 10, 5).date(), "US_FEDERAL")
    de = add_business_days(start, 3, "DE_FEDERAL")
    us = add_business_days(start, 3, "US_FEDERAL")
    assert de.date().isoformat() == "2026-10-08"
    assert us.date().isoformat() == "2026-10-07"


def test_eu_target_calendar_skips_a_pan_eu_holiday():
    # Easter Monday 2026 is 2026-04-06, in the EU_TARGET working-day set but not in
    # US_FEDERAL. An EU count starting Thursday 2026-04-02 must skip both Good
    # Friday (Apr 3) and Easter Monday (Apr 6): Fri 3 (Good Friday, SKIPPED),
    # weekend, Mon 6 (Easter Monday, SKIPPED), Tue 7 (1), Wed 8 (2).
    start = parse_ts("2026-04-02T09:00:00+00:00")
    assert not is_business_day(datetime(2026, 4, 6).date(), "EU_TARGET")
    assert is_business_day(datetime(2026, 4, 6).date(), "US_FEDERAL")
    eu = add_business_days(start, 2, "EU_TARGET")
    assert eu.date().isoformat() == "2026-04-08"


def test_brazil_count_skips_a_brazilian_national_holiday():
    # The Brazil LGPD 3-business-day clock (Regulation CD/ANPD 15/2024) counts
    # against BR_FEDERAL. Independencia do Brasil is Monday 2026-09-07, a Brazilian
    # national holiday and NOT a US federal one. A Brazilian count starting Friday
    # 2026-09-04 must skip it: weekend, Mon 7 (Independence, SKIPPED), Tue 8 (1),
    # Wed 9 (2), Thu 10 (3). Under US_FEDERAL Sep 7 2026 is Labor Day (also a
    # holiday), so for an honest contrast we use a Brazil-only holiday: Tiradentes,
    # Tuesday 2026-04-21, which BR_FEDERAL skips and US_FEDERAL does not.
    assert not is_business_day(datetime(2026, 4, 21).date(), "BR_FEDERAL")
    assert is_business_day(datetime(2026, 4, 21).date(), "US_FEDERAL")
    # Count 3 business days from Friday 2026-04-17: weekend, Mon 20 (1), Tue 21
    # (Tiradentes, SKIPPED), Wed 22 (2), Thu 23 (3).
    start = parse_ts("2026-04-17T09:00:00+00:00")
    br = add_business_days(start, 3, "BR_FEDERAL")
    us = add_business_days(start, 3, "US_FEDERAL")
    assert br.date().isoformat() == "2026-04-23"
    assert us.date().isoformat() == "2026-04-22"
    assert br != us  # the Brazilian holiday genuinely moves the deadline


# --- a deadline renders in the regulator's local zone; the instant is UTC ------

def test_render_local_shows_regulator_wall_clock_without_changing_the_instant():
    # The SEC deadline instant is 2026-06-23 23:59:59 UTC. Rendered in
    # America/New_York it reads as the same instant in EDT (UTC-4), 19:59:59.
    instant = datetime(2026, 6, 23, 23, 59, 59, tzinfo=timezone.utc)
    rendered = render_local(instant, "America/New_York")
    assert "2026-06-23 19:59:59 EDT" in rendered
    assert "America/New_York" in rendered
    # The stored instant is untouched: render_local is a pure read.
    assert instant == datetime(2026, 6, 23, 23, 59, 59, tzinfo=timezone.utc)


def test_same_utc_instant_reads_different_local_in_berlin_vs_london():
    # The defining cross-border nuance: one stored UTC instant is a different local
    # wall-clock in two zones. 2026-06-18 22:00:00 UTC is 00:00 next day in
    # Brussels/Berlin (CEST, UTC+2) but 23:00 same day in London (BST, UTC+1).
    instant = datetime(2026, 6, 18, 22, 0, 0, tzinfo=timezone.utc)
    berlin = render_local(instant, "Europe/Berlin")
    london = render_local(instant, "Europe/London")
    assert berlin != london
    assert "2026-06-19 00:00:00 CEST" in berlin
    assert "2026-06-18 23:00:00 BST" in london


def test_clock_local_deadline_is_render_only_and_canonical_stays_utc():
    # The Clock carries a display zone (render-only). local_deadline() derives the
    # local face from the SAME UTC deadline; the canonical deadline is unchanged.
    eng = ClockEngine()
    c = eng.start_sec_business_days(
        "inc-1:sec", "2026-06-16T02:31:00+00:00",
        display_tz="America/New_York")
    assert c.deadline == datetime(2026, 6, 23, 23, 59, 59, tzinfo=timezone.utc)
    assert "EDT (America/New_York)" in c.local_deadline()
    # A clock with no display zone renders no local face.
    plain = Clock("x", "c", c.started_at, c.deadline)
    assert plain.local_deadline() == ""


def test_start_hours_carries_display_tz_for_local_rendering():
    # A calendar-hour clock (NIS2/DORA/ICO) computes the UTC instant unchanged but
    # gains a local face from its display zone.
    eng = ClockEngine()
    c = eng.start_hours("NIS2 full (72h)", "inc-1:nis2",
                        "2026-06-16T02:14:00+00:00", 72,
                        display_tz="Europe/Brussels")
    assert c.deadline == datetime(2026, 6, 19, 2, 14, 0, tzinfo=timezone.utc)
    assert "Europe/Brussels" in c.local_deadline()


# --- the year-coverage guard still fires, per calendar ------------------------

def test_year_guard_fires_beyond_coverage_for_each_calendar():
    # Each calendar covers 2026-2028; a start in 2029 cannot be answered honestly
    # under any of them, so the guard fires rather than skipping that year's
    # weekends but not its holidays.
    for cal in HOLIDAY_CALENDARS:
        with pytest.raises(HolidayYearNotCovered):
            add_business_days(parse_ts("2029-06-01T09:00:00+00:00"), 1, cal)


def test_year_guard_fires_when_a_uk_count_rolls_into_an_uncovered_year():
    # Begins inside coverage (late 2028) but walks past the end of the UK table.
    with pytest.raises(HolidayYearNotCovered):
        add_business_days(parse_ts("2028-12-28T09:00:00+00:00"), 5, "UK_BANK")


def test_year_guard_names_the_calendar_and_covered_range():
    with pytest.raises(HolidayYearNotCovered) as exc:
        add_business_days(parse_ts("2029-06-01T09:00:00+00:00"), 1, "DE_FEDERAL")
    message = str(exc.value)
    assert "DE_FEDERAL" in message
    assert "2026-2028" in message


# --- unknown calendar / unknown zone fail loud, never silently fall back ------

def test_unknown_calendar_raises_rather_than_defaulting_to_us():
    with pytest.raises(UnknownHolidayCalendar):
        add_business_days(parse_ts("2026-06-16T02:14:00+00:00"), 4, "ZZ_NOWHERE")


def test_unknown_timezone_raises_rather_than_rendering_utc():
    with pytest.raises(UnknownTimezone):
        render_local(datetime(2026, 6, 23, 23, 59, 59, tzinfo=timezone.utc),
                     "Mars/Olympus_Mons")
