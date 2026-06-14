"""Clock-math boundary tests: the edges a depth-prober pokes on camera.

The canonical June 16 -> June 23 Juneteenth case is covered in
test_holiday_clock.py. This file pins the boundaries that case does not touch:
a weekend start, a federal-holiday start, a DST crossing, zero and negative day
counts, and (the real correctness gap the audit named) a year-boundary crossing.

The year-boundary case used to be a SILENT bug: the holiday table was 2026-only,
so a count rolling into 2027 skipped weekends but not 2027 federal holidays. That
gap is now closed two ways and both are locked here:

  * the holiday table covers 2026-2028, so a cross-year count skips the next
    year's holidays too (the now-correct behavior, pinned below), and
  * a count that reaches a year with no table raises HolidayYearNotCovered
    instead of being silently wrong (the guard, pinned below).

None of this moves any 2026 result: the SEC demo deadline is still 2026-06-23,
asserted here as a regression pin.
"""

import pytest

from warden.clocks import (
    HolidayYearNotCovered,
    add_business_days,
    is_business_day,
    parse_ts,
)


# --- the demo result must not move -------------------------------------

def test_sec_demo_deadline_is_still_june_23_after_holiday_table_extension():
    # The single most important pin: extending the holiday table to future years
    # must not change the 2026 answer the whole demo rests on.
    d = add_business_days(parse_ts("2026-06-16T02:14:00+00:00"), 4)
    assert d.date().isoformat() == "2026-06-23"


# --- weekend / holiday start -------------------------------------------

def test_weekend_start_counts_from_next_business_day():
    sat = parse_ts("2026-06-20T10:00:00+00:00")  # a Saturday
    assert not is_business_day(sat.date())
    d = add_business_days(sat, 4)
    assert d.weekday() < 5            # always ends on a business day
    assert is_business_day(d.date())


def test_federal_holiday_start_counts_from_next_business_day():
    # Start ON Juneteenth 2026-06-19 (a Friday holiday). The count begins the
    # following Monday 2026-06-22; four business days land on 2026-06-25 (Thu).
    juneteenth = parse_ts("2026-06-19T09:00:00+00:00")
    assert not is_business_day(juneteenth.date())
    d = add_business_days(juneteenth, 4)
    assert is_business_day(d.date())
    assert d.date().isoformat() == "2026-06-25"


# --- DST crossing is normalized to UTC ---------------------------------

def test_dst_crossing_is_normalized_to_utc():
    # EU DST ends 2026-10-25. A CEST (+02:00) timestamp and its UTC equal must
    # yield the same deadline: the clock counts in UTC, not wall-clock.
    a = add_business_days(parse_ts("2026-10-23T02:00:00+02:00"), 4)
    b = add_business_days(parse_ts("2026-10-23T00:00:00+00:00"), 4)
    assert a == b


def test_us_dst_spring_forward_is_normalized_to_utc():
    # US DST begins 2027-03-14. An EST/EDT-offset start and its UTC equal agree.
    a = add_business_days(parse_ts("2027-03-12T20:00:00-05:00"), 4)
    b = add_business_days(parse_ts("2027-03-13T01:00:00+00:00"), 4)
    assert a == b


# --- zero and negative day counts are pinned ---------------------------

def test_zero_days_returns_end_of_start_date():
    start = parse_ts("2026-06-16T02:14:00+00:00")
    assert add_business_days(start, 0).date().isoformat() == "2026-06-16"


def test_negative_days_is_a_no_op_like_zero():
    # The `while remaining > 0` guard means a negative count walks zero days; it
    # returns end-of-day on the start date, same as zero. Pinned so a refactor
    # cannot quietly change it.
    start = parse_ts("2026-06-16T02:14:00+00:00")
    assert add_business_days(start, -1).date().isoformat() == "2026-06-16"
    assert add_business_days(start, -1) == add_business_days(start, 0)


# --- year boundary: the gap the audit named, now closed and pinned -----

def test_year_boundary_skips_next_years_new_year_holiday():
    # The formerly-silent bug: 2026-12-30 counting four business days rolls into
    # 2027. Wed 31 (1); Fri Jan 1 2027 = New Year's holiday (SKIPPED, this is the
    # fix); Mon Jan 4 (2); Tue 5 (3); Wed 6 (4). With the 2027 table now present,
    # the deadline is 2027-01-06, NOT 2027-01-05 (which would be the wrong answer
    # a 2026-only table produced by skipping the weekend but not the holiday).
    d = add_business_days(parse_ts("2026-12-30T12:00:00+00:00"), 4)
    assert d.date().isoformat() == "2027-01-06"
    assert d.year == 2027


def test_year_boundary_lands_on_a_business_day_not_a_holiday():
    # A range of cross-year starts: every result is a real business day, never a
    # 2027 holiday silently treated as countable.
    for day in range(28, 32):
        start = parse_ts(f"2026-12-{day:02d}T09:00:00+00:00")
        d = add_business_days(start, 5)
        assert is_business_day(d.date())


def test_two_year_crossing_skips_2028_holidays_too():
    # A long count from late 2027 into 2028 must skip 2028 holidays as well,
    # proving the table is genuinely multi-year and not just 2026+2027.
    start = parse_ts("2027-12-29T09:00:00+00:00")
    d = add_business_days(start, 10)
    assert is_business_day(d.date())
    assert d.year == 2028


# --- the guard: a year with no table raises, never silently wrong ------

def test_guard_fires_for_a_start_beyond_the_covered_range():
    # 2029 is past the covered table; starting there cannot be answered honestly.
    with pytest.raises(HolidayYearNotCovered):
        add_business_days(parse_ts("2029-01-02T09:00:00+00:00"), 4)


def test_guard_fires_when_a_count_rolls_into_an_uncovered_year():
    # The count begins inside coverage (late 2028) but walks past the end of the
    # table; the guard catches the roll-over rather than skipping 2029 holidays.
    with pytest.raises(HolidayYearNotCovered):
        add_business_days(parse_ts("2028-12-28T09:00:00+00:00"), 5)


def test_guard_names_the_uncovered_year_and_the_covered_range():
    with pytest.raises(HolidayYearNotCovered) as exc:
        add_business_days(parse_ts("2029-06-01T09:00:00+00:00"), 1)
    message = str(exc.value)
    assert "2029" in message
    assert "2026-2028" in message
