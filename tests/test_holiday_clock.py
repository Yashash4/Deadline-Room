"""test_holiday_clock.py (A3) — the SEC business-day clock skips weekends
and US federal holidays, including the June 16 -> June 23 Juneteenth case."""

from datetime import datetime, timezone

from warden.clocks import ClockEngine, add_business_days, parse_ts

def test_sec_clock_skips_weekend_and_juneteenth():
    # Incident Tue 2026-06-16. Business days after: Wed 17, Thu 18,
    # (Fri 19 = Juneteenth holiday, skipped), (Sat 20 / Sun 21 skipped),
    # Mon 22, Tue 23. Deadline = end of Tue 2026-06-23.
    start = parse_ts("2026-06-16T02:14:00+00:00")
    deadline = add_business_days(start, 4)
    assert deadline.date() == datetime(2026, 6, 23, tzinfo=timezone.utc).date()


def test_naive_96h_clock_would_be_wrong_by_three_days():
    start = parse_ts("2026-06-16T02:14:00+00:00")
    naive = datetime(2026, 6, 20, 2, 14, tzinfo=timezone.utc)  # start + 96h
    real = add_business_days(start, 4)
    assert (real - naive).days >= 3  # the examiner-grade difference


def test_clock_engine_no_breach_when_released_in_time():
    eng = ClockEngine()
    eng.start_sec_business_days("inc-1:sec", "2026-06-16T02:14:00+00:00")
    eng.stop("inc-1:sec", "2026-06-18T09:00:00+00:00")
    assert eng.breaches("2026-07-01T00:00:00+00:00") == []
