"""test_holiday_clock.py (A3), the SEC business-day clock skips weekends
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


def test_sec_clock_default_trigger_is_materiality_determination():
    # The SEC clock counts from the materiality DETERMINATION, not occurrence; the
    # engine labels it so by default for the Examiner Packet to render honestly.
    eng = ClockEngine()
    c = eng.start_sec_business_days("inc-1:sec", "2026-06-16T02:31:00+00:00")
    assert c.trigger_event == "materiality determination"


def test_determination_moment_on_june_16_preserves_june_23_deadline():
    # Any determination timestamp on 2026-06-16 yields the same deadline date as
    # the occurrence anchor at 02:14, because add_business_days counts whole
    # business days from start.date(). This is why moving the SEC anchor from
    # occurrence to the determination moment keeps the demo date byte-identical.
    occurrence = add_business_days(parse_ts("2026-06-16T02:14:00+00:00"), 4)
    determination = add_business_days(parse_ts("2026-06-16T02:31:00+00:00"), 4)
    assert determination == occurrence
    assert determination.date().isoformat() == "2026-06-23"


def test_start_hours_default_trigger_is_incident_occurrence():
    # Defaulted so existing constructions (the NIS2/DORA T0 clocks before they are
    # given an explicit label) do not break.
    eng = ClockEngine()
    c = eng.start_hours("DORA major-incident (72h)", "inc-1:dora",
                        "2026-06-16T02:14:00+00:00", 72)
    assert c.trigger_event == "incident occurrence"
