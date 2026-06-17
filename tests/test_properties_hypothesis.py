"""Property-based tests (Hypothesis) over the Warden's generated input space.

The seeded fuzz files (test_exactly_once_fuzz.py, test_failure_fuzz.py,
test_replay_reorder_fuzz.py, test_trust_invariants.py, the clock tests) assert
the trust invariants on a FIXED sample: a master seed, a fixed loop count, a
handful of hand-picked edge cases. A formalist reads that as a coverage
statement. This file restates the SAME invariants as PROPERTIES over a generated
space, explored adaptively by Hypothesis with the deterministic profile in
conftest.py, so any failure shrinks to a minimal reproducing counterexample
printed with the invariant it breaks.

These are belt-and-suspenders to the model-checker (warden/modelcheck.py, E1.1):
the checker proves ABSENCE of bad states in the protocol graph; Hypothesis hunts
for bugs adaptively in the run path and the pure cores. The named invariants:

  REPLAY-DET   replay(log) reproduces byte-identical bytes and the same sha for
               any generated run; the sealed (sha, jsonl) is a pure function of
               the event sequence (replay is idempotent).
  EXACTLY-ONCE every filing lands exactly once under any kill / duplicate /
               ack-lost schedule: 0 keys accepted twice, 0 filings lost, no
               clock breached.
  CLOCK-CORRECT the business-day + holiday + timezone deadline math matches an
               INDEPENDENT reference computation; the arithmetic is monotonic in
               the count; a non-UTC input and its UTC-equivalent yield the
               identical deadline.
  DIFF-TZ      two filings for the SAME instant in different timezones NEVER
               produce a contradiction; genuinely different instants DO.
  LEDGER-IDEM  any permutation / duplication of a message multiset yields the
               same accepted set, exactly one ACCEPTED per distinct key.

Each test names its invariant in a `# INVARIANT:` comment and in its assertion
messages, so a failure report reads as the property plus the shrunk schedule,
not a haystack. @example(...) pins the on-camera regression cases (the
Juneteenth SEC clock, the position-B kill, the contradiction-on-a-branch run, a
same-instant-two-zones diff) so they are explicit, not just rediscovered.
"""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

from hypothesis import example, given
from hypothesis import strategies as st

from warden.clocks import (
    US_FEDERAL_HOLIDAYS,
    add_business_days,
    is_business_day,
    parse_ts,
)
from warden.diff import Containment, FactClaims, diff_claims
from warden.ledger import Disposition, IdempotencyLedger
from warden.replay import replay
from warden.simulate import BRANCHES, FailureSchedule, KillSchedule, run_incident

from tests.strategies import (
    business_day_inputs,
    clock_inputs,
    contradiction_branch,
    different_instant_pair,
    fact_claim_sets,
    failure_schedules,
    kill_schedules,
    message_multisets,
    same_instant_two_zones,
    same_instant_two_zones_ts,
)


def _accepts_per_key(result) -> dict[str, int]:
    counts: dict[str, int] = {}
    for e in result.log.entries():
        if e["type"] == "ledger" and e["payload"]["disposition"] == "accepted":
            key = e["payload"]["key"]
            counts[key] = counts.get(key, 0) + 1
    return counts


# A single clean baseline shared by the exactly-once properties.
BASELINE_FILINGS = run_incident().filings


# =====================================================================
# REPLAY-DET: replay is byte-identical and a pure function of the events
# =====================================================================

@given(schedule=kill_schedules(), contradiction=contradiction_branch)
@example(schedule=KillSchedule({("nis2", 1): "B"}), contradiction=None)
@example(schedule=KillSchedule({}), contradiction="sec")
def test_replay_is_byte_identical_property(schedule, contradiction):
    # INVARIANT REPLAY-DET: for any generated run, replay(log) reproduces the
    # byte-identical jsonl and the same sealed sha, and the simulation is a pure
    # function of its inputs (same inputs -> same sha), with no wall-clock or RNG
    # leak in the canonicalization path.
    first = run_incident(kill_schedule=schedule, contradiction_in=contradiction)

    replayed = replay(first.log)
    assert replayed.to_jsonl() == first.log.to_jsonl(), (
        f"REPLAY-DET violated: replay trace diverged "
        f"(kills={schedule.kills}, contradiction={contradiction})")
    assert replayed.sha256() == first.log.sha256(), (
        f"REPLAY-DET violated: replay sha diverged "
        f"(kills={schedule.kills}, contradiction={contradiction})")

    # Idempotence: replaying the replay does not move the bytes.
    assert replay(replayed).to_jsonl() == first.log.to_jsonl(), (
        "REPLAY-DET violated: replay is not idempotent")

    # Determinism: an independent re-run with the same inputs reseals identically.
    second = run_incident(kill_schedule=KillSchedule(dict(schedule.kills)),
                          contradiction_in=contradiction)
    assert second.log.sha256() == first.log.sha256(), (
        f"REPLAY-DET violated: same input produced a different sha "
        f"(kills={schedule.kills}, contradiction={contradiction})")


@given(schedule=failure_schedules())
def test_replay_byte_identical_under_interleaved_failures(schedule):
    # INVARIANT REPLAY-DET (interleaved): the asymmetric full-pipeline failure
    # space (A/B/ack_lost interleaved across branches) is also byte-identically
    # replayable.
    r = run_incident(failure_schedule=schedule)
    replayed = replay(r.log)
    assert replayed.to_jsonl() == r.log.to_jsonl(), (
        f"REPLAY-DET violated under interleaved failures "
        f"(failures={schedule.failures}, order={schedule.drain_order})")
    assert replayed.sha256() == r.log.sha256()


# =====================================================================
# EXACTLY-ONCE: each filing lands exactly once under any chaos schedule
# =====================================================================

@given(schedule=kill_schedules(), contradiction=contradiction_branch)
@example(schedule=KillSchedule({("nis2", 1): "B"}), contradiction=None)
@example(schedule=KillSchedule({("sec", 1): "B", ("dora", 1): "B"}),
         contradiction="nis2")
def test_exactly_once_under_kill_schedule(schedule, contradiction):
    # INVARIANT EXACTLY-ONCE: under any kill schedule (with or without a
    # contradiction mixed in), no dedup key is ACCEPTED more than once, no filing
    # is lost (the filing set never diverges from the clean baseline when there
    # is no contradiction relabel), every branch produces a filing, and no
    # statutory clock breaches.
    r = run_incident(kill_schedule=schedule, contradiction_in=contradiction)

    counts = _accepts_per_key(r)
    doubles = {k: v for k, v in counts.items() if v > 1}
    assert not doubles, (
        f"EXACTLY-ONCE violated: key(s) accepted more than once {doubles} "
        f"(kills={schedule.kills}, contradiction={contradiction})")

    assert set(r.filings) == set(BRANCHES), (
        f"EXACTLY-ONCE violated: not every branch filed "
        f"(kills={schedule.kills}, contradiction={contradiction})")

    assert r.breached_clocks == [], (
        f"EXACTLY-ONCE violated: a clock breached under chaos "
        f"{r.breached_clocks} (kills={schedule.kills})")

    if contradiction is None:
        # With no contradiction relabel the filing CONTENT must equal baseline.
        assert r.filings == BASELINE_FILINGS, (
            f"EXACTLY-ONCE violated: a filing was lost or changed "
            f"(kills={schedule.kills})")


_ACK_LOST_EVERY_BRANCH = FailureSchedule(
    {(b, 1): "ack_lost" for b in BRANCHES}, list(reversed(BRANCHES)))


@given(schedule=failure_schedules(), contradiction=contradiction_branch)
@example(schedule=_ACK_LOST_EVERY_BRANCH, contradiction=None)
@example(schedule=FailureSchedule({(b, 1): "B" for b in BRANCHES}, list(BRANCHES)),
         contradiction="sec")
def test_exactly_once_under_interleaved_failures(schedule, contradiction):
    # INVARIANT EXACTLY-ONCE (interleaved + ack-lost): the asymmetric partition
    # where the post lands but the ack is lost and /next re-serves the IDENTICAL
    # message (attempt unchanged) must still admit each key exactly once. The
    # pinned examples are the every-branch lost-ack case and an all-branch
    # position-B kill with a contradiction mixed in.
    r = run_incident(failure_schedule=schedule, contradiction_in=contradiction)
    counts = _accepts_per_key(r)
    doubles = {k: v for k, v in counts.items() if v > 1}
    assert not doubles, (
        f"EXACTLY-ONCE violated under interleaved failures: {doubles} "
        f"(failures={schedule.failures}, order={schedule.drain_order}, "
        f"contradiction={contradiction})")
    assert set(r.filings) == set(BRANCHES), (
        f"EXACTLY-ONCE violated: not every branch filed "
        f"(failures={schedule.failures})")
    assert r.breached_clocks == [], (
        f"EXACTLY-ONCE violated: a clock breached "
        f"(failures={schedule.failures})")
    if contradiction is None:
        assert r.filings == BASELINE_FILINGS, (
            f"EXACTLY-ONCE violated: a filing was lost or changed "
            f"(failures={schedule.failures})")


# =====================================================================
# CLOCK-CORRECT: independent reference, monotonicity, timezone-equivalence
# =====================================================================

def _reference_add_business_days(start: datetime, days: int) -> datetime:
    """An INDEPENDENT reference for the SEC business-day clock, written from the
    statutory rule directly (weekends + US federal holidays skipped), not by
    calling the implementation. It walks one calendar day at a time, decrementing
    the remaining count only on a business day, and lands at end-of-day UTC on
    the final day. Distinct code path from warden.clocks.add_business_days, so an
    agreement is a genuine cross-check, not a tautology."""
    d = start.date()
    remaining = days
    while remaining > 0:
        d = d + timedelta(days=1)
        if d.weekday() < 5 and d not in US_FEDERAL_HOLIDAYS:
            remaining -= 1
    return datetime.combine(d, time(23, 59, 59), tzinfo=timezone.utc)


@given(args=business_day_inputs())
@example(args=("2026-06-16T02:14:00+00:00", 4))   # the on-camera Juneteenth SEC clock
@example(args=("2026-06-20T10:00:00+00:00", 4))   # a weekend start
def test_business_day_math_matches_independent_reference(args):
    # INVARIANT CLOCK-CORRECT (reference agreement): add_business_days agrees with
    # an independent reference implementation of the SEC rule, and its result is
    # always a real business day (never a weekend or US federal holiday).
    ts, days = args
    start = parse_ts(ts)
    got = add_business_days(start, days)
    ref = _reference_add_business_days(start, days)
    assert got == ref, (
        f"CLOCK-CORRECT violated: add_business_days({ts}, {days})={got} "
        f"disagrees with the independent reference {ref}")
    # For days >= 1 the count always advances to a real business day. days == 0
    # returns end-of-day on the start date as-is (pinned in test_clock_boundaries),
    # which may be a weekend/holiday, so the business-day landing claim applies
    # only when the count actually walks (days >= 1).
    if days >= 1:
        assert is_business_day(got.date()), (
            f"CLOCK-CORRECT violated: deadline {got.date()} is not a business day")
        assert got.date().weekday() < 5
        assert got.date() not in US_FEDERAL_HOLIDAYS
    else:
        assert got.date() == start.date(), (
            f"CLOCK-CORRECT violated: zero-day count must return the start date, "
            f"got {got.date()} for start {start.date()}")


@given(ts=st.sampled_from([
    "2026-06-16T02:14:00+00:00",
    "2026-01-02T09:00:00+00:00",
    "2027-03-12T20:00:00-05:00",
    "2028-02-10T12:00:00+09:00",
]), a=st.integers(min_value=1, max_value=12),
    b=st.integers(min_value=1, max_value=12))
def test_business_day_math_is_monotonic_in_days(ts, a, b):
    # INVARIANT CLOCK-CORRECT (monotonicity): more business days is a strictly
    # later (never earlier) deadline; equal counts give equal deadlines.
    start = parse_ts(ts)
    da = add_business_days(start, a)
    db = add_business_days(start, b)
    if a < b:
        assert da < db, (
            f"CLOCK-CORRECT violated: {a} days ({da}) not < {b} days ({db})")
    elif a > b:
        assert da > db, (
            f"CLOCK-CORRECT violated: {a} days ({da}) not > {b} days ({db})")
    else:
        assert da == db


@given(zones=same_instant_two_zones_ts(),
       days=st.integers(min_value=0, max_value=12))
def test_business_day_deadline_is_timezone_invariant(zones, days):
    # INVARIANT CLOCK-CORRECT (timezone-equivalence): a non-UTC input and its
    # UTC-equivalent (the SAME instant, different zone label) yield the identical
    # deadline. The clock counts in UTC, never wall-clock.
    ts_a, ts_b = zones
    start_a = parse_ts(ts_a)
    start_b = parse_ts(ts_b)
    assert start_a == start_b  # the strategy guarantees the same instant
    assert add_business_days(start_a, days) == add_business_days(start_b, days), (
        f"CLOCK-CORRECT violated: timezone-equivalent inputs {ts_a} and {ts_b} "
        f"gave different deadlines for {days} business days")


@given(args=clock_inputs(), zones=same_instant_two_zones_ts())
def test_hours_clock_is_timezone_invariant_and_exact(args, zones):
    # INVARIANT CLOCK-CORRECT (hours clock): an hours-based statutory window is
    # exactly start + N hours in UTC, and is timezone-invariant (same instant in
    # two zones -> same deadline). This covers the NIS2 / DORA / ICO / NYDFS
    # hour-counted clocks.
    ts, hours = args
    start = parse_ts(ts)
    # exactness against an independent computation (parse then add):
    from warden.clocks import ClockEngine
    eng = ClockEngine()
    c = eng.start_hours("prop", "inc:prop", ts, hours)
    assert c.deadline == start + timedelta(hours=hours), (
        f"CLOCK-CORRECT violated: hours clock deadline {c.deadline} != "
        f"{start} + {hours}h")

    ts_a, ts_b = zones
    ea = ClockEngine()
    ea.start_hours("a", "inc:a", ts_a, hours)
    eb = ClockEngine()
    eb.start_hours("b", "inc:b", ts_b, hours)
    assert ea.get("inc:a").deadline == eb.get("inc:b").deadline, (
        f"CLOCK-CORRECT violated: hours clock not timezone-invariant "
        f"({ts_a} vs {ts_b})")


# =====================================================================
# DIFF-TZ: same instant in two zones is never a contradiction; different is
# =====================================================================

@given(pair=same_instant_two_zones())
@example(pair=(
    FactClaims("nis2", "2026-06-16T02:14:00+00:00", 48000, "LockBit 3.0",
               Containment.PARTIALLY_CONTAINED),
    FactClaims("sec", "2026-06-16T03:14:00+01:00", 48000, "LockBit 3.0",
               Containment.PARTIALLY_CONTAINED),
))
def test_same_instant_two_zones_is_never_contradiction(pair):
    # INVARIANT DIFF-TZ (no false positive): two filings whose incident_start is
    # the SAME instant expressed in different timezones, agreeing on every other
    # load-bearing fact, must NEVER produce a contradiction. The diff canonicalizes
    # to UTC before comparing.
    a, b = pair
    assert a.canonical()["incident_start_utc"] == b.canonical()["incident_start_utc"], (
        "strategy invariant broken: the two zones do not denote the same instant")
    conflicts = diff_claims([a, b])
    assert conflicts == [], (
        f"DIFF-TZ violated (false positive): same instant in two zones flagged "
        f"as contradiction: {[c.human() for c in conflicts]}")
    # symmetric: order of the two claims does not change the (empty) result.
    assert diff_claims([b, a]) == [], (
        "DIFF-TZ violated: diff is not symmetric on a timezone-equivalent pair")


@given(pair=different_instant_pair())
def test_different_instant_is_always_contradiction(pair):
    # INVARIANT DIFF-TZ (no false negative): two filings carrying genuinely
    # different incident instants (any zone labels) MUST be flagged on the
    # incident_start_utc field, regardless of the offsets dressing them.
    a, b = pair
    assert a.canonical()["incident_start_utc"] != b.canonical()["incident_start_utc"], (
        "strategy invariant broken: the two instants are actually equal")
    conflicts = diff_claims([a, b])
    fields = {c.field for c in conflicts}
    assert "incident_start_utc" in fields, (
        f"DIFF-TZ violated (false negative): genuinely different instants not "
        f"flagged. a={a.canonical()} b={b.canonical()} conflicts={conflicts}")


@given(spec=fact_claim_sets())
def test_diff_is_symmetric_and_conflict_set_is_order_independent(spec):
    # INVARIANT DIFF-TZ (symmetry): the diff conflict SET does not depend on the
    # order of the branches; a genuinely conflict-free set (timezone-relabeled
    # variants of one instant, every other field equal) is always green, and a
    # genuinely divergent set is never green.
    claims, is_clean = spec
    forward = diff_claims(claims)
    backward = diff_claims(list(reversed(claims)))

    def conflict_field_set(conflicts):
        # The unordered set of conflicting fields, independent of which branch is
        # named A vs B (the diff records each conflicting field per pair).
        return frozenset(c.field for c in conflicts)

    assert conflict_field_set(forward) == conflict_field_set(backward), (
        f"DIFF-TZ violated: conflict field set is order-dependent "
        f"(forward={[c.human() for c in forward]}, "
        f"backward={[c.human() for c in backward]})")

    if is_clean:
        assert forward == [], (
            f"DIFF-TZ violated: a conflict-free set (timezone relabels only) was "
            f"flagged: {[c.human() for c in forward]}")
    else:
        assert forward != [], (
            "DIFF-TZ violated: a genuinely divergent set was reported green")


# =====================================================================
# LEDGER-IDEM: any permutation / duplication yields the same accepted set
# =====================================================================

@given(deliveries=message_multisets())
def test_ledger_admits_each_key_exactly_once_property(deliveries):
    # INVARIANT LEDGER-IDEM: feeding the ledger any permutation of a message
    # multiset admits each distinct key exactly once; every later delivery of a
    # key is DUPLICATE_DROPPED; the accepted set is exactly the distinct keys;
    # nothing is lost or invented.
    distinct_keys = {k for k, _ in deliveries}
    ledger = IdempotencyLedger()
    accepted_per_key: dict[str, int] = {k: 0 for k in distinct_keys}
    for ordinal, (key, attempt) in enumerate(deliveries):
        ts = f"2026-06-16T03:{ordinal % 60:02d}:00+00:00"
        entry = ledger.record(key, attempt, ts)
        if entry.disposition is Disposition.ACCEPTED:
            accepted_per_key[key] += 1

    for key in distinct_keys:
        assert accepted_per_key[key] == 1, (
            f"LEDGER-IDEM violated: key {key} accepted {accepted_per_key[key]} "
            f"times (deliveries={deliveries})")
    assert ledger.accepted_keys() == distinct_keys, (
        f"LEDGER-IDEM violated: accepted set {ledger.accepted_keys()} != "
        f"distinct keys {distinct_keys}")
    assert ledger.duplicates_dropped() == len(deliveries) - len(distinct_keys), (
        "LEDGER-IDEM violated: duplicate-dropped count is wrong")
    assert len(ledger.history()) == len(deliveries), (
        "LEDGER-IDEM violated: history length != deliveries (something lost or "
        "invented)")


@given(deliveries=message_multisets(), perm_seed=st.integers(min_value=0, max_value=10_000))
def test_ledger_accepted_set_is_permutation_invariant(deliveries, perm_seed):
    # INVARIANT LEDGER-IDEM (permutation invariance): two different orderings of
    # the SAME delivery multiset yield the IDENTICAL accepted set. The first
    # occurrence wins regardless of interleaving.
    import random
    shuffled = list(deliveries)
    random.Random(perm_seed).shuffle(shuffled)

    def accepted_set(seq):
        ledger = IdempotencyLedger()
        for ordinal, (key, attempt) in enumerate(seq):
            ledger.record(key, attempt, f"2026-06-16T03:{ordinal % 60:02d}:00+00:00")
        return ledger.accepted_keys()

    assert accepted_set(deliveries) == accepted_set(shuffled), (
        "LEDGER-IDEM violated: accepted set depends on delivery order "
        f"(multiset={sorted(set(deliveries))})")
