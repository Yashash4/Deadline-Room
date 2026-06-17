"""Hypothesis strategies that generate the Warden's inputs.

Each strategy produces a real input to a real Warden component, so the property
tests in test_properties_hypothesis.py assert the named invariants OVER the
generated space, not just over the hand-picked examples the seeded fuzz files
already cover. The strategies are intentionally small in cardinality (a fixed
branch set, bounded attempts, a curated timezone list) so the bounded
derandomized profile in conftest.py explores them exhaustively-in-spirit while
the suite stays fast and reproducible.

What is generated:

  kill_schedules()        -> KillSchedule: A/B crash points across branches and
                             attempts (the legacy per-branch drain space).
  failure_schedules()     -> FailureSchedule: A/B/ack_lost across branches and
                             attempts plus a randomized cross-branch drain order
                             (the interleaved full-pipeline space, E1.5).
  fact_claim_sets()       -> (list[FactClaims], bool): a set of branch claims for
                             the diff, with a flag telling the test whether the
                             generated set is genuinely conflicting or only
                             timezone-relabeled (same instant, different zone).
  same_instant_two_zones()-> (FactClaims, FactClaims): two claims for the SAME
                             UTC instant expressed in two different timezones;
                             the diff must NEVER call these a contradiction.
  different_instant_pair()-> (FactClaims, FactClaims): two claims for genuinely
                             different instants; the diff MUST flag them.
  clock_inputs()          -> (str, int): an incident_start timestamp across zones
                             and a statutory-window length in hours.
  business_day_inputs()   -> (str, int): an incident_start and a business-day
                             count, for the SEC clock reference check.
  same_instant_two_zones_ts() -> (str, str): one UTC instant rendered in two
                             zones, for the clock timezone-equivalence property.
  message_multisets()     -> list[(key, attempt)]: a permutable/duplicable
                             multiset of ledger deliveries with at least one copy
                             of each distinct key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import strategies as st

from warden.diff import Containment, FactClaims
from warden.simulate import BRANCHES, FailureSchedule, KillSchedule

# The legacy crash positions (KillSchedule) and the full asymmetric set
# (FailureSchedule), mirrored from warden.simulate so the strategies stay in
# lockstep with the real input vocabulary.
KILL_POSITIONS = ("A", "B")
FAILURE_MODES = ("A", "B", "ack_lost")

# A curated set of fixed UTC offsets, as (label, offset-hours). Real IANA zones
# add DST complexity the diff/clock canonicalization already collapses to UTC;
# fixed offsets are sufficient to exercise the timezone-equivalence rule and keep
# the generated timestamps deterministic and offset-arithmetic exact.
FIXED_OFFSETS: tuple[tuple[str, int], ...] = (
    ("UTC", 0),
    ("CET", 1),
    ("CEST", 2),
    ("EST", -5),
    ("EDT", -4),
    ("IST", 5),         # +05:00 component of India's +05:30 is covered by +05/+06
    ("JST", 9),
    ("AEST", 10),
    ("HST", -10),
)


def _offset_str(hours: int) -> str:
    sign = "+" if hours >= 0 else "-"
    return f"{sign}{abs(hours):02d}:00"


def _iso_with_offset(instant_utc: datetime, offset_hours: int) -> str:
    """Render a UTC instant as an ISO-8601 string in the given fixed offset.

    The returned string denotes the SAME instant as instant_utc; only the wall
    clock and the trailing offset differ. parse_ts() must map it back to
    instant_utc, which is what the timezone-equivalence properties rest on.
    """
    local = instant_utc.astimezone(timezone(timedelta(hours=offset_hours)))
    return local.strftime("%Y-%m-%dT%H:%M:%S") + _offset_str(offset_hours)


# ---------------------------------------------------------------------------
# Kill / failure schedules
# ---------------------------------------------------------------------------

@st.composite
def kill_schedules(draw) -> KillSchedule:
    """A KillSchedule: each branch takes 0..3 kills on consecutive attempts,
    each at crash position A or B. Mirrors the seeded _random_schedule space but
    is explored adaptively and shrinks toward the empty schedule."""
    kills: dict[tuple[str, int], str] = {}
    for b in BRANCHES:
        n = draw(st.integers(min_value=0, max_value=3))
        for attempt in range(1, n + 1):
            kills[(b, attempt)] = draw(st.sampled_from(KILL_POSITIONS))
    return KillSchedule(kills)


@st.composite
def failure_schedules(draw) -> FailureSchedule:
    """A FailureSchedule: each branch takes 0..3 failures sampled from
    {A, B, ack_lost} on consecutive attempts, plus a randomized cross-branch
    drain order. Mirrors test_failure_fuzz._failure_schedule, explored
    adaptively. Shrinks toward no failures and the canonical drain order."""
    failures: dict[tuple[str, int], str] = {}
    for b in BRANCHES:
        n = draw(st.integers(min_value=0, max_value=3))
        for attempt in range(1, n + 1):
            failures[(b, attempt)] = draw(st.sampled_from(FAILURE_MODES))
    order = draw(st.permutations(list(BRANCHES)))
    return FailureSchedule(failures, list(order))


contradiction_branch = st.sampled_from([None, *BRANCHES])
"""The branch (or None) that initially mis-states its incident_start, driving the
contradiction-resolution path in run_incident."""

amendment_toggles = st.tuples(st.booleans(), st.booleans())
"""(amendment, nis2_counters_first): exercise the fact-amendment beat and the
bounded counter round of the negotiation guard."""


# ---------------------------------------------------------------------------
# Fact-claim sets for the diff
# ---------------------------------------------------------------------------

# A small pool of distinct UTC instants the diff can be fed. Bounded so a
# generated "agreement" set genuinely repeats one instant and a "conflict" set
# genuinely picks two different ones.
_BASE_INSTANTS: tuple[datetime, ...] = (
    datetime(2026, 6, 16, 2, 14, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 16, 2, 41, 0, tzinfo=timezone.utc),
    datetime(2026, 6, 16, 7, 0, 0, tzinfo=timezone.utc),
    datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
)

_RECORD_COUNTS = (48000, 2_100_000, 1, 999_999)
_ATTACKERS = ("LockBit 3.0", "lockbit3", "BlackCat", "Cl0p")
_CONTAINMENTS = tuple(Containment)


def _claim(branch: str, instant_utc: datetime, offset_hours: int,
           records: int, attacker: str, containment: Containment) -> FactClaims:
    return FactClaims(
        branch=branch,
        incident_start_ts=_iso_with_offset(instant_utc, offset_hours),
        records_affected=records,
        attacker=attacker,
        containment=containment,
    )


@st.composite
def same_instant_two_zones(draw) -> tuple[FactClaims, FactClaims]:
    """Two claims that agree on EVERY load-bearing fact, with the SAME incident
    instant expressed in two DIFFERENT timezones. The only thing that differs is
    the zone label and wall-clock string. diff_claims must return no conflict."""
    instant = draw(st.sampled_from(_BASE_INSTANTS))
    off_a, off_b = draw(
        st.lists(st.sampled_from([o for _, o in FIXED_OFFSETS]),
                 min_size=2, max_size=2, unique=True)
    )
    records = draw(st.sampled_from(_RECORD_COUNTS))
    attacker = draw(st.sampled_from(_ATTACKERS))
    containment = draw(st.sampled_from(_CONTAINMENTS))
    a = _claim("nis2", instant, off_a, records, attacker, containment)
    b = _claim("sec", instant, off_b, records, attacker, containment)
    return a, b


@st.composite
def different_instant_pair(draw) -> tuple[FactClaims, FactClaims]:
    """Two claims that agree on every OTHER load-bearing fact but carry genuinely
    DIFFERENT incident instants (any zone labels). diff_claims MUST flag the
    incident_start_utc field, no matter what offsets dress the two instants."""
    inst_a, inst_b = draw(
        st.lists(st.sampled_from(_BASE_INSTANTS), min_size=2, max_size=2, unique=True)
    )
    off_a = draw(st.sampled_from([o for _, o in FIXED_OFFSETS]))
    off_b = draw(st.sampled_from([o for _, o in FIXED_OFFSETS]))
    records = draw(st.sampled_from(_RECORD_COUNTS))
    attacker = draw(st.sampled_from(_ATTACKERS))
    containment = draw(st.sampled_from(_CONTAINMENTS))
    a = _claim("nis2", inst_a, off_a, records, attacker, containment)
    b = _claim("sec", inst_b, off_b, records, attacker, containment)
    return a, b


@st.composite
def fact_claim_sets(draw) -> tuple[list[FactClaims], bool]:
    """A set of 2..3 branch claims plus a flag: True if the set is genuinely
    conflict-free (one shared instant across timezone-relabeled variants, and
    every other field equal), False if at least one field genuinely differs.

    Used to assert the symmetric, order-independent behavior of diff_claims and
    that a relabeled-only set is always green while a genuinely divergent set is
    never green."""
    n = draw(st.integers(min_value=2, max_value=len(BRANCHES)))
    branches = BRANCHES[:n]
    instant = draw(st.sampled_from(_BASE_INSTANTS))
    records = draw(st.sampled_from(_RECORD_COUNTS))
    attacker = draw(st.sampled_from(_ATTACKERS))
    containment = draw(st.sampled_from(_CONTAINMENTS))
    make_conflict = draw(st.booleans())

    claims: list[FactClaims] = []
    offsets = [o for _, o in FIXED_OFFSETS]
    for i, b in enumerate(branches):
        off = draw(st.sampled_from(offsets))
        claims.append(_claim(b, instant, off, records, attacker, containment))

    if make_conflict:
        # Mutate exactly one field on exactly one branch so the set genuinely
        # conflicts. The mutation is a real value change, never a zone relabel.
        idx = draw(st.integers(min_value=0, max_value=n - 1))
        field = draw(st.sampled_from(
            ["instant", "records", "attacker", "containment"]))
        c = claims[idx]
        if field == "instant":
            other = draw(st.sampled_from(
                [d for d in _BASE_INSTANTS if d != instant]))
            off = draw(st.sampled_from(offsets))
            claims[idx] = _claim(c.branch, other, off, c.records_affected,
                                 c.attacker, c.containment)
        elif field == "records":
            other = draw(st.sampled_from(
                [r for r in _RECORD_COUNTS if r != records]))
            claims[idx] = _claim(c.branch, instant, draw(st.sampled_from(offsets)),
                                 other, c.attacker, c.containment)
        elif field == "attacker":
            # Pick an attacker that does NOT canonicalize to the same alias, so
            # the mutation is a genuine disagreement and not a LockBit alias.
            from warden.diff import canon_attacker
            base_canon = canon_attacker(attacker)
            choices = [a for a in _ATTACKERS if canon_attacker(a) != base_canon]
            if not choices:
                # Fall back to a record-count mutation if no genuinely different
                # attacker exists in the pool (keeps the conflict honest).
                other = draw(st.sampled_from(
                    [r for r in _RECORD_COUNTS if r != records]))
                claims[idx] = _claim(c.branch, instant,
                                     draw(st.sampled_from(offsets)), other,
                                     c.attacker, c.containment)
            else:
                other_attacker = draw(st.sampled_from(choices))
                claims[idx] = _claim(c.branch, instant,
                                     draw(st.sampled_from(offsets)),
                                     c.records_affected, other_attacker,
                                     c.containment)
        else:  # containment
            other = draw(st.sampled_from(
                [ct for ct in _CONTAINMENTS if ct != containment]))
            claims[idx] = _claim(c.branch, instant, draw(st.sampled_from(offsets)),
                                 c.records_affected, c.attacker, other)
        return claims, False

    return claims, True


# ---------------------------------------------------------------------------
# Clock inputs
# ---------------------------------------------------------------------------

# Start dates spread across the whole covered holiday span (2026-2028), avoiding
# the very end of 2028 so a business-day count cannot roll past the table and
# trip HolidayYearNotCovered (that boundary is pinned by example in
# test_clock_boundaries.py; here we test the in-range arithmetic property).
_START_DATES = st.dates(
    min_value=datetime(2026, 1, 1).date(),
    max_value=datetime(2028, 6, 30).date(),
)
_START_TIMES = st.times()
_OFFSET_HOURS = st.sampled_from([o for _, o in FIXED_OFFSETS])


@st.composite
def clock_inputs(draw) -> tuple[str, int]:
    """An incident_start timestamp in a generated timezone and a statutory-window
    length in hours (1..168, i.e. up to a week). For the hours-clock property."""
    d = draw(_START_DATES)
    t = draw(_START_TIMES)
    off = draw(_OFFSET_HOURS)
    naive = datetime.combine(d, t)
    local = naive.replace(tzinfo=timezone(timedelta(hours=off)))
    ts = local.strftime("%Y-%m-%dT%H:%M:%S") + _offset_str(off)
    hours = draw(st.integers(min_value=1, max_value=168))
    return ts, hours


@st.composite
def business_day_inputs(draw) -> tuple[str, int]:
    """An incident_start timestamp and a business-day count (0..15). Kept inside
    the covered holiday span so add_business_days never trips the year guard."""
    d = draw(_START_DATES)
    t = draw(_START_TIMES)
    off = draw(_OFFSET_HOURS)
    naive = datetime.combine(d, t)
    local = naive.replace(tzinfo=timezone(timedelta(hours=off)))
    ts = local.strftime("%Y-%m-%dT%H:%M:%S") + _offset_str(off)
    days = draw(st.integers(min_value=0, max_value=15))
    return ts, days


@st.composite
def same_instant_two_zones_ts(draw) -> tuple[str, str]:
    """One UTC instant rendered as ISO-8601 in two DIFFERENT fixed offsets. Both
    strings denote the identical instant; parse_ts and the clock math must treat
    them identically. For the clock timezone-equivalence property."""
    d = draw(_START_DATES)
    t = draw(_START_TIMES)
    instant = datetime.combine(d, t, tzinfo=timezone.utc)
    off_a, off_b = draw(
        st.lists(st.sampled_from([o for _, o in FIXED_OFFSETS]),
                 min_size=2, max_size=2, unique=True)
    )
    return _iso_with_offset(instant, off_a), _iso_with_offset(instant, off_b)


# ---------------------------------------------------------------------------
# Ledger message multisets
# ---------------------------------------------------------------------------

@st.composite
def message_multisets(draw) -> list[tuple[str, int]]:
    """A multiset of (dedup_key, attempt) deliveries: 1..6 distinct keys, each
    delivered 1..5 times (duplicate redeliveries) with arbitrary attempt
    numbers, then shuffled into an arbitrary interleaving. Every distinct key
    appears at least once. For the ledger idempotency / permutation property."""
    n_keys = draw(st.integers(min_value=1, max_value=6))
    keys = [f"draft:branch{k}:inc-prop:round-1" for k in range(n_keys)]
    deliveries: list[tuple[str, int]] = []
    for key in keys:
        copies = draw(st.integers(min_value=1, max_value=5))
        for _ in range(copies):
            attempt = draw(st.integers(min_value=1, max_value=9))
            deliveries.append((key, attempt))
    # A genuine interleaving permutation of the multiset.
    deliveries = draw(st.permutations(deliveries))
    return list(deliveries)
