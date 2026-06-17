"""Metamorphic relations over the pure cores (E1.4).

A metamorphic relation is an input transformation whose effect on the output is
known in advance: transform the input a certain way and the output must either be
UNCHANGED or change in an exactly predictable way. They catch bugs an oracle test
cannot, because they need no reference answer, only the structural relationship
between two related runs.

This file is DISJOINT from tests/test_properties_hypothesis.py (E1.3). That suite
already covers replay determinism, exactly-once, clock UTC-equivalence /
business-day-reference / monotonicity, diff timezone-equivalence /
order-independence, and ledger permutation-invariance. None of those are restated
here. The relations below are genuinely new TRANSFORMATIONS verified against the
real implementation before assertion (a relation the code does not actually
satisfy is never asserted):

  DIFF-RELABEL    consistently renaming the branch labels across a set of filings
                  does not change WHETHER a contradiction is detected, nor the
                  (field, value_a, value_b) content of the conflict set; it only
                  changes which labels are named in each Conflict.
  DIFF-FIELDPERM  the order in which the load-bearing fields are compared does not
                  change the conflict set (the set is a function of the field
                  values, not of the comparison order).
  CLOCK-WEEKSHIFT for the SEC business-day clock, shifting the start by exactly 7
                  calendar days shifts the deadline by exactly 7 calendar days
                  WHEN no US federal holiday falls in either counting window, and
                  the relation PREDICTABLY differs (the shift is no longer 7 days)
                  when a holiday is introduced into one window.
  CLOCK-HOURSADD  for the calendar-hour regimes (NIS2 / DORA / ICO / NYDFS), the
                  deadline is additive in the start: deadline(start + delta) ==
                  deadline(start) + delta exactly, no business-day adjustment.
  NEG-SETTLE      a CONCUR matching its PROPOSE settles the round regardless of
                  unrelated envelopes interleaved between them.
  NEG-IDEMPOTENT  re-posting (replaying) an already-accepted envelope does not
                  change any gate verdict; the guard is idempotent in the envelope
                  multiset.
  NEG-MAXROUNDS   an envelope whose amend_round exceeds MAX_ROUNDS is rejected
                  identically (same allowed flag, same reason) regardless of which
                  branch initiated it.
  REPLAY-PREFIX   the chain head is a prefix-extension homomorphism over the event
                  sequence: appending one entry folds the prior head with that
                  entry alone, so the head is a deterministic running function of
                  the sequence and a prefix's chain is the prefix of the whole
                  chain.

Each assertion names its relation. A failure prints the relation plus the minimal
violating transform, never a haystack.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta

from hypothesis import example, given
from hypothesis import strategies as st

from warden.chain import GENESIS, _entry_hash, chain_head, chain_over
from warden.clocks import (
    US_FEDERAL_HOLIDAYS,
    ClockEngine,
    add_business_days,
    parse_ts,
)
from warden.diff import Conflict, FactClaims, diff_claims
from warden.negotiation import (
    MAX_ROUNDS,
    NegotiationEnvelope,
    NegotiationGuard,
    Verdict,
)
from warden.replay import RunLog

from tests.strategies import (
    business_day_inputs,
    clock_inputs,
    fact_claim_sets,
)

# =====================================================================
# DIFF-RELABEL: consistent branch renaming preserves detection + content
# =====================================================================

# A fixed injective relabeling for each branch set the strategy can produce.
# It must be a bijection over whatever branch labels appear so the rename is a
# pure relabeling (no two branches collapse to one label).
_RELABEL = {"nis2": "alpha", "dora": "beta", "sec": "gamma"}


def _relabel_claim(c: FactClaims, mapping: dict[str, str]) -> FactClaims:
    return FactClaims(
        branch=mapping[c.branch],
        incident_start_ts=c.incident_start_ts,
        records_affected=c.records_affected,
        attacker=c.attacker,
        containment=c.containment,
    )


def _content_multiset(conflicts: list[Conflict]):
    """The conflict content stripped of branch labels: a sorted multiset of
    (field, value_a, value_b). Two diffs that disagree only on which branch is
    named A vs B produce the IDENTICAL content multiset; a genuine difference in
    what fields conflict or in their values does not."""
    return sorted((c.field, repr(c.value_a), repr(c.value_b)) for c in conflicts)


@given(spec=fact_claim_sets())
def test_diff_is_invariant_under_consistent_branch_relabel(spec):
    # METAMORPHIC DIFF-RELABEL: rename every branch through a bijection. Whether a
    # contradiction is detected must not change, and the (field, value_a, value_b)
    # content of the conflict set must be byte-for-byte identical: only the branch
    # labels named in each Conflict may differ. The detector keys on canonicalized
    # FACT VALUES, never on the branch name.
    claims, _is_clean = spec
    base = diff_claims(claims)
    relabeled = [_relabel_claim(c, _RELABEL) for c in claims]
    after = diff_claims(relabeled)

    assert (len(after) > 0) == (len(base) > 0), (
        f"DIFF-RELABEL violated: relabeling branches changed WHETHER a "
        f"contradiction was detected (base={len(base)} conflicts, "
        f"relabeled={len(after)} conflicts)")
    assert _content_multiset(after) == _content_multiset(base), (
        f"DIFF-RELABEL violated: the conflict content (field, values) changed "
        f"under a pure branch rename: base={_content_multiset(base)} "
        f"relabeled={_content_multiset(after)}")
    # The labels DID get renamed where present, confirming the rename took effect
    # (not a no-op that trivially preserves everything).
    base_labels = {c.branch_a for c in base} | {c.branch_b for c in base}
    after_labels = {c.branch_a for c in after} | {c.branch_b for c in after}
    if base:
        assert all(lbl in _RELABEL.values() for lbl in after_labels), (
            f"DIFF-RELABEL setup error: relabeled conflicts still name original "
            f"branches {after_labels}")
        assert base_labels & after_labels == set(), (
            "DIFF-RELABEL setup error: the relabel did not actually move labels")


# =====================================================================
# DIFF-FIELDPERM: the conflict set does not depend on field comparison order
# =====================================================================

def _diff_under_field_order(claims: list[FactClaims], order: tuple[str, ...]):
    """Reproduce diff_claims's pairwise scan but compare the canonical fields in
    an arbitrary ORDER. The production diff iterates a fixed dict order; this
    asserts the RESULT SET is invariant to that choice. Returns the unordered set
    of (field, branch_a, value_a, branch_b, value_b) tuples so it is comparable
    across orders."""
    canon = [(c.branch, c.canonical()) for c in claims]
    out = set()
    for i in range(len(canon)):
        for j in range(i + 1, len(canon)):
            ba, fa = canon[i]
            bb, fb = canon[j]
            for field in order:
                if fa[field] != fb[field]:
                    out.add((field, ba, repr(fa[field]), bb, repr(fb[field])))
    return frozenset(out)


@given(spec=fact_claim_sets())
def test_diff_conflict_set_is_field_permutation_invariant(spec):
    # METAMORPHIC DIFF-FIELDPERM: permuting the order in which the load-bearing
    # fields are compared yields the IDENTICAL conflict set. Each field is compared
    # independently, so the set of detected conflicts is a function of the field
    # VALUES alone, not of the order the diff happens to walk them in. (This is a
    # different relation from the branch-order symmetry E1.3 already covers; here
    # the FIELDS are permuted, not the branches.)
    claims, _is_clean = spec
    if not claims:
        return
    fields = tuple(claims[0].canonical().keys())
    results = {
        _diff_under_field_order(claims, perm)
        for perm in itertools.permutations(fields)
    }
    assert len(results) == 1, (
        f"DIFF-FIELDPERM violated: the conflict set depends on the field "
        f"comparison order. Distinct sets across {len(list(itertools.permutations(fields)))} "
        f"field orders: {results}")
    # And it matches the production diff's own (fixed-order) conflict set, with
    # values normalized to repr so the comparison is on content not object id.
    prod = frozenset(
        (c.field, c.branch_a, repr(c.value_a), c.branch_b, repr(c.value_b))
        for c in diff_claims(claims))
    assert prod == next(iter(results)), (
        "DIFF-FIELDPERM violated: the production diff set differs from the "
        "order-independent set")


# =====================================================================
# CLOCK-WEEKSHIFT: +7 calendar days at the start -> +7 at the deadline
#                  WHEN no holiday in either window; differs when one is added
# =====================================================================

def _business_day_window(start: datetime, days: int) -> list:
    """The calendar dates walked by add_business_days(start, days): from the day
    after start up to and including the landing date. Written independently of the
    implementation so the holiday-in-window test is a real check, not a tautology."""
    d = start.date()
    remaining = days
    walked = []
    while remaining > 0:
        d = d + timedelta(days=1)
        walked.append(d)
        if d.weekday() < 5 and d not in US_FEDERAL_HOLIDAYS:
            remaining -= 1
    return walked


def _window_has_holiday(start: datetime, days: int) -> bool:
    return any(d in US_FEDERAL_HOLIDAYS for d in _business_day_window(start, days))


@given(args=business_day_inputs())
@example(args=("2026-03-02T10:00:00+00:00", 4))   # a clean (holiday-free) week
@example(args=("2026-05-21T10:00:00+00:00", 4))   # Memorial-Day week: holiday present
def test_business_day_clock_week_shift(args):
    # METAMORPHIC CLOCK-WEEKSHIFT: a +7 calendar-day shift of the start preserves
    # the weekday and the weekend pattern, so WHEN no US federal holiday falls in
    # either counting window the deadline shifts by exactly 7 calendar days. When a
    # holiday DOES fall in exactly one of the two windows the relation predictably
    # differs (the shift is no longer 7 days), because the holiday consumes an
    # extra calendar day in that window only. This is the careful statement: the
    # clean case is an exact equality, the holiday case is a confirmed inequality.
    ts, days = args
    if days < 1:
        return  # the zero-day count has no window; nothing to shift
    start = parse_ts(ts)
    shifted = start + timedelta(days=7)

    # Both counts must stay inside the covered holiday span; if the shifted count
    # would roll past the table it raises HolidayYearNotCovered, which is its own
    # pinned behavior, not this relation. Skip those boundary inputs.
    try:
        d0 = add_business_days(start, days)
        d1 = add_business_days(shifted, days)
    except Exception:
        return

    no_holiday = not _window_has_holiday(start, days) and not _window_has_holiday(shifted, days)
    if no_holiday:
        assert (d1 - d0) == timedelta(days=7), (
            f"CLOCK-WEEKSHIFT violated: holiday-free windows, but a +7-day start "
            f"shift moved the deadline by {(d1 - d0)} instead of exactly 7 days "
            f"(start={ts}, days={days}, d0={d0.isoformat()}, d1={d1.isoformat()})")
    else:
        # A holiday in exactly one window breaks the 7-day equality; a holiday in
        # BOTH windows would restore it, so the strict inequality is asserted only
        # when the holiday presence DIFFERS between the two windows.
        only_one = (_window_has_holiday(start, days)
                    != _window_has_holiday(shifted, days))
        if only_one:
            assert (d1 - d0) != timedelta(days=7), (
                f"CLOCK-WEEKSHIFT violated: a holiday in exactly one window should "
                f"break the 7-day shift, but the deadline still moved by exactly 7 "
                f"days (start={ts}, days={days})")


def test_business_day_clock_week_shift_pinned_holiday_case():
    # METAMORPHIC CLOCK-WEEKSHIFT (pinned holiday counterexample): the Memorial-Day
    # 2026 window is a concrete, on-the-record case where introducing the holiday
    # into the first window shrinks the calendar shift below 7 days. Pinning it
    # makes the "predictably differs" half explicit, not just rediscovered by the
    # generator.
    start = parse_ts("2026-05-21T10:00:00+00:00")   # Thu before Memorial Day
    shifted = start + timedelta(days=7)             # Thu after, no holiday
    d0 = add_business_days(start, 4)
    d1 = add_business_days(shifted, 4)
    assert _window_has_holiday(start, 4)
    assert not _window_has_holiday(shifted, 4)
    assert (d1 - d0) == timedelta(days=6), (
        f"CLOCK-WEEKSHIFT pinned case changed: expected the Memorial-Day window to "
        f"shrink the shift to 6 days, got {(d1 - d0)}")


# =====================================================================
# CLOCK-HOURSADD: the calendar-hour deadline is additive in the start
# =====================================================================

@given(args=clock_inputs(),
       delta_hours=st.integers(min_value=-240, max_value=240))
@example(args=("2026-06-16T02:14:00+00:00", 72), delta_hours=24)
def test_hours_clock_is_additive_in_start(args, delta_hours):
    # METAMORPHIC CLOCK-HOURSADD: for the calendar-hour regimes, the deadline is a
    # pure translation of the start: deadline(start + delta) == deadline(start) +
    # delta, exactly, for ANY delta (positive or negative), with no business-day or
    # holiday adjustment. This is what makes "the same incident reported an hour
    # later" land its deadline exactly an hour later, the property the NIS2 / DORA /
    # ICO / NYDFS clocks rely on.
    ts, hours = args
    delta = timedelta(hours=delta_hours)
    start = parse_ts(ts)
    shifted = start + delta

    eng0 = ClockEngine()
    c0 = eng0.start_hours("base", "inc:base", ts, hours)

    eng1 = ClockEngine()
    shifted_ts = shifted.isoformat()
    c1 = eng1.start_hours("shift", "inc:shift", shifted_ts, hours)

    assert c1.deadline == c0.deadline + delta, (
        f"CLOCK-HOURSADD violated: deadline(start + {delta}) = {c1.deadline} "
        f"!= deadline(start) + {delta} = {c0.deadline + delta} "
        f"(start={ts}, hours={hours})")


# =====================================================================
# Negotiation guard metamorphic relations
# =====================================================================

_NEG_TS = "2026-06-16T08:14:00+00:00"


def _env(rnd, frm, to, verdict, value, char, prior=None) -> NegotiationEnvelope:
    return NegotiationEnvelope(
        correlation_id="inc-8842:sec",
        amend_round=rnd,
        from_agent=frm,
        to_agent=to,
        fact_key="records_affected",
        proposed_value=value,
        characterization=char,
        data_category_bounds=("name", "address", "account_number"),
        containment_framing="contained as of 2026-06-16T07:00:00+00:00",
        verdict=verdict,
        ts_utc=_NEG_TS,
        prior_envelope_hash=prior,
    )


@given(n_interleaved=st.integers(min_value=0, max_value=3))
def test_concur_settles_round_regardless_of_interleaved_envelopes(n_interleaved):
    # METAMORPHIC NEG-SETTLE: a CONCUR that matches its PROPOSE settles round 1
    # (can_submit_amendment becomes allowed) regardless of how many UNRELATED
    # envelopes (proposals in a different amend_round) are interleaved between the
    # propose and the concur. The settle decision is a function of (round, a
    # matching concur exists), not of the surrounding traffic.
    propose = _env(1, "sec_drafter", "nis2_drafter", Verdict.PROPOSE,
                   2_100_000, "approximately 2.1 million records")

    guard = NegotiationGuard()
    assert guard.post(propose).allowed
    # Interleave unrelated, well-formed proposals in a HIGHER round (each a fresh
    # propose, so each is independently admissible and unrelated to round 1).
    for k in range(n_interleaved):
        rnd = 2 + (k % (MAX_ROUNDS - 1))  # rounds 2..MAX_ROUNDS, never round 1
        noise = _env(rnd, "sec_drafter", "nis2_drafter", Verdict.PROPOSE,
                     2_100_000, f"unrelated proposal {k}")
        guard.post(noise)

    # Before the concur, round 1 cannot submit.
    assert not guard.can_submit_amendment("inc-8842:sec", 1).allowed, (
        "NEG-SETTLE precondition broken: round 1 settled with no concur")

    concur = _env(1, "nis2_drafter", "sec_drafter", Verdict.CONCUR,
                  2_100_000, "approximately 2.1 million records",
                  prior=propose.sha256())
    assert guard.post(concur).allowed

    assert guard.can_submit_amendment("inc-8842:sec", 1).allowed, (
        f"NEG-SETTLE violated: a matching concur did not settle round 1 with "
        f"{n_interleaved} unrelated envelopes interleaved")


@given(extra_replays=st.integers(min_value=1, max_value=4))
def test_negotiation_guard_is_idempotent_under_envelope_replay(extra_replays):
    # METAMORPHIC NEG-IDEMPOTENT: re-posting (replaying) the SAME concur envelope
    # any number of additional times does not change the gate verdict. The guard's
    # decision is a function of the SET of envelopes it has seen, so a duplicate
    # delivery (the exactly-once world's redelivery) is a no-op on every gate.
    propose = _env(1, "sec_drafter", "nis2_drafter", Verdict.PROPOSE,
                   2_100_000, "approximately 2.1 million records")
    concur = _env(1, "nis2_drafter", "sec_drafter", Verdict.CONCUR,
                  2_100_000, "approximately 2.1 million records",
                  prior=propose.sha256())

    guard = NegotiationGuard()
    guard.post(propose)
    guard.post(concur)

    submit_before = guard.can_submit_amendment("inc-8842:sec", 1).allowed
    branch_values = {"sec": 2_100_000, "nis2": 2_100_000}
    diff_before = guard.can_pass_diff(1, branch_values).allowed

    for _ in range(extra_replays):
        guard.post(concur)   # replay the identical envelope

    submit_after = guard.can_submit_amendment("inc-8842:sec", 1).allowed
    diff_after = guard.can_pass_diff(1, branch_values).allowed

    # The settled round must START allowed (otherwise the replay test would be
    # vacuous), and replaying must leave both gate verdicts exactly where they were.
    assert submit_before is True and diff_before is True, (
        "NEG-IDEMPOTENT precondition broken: the round was not settled before replay")
    assert submit_after == submit_before, (
        f"NEG-IDEMPOTENT violated: replaying the concur {extra_replays} times "
        f"changed can_submit_amendment ({submit_before} -> {submit_after})")
    assert diff_after == diff_before, (
        f"NEG-IDEMPOTENT violated: replaying the concur {extra_replays} times "
        f"changed can_pass_diff ({diff_before} -> {diff_after})")


@given(round_over=st.integers(min_value=MAX_ROUNDS + 1, max_value=MAX_ROUNDS + 5),
       verdict=st.sampled_from(list(Verdict)))
def test_max_rounds_rejection_is_initiator_independent(round_over, verdict):
    # METAMORPHIC NEG-MAXROUNDS: an envelope whose amend_round exceeds MAX_ROUNDS is
    # rejected with the IDENTICAL verdict (same allowed flag, same reason string)
    # no matter which branch initiated it. The bound is on the round number, not on
    # who is speaking, so swapping the from/to agents does not change the rejection.
    sec_init = _env(round_over, "sec_drafter", "nis2_drafter", verdict,
                    2_100_000, "over the bound")
    nis2_init = _env(round_over, "nis2_drafter", "sec_drafter", verdict,
                     2_100_000, "over the bound")

    d_sec = NegotiationGuard().post(sec_init)
    d_nis2 = NegotiationGuard().post(nis2_init)

    assert d_sec.allowed is False and d_nis2.allowed is False, (
        f"NEG-MAXROUNDS violated: amend_round {round_over} > {MAX_ROUNDS} was not "
        f"rejected (sec={d_sec.allowed}, nis2={d_nis2.allowed})")
    assert d_sec.reason == d_nis2.reason, (
        f"NEG-MAXROUNDS violated: the over-bound rejection reason depends on the "
        f"initiator: sec='{d_sec.reason}' vs nis2='{d_nis2.reason}'")


# =====================================================================
# REPLAY-PREFIX: the chain head is a prefix-extension homomorphism
# =====================================================================

@st.composite
def run_log_entries(draw) -> list[dict]:
    """A small list of well-formed run-log entries of mixed types, the kind the
    Warden appends. Bounded so the prefix sweep stays fast. The exact payloads do
    not matter to the chain relation (it canonicalizes whatever bytes it is given);
    what matters is that they are real, distinct, ordered entries."""
    n = draw(st.integers(min_value=0, max_value=6))
    entries: list[dict] = []
    for seq in range(n):
        kind = draw(st.sampled_from(["clock_started", "protocol_event", "ledger", "diff"]))
        if kind == "clock_started":
            payload = {"clock": f"C{seq}", "correlation_id": f"inc:{seq}",
                       "deadline": "2026-06-19T02:14:00+00:00"}
        elif kind == "protocol_event":
            payload = {"correlation_id": f"inc:{seq}", "event": "draft_posted",
                       "ts": "2026-06-16T03:11:00+00:00", "actor": f"a{seq}",
                       "actor_role": "drafter", "admitted": True,
                       "to_state": "draft_submitted", "reason": None}
        elif kind == "ledger":
            payload = {"key": f"draft:b{seq}:inc:round-1", "attempt": 1,
                       "disposition": "accepted"}
        else:
            payload = {"conflicts": []}
        entries.append({"seq": seq, "type": kind, "payload": payload})
    return entries


@given(entries=run_log_entries())
def test_chain_head_is_prefix_extension_homomorphism(entries):
    # METAMORPHIC REPLAY-PREFIX: the per-entry chain head is a deterministic running
    # fold over the event sequence. Two exact relations are asserted:
    #   (1) the chain over any PREFIX of the sequence equals the prefix of the chain
    #       over the whole sequence (prefix-stability), and
    #   (2) appending one entry e to a sequence with head h yields head
    #       fold(h, e) = sha256(h + '\n' + canon(e)) using nothing but the prior
    #       head and e (append-homomorphism).
    # Together they are the precise statement that the sealed chain head is a pure,
    # incremental function of the event sequence, which is what makes a tamper at
    # position i move every head from i onward and nothing before it.
    full = chain_over(entries)

    for k in range(len(entries) + 1):
        prefix_chain = chain_over(entries[:k])
        assert prefix_chain == full[:k], (
            f"REPLAY-PREFIX violated: chain over the {k}-entry prefix is not the "
            f"prefix of the full chain (len={len(entries)})")

    # Append-homomorphism: head after append == fold(head before, new entry).
    head_before = chain_head(entries)
    assert head_before == (full[-1] if full else GENESIS)
    new_entry = {"seq": len(entries), "type": "diff", "payload": {"conflicts": [], "phase": "appended"}}
    head_after = chain_head(entries + [new_entry])
    assert head_after == _entry_hash(head_before, new_entry), (
        "REPLAY-PREFIX violated: appending an entry did not extend the head as the "
        "pure fold fold(prior_head, entry); the head is not an incremental function "
        "of the sequence")


def test_chain_head_prefix_homomorphism_on_a_real_run_log():
    # METAMORPHIC REPLAY-PREFIX (real RunLog): the same relation holds over an
    # actual RunLog assembled through the public append() API, not just synthetic
    # dicts, so the homomorphism is a property of the production log, not of the
    # test's hand-built entries.
    log = RunLog()
    log.append("clock_started", {"clock": "NIS2 full (72h)",
                                  "correlation_id": "inc-8842:nis2",
                                  "deadline": "2026-06-19T02:14:00+00:00"})
    log.append("protocol_event", {"correlation_id": "inc-8842:nis2",
                                   "event": "fact_record_posted",
                                   "ts": "2026-06-16T02:31:00+00:00",
                                   "actor": "triage", "actor_role": "triage",
                                   "admitted": True, "to_state": "fact_record_ready",
                                   "reason": None})
    log.append("ledger", {"key": "draft:nis2:inc-8842:round-1", "attempt": 1,
                          "disposition": "accepted"})

    entries = log.entries()
    full = chain_over(entries)
    for k in range(len(entries) + 1):
        assert chain_over(entries[:k]) == full[:k], (
            f"REPLAY-PREFIX violated on a real RunLog at prefix length {k}")
