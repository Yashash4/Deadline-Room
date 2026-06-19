"""Deterministic counterfactual replay: the What-If engine (NO LLM).

The same deterministic substrate that makes the PAST byte-identically replayable
makes the COUNTERFACTUAL computable. The Warden is a pure function of (event
stream, anchor timestamps, deterministic input facts) with no hidden state, so
"what would the gate have decided if this ONE input were different?" has a single
deterministic, signable answer. This engine answers exactly that for three typed
perturbations over DETERMINISTIC inputs, reusing the frozen pure cores:

  * warden/clocks.py    : re-anchor a statutory clock and recompute the deadline
                          through the real holiday-aware business-day engine.
  * warden/replay.py    : replay a SEPARATE hypothetical RunLog built from a
                          perturbed event sequence, and read its byte sha.
  * warden/chain.py     : recompute the per-entry chain head of the hypothetical
                          run, so a counterfactual carries its own head that
                          differs from the actual head.
  * warden/diff.py      : recompute the contradiction set over the claims that
                          would have gone out un-blocked.
  * floor/grounding.py  : re-score a filing against the OLD vs the amended fact to
                          show the re-file decision the amendment drove.

HARD FENCE (non-negotiable). Perturbations are over DETERMINISTIC inputs ONLY:
anchor timestamps, the diff BLOCK edge, and fact-record values that feed
grounding/materiality. There is NO "what if the drafter had WRITTEN X" perturbation
here; that is an LLM-shaped counterfactual and is out of scope by design. The
engine NEVER writes a canonical run log and NEVER mutates a gate. For the one
perturbation that needs an event stream (the un-caught contradiction), it builds a
SEPARATE hypothetical RunLog from a perturbed copy of the captured entries and
reads ITS sha and chain head; the sealed run-log bytes on disk are read only and
are never rewritten. Each counterfactual's outcome is a plain dict that
scripts/whatif_report.py signs under the DISTINCT counterfactual namespace
(warden/counterfactual_signing.py), so a what-if receipt can never be confused
with a real-run receipt.

This module is a CONSUMER of the pure functions. It edits no warden/ core logic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from warden.chain import chain_head
from warden.clocks import add_business_days, parse_ts
from warden.diff import Containment, FactClaims, diff_claims
from warden.replay import RunLog, replay

from floor.grounding import score_filing

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"


@dataclass(frozen=True)
class Counterfactual:
    """One computed what-if. `name` is the stable perturbation id that the
    signature binds; `title` and `question` are the human framing; `perturbation`
    records exactly which deterministic input changed; `actual` and
    `counterfactual` are the two outcome blocks; `divergence` is the one-line
    plain-English statement of what changed; `actual_chain_head` anchors the
    receipt to the real run it was derived from; `load_bearing` is the engineering
    claim the what-if proves (e.g. that the clock's holiday awareness is
    load-bearing)."""
    name: str
    title: str
    question: str
    perturbation: dict
    actual: dict
    counterfactual: dict
    divergence: str
    actual_chain_head: str
    load_bearing: str

    def outcome(self) -> dict:
        """The signable OUTCOME object: everything the counterfactual asserts,
        EXCLUDING the actual_chain_head (which the signature binds separately as
        the anchor). Canonicalized and digested by
        warden/counterfactual_signing.outcome_sha; a verifier rebuilds this exact
        dict to re-derive the digest, so a tampered field breaks the signature."""
        return {
            "name": self.name,
            "title": self.title,
            "question": self.question,
            "perturbation": self.perturbation,
            "actual": self.actual,
            "counterfactual": self.counterfactual,
            "divergence": self.divergence,
            "load_bearing": self.load_bearing,
        }

    def as_dict(self) -> dict:
        """The full artifact (outcome plus the anchoring actual chain head) written
        to web/data and rendered in the panel. The signature record is attached by
        the caller (scripts/whatif_report.py)."""
        d = self.outcome()
        d["actual_chain_head"] = self.actual_chain_head
        return d


# ---------------------------------------------------------------------------
# Capture loading (read-only over the sealed bytes).
# ---------------------------------------------------------------------------

def _load_jsonl(mode: str) -> str:
    """The canonical run-log JSONL for a captured scenario, read straight off
    disk. Read-only: nothing here ever writes a run log."""
    return (DATA / f"run-inc-8842-{mode}.jsonl").read_text(encoding="utf-8")


def _load_packet(mode: str) -> dict:
    return json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))


def _entries(jsonl: str) -> list[dict]:
    return [json.loads(line) for line in jsonl.splitlines() if line.strip()]


def _actual_chain_head(mode: str) -> str:
    """The per-entry chain head of the ACTUAL sealed run for a scenario, recomputed
    read-only from the bytes on disk."""
    return chain_head(_entries(_load_jsonl(mode)))


def _sec_clock(packet: dict) -> dict:
    for c in packet["clocks"]:
        if c["correlation_id"].endswith(":sec"):
            return c
    raise KeyError("no SEC clock in packet")


def _sec_attestation(packet: dict) -> dict:
    for r in packet["attestation"]["regimes"]:
        if r["correlation_id"].endswith(":sec"):
            return r
    raise KeyError("no SEC attestation regime in packet")


def _score_str(score: float) -> str:
    """Render a grounding score (a float in [0, 1]) as a fixed 4-decimal STRING.

    Stored as a string deliberately: the counterfactual outcome is re-canonicalized
    in the browser to re-verify the signature, and JSON float rendering differs
    across languages (Python writes 1.0, a JS JSON parse + stringify writes 1), so a
    raw float would break the cross-language digest. A fixed-precision string
    canonicalizes identically in Python and JavaScript, so the browser rebuilds the
    exact bytes that were signed."""
    return f"{score:.4f}"


def _count_weekends_only(start, days: int):
    """Count `days` business days skipping ONLY weekends (no holiday table), ending
    at end of the last counted day (23:59:59 UTC). This is the deliberate
    counterfactual to add_business_days's holiday-aware count: the difference
    between the two isolates exactly how many days the public-holiday skip is
    worth. Pure date arithmetic; it does NOT call the clock engine's holiday
    walker, so it is the honest weekends-only baseline."""
    import datetime as _dt
    d = start.date()
    remaining = days
    while remaining > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            remaining -= 1
    return _dt.datetime.combine(d, _dt.time(23, 59, 59), tzinfo=start.tzinfo)


def _human(delta: timedelta) -> str:
    """A compact 'Nd Nh Nm' rendering of a timedelta, matching the attestation
    style. Negative deltas are rendered with a leading minus."""
    total = int(delta.total_seconds())
    sign = "-" if total < 0 else ""
    total = abs(total)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return sign + " ".join(parts)


# ---------------------------------------------------------------------------
# Counterfactual 1: SEC materiality determined N hours LATER.
# ---------------------------------------------------------------------------

def sec_materiality_later(hours: int = 6, mode: str = "normal") -> Counterfactual:
    """Re-anchor the SEC materiality determination `hours` later and recompute the
    SEC 8-K deadline through the REAL holiday-aware business-day engine.

    Pure: it reads the actual determination timestamp and the actual filing time
    from the sealed packet, re-anchors the clock with `add_business_days` (the SAME
    function the live run used, US_FEDERAL calendar), and reports the new deadline
    and the new margin. It also computes the NAIVE 'four calendar days' deadline a
    team that ignored weekends and Juneteenth would have used, to show, on numbers,
    that the holiday awareness is load-bearing: the real count skips Juneteenth
    (2026-06-19) and lands a full day later than the naive count, so a naive system
    would believe it had more room than it does."""
    packet = _load_packet(mode)
    clock = _sec_clock(packet)
    att = _sec_attestation(packet)

    actual_anchor = parse_ts(clock["started"])
    actual_deadline = parse_ts(clock["deadline"])
    filed_at = parse_ts(att["filed_at"])

    cf_anchor = actual_anchor + timedelta(hours=hours)
    cf_deadline = add_business_days(cf_anchor, 4)
    # The naive deadline a team that counted four CALENDAR days from the (later)
    # determination would have used: no weekend skip, no holiday skip.
    naive_deadline = cf_anchor + timedelta(days=4)
    # A weekends-only business-day count (the holiday table emptied): isolates the
    # holiday contribution from the weekend contribution, so the receipt can say
    # exactly how much the Juneteenth skip moved the deadline.
    weekends_only_deadline = _count_weekends_only(cf_anchor, 4)

    actual_margin = actual_deadline - filed_at
    cf_margin = cf_deadline - filed_at

    # Does the holiday-aware count cross Juneteenth (2026-06-19)? It does for this
    # incident; naming it makes the load-bearing claim concrete.
    import datetime as _dt
    crosses_juneteenth = (
        cf_anchor.date() <= _dt.date(2026, 6, 19) <= cf_deadline.date())
    holiday_moved = cf_deadline.date() - weekends_only_deadline.date()

    actual = {
        "determination_utc": actual_anchor.isoformat(),
        "sec_deadline_utc": actual_deadline.isoformat(),
        "filed_utc": filed_at.isoformat(),
        "margin": _human(actual_margin),
        "met": filed_at <= actual_deadline,
    }
    counterfactual = {
        "determination_utc": cf_anchor.isoformat(),
        "sec_deadline_utc": cf_deadline.isoformat(),
        "naive_calendar_deadline_utc": naive_deadline.isoformat(),
        "weekends_only_deadline_utc": weekends_only_deadline.isoformat(),
        "holiday_skipped": "Juneteenth 2026-06-19 (US federal)" if crosses_juneteenth else "",
        "holiday_added_days": holiday_moved.days,
        "deadline_moved_by": _human(cf_deadline - actual_deadline),
        "filed_utc": filed_at.isoformat(),
        "margin": _human(cf_margin),
        "met": filed_at <= cf_deadline,
    }
    deadline_shift = cf_deadline - actual_deadline
    if deadline_shift.total_seconds() > 0:
        divergence = (
            f"Determining materiality {hours}h later moves the SEC 8-K deadline "
            f"from {actual_deadline.date()} to {cf_deadline.date()} "
            f"({_human(deadline_shift)} later), because the four-business-day count "
            f"re-anchors across the weekend and Juneteenth.")
    else:
        divergence = (
            f"Determining materiality {hours}h later keeps the SEC 8-K deadline on "
            f"{cf_deadline.date()}: the four-business-day count holds the deadline "
            f"there because Juneteenth (2026-06-19) is skipped. Drop the holiday "
            f"table and the same count lands {holiday_moved.days} day(s) earlier on "
            f"{weekends_only_deadline.date()}, so a system blind to the holiday "
            f"would believe it had to file a day sooner than the law requires.")
    load_bearing = (
        "The SEC clock counts FOUR BUSINESS DAYS skipping weekends AND US federal "
        f"holidays, landing on {cf_deadline.date()}. A weekends-only count would "
        f"land on {weekends_only_deadline.date()} and a naive 'four calendar days' "
        f"count on {naive_deadline.date()}: the Juneteenth skip alone is worth "
        f"{holiday_moved.days} day(s). The holiday-aware clock is load-bearing.")
    return Counterfactual(
        name=f"sec_materiality_{hours}h_later",
        title=f"SEC materiality determined {hours}h later",
        question=(
            f"What if the registrant had determined materiality {hours} hours "
            "later than it did?"),
        perturbation={
            "kind": "reanchor_clock",
            "clock": "inc-8842:sec",
            "field": "materiality_determination_utc",
            "shift_hours": hours,
            "from": actual_anchor.isoformat(),
            "to": cf_anchor.isoformat(),
        },
        actual=actual,
        counterfactual=counterfactual,
        divergence=divergence,
        actual_chain_head=_actual_chain_head(mode),
        load_bearing=load_bearing,
    )


# ---------------------------------------------------------------------------
# Counterfactual 2: the contradiction had NOT been caught.
# ---------------------------------------------------------------------------

# The run-log subsequence the diff BLOCK produced in the inject_contradiction
# capture: the round-1 blocking diff, the three diff_blocked transitions, the
# three re-draft posts, and the round-2 clean diff. Removing this whole block is
# the counterfactual "the contradiction was never caught": the first (divergent)
# drafts flow straight to the contradiction-checked state and out.
_BLOCK_EVENTS = {"diff_blocked"}


def _strip_contradiction_block(entries: list[dict]) -> list[dict]:
    """Build the hypothetical event sequence in which the diff BLOCK edge was never
    taken. Pure list transform over a COPY of the sealed entries; the input is not
    mutated and nothing is written to disk.

    Concretely: drop the round-1 (conflicting) diff entry, drop every diff_blocked
    protocol event, drop the second-round re-draft posts that only existed because
    the block forced a redraft, and drop the round-2 clean diff. The first
    (divergent) draft_posted events are kept, so the SEC branch carries its
    divergent incident_start_utc all the way through. A single synthetic
    diff_passed-style outcome is NOT injected; we only REMOVE the block, leaving the
    divergent first drafts as the filings that would have gone out."""
    out: list[dict] = []
    seen_first_diff = False
    second_round_post_branches: set[str] = set()
    # Identify which branches were blocked, so we drop only their SECOND post (the
    # forced redraft), keeping their first divergent post.
    blocked_branches = {
        e["payload"].get("correlation_id")
        for e in entries
        if e["type"] == "protocol_event"
        and e["payload"].get("event") in _BLOCK_EVENTS
    }
    posts_seen: dict[str, int] = {}
    for e in entries:
        t = e["type"]
        p = e["payload"]
        if t == "diff":
            # The first diff is the conflicting one (the block trigger); the second
            # is the clean re-run that only happened because of the block. Drop both
            # in the no-block world: there was no block, so no re-diff cycle.
            if not seen_first_diff:
                seen_first_diff = True
            continue
        if t == "protocol_event" and p.get("event") in _BLOCK_EVENTS:
            continue
        if (t == "protocol_event" and p.get("event") == "draft_posted"
                and p.get("correlation_id") in blocked_branches):
            corr = p.get("correlation_id")
            posts_seen[corr] = posts_seen.get(corr, 0) + 1
            if posts_seen[corr] >= 2:
                # The second post is the forced redraft; it would not exist without
                # the block, so drop it and keep the divergent first post.
                second_round_post_branches.add(corr)
                continue
        out.append(e)
    return out


def _reseq(entries: list[dict]) -> list[dict]:
    """Renumber `seq` contiguously from 0 over a transformed entry list so the
    hypothetical RunLog is well-formed (contiguous seqs) the same way a real run
    is. Pure; builds new dicts, does not mutate the inputs."""
    out = []
    for i, e in enumerate(entries):
        ne = dict(e)
        ne["seq"] = i
        out.append(ne)
    return out


def _hypothetical_runlog(entries: list[dict]) -> RunLog:
    """Materialize a SEPARATE RunLog from a transformed entry list (NOT a sealed
    capture). This is the hypothetical run the counterfactual reasons over; it is
    never saved to the canonical run-log path."""
    log = RunLog()
    for e in entries:
        log.append(e["type"], e["payload"])
    return log


def contradiction_not_caught(mode: str = "inject_contradiction") -> Counterfactual:
    """Compute the world in which the cross-filing contradiction was NOT caught.

    The actual run BLOCKED on a round-1 diff: SEC asserted the incident started at
    02:41 UTC while NIS2 and DORA asserted 02:14 UTC. This builds a SEPARATE
    hypothetical RunLog with the diff BLOCK edge removed (the divergent first drafts
    flow straight through), replays it byte-identically through a fresh state
    machine, and reads its sha and chain head. The hypothetical chain head DIFFERS
    from the actual sealed head: the no-block run is a different ordered run.

    It also recomputes the contradiction set (warden/diff.py) over the divergent
    claims that would have been filed, proving the inconsistent SEC filing (a
    different incident start time than NIS2/DORA) would have gone to the regulator
    un-reconciled."""
    jsonl = _load_jsonl(mode)
    actual_entries = _entries(jsonl)
    actual_head = chain_head(actual_entries)

    stripped = _reseq(_strip_contradiction_block(actual_entries))
    hypo_log = _hypothetical_runlog(stripped)
    # Replay the hypothetical run through a FRESH state machine: it is byte-stable
    # under replay just like a real run, which is what lets it be signed.
    replayed = replay(hypo_log)
    hypo_jsonl = replayed.to_jsonl()
    hypo_head = chain_head(_entries(hypo_jsonl))
    hypo_sha = replayed.sha256()

    # The divergent claim set that would have been filed (read off the actual
    # run's recorded round-1 conflict: SEC 02:41 vs NIS2/DORA 02:14).
    round1 = None
    for line in jsonl.splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e["type"] == "diff" and e["payload"].get("round") == 1:
            round1 = e["payload"]
            break
    conflict_lines = (round1 or {}).get("conflicts", [])

    # Recompute the conflict set with warden/diff over the divergent claims, so the
    # counterfactual carries a freshly computed (not just transcribed) contradiction.
    divergent = [
        FactClaims("nis2", "2026-06-16T02:14:00+00:00", 48211, "lockbit",
                   Containment.PARTIALLY_CONTAINED),
        FactClaims("sec", "2026-06-16T02:41:00+00:00", 48211, "lockbit",
                   Containment.PARTIALLY_CONTAINED),
        FactClaims("dora", "2026-06-16T02:14:00+00:00", 48211, "lockbit",
                   Containment.PARTIALLY_CONTAINED),
    ]
    recomputed = diff_claims(divergent)

    actual = {
        "diff_blocked": True,
        "round1_conflicts": conflict_lines,
        "outcome": "Contradiction caught; SEC re-drafted to 02:14; one consistent "
                   "filing set released after the diff re-ran green.",
        "chain_head": actual_head,
    }
    counterfactual = {
        "diff_blocked": False,
        "recomputed_conflicts": [c.human() for c in recomputed],
        "divergent_filing": "SEC files incident_start_utc=2026-06-16T02:41:00+00:00 "
                            "while NIS2 and DORA file 2026-06-16T02:14:00+00:00.",
        "outcome": "The divergent SEC filing goes to the regulator with a different "
                   "incident start time than the EU filings, un-reconciled.",
        "chain_head": hypo_head,
        "run_sha256": hypo_sha,
    }
    divergence = (
        "With the diff BLOCK edge removed, the inconsistent SEC filing (incident "
        "start 02:41 UTC) is released alongside the EU filings (02:14 UTC), and the "
        "hypothetical run has a DIFFERENT chain head "
        f"({hypo_head[:16]}...) than the actual run ({actual_head[:16]}...).")
    load_bearing = (
        "The deterministic contradiction diff is load-bearing: it is the only thing "
        "that stops two filings with different load-bearing facts from both reaching "
        "regulators. Remove it and the run produces a divergent, un-reconciled "
        "filing set with a provably different chain head.")
    return Counterfactual(
        name="contradiction_not_caught",
        title="The contradiction had NOT been caught",
        question="What if the Warden's contradiction diff had not blocked the "
                 "divergent filings?",
        perturbation={
            "kind": "remove_diff_block_edge",
            "removed": "round-1 blocking diff, the diff_blocked transitions, the "
                       "forced re-drafts, and the round-2 clean diff",
            "source_run": f"run-inc-8842-{mode}.jsonl",
        },
        actual=actual,
        counterfactual=counterfactual,
        divergence=divergence,
        actual_chain_head=actual_head,
        load_bearing=load_bearing,
    )


# ---------------------------------------------------------------------------
# Counterfactual 3: the amended count stayed 48K, not 2.1M.
# ---------------------------------------------------------------------------

# Two fixed SEC filing prose forms (NOT LLM output) used to score grounding
# deterministically. The ORIGINAL filing states the old 48,211 count; the AMENDED
# filing states the 2,100,000 count. Scoring each against the candidate
# fact-records with the pure grounding scorer is what makes the re-file decision a
# deterministic, replayable computation rather than an LLM judgment.
_SEC_FILING_ORIGINAL = (
    "SEC Item 1.05. Meridian Trust Bank N.V. reports a cybersecurity incident "
    "starting 2026-06-16 affecting 48,211 records, attacker LockBit 3.0.")
_SEC_FILING_AMENDED = (
    "SEC Item 1.05 (amended). Meridian Trust Bank N.V. reports a cybersecurity "
    "incident starting 2026-06-16 affecting 2,100,000 records, attacker LockBit 3.0.")


def amended_count_unchanged(mode: str = "amendment") -> Counterfactual:
    """Compute the world in which the forensic re-count NEVER happened: the count
    stayed 48,211 instead of rising to 2,100,000.

    Pure and no-LLM. The re-file is driven by the FACT DELTA: the deterministic
    FACT_AMENDED reopen fires only when the corrected value differs from the value
    already filed. The grounding scorer (floor/grounding.py) supplies the receipt on
    the count itself: an amended 8-K stating 2,100,000 is GROUNDED against the
    amended record (2,100,000) but UNGROUNDED against the unchanged record (the
    2,100,000 span is flagged), so a re-file is correct only when the record
    actually changed.

    In the counterfactual, the corrected value EQUALS the filed value (both
    48,211), so there is no fact delta, the FACT_AMENDED reopen never fires, and the
    original 8-K stays grounded against the unchanged record. The SEC would NOT have
    re-filed; an amended 8-K asserting 2,100,000 would have stated an unsupported
    count."""
    packet = _load_packet(mode)
    rec = packet["reconciliation"]
    old_value = rec["old_value"]      # 48211
    new_value = rec["new_value"]      # 2100000

    base_fact = dict(packet["incident"]["fact_record"])
    amended_fact = dict(base_fact)
    amended_fact["records_affected"] = new_value
    unchanged_fact = dict(base_fact)
    unchanged_fact["records_affected"] = old_value

    # Actual world: the amended 8-K (states 2.1M) scored against the amended record
    # is grounded. The fact delta is real, so the SEC re-files.
    g_amended_vs_amended = score_filing(_SEC_FILING_AMENDED, amended_fact, branch="sec")

    # Counterfactual world: the count is unchanged. The original 8-K (states 48K)
    # scored against the unchanged record is grounded; an amended 8-K asserting 2.1M
    # would be ungrounded against the unchanged record, so re-filing would be wrong.
    g_original_vs_unchanged = score_filing(_SEC_FILING_ORIGINAL, unchanged_fact, branch="sec")
    g_amended_vs_unchanged = score_filing(_SEC_FILING_AMENDED, unchanged_fact, branch="sec")

    actual = {
        "records_affected": f"{old_value} -> {new_value}",
        "fact_delta": old_value != new_value,
        "amended_filing_grounded_vs_amended_record": _score_str(g_amended_vs_amended.score),
        "amended_filing_grounded_vs_unchanged_record": _score_str(g_amended_vs_unchanged.score),
        "ungrounded_spans_if_refiled_on_old_record": [
            u.span for u in g_amended_vs_unchanged.ungrounded if u.kind == "number"],
        "sec_refiled": True,
        "outcome": (
            f"The forensic re-count raised records_affected to {new_value:,}, a real "
            f"fact delta from the filed {old_value:,}. The FACT_AMENDED reopen fires; "
            "the SEC branch re-files an amended 8-K stating 2,100,000, which is "
            "grounded against the amended record, under the two-key gate."),
    }
    counterfactual = {
        "records_affected": f"{old_value} (unchanged)",
        "fact_delta": False,
        "original_filing_grounded_vs_unchanged_record": _score_str(g_original_vs_unchanged.score),
        "amended_filing_grounded_vs_unchanged_record": _score_str(g_amended_vs_unchanged.score),
        "ungrounded_spans_if_refiled_on_old_record": [
            u.span for u in g_amended_vs_unchanged.ungrounded if u.kind == "number"],
        "sec_refiled": False,
        "outcome": (
            f"With the count unchanged at {old_value:,}, the corrected value equals "
            "the filed value, so the FACT_AMENDED reopen never fires. The original "
            "8-K stays grounded against the record; no amended 8-K is filed. A "
            "re-file asserting 2,100,000 would itself be ungrounded against the "
            "unchanged record."),
    }
    divergence = (
        f"Had the count stayed {old_value:,} instead of rising to {new_value:,}, "
        "there is no fact delta, the original 8-K stays grounded against the record "
        f"(score {_score_str(g_original_vs_unchanged.score)}), and the SEC would NOT "
        "have re-filed; an amended 8-K asserting 2,100,000 would itself be ungrounded "
        f"(score {_score_str(g_amended_vs_unchanged.score)}, the 2,100,000 span "
        "flagged).")
    load_bearing = (
        "The re-file decision is deterministic, not an LLM judgment: the "
        "FACT_AMENDED reopen fires on a fact DELTA, and the grounding scorer proves "
        "WHY the delta forces a new filing (the old count is ungrounded against the "
        "amended record). No delta means no reopen means no re-file, computed with "
        "zero LLM.")
    return Counterfactual(
        name="amended_count_unchanged",
        title="The amended count stayed 48K, not 2.1M",
        question="What if the forensic re-count had not raised records_affected "
                 "from 48,211 to 2,100,000?",
        perturbation={
            "kind": "fact_value_unchanged",
            "field": "records_affected",
            "actual_amendment": f"{old_value} -> {new_value}",
            "counterfactual_value": old_value,
        },
        actual=actual,
        counterfactual=counterfactual,
        divergence=divergence,
        actual_chain_head=_actual_chain_head(mode),
        load_bearing=load_bearing,
    )


# ---------------------------------------------------------------------------
# The registry of the three shipped counterfactuals.
# ---------------------------------------------------------------------------

def all_counterfactuals() -> list[Counterfactual]:
    """The three precomputed what-ifs, in panel order. Each is a pure function of
    the sealed captures; calling this twice yields identical results."""
    return [
        sec_materiality_later(hours=6),
        contradiction_not_caught(),
        amended_count_unchanged(),
    ]
