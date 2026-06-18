"""The per-model hallucination leaderboard (scripts/model_leaderboard.py).

The leaderboard drafts one filing per model per incident, scores each with the
frozen grounding oracle, and tallies four per-model rates (ungrounded-span,
count-error, date-error, actor-error), each with a 95% interval from
floor/eval_stats.py. These tests pin that math on the committed cache so the whole
receipt re-runs KEYLESS:

  1. The rate tally is the EXACT oracle outcome over the cache: for each model the
     four counts equal an independent re-score of the cached filings, and each
     rate's point estimate is count/n.
  2. The eval_stats intervals are applied: every rate carries a Wilson and a
     seeded-bootstrap 95% interval bracketing the point, with n = the incident
     count.
  3. The scoring is deterministic: score() over the same corpus and cache returns
     byte-identical numbers on every call (no network, no clock, no RNG leak).
  4. A poisoned filing (an invented count and actor) is caught by the SAME oracle
     the leaderboard uses, so the tally is a real measurement, not a rigged 0.

No live model call anywhere in this file: the cache is the only model output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from floor.grounding import score_filing
from scripts.model_leaderboard import (
    MODELS,
    load_cache,
    load_corpus,
    score,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE = REPO_ROOT / "tests" / "fixtures" / "leaderboard_cache.json"


def _corpus_and_cache():
    return load_corpus(), load_cache()


def test_cache_covers_every_model_and_incident():
    corpus, cache = _corpus_and_cache()
    incident_ids = {e["id"] for e in corpus["entries"]}
    for _provider, model, _label, _kind, _mt in MODELS:
        assert model in cache["models"], f"cache missing model {model}"
        filings = cache["models"][model]["filings"]
        assert set(filings) == incident_ids, (
            f"model {model} cache does not cover exactly the corpus incidents")


def test_rate_counts_equal_independent_rescore():
    """The four per-model counts equal a fresh, independent re-score of the cached
    filings by the frozen oracle, so the tally is the oracle's verdict, not a
    pre-baked number in the cache."""
    corpus, cache = _corpus_and_cache()
    records = {e["id"]: e["fact_record"] for e in corpus["entries"]}
    result = score(corpus, cache)
    by_model = {r["model"]: r for r in result["rows"]}
    for _provider, model, _label, _kind, _mt in MODELS:
        filings = cache["models"][model]["filings"]
        exp_any = exp_count = exp_date = exp_actor = 0
        for incident_id, fact in records.items():
            res = score_filing(filings[incident_id], fact, branch="leaderboard")
            kinds = {u.kind for u in res.ungrounded}
            exp_any += 1 if kinds else 0
            exp_count += 1 if "number" in kinds else 0
            exp_date += 1 if "date" in kinds else 0
            exp_actor += 1 if "named_entity" in kinds else 0
        row = by_model[model]
        assert row["counts"]["ungrounded"] == exp_any
        assert row["counts"]["count_error"] == exp_count
        assert row["counts"]["date_error"] == exp_date
        assert row["counts"]["actor_error"] == exp_actor


def test_rate_point_is_count_over_n():
    corpus, cache = _corpus_and_cache()
    n = len(corpus["entries"])
    result = score(corpus, cache)
    for row in result["rows"]:
        assert row["n"] == n
        c = row["counts"]
        assert row["ungrounded_rate"]["point"] == pytest.approx(c["ungrounded"] / n)
        assert row["count_error_rate"]["point"] == pytest.approx(c["count_error"] / n)
        assert row["date_error_rate"]["point"] == pytest.approx(c["date_error"] / n)
        assert row["actor_error_rate"]["point"] == pytest.approx(c["actor_error"] / n)


def test_intervals_applied_and_bracket_the_point():
    """Every rate carries both eval_stats intervals (Wilson + seeded bootstrap),
    each bracketing the point, with n the incident count. This proves the
    floor/eval_stats.py intervals are actually applied to every leaderboard rate."""
    corpus, cache = _corpus_and_cache()
    n = len(corpus["entries"])
    result = score(corpus, cache)
    for row in result["rows"]:
        for key in ("ungrounded_rate", "count_error_rate", "date_error_rate",
                    "actor_error_rate"):
            ci = row[key]
            assert ci["n"] == n
            for method in ("wilson", "bootstrap"):
                m = ci[method]
                assert m["method"] == method
                assert 0.0 <= m["low"] <= ci["point"] <= m["high"] <= 1.0


def test_score_is_deterministic():
    corpus, cache = _corpus_and_cache()
    a = json.dumps(score(corpus, cache), sort_keys=True)
    b = json.dumps(score(corpus, cache), sort_keys=True)
    assert a == b


def test_oracle_catches_a_poisoned_filing():
    """The leaderboard's tally is only meaningful if the oracle it uses actually
    flags a hallucination. A filing with an invented count and an invented
    version-tagged actor must be flagged by the same score_filing the leaderboard
    calls, so a 0.00 rate means clean, not blind."""
    corpus, _cache = _corpus_and_cache()
    fact = corpus["entries"][0]["fact_record"]
    poisoned = (
        "On 16 June 2026, the BlackMatter 4.2 ransomware group exposed 9,500,000 "
        "records held by the entity.")
    res = score_filing(poisoned, fact, branch="poison")
    kinds = {u.kind for u in res.ungrounded}
    assert "number" in kinds
    assert "named_entity" in kinds


def test_every_model_source_is_labeled():
    """Each model row carries a source of 'live' or 'illustrative', so the receipt
    can state honestly whether a model's cached output is real or a stand-in."""
    corpus, cache = _corpus_and_cache()
    result = score(corpus, cache)
    for row in result["rows"]:
        assert row["source"] in ("live", "illustrative")
