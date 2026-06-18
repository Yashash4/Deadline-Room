"""The open vs closed head-to-head (scripts/open_vs_closed.py).

The receipt runs the OPEN models (DeepSeek-V3.2, MiniMax-M2.7, Qwen2.5-72B) and
the CLOSED models (claude-opus-4-1, gpt-5-chat-latest) on the two gate judgments,
both sides graded by the SAME frozen no-LLM oracle: materiality accuracy against
the human label, and faithfulness via the grounding oracle. These tests pin the
math on the committed cache so the whole receipt re-runs KEYLESS:

  1. Per-model materiality accuracy equals an independent re-count of the cached
     verdicts against the human labels; per-model faithfulness equals an
     independent re-score of the cached filings by floor/grounding.py.
  2. The open-vs-closed side tallies are the exact sum of their members: the open
     side aggregates the three Featherless models, the closed side the two AI/ML
     models, on both judgments.
  3. The eval_stats intervals are applied to every rate (Wilson + seeded
     bootstrap), each bracketing its point, with the right n.
  4. The scoring is deterministic: same corpora + same cache -> byte-identical
     numbers on every call.

No live model call anywhere in this file: the cache is the only model output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from floor.grounding import score_filing
from scripts.open_vs_closed import (
    ALL_MODELS,
    CLOSED_MODELS,
    IMMATERIAL,
    MATERIAL,
    OPEN_MODELS,
    THRESHOLD,
    _faithfulness_records,
    load_cache,
    load_grounding_corpus,
    load_materiality_corpus,
    score,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _inputs():
    return (load_materiality_corpus(), load_grounding_corpus(), load_cache())


def test_cache_covers_every_model_and_both_judgments():
    mat_corpus, grounding_corpus, cache = _inputs()
    mat_ids = {e["id"] for e in mat_corpus["entries"]}
    record_ids = set(_faithfulness_records(grounding_corpus))
    for _provider, model, _label, _mt, _ft in ALL_MODELS:
        assert model in cache["models"], f"cache missing model {model}"
        mc = cache["models"][model]
        assert set(mc["materiality"]) == mat_ids, (
            f"{model} materiality cache does not cover the corpus")
        assert set(mc["faithfulness"]) == record_ids, (
            f"{model} faithfulness cache does not cover the records")


def test_per_model_materiality_matches_independent_count():
    mat_corpus, grounding_corpus, cache = _inputs()
    result = score(mat_corpus, grounding_corpus, cache)
    by_model = {m["model"]: m for m in result["models"]}
    truth = {e["id"]: e["label"] for e in mat_corpus["entries"]}
    for _provider, model, _label, _mt, _ft in ALL_MODELS:
        verdicts = cache["models"][model]["materiality"]
        correct = 0
        for item_id, label in truth.items():
            v = verdicts[item_id]["material"]
            predicted = MATERIAL if v else IMMATERIAL
            correct += 1 if predicted == label else 0
        row = by_model[model]
        assert row["materiality_correct"] == correct
        assert row["materiality_total"] == len(truth)
        assert row["materiality_accuracy"]["point"] == pytest.approx(
            correct / len(truth))


def test_per_model_faithfulness_matches_independent_rescore():
    mat_corpus, grounding_corpus, cache = _inputs()
    records = _faithfulness_records(grounding_corpus)
    result = score(mat_corpus, grounding_corpus, cache)
    by_model = {m["model"]: m for m in result["models"]}
    for _provider, model, _label, _mt, _ft in ALL_MODELS:
        filings = cache["models"][model]["faithfulness"]
        faithful = 0
        for record_id, fact in records.items():
            res = score_filing(filings[record_id], fact, branch=record_id)
            faithful += 1 if res.score >= THRESHOLD else 0
        row = by_model[model]
        assert row["faithful"] == faithful
        assert row["faithful_total"] == len(records)
        assert row["faithfulness_rate"]["point"] == pytest.approx(
            faithful / len(records))


def test_side_tally_is_sum_of_members():
    """The open side aggregates exactly the three Featherless models and the closed
    side exactly the two AI/ML models, on both judgments."""
    mat_corpus, grounding_corpus, cache = _inputs()
    result = score(mat_corpus, grounding_corpus, cache)
    by_model = {m["model"]: m for m in result["models"]}
    sides = {
        "open": [m for _p, m, _l, _mt, _ft in OPEN_MODELS],
        "closed": [m for _p, m, _l, _mt, _ft in CLOSED_MODELS],
    }
    for side, members in sides.items():
        exp_mat_correct = sum(by_model[m]["materiality_correct"] for m in members)
        exp_mat_total = sum(by_model[m]["materiality_total"] for m in members)
        exp_faith = sum(by_model[m]["faithful"] for m in members)
        exp_faith_total = sum(by_model[m]["faithful_total"] for m in members)
        s = result["sides"][side]
        assert s["materiality_correct"] == exp_mat_correct
        assert s["materiality_total"] == exp_mat_total
        assert s["faithful"] == exp_faith
        assert s["faithful_total"] == exp_faith_total
        assert s["materiality_accuracy"]["point"] == pytest.approx(
            exp_mat_correct / exp_mat_total)
        assert s["faithfulness_rate"]["point"] == pytest.approx(
            exp_faith / exp_faith_total)


def test_intervals_applied_and_bracket_the_point():
    mat_corpus, grounding_corpus, cache = _inputs()
    result = score(mat_corpus, grounding_corpus, cache)
    targets = [(m["materiality_accuracy"], m["materiality_total"]) for m in result["models"]]
    targets += [(m["faithfulness_rate"], m["faithful_total"]) for m in result["models"]]
    for side in result["sides"].values():
        targets.append((side["materiality_accuracy"], side["materiality_total"]))
        targets.append((side["faithfulness_rate"], side["faithful_total"]))
    for ci, n in targets:
        assert ci["n"] == n
        for method in ("wilson", "bootstrap"):
            m = ci[method]
            assert m["method"] == method
            assert 0.0 <= m["low"] <= ci["point"] <= m["high"] <= 1.0


def test_score_is_deterministic():
    mat_corpus, grounding_corpus, cache = _inputs()
    a = json.dumps(score(mat_corpus, grounding_corpus, cache), sort_keys=True)
    b = json.dumps(score(mat_corpus, grounding_corpus, cache), sort_keys=True)
    assert a == b


def test_oracle_catches_a_poisoned_filing():
    """The faithfulness side is only meaningful if its oracle flags a
    hallucination. A filing with an invented count must be flagged by the same
    score_filing the head-to-head uses."""
    _mat, grounding_corpus, _cache = _inputs()
    fact = grounding_corpus["fact_record"]
    poisoned = (
        "On 16 June 2026, LockBit 3.0 exposed 9,500,000 records held by "
        "Meridian Trust Bank N.V.")
    res = score_filing(poisoned, fact, branch="poison")
    assert res.score < THRESHOLD


def test_every_model_source_is_labeled():
    mat_corpus, grounding_corpus, cache = _inputs()
    result = score(mat_corpus, grounding_corpus, cache)
    for m in result["models"]:
        assert m["source"] in ("live", "illustrative")
