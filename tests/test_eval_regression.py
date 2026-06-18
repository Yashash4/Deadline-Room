"""The regression-on-prompt-change eval gate (scripts/eval_regression.py).

The gate recomputes the scoring-side faithfulness metrics over the committed corpora
and model-output caches and fails CI when any metric regresses past its committed
bound. These tests prove the gate works without a single live model call:

  1. On the committed baseline the gate PASSES (exits 0) and reports no regression.
  2. A synthetic degraded input (a lowered metric written into a temp copy of the
     baseline) makes the gate FAIL nonzero, and the regressed metric is named.
  3. The baseline file round-trips: every metric recomputed from the live scoring
     state matches the committed baseline within rounding, so the committed file is
     an honest snapshot, not a stale guess.
  4. The recompute is deterministic: same inputs -> byte-identical metrics.

The gate is keyless and offline; nothing here calls a model or reads a key.
"""

from __future__ import annotations

import json

import pytest

from scripts.eval_regression import (
    Comparison,
    build_comparisons,
    compute_metrics,
    load_baseline,
    run_gate,
)


def test_gate_passes_on_the_committed_baseline():
    """The committed baseline is the current scoring state, so the gate exits 0 and
    no comparison is marked regressed."""
    assert run_gate() == 0
    baseline = load_baseline()
    metrics = compute_metrics()
    comparisons = build_comparisons(baseline, metrics)
    regressed = [c.name for c in comparisons if c.regressed]
    assert regressed == [], f"unexpected regressions on the baseline: {regressed}"


def test_recompute_matches_the_committed_baseline():
    """Every metric recomputed from the live scoring state equals the committed
    baseline within rounding, so the committed file round-trips."""
    baseline = load_baseline()
    metrics = compute_metrics()

    assert metrics["corpus"]["precision"] == pytest.approx(
        baseline["corpus"]["precision"]["baseline"], abs=1e-4)
    assert metrics["corpus"]["recall"] == pytest.approx(
        baseline["corpus"]["recall"]["baseline"], abs=1e-4)
    assert metrics["corpus"]["confusion"] == baseline["corpus"]["confusion"]

    for model, base_rates in baseline["leaderboard"]["models"].items():
        meas = metrics["leaderboard"]["models"][model]
        for rate, value in base_rates.items():
            assert meas[rate] == pytest.approx(value, abs=1e-4)

    for model, base_m in baseline["open_vs_closed"]["models"].items():
        meas = metrics["open_vs_closed"]["models"][model]
        assert meas["faithfulness_rate"] == pytest.approx(
            base_m["faithfulness_rate"], abs=1e-4)
        assert meas["materiality_accuracy"] == pytest.approx(
            base_m["materiality_accuracy"], abs=1e-4)


def test_synthetic_precision_drop_fails_the_gate():
    """Lowering the MEASURED corpus precision below the floor (simulating a scorer that
    silently lost accuracy) makes the comparison regress and the gate fail."""
    baseline = load_baseline()
    metrics = compute_metrics()
    # Force the measured precision under the committed floor.
    floor = baseline["corpus"]["precision"]["floor"]
    metrics["corpus"]["precision"] = floor - 0.2
    comparisons = build_comparisons(baseline, metrics)
    regressed = [c.name for c in comparisons if c.regressed]
    assert "corpus.precision" in regressed


def test_synthetic_recall_drop_fails_the_gate():
    """A recall drop below the floor is a regression naming corpus.recall."""
    baseline = load_baseline()
    metrics = compute_metrics()
    floor = baseline["corpus"]["recall"]["floor"]
    metrics["corpus"]["recall"] = floor - 0.1
    comparisons = build_comparisons(baseline, metrics)
    assert "corpus.recall" in [c.name for c in comparisons if c.regressed]


def test_synthetic_leaderboard_rate_rise_fails_the_gate():
    """A per-model error rate rising above the ceiling (the scorer newly false-flagging
    a clean cached filing) is a regression in the lower-is-better direction."""
    baseline = load_baseline()
    metrics = compute_metrics()
    model = next(iter(baseline["leaderboard"]["models"]))
    ceiling = baseline["leaderboard"]["ceiling"]
    metrics["leaderboard"]["models"][model]["count_error_rate"] = ceiling + 0.3
    comparisons = build_comparisons(baseline, metrics)
    regressed = [c.name for c in comparisons if c.regressed]
    assert f"leaderboard.{model}.count_error_rate" in regressed


def test_synthetic_faithfulness_drop_fails_the_gate():
    """A per-model faithfulness rate dropping below the floor is a regression."""
    baseline = load_baseline()
    metrics = compute_metrics()
    model = next(iter(baseline["open_vs_closed"]["models"]))
    floor = baseline["open_vs_closed"]["faithfulness_floor"]
    metrics["open_vs_closed"]["models"][model]["faithfulness_rate"] = floor - 0.1
    comparisons = build_comparisons(baseline, metrics)
    regressed = [c.name for c in comparisons if c.regressed]
    assert f"open_vs_closed.{model}.faithfulness_rate" in regressed


def test_gate_fails_nonzero_on_a_degraded_baseline_copy(tmp_path, monkeypatch):
    """End-to-end: point the gate at a TEMP baseline whose recorded floor is set above
    the achievable metric, so the live recompute falls below it and run_gate() exits
    nonzero. This exercises the full run_gate path, not just build_comparisons."""
    import scripts.eval_regression as mod

    baseline = load_baseline()
    # Raise the precision floor above 1.0 so any real measured precision regresses.
    baseline["corpus"]["precision"]["floor"] = 1.5
    degraded = tmp_path / "eval_baseline_degraded.json"
    degraded.write_text(json.dumps(baseline), encoding="utf-8")
    monkeypatch.setattr(mod, "BASELINE", degraded)

    assert mod.run_gate() == 1


def test_within_tolerance_is_not_a_regression():
    """A metric that dips by less than the tolerance and stays above the floor is NOT a
    regression: the gate allows benign re-tuning slack."""
    baseline = load_baseline()
    tol = baseline["tolerance"]
    base = 0.9
    floor = 0.5
    # A dip smaller than the tolerance, still above the floor.
    c = Comparison("x", base - tol / 2, base, floor, "higher_is_better", tol)
    assert not c.regressed
    # A dip larger than the tolerance is a regression even above the floor.
    c2 = Comparison("x", base - tol * 2, base, floor, "higher_is_better", tol)
    assert c2.regressed


def test_compute_metrics_is_deterministic():
    a = json.dumps(compute_metrics(), sort_keys=True)
    b = json.dumps(compute_metrics(), sort_keys=True)
    assert a == b
