"""The pure eval statistics: Wilson interval, seeded bootstrap, and ablation.

floor/eval_stats.py answers the two questions an ML-eval reviewer asks of the
single-point grounding metric: "what is the uncertainty at n=20" (a 95%
confidence interval two independent ways) and "does the deterministic guard earn
its place" (an ablation of guard ON vs a pass-everything baseline). These tests
pin the interval math on hand-checkable inputs, pin the ablation row counts and
the guard-on-beats-guard-off result on the corpus, and prove the bootstrap is
deterministic (same seed -> identical interval), which is what keeps the receipt
byte-reproducible.
"""

import json
import math
from pathlib import Path

import pytest

from floor.eval_stats import (
    Z_95,
    AblationResult,
    ProportionCI,
    bootstrap_interval,
    proportion_ci,
    run_ablation,
    wilson_interval,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "tests" / "fixtures" / "grounding_corpus.json"


def _load_corpus():
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def pytest_approx(value):
    """Tight tolerance so the interval bounds are pinned, not loosely asserted."""
    return pytest.approx(value, abs=1e-9)


# --- Wilson score interval, pinned on hand-computable inputs ---------------
def _wilson_by_hand(s: int, n: int) -> tuple[float, float]:
    """The Wilson 95% bounds recomputed from first principles, independent of the
    module, so the test is a real cross-check and not the implementation copied."""
    p = s / n
    z = Z_95
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1.0 - p) / n + z2 / (4 * n * n))
    return center - margin, center + margin


def test_wilson_interval_matches_hand_computation():
    # The corpus's actual precision (6 of 7 flagged are real) and recall (6 of
    # 10 hallucinations caught) plus a clean midpoint case.
    for s, n in ((6, 7), (6, 10), (8, 10), (5, 10)):
        ci = wilson_interval(s, n)
        assert ci.method == "wilson"
        assert ci.n == n
        assert ci.point == s / n
        low, high = _wilson_by_hand(s, n)
        assert ci.low == pytest_approx(low)
        assert ci.high == pytest_approx(high)


def test_wilson_interval_is_symmetric_at_one_half():
    # At p = 0.5 the Wilson interval is symmetric about 0.5.
    ci = wilson_interval(5, 10)
    assert ci.point == 0.5
    assert ci.low == pytest_approx(1.0 - ci.high)


def test_wilson_interval_stays_in_unit_range_at_edges():
    # 0 successes -> lower bound exactly 0; n successes -> upper bound exactly 1.
    zero = wilson_interval(0, 10)
    assert zero.low == 0.0
    assert 0.0 < zero.high < 1.0
    allhit = wilson_interval(10, 10)
    assert allhit.high == 1.0
    assert 0.0 < allhit.low < 1.0


def test_wilson_interval_handles_empty_n():
    # No observations: point 1.0 over the widest possible interval, so the
    # absence of data is visible rather than a spurious tight band.
    ci = wilson_interval(0, 0)
    assert ci.point == 1.0
    assert (ci.low, ci.high) == (0.0, 1.0)
    assert ci.n == 0


def test_wilson_interval_rejects_bad_counts():
    with pytest.raises(ValueError):
        wilson_interval(8, 5)
    with pytest.raises(ValueError):
        wilson_interval(-1, 5)


# --- the seeded bootstrap, pinned and proven deterministic -----------------
def test_bootstrap_interval_is_deterministic_across_calls():
    # The headline property: the same samples and the same seed yield a
    # byte-identical interval, which is what keeps the printed receipt
    # reproducible run to run.
    samples = [1] * 6 + [0] * 4
    a = bootstrap_interval(samples, seed=20260618)
    b = bootstrap_interval(samples, seed=20260618)
    assert a == b
    assert a.as_dict() == b.as_dict()


def test_bootstrap_interval_point_equals_sample_mean():
    samples = [1] * 6 + [0] * 4
    ci = bootstrap_interval(samples, seed=20260618)
    assert ci.point == 0.6
    assert ci.method == "bootstrap"
    assert ci.n == 10
    # The percentile bounds bracket the point estimate.
    assert ci.low <= ci.point <= ci.high


def test_bootstrap_interval_pinned_bounds_on_known_input():
    # Pin the exact bounds the default-seeded bootstrap produces for 6/10, so a
    # change to the resampling logic is caught. These are byte-stable.
    ci = bootstrap_interval([1] * 6 + [0] * 4, seed=20260618)
    assert ci.low == pytest_approx(0.3)
    assert ci.high == pytest_approx(0.9)


def test_bootstrap_interval_rejects_non_binary_samples():
    with pytest.raises(ValueError):
        bootstrap_interval([1, 0, 2], seed=1)


def test_bootstrap_all_successes_collapses_to_one():
    ci = bootstrap_interval([1] * 8, seed=20260618)
    assert ci.point == 1.0
    assert ci.low == 1.0
    assert ci.high == 1.0


# --- proportion_ci bundles both estimators ---------------------------------
def test_proportion_ci_carries_both_intervals_and_n():
    out = proportion_ci(6, 7)
    assert out["n"] == 7
    # The bundled point is rounded for display; it matches 6/7 to 4 places.
    assert out["point"] == round(6 / 7, 4)
    assert out["wilson"]["method"] == "wilson"
    assert out["bootstrap"]["method"] == "bootstrap"
    # Both estimators agree on the point estimate.
    assert out["wilson"]["point"] == out["bootstrap"]["point"]


def test_proportion_ci_is_deterministic():
    a = proportion_ci(6, 10, seed=20260618)
    b = proportion_ci(6, 10, seed=20260618)
    assert a == b


# --- the ablation over the real corpus -------------------------------------
def test_run_ablation_row_counts_on_corpus():
    # Guard ON is the real scorer: the corpus yields exactly this confusion
    # matrix (6 hallucinations caught, 1 boilerplate false positive, 9 faithful
    # cleared, 4 hallucinations missed by design).
    corpus = _load_corpus()
    res = run_ablation(corpus)
    assert isinstance(res, AblationResult)
    assert res.n == 20
    on = res.guard_on
    assert (on.tp, on.fp, on.tn, on.fn) == (6, 1, 9, 4)
    assert on.precision == pytest_approx(6 / 7)
    assert on.recall == pytest_approx(0.6)
    # Guard OFF flags nothing: every truth-positive is a false negative, every
    # truth-negative a true negative, and no positive prediction is ever made.
    off = res.guard_off
    assert (off.tp, off.fp, off.tn, off.fn) == (0, 0, 10, 10)
    assert off.recall == 0.0
    # The on and off arms partition the same 20 entries identically.
    assert on.tp + on.fp + on.tn + on.fn == 20
    assert off.tp + off.fp + off.tn + off.fn == 20


def test_guard_on_strictly_beats_guard_off_on_recall():
    # The deterministic spine's measured value: it catches real hallucinations
    # the pass-everything baseline misses entirely. Recall is the metric that
    # actually counts catches, and the guard strictly wins there.
    corpus = _load_corpus()
    res = run_ablation(corpus)
    assert res.guard_on.recall > res.guard_off.recall
    assert res.recall_delta == pytest_approx(0.6)
    # The baseline's precision is the vacuous no-prediction 1.0, so the guard
    # does not beat it on precision; the test states this honestly rather than
    # overclaiming.
    assert res.guard_off.precision == 1.0
    assert res.precision_delta == pytest_approx(6 / 7 - 1.0)


def test_run_ablation_is_pure_and_deterministic():
    corpus = _load_corpus()
    a = run_ablation(corpus).as_dict()
    b = run_ablation(corpus).as_dict()
    assert a == b


def test_run_ablation_accepts_injected_scorer():
    # The score_fn seam lets E5.2 / E5.4 reuse the ablation with a different
    # scorer. A degenerate flag-everything scorer makes every entry a positive,
    # so recall is 1.0 and precision is the hallucinated fraction.
    corpus = _load_corpus()

    class _Flagged:
        score = 0.0  # below threshold for every filing

    def flag_everything(text, record, *, branch=""):
        return _Flagged()

    res = run_ablation(corpus, score_fn=flag_everything)
    on = res.guard_on
    assert on.fn == 0  # nothing missed when everything is flagged
    assert on.recall == 1.0
    assert on.tp + on.fp == 20  # every entry predicted positive


# --- ProportionCI formatting -----------------------------------------------
def test_proportion_ci_format_is_stable():
    ci = ProportionCI(point=0.857, low=0.487, high=0.974, n=7, method="wilson")
    assert ci.format() == "0.857 [0.487, 0.974] (n=7, wilson)"
