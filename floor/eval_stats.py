"""Pure statistics for the grounding eval: confidence intervals and ablation.

The grounding eval (scripts/grounding_report.py --eval) reports a single point:
precision 0.857, recall 0.600 on 20 labeled items. Two questions a careful
ML-eval reviewer asks of any single point are answered here, with no LLM, no
clock, no network, no global state, so the receipt stays replayable and keyless:

  1. "n=20 is small, what is the uncertainty?" -> a 95% confidence interval for
     each proportion (precision and recall), reported WITH n. We provide two
     independent estimators so the interval is not a single formula's artifact:
     a closed-form WILSON score interval (exact, the right default for a small
     binomial), and a deterministic, seeded BOOTSTRAP (a resampling estimate
     that is byte-reproducible because the RNG is seeded explicitly). Both are
     pure functions; the bootstrap with a fixed seed returns the identical
     interval on every call.

  2. "does the deterministic guard earn its place?" -> an ABLATION. We run the
     same labeled corpus through the real grounding scorer (guard ON) and
     through a degenerate pass-everything baseline (guard OFF, accept every
     filing as faithful), and report the precision and recall of each plus the
     delta. The delta is the measured value of the deterministic spine: how much
     faithfulness signal the guard adds over flagging nothing.

This module is the shared statistics foundation the rest of the AI-quality epic
imports (the per-model leaderboard, calibration, the regression gate). The public
API is small and documented:

  wilson_interval(successes, n)        -> ProportionCI   (closed form)
  bootstrap_interval(samples, *, seed) -> ProportionCI   (seeded resample)
  proportion_ci(successes, n, *, seed) -> dict with both intervals and n
  run_ablation(corpus)                 -> AblationResult  (guard on vs off)

Everything is a pure function of its inputs. Same inputs (and same seed for the
bootstrap) always yield the identical result.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

# The two-sided z critical value for a 95% confidence interval, the 0.975
# quantile of the standard normal. Hard-coded to a fixed value so the interval
# is byte-reproducible and carries no dependency on a stats library's inverse-CDF
# implementation. This is the standard 1.96 to full double precision.
Z_95 = 1.959963984540054

# How many bootstrap resamples back the percentile interval. Fixed so the result
# is reproducible; large enough that the 2.5 / 97.5 percentiles are stable for a
# corpus of tens of items.
BOOTSTRAP_RESAMPLES = 10000

# The default seed for the deterministic bootstrap. Any caller may override it;
# the point is only that SOME explicit seed is always used, never the system
# entropy, so two runs agree byte for byte.
DEFAULT_BOOTSTRAP_SEED = 20260618

# The eval treats a filing as a positive prediction (the scorer FLAGGED it as
# hallucinated) when its grounding score is below this threshold. Matches
# scripts/grounding_report.THRESHOLD and floor.run_floor.GROUNDING_THRESHOLD.
THRESHOLD = 1.0
HALLUCINATED = "hallucinated"


@dataclass(frozen=True)
class ProportionCI:
    """A point estimate of a proportion with a 95% confidence interval and n.

    point   : successes / n in [0, 1] (1.0 by convention when n == 0).
    low/high : the inclusive 95% interval bounds, clamped to [0, 1].
    n       : the sample size the proportion was measured over.
    method  : which estimator produced the interval ('wilson' or 'bootstrap').
    """
    point: float
    low: float
    high: float
    n: int
    method: str

    def as_dict(self) -> dict:
        return {
            "point": round(self.point, 4),
            "low": round(self.low, 4),
            "high": round(self.high, 4),
            "n": self.n,
            "method": self.method,
        }

    def format(self) -> str:
        """A compact human line: '0.857 [0.487, 0.974] (n=7, wilson)'."""
        return (f"{self.point:.3f} [{self.low:.3f}, {self.high:.3f}] "
                f"(n={self.n}, {self.method})")


def _clamp(x: float) -> float:
    """Clamp a bound into the valid proportion range [0, 1]."""
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def wilson_interval(successes: int, n: int) -> ProportionCI:
    """The 95% Wilson score interval for a binomial proportion.

    Closed form, exact, and the right default for a small n: unlike the normal
    (Wald) interval it never runs past [0, 1] and stays sensible at 0 or n
    successes. Pure function of (successes, n).

    Conventions at the edges: n == 0 yields point 1.0 over the full [0, 1]
    interval (no observations, maximal uncertainty); this mirrors the eval's
    'no predictions -> precision 1.0' convention while still reporting the widest
    possible interval so the absence of data is visible.
    """
    if successes < 0 or n < 0 or successes > n:
        raise ValueError(
            f"wilson_interval needs 0 <= successes <= n, got "
            f"successes={successes}, n={n}")
    if n == 0:
        return ProportionCI(point=1.0, low=0.0, high=1.0, n=0, method="wilson")
    p = successes / n
    z = Z_95
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1.0 - p) / n + z2 / (4 * n * n))
    low = _clamp(center - margin)
    high = _clamp(center + margin)
    # At the exact edges p == 0 and p == 1 the bound is mathematically 0 and 1;
    # snap away the floating-point residue (0.9999999999999999) so the reported
    # bound is clean for downstream consumers, not just for display rounding.
    if successes == 0:
        low = 0.0
    if successes == n:
        high = 1.0
    return ProportionCI(point=p, low=low, high=high, n=n, method="wilson")


def bootstrap_interval(samples: list[int], *,
                       seed: int = DEFAULT_BOOTSTRAP_SEED,
                       resamples: int = BOOTSTRAP_RESAMPLES) -> ProportionCI:
    """The 95% bootstrap percentile interval for a proportion over 0/1 samples.

    `samples` is a list of binary outcomes (1 = success, 0 = failure). The
    estimator draws `resamples` resamples WITH replacement using a seeded RNG,
    computes the mean of each, and takes the 2.5 / 97.5 percentiles. Because the
    RNG is seeded explicitly (never the system clock), the same (samples, seed)
    always returns the identical interval, so the receipt is byte-reproducible.

    This is the second, independent estimator (Wilson is the first): a reviewer
    can see the closed-form and resampling intervals agree, which is more
    convincing than either alone. Pure function of (samples, seed, resamples).
    """
    for s in samples:
        if s not in (0, 1):
            raise ValueError(
                f"bootstrap_interval expects 0/1 samples, got {s!r}")
    n = len(samples)
    if n == 0:
        return ProportionCI(point=1.0, low=0.0, high=1.0, n=0,
                            method="bootstrap")
    point = sum(samples) / n
    rng = random.Random(seed)
    means: list[float] = []
    for _ in range(resamples):
        total = 0
        for _ in range(n):
            total += samples[rng.randrange(n)]
        means.append(total / n)
    means.sort()
    low = _percentile(means, 2.5)
    high = _percentile(means, 97.5)
    return ProportionCI(
        point=point,
        low=_clamp(low),
        high=_clamp(high),
        n=n,
        method="bootstrap",
    )


def _percentile(sorted_values: list[float], pct: float) -> float:
    """The pct-th percentile of an already-sorted list, by linear interpolation
    between the two nearest ranks. pct is in [0, 100]. Deterministic; no numpy."""
    if not sorted_values:
        raise ValueError("percentile of an empty list is undefined")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low_idx = int(math.floor(rank))
    high_idx = int(math.ceil(rank))
    if low_idx == high_idx:
        return sorted_values[low_idx]
    frac = rank - low_idx
    return sorted_values[low_idx] + frac * (
        sorted_values[high_idx] - sorted_values[low_idx])


def _samples_from_counts(successes: int, n: int) -> list[int]:
    """A 0/1 sample list with `successes` ones and `n - successes` zeros. The
    bootstrap is invariant to order, so a canonical layout is fine and keeps the
    proportion_ci result a pure function of the two counts."""
    if successes < 0 or n < 0 or successes > n:
        raise ValueError(
            f"_samples_from_counts needs 0 <= successes <= n, got "
            f"successes={successes}, n={n}")
    return [1] * successes + [0] * (n - successes)


def proportion_ci(successes: int, n: int, *,
                  seed: int = DEFAULT_BOOTSTRAP_SEED) -> dict:
    """Both 95% intervals (Wilson and seeded bootstrap) for one proportion, with
    n. The single entry point a report calls per metric. Returns a dict:

        {'point': p, 'n': n,
         'wilson': {...}, 'bootstrap': {...}}

    Pure and deterministic for a fixed seed.
    """
    wilson = wilson_interval(successes, n)
    boot = bootstrap_interval(_samples_from_counts(successes, n), seed=seed)
    return {
        "point": round(wilson.point, 4),
        "n": n,
        "wilson": wilson.as_dict(),
        "bootstrap": boot.as_dict(),
    }


# ---------------------------------------------------------------------------
# Ablation: the deterministic guard ON (the real scorer) versus OFF (a
# degenerate pass-everything baseline that flags nothing). The delta is the
# measured value of the deterministic spine.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AblationArm:
    """One arm of the ablation: a named configuration and its confusion matrix
    plus the precision and recall it achieves over the labeled corpus."""
    name: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
        }


@dataclass(frozen=True)
class AblationResult:
    """The guard-on vs guard-off ablation over the corpus, with the delta the
    deterministic guard contributes on each metric."""
    guard_on: AblationArm
    guard_off: AblationArm
    n: int

    @property
    def precision_delta(self) -> float:
        return self.guard_on.precision - self.guard_off.precision

    @property
    def recall_delta(self) -> float:
        return self.guard_on.recall - self.guard_off.recall

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "guard_on": self.guard_on.as_dict(),
            "guard_off": self.guard_off.as_dict(),
            "precision_delta": round(self.precision_delta, 4),
            "recall_delta": round(self.recall_delta, 4),
        }


def _precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    """Precision and recall from confusion-matrix counts, with the same
    degenerate-case conventions the eval uses: no positive predictions ->
    precision 1.0 (no false alarms); no actual positives -> recall 1.0."""
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall


def run_ablation(corpus: dict, *, score_fn=None) -> AblationResult:
    """Run the labeled corpus through the deterministic guard ON and OFF.

    Guard ON: the real grounding scorer flags a filing as hallucinated when its
    grounding score is below the threshold (the production behavior).

    Guard OFF: a degenerate pass-everything baseline that accepts EVERY filing
    as faithful (it flags nothing). This is the "what if there were no
    deterministic spine" arm: it never raises a false alarm (precision is the
    no-prediction convention 1.0) but it also catches nothing, so its recall is
    0 whenever the corpus carries any hallucination.

    The corpus is the same dict scripts/grounding_report.evaluate_corpus reads:
    {'fact_record', 'amended_fact_record', 'entries': [...]}. Each entry carries
    its text, the record name it is scored against, and a human label. Pure
    function of the corpus (and the injected score_fn, which defaults to the
    frozen floor.grounding.score_filing). The delta on the result is the measured
    value of the deterministic guard.
    """
    if score_fn is None:
        from floor.grounding import score_filing as score_fn  # noqa: E402
    records = {
        "fact_record": corpus["fact_record"],
        "amended_fact_record": corpus["amended_fact_record"],
    }
    on_tp = on_fp = on_tn = on_fn = 0
    off_tp = off_fp = off_tn = off_fn = 0
    for entry in corpus["entries"]:
        record = records[entry["record"]]
        truth_positive = entry["label"] == HALLUCINATED
        # Guard ON: the real scorer.
        result = score_fn(entry["text"], record, branch=str(entry["id"]))
        on_positive = result.score < THRESHOLD
        # Guard OFF: pass-everything, never flags.
        off_positive = False
        on_tp, on_fp, on_tn, on_fn = _tally(
            on_tp, on_fp, on_tn, on_fn, truth_positive, on_positive)
        off_tp, off_fp, off_tn, off_fn = _tally(
            off_tp, off_fp, off_tn, off_fn, truth_positive, off_positive)
    on_p, on_r = _precision_recall(on_tp, on_fp, on_fn)
    off_p, off_r = _precision_recall(off_tp, off_fp, off_fn)
    guard_on = AblationArm("guard_on", on_tp, on_fp, on_tn, on_fn, on_p, on_r)
    guard_off = AblationArm(
        "guard_off", off_tp, off_fp, off_tn, off_fn, off_p, off_r)
    return AblationResult(guard_on=guard_on, guard_off=guard_off,
                          n=len(corpus["entries"]))


def _tally(tp: int, fp: int, tn: int, fn: int,
           truth_positive: bool, predicted_positive: bool):
    """Advance one confusion-matrix cell for a single (truth, prediction) pair."""
    if truth_positive and predicted_positive:
        tp += 1
    elif truth_positive and not predicted_positive:
        fn += 1
    elif (not truth_positive) and predicted_positive:
        fp += 1
    else:
        tn += 1
    return tp, fp, tn, fn
