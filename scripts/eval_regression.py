"""Regression-on-prompt-change eval gate: a prompt or scoring change that silently
degrades faithfulness FAILS CI.

A prompt edit, a tweak to the grounding scorer, or a re-tuned threshold can quietly
make the faithfulness check worse and no human-facing number moves. This gate turns
the eval into a test. It recomputes the SCORING-side metrics over the committed
corpora and the committed model-output caches, compares them against the committed
baseline (tests/fixtures/eval_baseline.json), and EXITS NONZERO when any metric
regresses past its bound, naming the metric that moved. Within bounds it prints the
full comparison and exits 0.

The gate is KEYLESS and OFFLINE. It is scoped strictly to the scoring side: it makes
NO model call and reads NO key. The only inputs are the deterministic grounding
scorer (floor/grounding.score_filing), the same scoring scripts/grounding_report.py
reports over the labeled corpus, and the cached raw model outputs the leaderboard and
open-vs-closed receipts re-score. So CI runs it with no secrets and gets the
identical verdict every time.

Three metric families are checked, each in the direction a degradation moves it:

  1. Corpus precision and recall over tests/fixtures/grounding_corpus.json. HIGHER
     is better; a drop below the committed FLOOR (or more than TOLERANCE below the
     baseline) is a regression. This is the scorer losing accuracy on the labeled
     faithfulness corpus.

  2. Per-model error rates over tests/fixtures/leaderboard_cache.json (the
     ungrounded / count / date / actor rates the frozen oracle assigns the cached
     filings). LOWER is better; a rise above the committed CEILING (or more than
     TOLERANCE above the baseline) is a regression. This is the scorer newly
     false-flagging clean cached filings.

  3. Per-model faithfulness rate and materiality accuracy over
     tests/fixtures/open_vs_closed_cache.json. HIGHER is better; a drop below the
     committed FLOOR (or more than TOLERANCE below the baseline) is a regression.
     This is a cached filing newly judged ungrounded by a degraded scorer.

Run it:

  py scripts/eval_regression.py            (the gate: 0 within bounds, nonzero on a
                                            regression naming the metric)
  py scripts/eval_regression.py --json      (the same comparison as JSON)
  py scripts/eval_regression.py --record     (rewrite the baseline file from the
                                            current scoring state; review the diff)

The recompute is pure: same corpora + same caches -> byte-identical metrics on every
call. Nothing here enters the hashed run-log; it is offline tooling beside the floor
run, never inside it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.grounding import score_filing  # noqa: E402
from scripts.model_leaderboard import MODELS  # noqa: E402
from scripts.model_leaderboard import load_cache as load_leaderboard_cache  # noqa: E402
from scripts.model_leaderboard import load_corpus as load_leaderboard_corpus  # noqa: E402
from scripts.model_leaderboard import score as score_leaderboard  # noqa: E402
from scripts.open_vs_closed import ALL_MODELS  # noqa: E402
from scripts.open_vs_closed import load_cache as load_ovc_cache  # noqa: E402
from scripts.open_vs_closed import load_grounding_corpus  # noqa: E402
from scripts.open_vs_closed import load_materiality_corpus  # noqa: E402
from scripts.open_vs_closed import score as score_ovc  # noqa: E402

BASELINE = REPO_ROOT / "tests" / "fixtures" / "eval_baseline.json"
GROUNDING_CORPUS = REPO_ROOT / "tests" / "fixtures" / "grounding_corpus.json"

# The pass bar the corpus scorer uses: a filing is flagged HALLUCINATED when its
# grounding score is below this. Matches scripts/grounding_report.THRESHOLD,
# floor.eval_stats.THRESHOLD and floor.run_floor.GROUNDING_THRESHOLD.
THRESHOLD = 1.0
HALLUCINATED = "hallucinated"

# The error-rate kinds in the leaderboard cache, mapped to the oracle span kind that
# drives each. 'ungrounded' is any flag at all.
_LEADERBOARD_RATES = ("ungrounded_rate", "count_error_rate", "date_error_rate",
                      "actor_error_rate")


def load_baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _corpus_confusion(corpus: dict) -> dict:
    """Score every labeled corpus entry with the frozen grounding scorer and return
    the confusion-matrix counts. This is the SAME scoring scripts/grounding_report.py
    runs over the same corpus (score_filing against the entry's record, positive =
    flagged below threshold, ground truth = the human 'hallucinated' label), recomputed
    here directly from floor.grounding so the gate does not depend on the report
    module. Pure function of the corpus dict."""
    records = {
        "fact_record": corpus["fact_record"],
        "amended_fact_record": corpus["amended_fact_record"],
    }
    tp = fp = tn = fn = 0
    for entry in corpus["entries"]:
        record = records[entry["record"]]
        result = score_filing(entry["text"], record, branch=str(entry["id"]))
        scorer_positive = result.score < THRESHOLD
        truth_positive = entry["label"] == HALLUCINATED
        if truth_positive and scorer_positive:
            tp += 1
        elif truth_positive and not scorer_positive:
            fn += 1
        elif (not truth_positive) and scorer_positive:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    """Precision and recall from confusion-matrix counts, with the degenerate-case
    conventions the eval uses: no positive predictions -> precision 1.0; no actual
    positives -> recall 1.0."""
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall


def compute_metrics() -> dict:
    """Recompute every scoring-side metric the gate checks, keyless and offline.
    Returns a dict mirroring the baseline layout's measured values. Pure: same
    corpora + same caches yield byte-identical metrics."""
    corpus = json.loads(GROUNDING_CORPUS.read_text(encoding="utf-8"))
    confusion = _corpus_confusion(corpus)
    precision, recall = _precision_recall(
        confusion["tp"], confusion["fp"], confusion["fn"])

    leaderboard = score_leaderboard(
        load_leaderboard_corpus(), load_leaderboard_cache())
    lb_models: dict = {}
    lb_n = leaderboard["n_incidents"]
    by_lb = {r["model"]: r for r in leaderboard["rows"]}
    for _provider, model, _label, _kind, _mt in MODELS:
        row = by_lb[model]
        lb_models[model] = {
            rate: row[rate]["point"] for rate in _LEADERBOARD_RATES
        }

    ovc = score_ovc(
        load_materiality_corpus(), load_grounding_corpus(), load_ovc_cache())
    ovc_models: dict = {}
    by_ovc = {m["model"]: m for m in ovc["models"]}
    n_faith = n_mat = 0
    for _provider, model, _label, _mt, _ft in ALL_MODELS:
        m = by_ovc[model]
        ovc_models[model] = {
            "faithfulness_rate": m["faithfulness_rate"]["point"],
            "materiality_accuracy": m["materiality_accuracy"]["point"],
        }
        n_faith = m["faithful_total"]
        n_mat = m["materiality_total"]

    return {
        "corpus": {
            "n": len(corpus["entries"]),
            "confusion": confusion,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        },
        "leaderboard": {
            "n": lb_n,
            "models": lb_models,
        },
        "open_vs_closed": {
            "n_faithfulness": n_faith,
            "n_materiality": n_mat,
            "models": ovc_models,
        },
    }


class Comparison:
    """One metric's measured value against its baseline and bound, with the verdict.

    direction is 'higher_is_better' or 'lower_is_better'. bound is the FLOOR (for
    higher-is-better) or the CEILING (for lower-is-better). The metric regresses when
    it crosses the bound, or when it moves past the baseline by more than tolerance in
    the bad direction."""

    def __init__(self, name: str, measured: float, baseline: float, bound: float,
                 direction: str, tolerance: float) -> None:
        self.name = name
        self.measured = measured
        self.baseline = baseline
        self.bound = bound
        self.direction = direction
        self.tolerance = tolerance

    @property
    def regressed(self) -> bool:
        if self.direction == "higher_is_better":
            if self.measured < self.bound:
                return True
            return self.measured < self.baseline - self.tolerance
        # lower_is_better
        if self.measured > self.bound:
            return True
        return self.measured > self.baseline + self.tolerance

    @property
    def delta(self) -> float:
        return self.measured - self.baseline

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "measured": round(self.measured, 4),
            "baseline": round(self.baseline, 4),
            "bound": round(self.bound, 4),
            "direction": self.direction,
            "delta": round(self.delta, 4),
            "regressed": self.regressed,
        }


def build_comparisons(baseline: dict, metrics: dict) -> list[Comparison]:
    """Pair every measured metric with its baseline and bound into a flat list of
    Comparison objects, in a stable, deterministic order. Pure function of the two
    dicts."""
    tol = baseline["tolerance"]
    out: list[Comparison] = []

    corpus_b = baseline["corpus"]
    corpus_m = metrics["corpus"]
    out.append(Comparison(
        "corpus.precision", corpus_m["precision"],
        corpus_b["precision"]["baseline"], corpus_b["precision"]["floor"],
        "higher_is_better", tol))
    out.append(Comparison(
        "corpus.recall", corpus_m["recall"],
        corpus_b["recall"]["baseline"], corpus_b["recall"]["floor"],
        "higher_is_better", tol))

    lb_b = baseline["leaderboard"]
    ceiling = lb_b["ceiling"]
    for model in lb_b["models"]:
        base_rates = lb_b["models"][model]
        meas_rates = metrics["leaderboard"]["models"][model]
        for rate in _LEADERBOARD_RATES:
            out.append(Comparison(
                f"leaderboard.{model}.{rate}", meas_rates[rate],
                base_rates[rate], ceiling, "lower_is_better", tol))

    ovc_b = baseline["open_vs_closed"]
    for model in ovc_b["models"]:
        base_m = ovc_b["models"][model]
        meas_m = metrics["open_vs_closed"]["models"][model]
        out.append(Comparison(
            f"open_vs_closed.{model}.faithfulness_rate",
            meas_m["faithfulness_rate"], base_m["faithfulness_rate"],
            ovc_b["faithfulness_floor"], "higher_is_better", tol))
        out.append(Comparison(
            f"open_vs_closed.{model}.materiality_accuracy",
            meas_m["materiality_accuracy"], base_m["materiality_accuracy"],
            ovc_b["materiality_floor"], "higher_is_better", tol))

    return out


def _print_comparisons(comparisons: list[Comparison]) -> None:
    print(f"  {'metric':52s}{'measured':>10s}{'baseline':>10s}"
          f"{'bound':>9s}{'verdict':>10s}")
    for c in comparisons:
        verdict = "REGRESS" if c.regressed else "ok"
        bound_label = "floor" if c.direction == "higher_is_better" else "ceil"
        print(f"  {c.name:52s}{c.measured:>10.3f}{c.baseline:>10.3f}"
              f"{c.bound:>9.3f}{verdict:>10s}  ({bound_label})")


def run_gate() -> int:
    """The gate. Recompute every scoring-side metric, compare against the committed
    baseline, print the comparison, and return 0 within bounds or 1 on any
    regression (naming each regressed metric). Returns 2 if the baseline file is
    missing."""
    print("=" * 84)
    print("EVAL REGRESSION GATE: scoring-side faithfulness metrics vs the committed baseline")
    print("=" * 84)
    if not BASELINE.exists():
        print(f"eval_regression: baseline not found at {BASELINE}. Run "
              "'py scripts/eval_regression.py --record' to write it.",
              file=sys.stderr)
        return 2
    baseline = load_baseline()
    metrics = compute_metrics()
    comparisons = build_comparisons(baseline, metrics)
    print(f"Recomputed keyless over the committed corpora and caches. "
          f"Tolerance {baseline['tolerance']:.2f}; "
          f"higher-is-better metrics carry a floor, lower-is-better a ceiling.")
    print()
    _print_comparisons(comparisons)
    print()
    regressed = [c for c in comparisons if c.regressed]
    if regressed:
        print(f"VERDICT: FAIL. {len(regressed)} metric(s) regressed past the bound:")
        for c in regressed:
            move = "below floor" if c.direction == "higher_is_better" else "above ceiling"
            print(f"  {c.name}: measured {c.measured:.3f}, baseline "
                  f"{c.baseline:.3f}, bound {c.bound:.3f} ({move}, "
                  f"delta {c.delta:+.3f})")
        print("A prompt or scoring change degraded faithfulness. Investigate the")
        print("scorer or the prompt; refresh the baseline only after an intended,")
        print("reviewed change (py scripts/eval_regression.py --record).")
        print("=" * 84)
        return 1
    print("VERDICT: PASS. Every scoring-side metric is within bounds of the baseline.")
    print("No silent faithfulness regression.")
    print("=" * 84)
    return 0


def run_json() -> int:
    """The same comparison as machine-readable JSON. Keyless. Returns 0 within bounds,
    1 on a regression, 2 if the baseline is missing."""
    if not BASELINE.exists():
        print(f"eval_regression: baseline not found at {BASELINE}", file=sys.stderr)
        return 2
    baseline = load_baseline()
    metrics = compute_metrics()
    comparisons = build_comparisons(baseline, metrics)
    regressed = [c for c in comparisons if c.regressed]
    print(json.dumps({
        "metrics": metrics,
        "comparisons": [c.as_dict() for c in comparisons],
        "regressed": [c.name for c in regressed],
        "passed": not regressed,
    }, indent=2))
    return 1 if regressed else 0


def run_record() -> int:
    """Rewrite the baseline file from the CURRENT scoring state, preserving the
    documented bounds (tolerance, floors, ceiling) and the prose. This is the only
    path that changes the committed baseline; review the diff before committing.
    Keyless. Returns 0."""
    metrics = compute_metrics()
    if BASELINE.exists():
        baseline = load_baseline()
    else:
        # First write: use the same conservative default bounds documented in the
        # fixture so a fresh baseline still gates.
        baseline = {
            "about": "",
            "tolerance": 0.05,
            "corpus": {
                "source": "",
                "precision": {"floor": 0.75, "direction": "higher_is_better"},
                "recall": {"floor": 0.5, "direction": "higher_is_better"},
            },
            "leaderboard": {"source": "", "ceiling": 0.25,
                            "direction": "lower_is_better"},
            "open_vs_closed": {"source": "", "faithfulness_floor": 0.5,
                               "materiality_floor": 0.75,
                               "direction": "higher_is_better"},
        }
    c = metrics["corpus"]
    baseline["corpus"]["n"] = c["n"]
    baseline["corpus"]["confusion"] = c["confusion"]
    baseline["corpus"]["precision"]["baseline"] = c["precision"]
    baseline["corpus"]["recall"]["baseline"] = c["recall"]
    baseline["leaderboard"]["n"] = metrics["leaderboard"]["n"]
    baseline["leaderboard"]["models"] = metrics["leaderboard"]["models"]
    baseline["open_vs_closed"]["n_faithfulness"] = (
        metrics["open_vs_closed"]["n_faithfulness"])
    baseline["open_vs_closed"]["n_materiality"] = (
        metrics["open_vs_closed"]["n_materiality"])
    baseline["open_vs_closed"]["models"] = metrics["open_vs_closed"]["models"]
    BASELINE.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    print(f"eval_regression --record: wrote the baseline to {BASELINE}")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "--record" in args:
        return run_record()
    if "--json" in args:
        return run_json()
    return run_gate()


if __name__ == "__main__":
    raise SystemExit(main())
