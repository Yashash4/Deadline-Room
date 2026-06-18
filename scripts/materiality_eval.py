"""Judge-runnable materiality cross-check receipt: inter-model agreement,
per-model accuracy, and confidence calibration, all keyless by default.

The SEC branch is gated on a materiality JUDGMENT (floor/materiality.py) that two
DIFFERENT open models render on the same canonical fact-record. The shipped
agreement signal is a bare "agree/disagree". An eval scientist asks three sharper
questions of that cross-check, and this receipt answers all three over a small
human-labeled corpus (tests/fixtures/materiality_corpus.json, ~12 items spanning
clear-material, clear-immaterial, and borderline cases):

  1. Cohen's KAPPA between the two models. Raw agreement is misleading when one
     label dominates: two models that both call most incidents material share a
     high raw agreement that says little. Kappa is chance-corrected, so it
     separates "agree because the case is easy" from "agree informatively".

  2. Each model's ACCURACY against the human ground-truth label. The two models
     are graded independently against what a securities-law reviewer says, so the
     receipt shows not just whether the models agree with EACH OTHER but whether
     each is RIGHT.

  3. The confidence CALIBRATION (expected calibration error, ECE). Each model
     reports a confidence; ECE measures whether a model that says 80% is right
     about 80% of the time. A well-calibrated confidence is what lets the Warden
     trust a high-confidence verdict and escalate a low-confidence one.

KEYLESS by default. The two models' opinions are recorded ONCE into a committed
cache (tests/fixtures/materiality_opinions_cache.json); the default SCORING path
reads that cache and makes NO model call, so a judge (and the test suite) re-runs
this with no API key and gets the identical numbers every time. The scoring is a
pure function of the corpus and the cache.

  py scripts/materiality_eval.py            (keyless: score from the cache)
  py scripts/materiality_eval.py --json     (the same numbers as JSON)
  py scripts/materiality_eval.py --record   (refresh the cache from live models;
                                             needs FEATHERLESS_API_KEY)

The --record path is the ONLY one that calls a model. It uses the same
emit_confidence=True path on floor.materiality.assess_materiality (which defaults
OFF, so the production gate is untouched) to capture each model's verdict and
confidence, then rewrites the cache. The scoring path never imports a network
client.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.eval_stats import cohen_kappa, expected_calibration_error  # noqa: E402

CORPUS = REPO_ROOT / "tests" / "fixtures" / "materiality_corpus.json"
CACHE = REPO_ROOT / "tests" / "fixtures" / "materiality_opinions_cache.json"

# The number of equal-width confidence buckets the ECE is computed over. Fixed so
# the receipt is reproducible; 10 is the standard reliability-diagram resolution.
ECE_BINS = 10

MATERIAL = "material"
IMMATERIAL = "immaterial"


def load_corpus() -> dict:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def load_cache() -> dict:
    return json.loads(CACHE.read_text(encoding="utf-8"))


def _label_of(material: bool) -> str:
    """The categorical label for a boolean materiality verdict."""
    return MATERIAL if material else IMMATERIAL


def score(corpus: dict, cache: dict) -> dict:
    """Compute the full receipt: kappa, per-model accuracy, and ECE, from the
    corpus and the cached model opinions. Pure function of its two inputs, no
    network. Returns a dict with the per-model labels, the per-model accuracy and
    confidence series, the two label sequences kappa is computed over, and the
    headline numbers. Raises KeyError if the cache is missing an item the corpus
    contains, so a stale cache fails loudly rather than scoring a subset."""
    opinions = cache["opinions"]
    primary_labels: list[str] = []
    second_labels: list[str] = []
    primary_correct: list[int] = []
    second_correct: list[int] = []
    primary_conf: list[float] = []
    second_conf: list[float] = []
    rows: list[dict] = []
    for entry in corpus["entries"]:
        item_id = entry["id"]
        truth = entry["label"]
        op = opinions[item_id]
        p_label = _label_of(op["primary"]["material"])
        s_label = _label_of(op["second"]["material"])
        p_ok = 1 if p_label == truth else 0
        s_ok = 1 if s_label == truth else 0
        primary_labels.append(p_label)
        second_labels.append(s_label)
        primary_correct.append(p_ok)
        second_correct.append(s_ok)
        primary_conf.append(float(op["primary"]["confidence"]))
        second_conf.append(float(op["second"]["confidence"]))
        rows.append({
            "id": item_id,
            "truth": truth,
            "primary": p_label,
            "primary_correct": bool(p_ok),
            "primary_confidence": float(op["primary"]["confidence"]),
            "second": s_label,
            "second_correct": bool(s_ok),
            "second_confidence": float(op["second"]["confidence"]),
            "models_agree": p_label == s_label,
        })
    n = len(rows)
    kappa = cohen_kappa(primary_labels, second_labels)
    raw_agreement = sum(
        1 for a, b in zip(primary_labels, second_labels) if a == b) / n
    primary_accuracy = sum(primary_correct) / n
    second_accuracy = sum(second_correct) / n
    primary_ece = expected_calibration_error(
        primary_conf, primary_correct, bins=ECE_BINS)
    second_ece = expected_calibration_error(
        second_conf, second_correct, bins=ECE_BINS)
    return {
        "n": n,
        "primary_model": cache["primary_model"],
        "second_model": cache["second_model"],
        "kappa": kappa,
        "raw_agreement": raw_agreement,
        "primary_accuracy": primary_accuracy,
        "second_accuracy": second_accuracy,
        "primary_ece": primary_ece,
        "second_ece": second_ece,
        "rows": rows,
    }


def _kappa_strength(kappa: float) -> str:
    """The conventional Landis and Koch verbal band for a kappa value, used only
    to annotate the printed receipt (never gated on)."""
    if kappa < 0.0:
        return "less than chance"
    if kappa < 0.20:
        return "slight"
    if kappa < 0.40:
        return "fair"
    if kappa < 0.60:
        return "moderate"
    if kappa < 0.80:
        return "substantial"
    return "almost perfect"


def print_report(result: dict) -> None:
    print("=" * 72)
    print("MATERIALITY CROSS-CHECK: inter-model agreement, accuracy, calibration")
    print("=" * 72)
    print(f"Corpus: {result['n']} human-labeled incidents "
          "(clear-material, clear-immaterial, borderline).")
    print(f"Primary model: {result['primary_model']}")
    print(f"Second model:  {result['second_model']}")
    print("Scored from the committed opinion cache: no API key, fully replayable.")
    print()

    print("Per-item (M = material, I = immaterial; * marks a model wrong vs human):")
    for r in result["rows"]:
        p = "M" if r["primary"] == MATERIAL else "I"
        s = "M" if r["second"] == MATERIAL else "I"
        t = "M" if r["truth"] == MATERIAL else "I"
        p_mark = " " if r["primary_correct"] else "*"
        s_mark = " " if r["second_correct"] else "*"
        agree = "agree   " if r["models_agree"] else "DISAGREE"
        print(f"  {r['id']:28s} truth={t}  primary={p}{p_mark}"
              f"(c={r['primary_confidence']:.2f})  "
              f"second={s}{s_mark}(c={r['second_confidence']:.2f})  {agree}")
    print()

    kappa = result["kappa"]
    print("Inter-model agreement (do the two models concur?):")
    print(f"  raw agreement   {result['raw_agreement']:.3f}  "
          "(fraction of items the two models label the same)")
    print(f"  Cohen's kappa   {kappa:.3f}  "
          f"({_kappa_strength(kappa)}, chance-corrected)")
    print("  Kappa discounts the agreement expected by chance, so it separates")
    print("  agreeing because a case is easy from agreeing informatively.")
    print()

    print("Accuracy vs the human ground-truth label (is each model right?):")
    print(f"  primary accuracy  {result['primary_accuracy']:.3f}")
    print(f"  second accuracy   {result['second_accuracy']:.3f}")
    print()

    print("Confidence calibration (does stated confidence match accuracy?):")
    print(f"  primary ECE       {result['primary_ece']:.3f}  "
          "(expected calibration error, lower is better)")
    print(f"  second ECE        {result['second_ece']:.3f}")
    print("  ECE buckets the verdicts by stated confidence and compares each")
    print("  bucket's mean confidence to its realised accuracy; 0 is perfect.")
    print("=" * 72)


def run_score() -> int:
    """The default keyless path: load the corpus and the cached opinions, score,
    and print the receipt. Returns 0 on success, 2 if a fixture is missing."""
    if not CORPUS.exists():
        print(f"materiality_eval: corpus not found at {CORPUS}", file=sys.stderr)
        return 2
    if not CACHE.exists():
        print(f"materiality_eval: opinion cache not found at {CACHE}. Run "
              "'py scripts/materiality_eval.py --record' to build it (needs a key).",
              file=sys.stderr)
        return 2
    result = score(load_corpus(), load_cache())
    print_report(result)
    return 0


def run_json() -> int:
    """The same scored numbers as machine-readable JSON (drops the per-item rows'
    formatting but keeps the headline metrics and the rows). Keyless."""
    if not CORPUS.exists() or not CACHE.exists():
        print("materiality_eval: corpus or cache missing", file=sys.stderr)
        return 2
    result = score(load_corpus(), load_cache())
    out = {k: v for k, v in result.items() if k != "rows"}
    out["rows"] = result["rows"]
    print(json.dumps(out, indent=2))
    return 0


def run_record() -> int:
    """Refresh the opinion cache from LIVE models. This is the ONLY path that
    calls a model; it needs FEATHERLESS_API_KEY. It runs each corpus item through
    BOTH materiality heroes with emit_confidence=True (which defaults OFF in
    production, so the gate is untouched), parses each verdict and confidence
    deterministically, and rewrites tests/fixtures/materiality_opinions_cache.json
    so the keyless scoring path above reproduces these numbers. Returns 0 on a
    full refresh, nonzero on a missing key or a transport failure."""
    import os

    from floor import roster
    from floor.materiality import assess_materiality

    api_key = os.environ.get("FEATHERLESS_API_KEY")
    if not api_key:
        print("materiality_eval --record: FEATHERLESS_API_KEY is not set; the "
              "record path needs a live key. The default scoring path is keyless.",
              file=sys.stderr)
        return 2
    corpus = load_corpus()
    p_provider, p_model = roster.MATERIALITY_HERO
    s_provider, s_model = roster.MATERIALITY_SECOND_HERO
    opinions: dict = {}
    for entry in corpus["entries"]:
        fact = entry["fact_record"]
        p_verdict, p_conf = assess_materiality(
            fact, model=p_model, provider=p_provider, api_key=api_key,
            emit_confidence=True)
        s_verdict, s_conf = assess_materiality(
            fact, model=s_model, provider=s_provider, api_key=api_key,
            max_tokens=2000, emit_confidence=True)
        opinions[entry["id"]] = {
            "primary": {"material": p_verdict.material,
                        "confidence": p_conf if p_conf is not None else 0.5},
            "second": {"material": s_verdict.material,
                       "confidence": s_conf if s_conf is not None else 0.5},
        }
        print(f"  recorded {entry['id']}: primary={p_verdict.material} "
              f"second={s_verdict.material}")
    existing = load_cache() if CACHE.exists() else {}
    cache = {
        "about": existing.get("about", "Committed cache of the two open-model "
                 "materiality opinions over the materiality corpus."),
        "primary_model": p_model,
        "primary_provider": p_provider,
        "second_model": s_model,
        "second_provider": s_provider,
        "opinions": opinions,
    }
    CACHE.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"materiality_eval --record: wrote {len(opinions)} opinions to {CACHE}")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "--record" in args:
        return run_record()
    if "--json" in args:
        return run_json()
    return run_score()


if __name__ == "__main__":
    raise SystemExit(main())
