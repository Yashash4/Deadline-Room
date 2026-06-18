"""Open vs closed models, head-to-head on the two gate judgments, one oracle.

The Deadline Room makes two qualitative calls an LLM is trusted with and a
deterministic spine then checks: the SEC materiality JUDGMENT (does the clock even
trigger) and the FAITHFULNESS of a drafted filing (does every load-bearing span
trace to the fact-record). This receipt runs those two judgments as a direct
OPEN vs CLOSED head-to-head:

  OPEN   : DeepSeek-V3.2, MiniMax-M2.7, Qwen2.5-72B   (Featherless, self-hostable)
  CLOSED : claude-opus-4-1, gpt-5-chat-latest          (AI/ML API gateway)

Both sides are graded by the SAME frozen, no-LLM oracle, never by themselves:

  materiality  : floor.materiality.assess_materiality renders each model's verdict
                 over tests/fixtures/materiality_corpus.json; accuracy is measured
                 against the HUMAN ground-truth label.
  faithfulness : each model drafts a filing from a grounding-corpus fact-record and
                 floor.grounding.score_filing scores it; the faithfulness rate is
                 the fraction of filings the oracle finds fully grounded.

Each side's accuracy and faithfulness are reported with a 95% confidence interval
(Wilson + seeded bootstrap) from floor.eval_stats, because a rate over a dozen
judgments is a point estimate and the band is the honest signal.

KEYLESS by default. The raw model outputs (the materiality verdicts and the
drafted filings) are recorded ONCE into a committed cache (tests/fixtures/
open_vs_closed_cache.json); the default SCORING path reads that cache and makes NO
model call, so a judge and the test suite re-run this with no API key and get the
identical numbers every time. The SCORING math (both oracles, the tallies, the
intervals) is always real and keyless. Only the cached raw model output may be
illustrative when a live call was not possible: each model carries a "source" of
"live" or "illustrative" and this receipt prints it honestly.

  py scripts/open_vs_closed.py            (keyless: score from the cache)
  py scripts/open_vs_closed.py --json      (the same numbers as JSON)
  py scripts/open_vs_closed.py --record     (refresh the cache from live models;
                                             needs FEATHERLESS_API_KEY for the open
                                             models and AIML_API_KEY for the closed)

The --record path is the ONLY one that calls a model. It drives the models
SEQUENTIALLY, one model fully through both judgments before the next, so
Featherless only ever runs one big model at a time and the pinned roster stays
under the model-switch cap.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.eval_stats import proportion_ci  # noqa: E402
from floor.grounding import score_filing  # noqa: E402

MATERIALITY_CORPUS = REPO_ROOT / "tests" / "fixtures" / "materiality_corpus.json"
GROUNDING_CORPUS = REPO_ROOT / "tests" / "fixtures" / "grounding_corpus.json"
CACHE = REPO_ROOT / "tests" / "fixtures" / "open_vs_closed_cache.json"

# The faithfulness pass bar: a filing is FAITHFUL when every load-bearing span the
# oracle checks traces to the fact-record (grounding score == 1.0). Matches
# floor.run_floor.GROUNDING_THRESHOLD and scripts/grounding_report.THRESHOLD.
THRESHOLD = 1.0

# The regime each faithfulness filing is drafted under. One fixed regime keeps the
# prompt constant across models so the only variable is the model.
FAITHFULNESS_REGIME = "NIS2"

# The two model sides. Each row is (provider, model, label, max_tokens). MiniMax
# is a reasoning model that spends an internal preamble before visible content, so
# it gets the larger budget the materiality second-opinion already uses for it.
OPEN_MODELS = [
    ("featherless", "deepseek-ai/DeepSeek-V3.2", "DeepSeek-V3.2", 500, 700),
    ("featherless", "MiniMaxAI/MiniMax-M2.7", "MiniMax-M2.7", 2000, 2000),
    ("featherless", "Qwen/Qwen2.5-72B-Instruct", "Qwen2.5-72B", 500, 700),
]
CLOSED_MODELS = [
    ("aimlapi", "claude-opus-4-1-20250805", "claude-opus-4-1", 500, 700),
    ("aimlapi", "gpt-5-chat-latest", "gpt-5-chat-latest", 500, 700),
]
# (provider, model, label, materiality_max_tokens, faithfulness_max_tokens)
ALL_MODELS = OPEN_MODELS + CLOSED_MODELS

MATERIAL = "material"
IMMATERIAL = "immaterial"


def load_materiality_corpus() -> dict:
    return json.loads(MATERIALITY_CORPUS.read_text(encoding="utf-8"))


def load_grounding_corpus() -> dict:
    return json.loads(GROUNDING_CORPUS.read_text(encoding="utf-8"))


def load_cache() -> dict:
    return json.loads(CACHE.read_text(encoding="utf-8"))


def _label_of(material: bool) -> str:
    return MATERIAL if material else IMMATERIAL


def _faithfulness_records(grounding_corpus: dict) -> dict:
    """The fact-records the faithfulness filings are drafted from and scored
    against, keyed by a stable id. The canonical incident and its amended form,
    so each model drafts the same two filings and the oracle scores each against
    its own record."""
    return {
        "fact_record": grounding_corpus["fact_record"],
        "amended_fact_record": grounding_corpus["amended_fact_record"],
    }


def _score_model_materiality(model_cache: dict, corpus: dict) -> dict:
    """Score one model's cached materiality verdicts against the human labels.
    Returns the correct count, total, and per-item rows. Pure; the oracle here is
    the human ground-truth comparison, no model call."""
    verdicts = model_cache["materiality"]
    correct = 0
    rows: list[dict] = []
    for entry in corpus["entries"]:
        item_id = entry["id"]
        truth = entry["label"]
        verdict = verdicts[item_id]
        label = _label_of(verdict["material"])
        ok = label == truth
        correct += 1 if ok else 0
        rows.append({"id": item_id, "truth": truth, "verdict": label,
                     "correct": ok})
    return {"correct": correct, "total": len(corpus["entries"]), "rows": rows}


def _score_model_faithfulness(model_cache: dict, records: dict) -> dict:
    """Score one model's cached drafted filings with the frozen grounding oracle.
    A filing is FAITHFUL when its grounding score clears the threshold. Returns
    the faithful count, total, and per-filing rows. Pure function of the cache and
    the records, no model call."""
    filings = model_cache["faithfulness"]
    faithful = 0
    rows: list[dict] = []
    for record_id, fact in records.items():
        text = filings[record_id]
        result = score_filing(text, fact, branch=record_id)
        ok = result.score >= THRESHOLD
        faithful += 1 if ok else 0
        rows.append({"record": record_id, "score": round(result.score, 4),
                     "faithful": ok,
                     "ungrounded": [
                         {"kind": u.kind, "span": u.span} for u in result.ungrounded
                     ]})
    return {"faithful": faithful, "total": len(records), "rows": rows}


def score(materiality_corpus: dict, grounding_corpus: dict, cache: dict) -> dict:
    """Compute the full head-to-head: per model and per SIDE (open vs closed), the
    materiality accuracy and the faithfulness rate, each with a 95% interval, from
    the corpora and the cached raw outputs. Pure function of its inputs, no
    network. Raises KeyError on a stale cache missing a model or item."""
    records = _faithfulness_records(grounding_corpus)
    models = cache["models"]
    per_model: list[dict] = []
    side_tally = {
        "open": {"mat_correct": 0, "mat_total": 0, "faith_ok": 0, "faith_total": 0},
        "closed": {"mat_correct": 0, "mat_total": 0, "faith_ok": 0, "faith_total": 0},
    }
    for provider, model, label, _mat_mt, _faith_mt in ALL_MODELS:
        side = "open" if provider == "featherless" else "closed"
        mc = models[model]
        mat = _score_model_materiality(mc, materiality_corpus)
        faith = _score_model_faithfulness(mc, records)
        per_model.append({
            "model": model,
            "label": label,
            "side": side,
            "source": mc.get("source", "illustrative"),
            "materiality_accuracy": proportion_ci(mat["correct"], mat["total"]),
            "faithfulness_rate": proportion_ci(faith["faithful"], faith["total"]),
            "materiality_correct": mat["correct"],
            "materiality_total": mat["total"],
            "faithful": faith["faithful"],
            "faithful_total": faith["total"],
            "materiality_rows": mat["rows"],
            "faithfulness_rows": faith["rows"],
        })
        t = side_tally[side]
        t["mat_correct"] += mat["correct"]
        t["mat_total"] += mat["total"]
        t["faith_ok"] += faith["faithful"]
        t["faith_total"] += faith["total"]
    sides: dict = {}
    for side, t in side_tally.items():
        sides[side] = {
            "materiality_accuracy": proportion_ci(t["mat_correct"], t["mat_total"]),
            "faithfulness_rate": proportion_ci(t["faith_ok"], t["faith_total"]),
            "materiality_correct": t["mat_correct"],
            "materiality_total": t["mat_total"],
            "faithful": t["faith_ok"],
            "faithful_total": t["faith_total"],
        }
    return {"sides": sides, "models": per_model}


def _rate_cell(ci: dict) -> str:
    """A compact 'point [low, high]' rate cell from a proportion_ci dict."""
    w = ci["wilson"]
    return f"{ci['point']:.2f} [{w['low']:.2f},{w['high']:.2f}]"


def print_report(result: dict) -> None:
    print("=" * 78)
    print("OPEN vs CLOSED, head-to-head on the two gate judgments, one frozen oracle")
    print("=" * 78)
    print("Both sides are graded by the SAME no-LLM oracle, never by themselves:")
    print("  materiality  = accuracy vs the human ground-truth label.")
    print("  faithfulness = fraction of drafted filings the grounding oracle finds")
    print("                 fully grounded (every load-bearing span traces to fact).")
    print("Rates are 'point [Wilson 95% low, high]'. Cache source per model: 'live'")
    print("= real model output, 'illustrative' = a labeled plausible draft used only")
    print("because a live call was unavailable.")
    print()
    print(f"  {'side':8s}{'materiality acc (vs human)':>30s}"
          f"{'faithfulness (vs oracle)':>28s}")
    for side in ("open", "closed"):
        s = result["sides"][side]
        print(f"  {side:8s}{_rate_cell(s['materiality_accuracy']):>30s}"
              f"{_rate_cell(s['faithfulness_rate']):>28s}")
    print()
    print("Per model:")
    print(f"  {'model':18s}{'side':8s}{'src':7s}"
          f"{'materiality':>16s}{'faithfulness':>18s}")
    for m in result["models"]:
        src = "live" if m["source"] == "live" else "illus"
        print(f"  {m['label']:18s}{m['side']:8s}{src:7s}"
              f"{_rate_cell(m['materiality_accuracy']):>16s}"
              f"{_rate_cell(m['faithfulness_rate']):>18s}")
    print()
    print("  Read honestly: the materiality corpus is small and includes borderline")
    print("  cases where reasonable reviewers differ, and the faithfulness set is the")
    print("  canonical incident in original and amended form. The intervals are wide")
    print("  because n is small; that width is the point. Both sides face the exact")
    print("  same oracle, so the comparison is fair, and the seeded bootstrap inside")
    print("  each interval prints the same bounds every time.")
    print("=" * 78)


def run_score() -> int:
    """The default keyless path: load the corpora and the cache, score, print.
    Returns 0 on success, 2 if a fixture is missing."""
    for path in (MATERIALITY_CORPUS, GROUNDING_CORPUS):
        if not path.exists():
            print(f"open_vs_closed: corpus not found at {path}", file=sys.stderr)
            return 2
    if not CACHE.exists():
        print(f"open_vs_closed: cache not found at {CACHE}. Run "
              "'py scripts/open_vs_closed.py --record' to build it (needs keys).",
              file=sys.stderr)
        return 2
    result = score(load_materiality_corpus(), load_grounding_corpus(), load_cache())
    print_report(result)
    return 0


def run_json() -> int:
    """The same scored numbers as machine-readable JSON. Keyless."""
    for path in (MATERIALITY_CORPUS, GROUNDING_CORPUS, CACHE):
        if not path.exists():
            print("open_vs_closed: corpus or cache missing", file=sys.stderr)
            return 2
    result = score(load_materiality_corpus(), load_grounding_corpus(), load_cache())
    print(json.dumps(result, indent=2))
    return 0


def run_record() -> int:
    """Refresh the head-to-head cache from LIVE models. This is the ONLY path that
    calls a model. It needs FEATHERLESS_API_KEY for the open models and
    AIML_API_KEY for the closed ones. It drives the models SEQUENTIALLY: one model
    completes BOTH judgments (every materiality verdict, then every drafted filing)
    before the next model starts, so Featherless only runs one big model at a time
    and the pinned roster stays under the switch cap. The cached raw outputs are
    re-scored keyless by the path above. Returns 0 on a full refresh, nonzero on a
    missing key. This path does not fabricate any output."""
    import os

    from _env import load_env

    from floor.drafter import draft_filing
    from floor.materiality import assess_materiality

    load_env()
    feather = os.environ.get("FEATHERLESS_API_KEY")
    aiml = os.environ.get("AIML_API_KEY")
    if not feather:
        print("open_vs_closed --record: FEATHERLESS_API_KEY is not set; the open "
              "models need it. The default scoring path is keyless.",
              file=sys.stderr)
        return 2
    if not aiml:
        print("open_vs_closed --record: AIML_API_KEY is not set; the closed models "
              "need it. The default scoring path is keyless.", file=sys.stderr)
        return 2
    mat_corpus = load_materiality_corpus()
    records = _faithfulness_records(load_grounding_corpus())
    models_out: dict = {}
    for provider, model, label, mat_mt, faith_mt in ALL_MODELS:
        side = "open" if provider == "featherless" else "closed"
        api_key = feather if provider == "featherless" else aiml
        print(f"  judging on {label} ({provider}, {side}) ...")
        materiality: dict = {}
        for entry in mat_corpus["entries"]:
            verdict = assess_materiality(
                entry["fact_record"], model=model, provider=provider,
                api_key=api_key, max_tokens=mat_mt, timeout=90)
            materiality[entry["id"]] = {"material": verdict.material}
            print(f"    materiality {entry['id']}: {verdict.material}")
        faithfulness: dict = {}
        for record_id, fact in records.items():
            text = draft_filing(
                fact, model=model, provider=provider, api_key=api_key,
                regime=FAITHFULNESS_REGIME, max_tokens=faith_mt, timeout=90)
            faithfulness[record_id] = text
            print(f"    faithfulness {record_id}: {len(text)} chars")
        models_out[model] = {
            "label": label,
            "provider": provider,
            "side": side,
            "source": "live",
            "materiality": materiality,
            "faithfulness": faithfulness,
        }
    cache = {
        "about": "Committed cache of the raw OPEN vs CLOSED model outputs on the "
                 "two gate judgments (materiality verdicts over the materiality "
                 "corpus, drafted filings over the grounding-corpus fact-records), "
                 "recorded so scripts/open_vs_closed.py re-runs KEYLESS. The "
                 "SCORING (both oracles, the tallies, the intervals) is always real "
                 "and keyless; only the raw model output is cached. Each model "
                 "carries a 'source' of 'live' (real model output) or "
                 "'illustrative' (a labeled plausible draft used only when a live "
                 "call was unavailable). To refresh against live models run "
                 "py scripts/open_vs_closed.py --record (needs FEATHERLESS_API_KEY "
                 "and AIML_API_KEY).",
        "faithfulness_regime": FAITHFULNESS_REGIME,
        "models": models_out,
    }
    CACHE.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"open_vs_closed --record: wrote {len(models_out)} models to {CACHE}")
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
