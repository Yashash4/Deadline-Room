"""Per-model hallucination leaderboard, scored by the frozen grounding oracle.

This is the AI-quality measurement half of the partner story. The corpus is
model-agnostic; this harness turns it into a real model COMPARISON. For each
incident fact-record, each model drafts ONE filing through floor.drafter.llm_complete,
the deterministic floor.grounding.score_filing oracle scores it, and the script
tallies four per-model rates:

  ungrounded-span rate : the fraction of drafted filings that carry at least one
                         load-bearing span the oracle could not trace to the
                         fact-record (any kind of flag at all).
  count-error rate     : the fraction whose flags include a count-shaped number
                         that disagrees with records_affected.
  date-error rate      : the fraction whose flags include a written/ISO date that
                         disagrees with the incident date.
  actor-error rate     : the fraction whose flags include a named breach actor not
                         present in the fact-record.

Each rate is reported with its 95% confidence interval (Wilson + seeded
bootstrap) from floor.eval_stats, because a rate over a dozen filings is a point
estimate and a careful reviewer asks for the band, not the bare number.

KEYLESS by default. The raw model outputs (one drafted filing per model per
incident) are recorded ONCE into a committed cache (tests/fixtures/
leaderboard_cache.json); the default SCORING path reads that cache and makes NO
model call, so a judge and the test suite re-run this with no API key and get the
identical rates every time. The SCORING math (the oracle, the rate tally, the
intervals) is always real and keyless. Only the cached raw filing text may be
illustrative when a live call was not possible: the cache carries a per-model
"source" of "live" or "illustrative" and this receipt prints it honestly.

  py scripts/model_leaderboard.py           (keyless: score from the cache)
  py scripts/model_leaderboard.py --json     (the same numbers as JSON)
  py scripts/model_leaderboard.py --record    (refresh the cache from live models;
                                               needs FEATHERLESS_API_KEY for the
                                               open models and AIML_API_KEY for the
                                               closed ones)

The --record path is the ONLY one that calls a model. It drives the models
SEQUENTIALLY, one big model fully through the incident set before the next, so
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

CORPUS = REPO_ROOT / "tests" / "fixtures" / "materiality_corpus.json"
CACHE = REPO_ROOT / "tests" / "fixtures" / "leaderboard_cache.json"

# The models on the leaderboard, in print order: the three OPEN models on
# Featherless, then the two CLOSED models on the AI/ML API gateway. Each row is
# (provider, model, label, max_tokens). MiniMax is a reasoning model that spends
# an internal preamble before visible content, so it gets the larger budget the
# UK drafter already uses for it; the others draft cleanly in the default budget.
MODELS = [
    ("featherless", "deepseek-ai/DeepSeek-V3.2", "DeepSeek-V3.2", "open", 700),
    ("featherless", "MiniMaxAI/MiniMax-M2.7", "MiniMax-M2.7", "open", 2000),
    ("featherless", "Qwen/Qwen2.5-72B-Instruct", "Qwen2.5-72B", "open", 700),
    ("aimlapi", "claude-opus-4-1-20250805", "claude-opus-4-1", "closed", 700),
    ("aimlapi", "gpt-5-chat-latest", "gpt-5-chat-latest", "closed", 700),
]

# The regime each filing is drafted under for the leaderboard. One fixed regime
# keeps the prompt constant across models so the only variable is the model.
LEADERBOARD_REGIME = "NIS2"


def load_corpus() -> dict:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def load_cache() -> dict:
    return json.loads(CACHE.read_text(encoding="utf-8"))


def _flag_kinds(filing_text: str, fact_record: dict) -> set[str]:
    """Score one filing and return the SET of ungrounded-span kinds the frozen
    oracle flagged ('number', 'date', 'named_entity'), or an empty set when the
    filing is fully grounded. Pure function of (filing_text, fact_record)."""
    result = score_filing(filing_text, fact_record, branch="leaderboard")
    return {u.kind for u in result.ungrounded}


def score(corpus: dict, cache: dict) -> dict:
    """Compute the full leaderboard: per model, the four rates each with a 95%
    interval, from the corpus fact-records and the cached drafted filings. Pure
    function of its two inputs, no network. Raises KeyError if the cache is
    missing a model or an incident the corpus carries, so a stale cache fails
    loudly rather than scoring a subset."""
    records = {e["id"]: e["fact_record"] for e in corpus["entries"]}
    incident_ids = [e["id"] for e in corpus["entries"]]
    cached = cache["models"]
    rows: list[dict] = []
    for provider, model, label, kind, _max_tokens in MODELS:
        entry = cached[model]
        filings = entry["filings"]
        n = 0
        any_flag = count_err = date_err = actor_err = 0
        per_incident: list[dict] = []
        for incident_id in incident_ids:
            fact = records[incident_id]
            text = filings[incident_id]
            flags = _flag_kinds(text, fact)
            n += 1
            has_any = bool(flags)
            has_count = "number" in flags
            has_date = "date" in flags
            has_actor = "named_entity" in flags
            any_flag += 1 if has_any else 0
            count_err += 1 if has_count else 0
            date_err += 1 if has_date else 0
            actor_err += 1 if has_actor else 0
            per_incident.append({
                "id": incident_id,
                "ungrounded": has_any,
                "count_error": has_count,
                "date_error": has_date,
                "actor_error": has_actor,
            })
        rows.append({
            "model": model,
            "label": label,
            "provider": provider,
            "kind": kind,
            "source": entry.get("source", "illustrative"),
            "n": n,
            "ungrounded_rate": proportion_ci(any_flag, n),
            "count_error_rate": proportion_ci(count_err, n),
            "date_error_rate": proportion_ci(date_err, n),
            "actor_error_rate": proportion_ci(actor_err, n),
            "counts": {
                "ungrounded": any_flag,
                "count_error": count_err,
                "date_error": date_err,
                "actor_error": actor_err,
            },
            "per_incident": per_incident,
        })
    return {
        "n_incidents": len(incident_ids),
        "rows": rows,
    }


def _rate_cell(ci: dict) -> str:
    """A compact 'point [low, high]' rate cell from a proportion_ci dict."""
    w = ci["wilson"]
    return f"{ci['point']:.2f} [{w['low']:.2f},{w['high']:.2f}]"


def print_report(result: dict) -> None:
    print("=" * 78)
    print("PER-MODEL HALLUCINATION LEADERBOARD (scored by the frozen grounding oracle)")
    print("=" * 78)
    print(f"Each model drafted one filing per incident over {result['n_incidents']} "
          "incidents.")
    print("The deterministic floor/grounding.py oracle scored every filing; no model")
    print("scores itself. Rates are 'point [Wilson 95% low, high]'. Lower is better.")
    print("Cache source per model: 'live' = real model output, 'illustrative' = a")
    print("labeled plausible draft used only because a live call was unavailable.")
    print()
    header = (f"  {'model':18s}{'src':6s}{'open?':7s}{'ungrounded':>18s}"
              f"{'count-err':>18s}{'date-err':>18s}{'actor-err':>18s}")
    print(header)
    for r in result["rows"]:
        open_closed = "open" if r["kind"] == "open" else "closed"
        src = "live" if r["source"] == "live" else "illus"
        print(f"  {r['label']:18s}{src:6s}{open_closed:7s}"
              f"{_rate_cell(r['ungrounded_rate']):>18s}"
              f"{_rate_cell(r['count_error_rate']):>18s}"
              f"{_rate_cell(r['date_error_rate']):>18s}"
              f"{_rate_cell(r['actor_error_rate']):>18s}")
    print()
    print("  Read honestly: the oracle is conservative (it checks count-shaped")
    print("  numbers, dates, and version-tagged actors), so a 0.00 ungrounded rate")
    print("  means no model invented one of THOSE load-bearing spans, not that the")
    print("  prose is perfect. The intervals are wide because n is small; that width")
    print("  is the honest signal, and the bootstrap inside each interval is seeded")
    print("  so this prints the same bounds every time.")
    print("=" * 78)


def run_score() -> int:
    """The default keyless path: load the corpus and the cached filings, score,
    and print the leaderboard. Returns 0 on success, 2 if a fixture is missing."""
    if not CORPUS.exists():
        print(f"model_leaderboard: corpus not found at {CORPUS}", file=sys.stderr)
        return 2
    if not CACHE.exists():
        print(f"model_leaderboard: cache not found at {CACHE}. Run "
              "'py scripts/model_leaderboard.py --record' to build it (needs keys).",
              file=sys.stderr)
        return 2
    result = score(load_corpus(), load_cache())
    print_report(result)
    return 0


def run_json() -> int:
    """The same scored numbers as machine-readable JSON. Keyless."""
    if not CORPUS.exists() or not CACHE.exists():
        print("model_leaderboard: corpus or cache missing", file=sys.stderr)
        return 2
    result = score(load_corpus(), load_cache())
    print(json.dumps(result, indent=2))
    return 0


def run_record() -> int:
    """Refresh the leaderboard cache from LIVE models. This is the ONLY path that
    calls a model. It needs FEATHERLESS_API_KEY for the open models and
    AIML_API_KEY for the closed ones. It drives the models SEQUENTIALLY: one model
    drafts the full incident set before the next model starts, so Featherless only
    runs one big model at a time and the pinned roster stays under the switch cap.
    Each drafted filing is the raw model output; the scoring path above re-derives
    the rates from it keyless. Returns 0 on a full refresh, nonzero on a missing
    key. A model the keys cannot reach is left to the operator to handle; this
    path does not fabricate output."""
    import os

    from _env import load_env

    from floor.drafter import draft_filing

    load_env()
    feather = os.environ.get("FEATHERLESS_API_KEY")
    aiml = os.environ.get("AIML_API_KEY")
    if not feather:
        print("model_leaderboard --record: FEATHERLESS_API_KEY is not set; the "
              "open models need it. The default scoring path is keyless.",
              file=sys.stderr)
        return 2
    if not aiml:
        print("model_leaderboard --record: AIML_API_KEY is not set; the closed "
              "models need it. The default scoring path is keyless.",
              file=sys.stderr)
        return 2
    corpus = load_corpus()
    models_out: dict = {}
    for provider, model, label, kind, max_tokens in MODELS:
        api_key = feather if provider == "featherless" else aiml
        filings: dict = {}
        print(f"  drafting on {label} ({provider}) ...")
        for entry in corpus["entries"]:
            fact = entry["fact_record"]
            text = draft_filing(
                fact, model=model, provider=provider, api_key=api_key,
                regime=LEADERBOARD_REGIME, max_tokens=max_tokens, timeout=90)
            filings[entry["id"]] = text
            print(f"    {entry['id']}: {len(text)} chars")
        models_out[model] = {
            "label": label,
            "provider": provider,
            "kind": kind,
            "source": "live",
            "filings": filings,
        }
    cache = {
        "about": "Committed cache of one drafted filing per model per incident "
                 "over tests/fixtures/materiality_corpus.json, recorded so "
                 "scripts/model_leaderboard.py re-runs KEYLESS. The SCORING (the "
                 "grounding oracle, the rate tally, the intervals) is always real "
                 "and keyless; only this raw filing text is cached. Each model "
                 "carries a 'source' of 'live' (real model output) or "
                 "'illustrative' (a labeled plausible draft used only when a live "
                 "call was unavailable). To refresh against live models run "
                 "py scripts/model_leaderboard.py --record (needs FEATHERLESS_API_KEY "
                 "and AIML_API_KEY).",
        "regime": LEADERBOARD_REGIME,
        "models": models_out,
    }
    CACHE.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    print(f"model_leaderboard --record: wrote {len(models_out)} models to {CACHE}")
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
