"""Provider-portability check for the drafting pipeline (E5.7 part 4).

The multi-model gateway story is only credible if the SAME drafting call SUCCEEDS
on a DIFFERENT provider, not just a different model behind one proxy. This script
runs the identical draft_filing call against a pair of EQUIVALENT models, one on
each provider (Featherless and the AI/ML API gateway), over the canonical
fact-record, and reports for each side: did the call produce a filing, and does
that filing CLEAR the deterministic grounding scorer against the fact-record. If
both sides produce a grounded filing, the pipeline is portable across providers.

Honest by construction, exactly like the E5.2 caches:

  - The SCORING (floor.grounding.score_filing) is ALWAYS real and keyless. Only
    the raw model output is ever cached.
  - When a live provider key is present and the call succeeds, the side is labeled
    source="live". When it is not (the common case: the Featherless slot is held,
    the AI/ML gateway is flaky, no key), the side falls back to a COMMITTED cached
    response labeled source="illustrative". The label is never hidden.
  - Live calls are TIME-BOXED and never block: a transport/timeout failure falls
    back to the cache rather than stalling the run, so this script never hangs on
    an unreliable provider.

Run it:
  py scripts/portability_check.py           # prefer live, fall back to cache
  py scripts/portability_check.py --cached  # force the cached path (no network)
  py scripts/portability_check.py --record   # refresh the cache from live models
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from floor import grounding, roster  # noqa: E402
from floor.drafter import DrafterError, draft_filing  # noqa: E402

CACHE_FILE = _REPO / "tests" / "fixtures" / "portability_cache.json"

# The canonical fact-record the portability draft is scored against. Kept in step
# with floor.run_floor.CANONICAL_FACTS so a grounded filing on either provider
# traces to the same facts.
FACT_RECORD = {
    "incident_id": "inc-8842",
    "incident_start_utc": "2026-06-16T02:14:00+00:00",
    "records_affected": 48211,
    "attacker": "LockBit 3.0",
    "containment": "partially_contained",
    "systems": ["core banking ledger", "customer KYC store"],
    "data_categories": ["name", "address", "account_number"],
    "regulated_entity": "Meridian Trust Bank N.V.",
    "competent_authority": "national CSIRT (NIS2)",
}

# The equivalent-model pair, one per provider. Both draft the SAME NIS2 filing, so
# a success on each proves the pipeline is provider-portable. The Featherless side
# is the hero open model; the AI/ML side is the gateway's equivalent named model.
PROVIDER_PAIR = (
    ("featherless", roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2"),
    ("aimlapi", roster.AIMLAPI, "claude-sonnet-4-20250514"),
)

# A short live time-box so an unreliable provider never stalls the run.
LIVE_TIMEOUT_S = 20


def _load_cache() -> dict:
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _draft_live(provider: str, model: str) -> str | None:
    """One time-boxed live draft, or None if it failed (missing key, transport,
    timeout, terminal error). Never raises: a failure means fall back to cache."""
    try:
        return draft_filing(FACT_RECORD, model=model, provider=provider,
                            regime="NIS2", timeout=LIVE_TIMEOUT_S, max_attempts=1)
    except DrafterError:
        return None


def check(*, prefer_live: bool) -> dict:
    """Run the portability check over the provider pair. For each side, get a
    filing (live when available and prefer_live, else the committed cache) and
    score it with the real grounding oracle. Returns a result dict with one entry
    per provider plus an overall portable flag."""
    cache = _load_cache()
    cached_sides = cache.get("sides", {})
    sides = []
    for label, provider, model in PROVIDER_PAIR:
        text = None
        source = "illustrative"
        if prefer_live:
            text = _draft_live(provider, model)
            if text is not None:
                source = "live"
        if text is None:
            cached = cached_sides.get(label, {})
            text = cached.get("raw_response", "")
            source = cached.get("source", "illustrative")
            model = cached.get("model", model)
        score = grounding.score_filing(text, FACT_RECORD, branch=label)
        sides.append({
            "provider": label,
            "model": model,
            "source": source,
            "produced_filing": bool(text.strip()),
            "grounding_score": round(score.score, 4),
            "grounded": not score.ungrounded,
            "ungrounded": [
                {"kind": u.kind, "span": u.span, "reason": u.reason}
                for u in score.ungrounded
            ],
        })
    portable = all(s["produced_filing"] and s["grounded"] for s in sides)
    return {
        "portable": portable,
        "fact_record_incident_id": FACT_RECORD["incident_id"],
        "sides": sides,
    }


def record() -> int:
    """Refresh the committed cache from LIVE models on both providers. Each side is
    recorded with its honest source label: "live" when the call succeeded, else the
    EXISTING cached illustrative entry is kept (never overwritten with an empty
    body), so a partial refresh degrades honestly. Writes the cache file."""
    cache = _load_cache()
    sides = cache.get("sides", {})
    for label, provider, model in PROVIDER_PAIR:
        text = _draft_live(provider, model)
        if text is not None and text.strip():
            sides[label] = {"model": model, "source": "live", "raw_response": text}
            print(f"recorded LIVE {label} ({model})")
        else:
            print(f"live {label} unavailable; kept existing cache entry")
    cache.setdefault("about", _CACHE_ABOUT)
    cache["sides"] = sides
    CACHE_FILE.write_text(
        json.dumps(cache, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {CACHE_FILE}")
    return 0


_CACHE_ABOUT = (
    "Committed cache of the raw drafted filings on the two providers' equivalent "
    "models for the E5.7 portability check, recorded so scripts/portability_check.py "
    "and tests/test_portability.py run KEYLESS and never block on a flaky provider. "
    "The grounding SCORE is always recomputed real and keyless; only the raw model "
    "output is cached. source=live is a real model output; source=illustrative is a "
    "labeled plausible filing used when no live provider was reachable. Refresh with "
    "py scripts/portability_check.py --record (needs FEATHERLESS_API_KEY + AIML_API_KEY)."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cached", action="store_true",
                        help="force the cached path (no live call at all)")
    parser.add_argument("--record", action="store_true",
                        help="refresh the cache from live models, then exit")
    args = parser.parse_args(argv)
    if args.record:
        return record()
    result = check(prefer_live=not args.cached)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    verdict = "PORTABLE" if result["portable"] else "NOT PORTABLE"
    print(f"\nportability: {verdict}")
    for s in result["sides"]:
        print(f"  {s['provider']:12s} {s['model']:32s} source={s['source']:12s} "
              f"grounded={s['grounded']} score={s['grounding_score']}")
    return 0 if result["portable"] else 1


if __name__ == "__main__":
    sys.exit(main())
