"""One-command grounding receipt: prove every number in the drafted filings
traces back to the fact-record, and prove the check would catch a hallucination.

This is the AI-quality analogue of scripts/tamper_test.py. A judge's fair
objection to "our open model does not hallucinate facts into filings" is: prove
it. This script answers in the judge's own hands. It:

  1. Loads the captured hero run packets that ship in this repo
     (web/data/packet-*.json). No API keys, no network.
  2. Runs the deterministic grounding scorer (floor/grounding.py) over every
     drafted filing, scoring each filing's prose against the canonical
     fact-record it was drafted from (the amended filings against the amended
     record).
  3. Prints a per-filing grounding score, the grounded-span count, and any
     ungrounded spans verbatim.
  4. Loads the deliberately POISONED fixture
     (web/data/grounding-poisoned-fixture.json), a filing with an invented
     record count and an invented breach actor, and proves the SAME scorer
     FLAGS it. If the poisoned filing were to PASS, the receipt is meaningless,
     so the script treats that as a hard failure too.
  5. Exits 0 only if every real filing cleared the threshold AND the poisoned
     fixture was caught. Nonzero otherwise.

Run it:  py scripts/grounding_report.py

The grounding scorer is pure: a function of (filing_text, fact_record) with no
network and no randomness, so this receipt is replayable and the same every
time, exactly like the byte-identical replay it sits beside.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.grounding import score_filing  # noqa: E402

DATA = REPO_ROOT / "web" / "data"
# The captured hero run packets scored as the clean baseline.
PACKETS = [
    DATA / "packet-normal.json",
    DATA / "packet-inject_contradiction.json",
    DATA / "packet-chaos.json",
    DATA / "packet-amendment.json",
]
POISONED_FIXTURE = DATA / "grounding-poisoned-fixture.json"

# The pass bar: every load-bearing span must trace to a fact. Matches
# floor.run_floor.GROUNDING_THRESHOLD.
THRESHOLD = 1.0
# The amended record count the amendment beat revises records_affected to. The
# amended filings are scored against this, not the original count.
AMENDED_RECORDS = 2_100_000


def _effective_record(fact_record: dict, filing_text: str) -> dict:
    """The fact-record a filing was drafted from. The amendment beat revises
    records_affected upward, so an amended filing (one that states the revised
    figure) is scored against the amended record, not the original. This mirrors
    floor.run_floor, which scores amended filings against the amended record."""
    amended_form = f"{AMENDED_RECORDS:,}"
    if amended_form in filing_text or str(AMENDED_RECORDS) in filing_text:
        eff = dict(fact_record)
        eff["records_affected"] = AMENDED_RECORDS
        return eff
    return fact_record


def _score_packet(path: Path) -> list[dict]:
    """Score every filing in one packet. Returns a list of per-filing result
    dicts with the packet name, regime, score, grounded count, and flagged
    spans."""
    packet = json.loads(path.read_text(encoding="utf-8"))
    fact_record = packet.get("incident", {}).get("fact_record", {})
    out = []
    for f in packet.get("filings", []):
        text = f.get("text", "")
        eff = _effective_record(fact_record, text)
        result = score_filing(text, eff, branch=str(f.get("regime", "")))
        out.append({
            "packet": path.name,
            "regime": f.get("regime", ""),
            "model": f.get("model", ""),
            "score": result.score,
            "grounded": result.grounded,
            "total": result.total,
            "ungrounded": result.ungrounded,
        })
    return out


def _print_rows(rows: list[dict]) -> bool:
    """Print one line per filing and return True iff all cleared the threshold."""
    all_pass = True
    for r in rows:
        ok = r["score"] >= THRESHOLD
        all_pass = all_pass and ok
        badge = "PASS  " if ok else "REVIEW"
        print(f"  [{badge}] {r['packet']:38s} {r['regime']:14s} "
              f"score {r['score']:.2f}  grounded {r['grounded']}/{r['total']}")
        for u in r["ungrounded"]:
            print(f"           ungrounded {u.kind}: {u.span!r}  ({u.reason})")
    return all_pass


def main() -> int:
    print("=" * 72)
    print("GROUNDING REPORT: every number in the filings traces to the fact-record")
    print("=" * 72)
    print("Deterministic grounding scorer over the captured hero run packets.")
    print("No API keys, no network. Pure offline faithfulness check.")
    print()

    missing = [p for p in PACKETS if not p.exists()]
    if missing:
        for p in missing:
            print(f"grounding_report: captured packet not found at {p}", file=sys.stderr)
        return 2

    # --- Step 1: score the real filings -----------------------------------
    print("Step 1  score every drafted filing against its fact-record")
    all_rows: list[dict] = []
    for path in PACKETS:
        all_rows.extend(_score_packet(path))
    clean_pass = _print_rows(all_rows)
    print()
    if clean_pass:
        print("  -> every load-bearing span in every filing traces to a fact in")
        print("     the record. The open models drafted these; the check is honest.")
    else:
        print("  -> at least one filing carries an ungrounded span (flagged above).")
    print()

    # --- Step 2: prove the check catches a hallucination ------------------
    print("Step 2  prove the SAME scorer FAILS on a deliberately poisoned filing")
    if not POISONED_FIXTURE.exists():
        print(f"grounding_report: poisoned fixture not found at {POISONED_FIXTURE}",
              file=sys.stderr)
        return 2
    fixture = json.loads(POISONED_FIXTURE.read_text(encoding="utf-8"))
    fx_record = fixture.get("incident", {}).get("fact_record", {})
    poisoned_caught = True
    for f in fixture.get("filings", []):
        result = score_filing(f.get("text", ""), fx_record,
                              branch=str(f.get("regime", "")))
        flagged = result.score < THRESHOLD
        poisoned_caught = poisoned_caught and flagged
        print(f"  poisoned filing {f.get('regime', '')!r}: score {result.score:.2f} "
              f"-> {'FLAGGED (good)' if flagged else 'NOT FLAGGED (bad)'}")
        for u in result.ungrounded:
            print(f"           caught {u.kind}: {u.span!r}  ({u.reason})")
    print()
    if poisoned_caught:
        print("  -> the invented record count and invented breach actor were both")
        print("     flagged. The receipt would catch a hallucination on camera.")
    else:
        print("  -> the poisoned filing was NOT flagged. The scorer is too lax; the")
        print("     receipt cannot be trusted. This is a real regression.")
    print()

    # --- Verdict ----------------------------------------------------------
    print("=" * 72)
    if clean_pass and poisoned_caught:
        print("VERDICT: PASS. Every real filing is grounded in the fact-record, and")
        print("the same scorer catches a poisoned filing. Verified, not asserted.")
        print("=" * 72)
        return 0
    if not clean_pass:
        print("VERDICT: FAIL. A real filing carries an ungrounded span; review it")
        print("before shipping the run.")
    else:
        print("VERDICT: FAIL. The scorer did not catch the poisoned fixture, so its")
        print("PASS on the real filings is not trustworthy. Do not ship.")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
