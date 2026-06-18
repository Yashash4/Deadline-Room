"""One-command citation-accuracy receipt: every [cite: <id>] in a filing resolves
to a real corpus chunk, and the check would catch a bad citation.

E3.11's accuracy spine, in the judge's own hands. This is the citation analogue of
scripts/grounding_report.py. A fair objection to "our filings cite the real
statutory article" is: prove it, and prove the check would catch a wrong citation.
This script answers both, keyless and offline:

  1. Loads the built regulation corpus index (floor/corpus/index.json) and reports
     the chunk count.
  2. Runs the deterministic citation-accuracy validator (floor/citation_check.py)
     over a GOOD filing whose [cite: ...] tags all name real chunk ids, and shows
     every citation resolving.
  3. Runs the SAME validator over a BAD filing that cites an invented article id
     (NIS2-Art99 and SEC-Item-9.99, neither in the corpus), and proves the
     validator FLAGS the unresolved citations. If the bad filing were to PASS, the
     receipt is meaningless, so the script treats that as a hard failure too.
  4. Exits 0 only if the good filing fully resolved AND the bad filing was caught.
     Nonzero otherwise.

Run it:  py scripts/citation_check.py

The validator is pure: a function of (filing_text, corpus_chunk_ids) with no
network and no randomness, so this receipt is replayable and identical every time,
exactly like the byte-identical replay it sits beside. The corpus + validator are
derived reference data; nothing here gates, clocks, or enters the hashed run-log.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.citation_check import check_citations  # noqa: E402
from floor.regcorpus import all_chunk_ids  # noqa: E402

# A GOOD filing: every [cite: <id>] names a real chunk in the corpus. This is the
# shape an E5.9-retriever-grounded filing will carry once the drafters cite the
# retrieved passages: each factual section tagged with the statutory clause it
# satisfies.
GOOD_FILING = (
    "NIS2 Article 23 incident notification. We submit this 72-hour incident "
    "notification of a significant incident [cite: NIS2-Art23(4)] caused by a "
    "malicious act with possible cross-border impact [cite: NIS2-Art23(1)]. The "
    "incident is significant because it caused severe operational disruption "
    "[cite: NIS2-Art23(3)].\n"
    "Separately, as the personal-data breach reached the supervisory-authority "
    "threshold, the controller notified the lead supervisory authority within 72 "
    "hours [cite: GDPR-Art33], a breach of security within the meaning of the "
    "Regulation [cite: GDPR-Art4(12)].\n"
    "The SEC Form 8-K Item 1.05 disclosure describes the material aspects of the "
    "nature, scope, and timing of the incident [cite: SEC-Form8K-Item1.05(a)], "
    "filed within four business days of the materiality determination "
    "[cite: SEC-Form8K-Item1.05-Instruction1]."
)

# A BAD filing: it cites articles that DO NOT EXIST in the corpus (an invented NIS2
# article number and an invented SEC item). A model that drifts from the real
# obligation and invents a citation produces exactly this, which is the failure the
# validator exists to catch.
BAD_FILING = (
    "NIS2 incident notification. We notify under NIS2 Article 99 "
    "[cite: NIS2-Art99], and disclose under SEC Item 9.99 "
    "[cite: SEC-Item-9.99]. The 72-hour duty [cite: NIS2-Art23(4)] is also "
    "cited correctly here."
)


def _print_filing(label: str, result) -> None:
    print(f"  {label}")
    print(f"    cited      : {result.cited}")
    print(f"    resolved   : {result.resolved}")
    print(f"    unresolved : {result.unresolved}")


def main() -> int:
    print("=" * 72)
    print("CITATION-ACCURACY RECEIPT: every [cite: id] resolves to a real corpus "
          "chunk")
    print("=" * 72)
    print("Deterministic citation validator over the built regulation corpus.")
    print("No API keys, no network. Pure offline citation-accuracy check.")
    print()

    try:
        ids = all_chunk_ids()
    except (FileNotFoundError, ValueError) as e:
        print(f"citation_check: corpus index not loadable: {e}", file=sys.stderr)
        print("Run scripts/build_corpus.py first.", file=sys.stderr)
        return 2
    print(f"Corpus index: {len(ids)} citeable chunks loaded from "
          f"floor/corpus/index.json.")
    print()

    # --- Step 1: the good filing fully resolves ---------------------------
    print("Step 1  a GOOD filing whose every [cite: id] names a real chunk")
    good = check_citations(GOOD_FILING, ids)
    _print_filing("good filing:", good)
    good_ok = good.all_resolved and bool(good.cited)
    print(f"    -> {'PASS' if good_ok else 'FAIL'}: "
          f"{len(good.resolved)} of {len(good.cited)} citations resolved.")
    print()

    # --- Step 2: prove the validator catches a bad citation ---------------
    print("Step 2  prove the SAME validator FLAGS a filing with invented citations")
    bad = check_citations(BAD_FILING, ids)
    _print_filing("bad filing:", bad)
    bad_caught = bool(bad.unresolved)
    print(f"    -> {'PASS' if bad_caught else 'FAIL'}: "
          f"flagged {len(bad.unresolved)} unresolved citation(s) "
          f"{bad.unresolved}.")
    print()

    # --- Verdict ----------------------------------------------------------
    print("=" * 72)
    if good_ok and bad_caught:
        print("VERDICT: PASS. The good filing's citations all resolve to real")
        print("statutory chunks, and the same validator catches an invented")
        print("citation. The citation-accuracy spine is verified, not asserted.")
        print("=" * 72)
        return 0
    if not good_ok:
        print("VERDICT: FAIL. The good filing has an unresolved citation; the")
        print("corpus or the citation ids are out of sync. Rebuild the corpus.")
    else:
        print("VERDICT: FAIL. The validator did NOT catch the invented citation,")
        print("so its PASS on the good filing is not trustworthy. Do not ship.")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
