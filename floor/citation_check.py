"""Citation-accuracy validator: every [cite: <id>] in a filing resolves to a real
corpus chunk.

E3.11's accuracy spine. A production regulated-filing system must draft against the
real legal text and CITE it, so an examiner can trace a filing sentence to the
clause it satisfies, and so a model's drift from the real obligation is caught. The
corpus (floor/regcorpus.py + floor/corpus/) is the source-of-truth statutory text,
chunked with stable human-citation ids. This module is the deterministic checker
that, given a filing's inline `[cite: <id>]` tags, confirms every cited id resolves
to a real chunk in the built index. An unresolved citation is flagged.

This is the citation analogue of grounding.py's `validate_citations` (which checks
[field: <name>] tags against the fact-record keys). Here the resolution target is
the REGULATION CORPUS, not the fact-record: a [cite: NIS2-Art23(4)] is valid iff
NIS2-Art23(4) is a real chunk id in floor/corpus/index.json.

Three hard properties, mirroring grounding.py:

  1. Pure function of (filing_text, corpus_chunk_ids). No network, no clock, no
     randomness. Same inputs, same CitationCheckResult, always.
  2. It is a VALIDATOR / SCORER, never a gate. Nothing here blocks a filing, moves
     a transition, stops a clock, or releases. It reads text already produced and
     reports which citations resolved and which did not.
  3. The drafters do not have to emit [cite: id] tags yet (that is the E5.9
     retriever wiring). A filing with no [cite: ...] tags is not an error; it
     simply has no citations to validate. What this proves NOW is that the checker
     catches a BAD citation (an id with no chunk) and passes a GOOD one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from floor.regcorpus import all_chunk_ids

# An inline citation tag: [cite: <id>]. The id is the stable human-citation string,
# which can carry letters, digits, and the punctuation that appears in real
# citations (NIS2-Art23(4), SEC-Form8K-Item1.05(a), GDPR-Art5(1)(c),
# DORA-2022/2554-Art19(1), 23NYCRR500.17(a)). So the id pattern is "everything up
# to the closing bracket", trimmed, rather than a restrictive character class that
# would silently drop a real citation's parentheses or slashes.
_CITATION = re.compile(r"\[cite:\s*([^\]]+?)\s*\]")


@dataclass
class CitationCheckResult:
    """The citation-accuracy result for one filing. cited == resolved + unresolved
    (as multisets in order of appearance, deduplicated only within each list by
    preserving first appearance order)."""
    cited: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)

    @property
    def all_resolved(self) -> bool:
        """True when every cited id resolved to a real chunk (an empty filing with
        no citations trivially passes: there is nothing unresolved)."""
        return not self.unresolved

    def as_dict(self) -> dict:
        return {
            "cited": self.cited,
            "resolved": self.resolved,
            "unresolved": self.unresolved,
            "all_resolved": self.all_resolved,
        }


def check_citations(filing_text: str,
                    chunk_ids: set[str] | None = None) -> CitationCheckResult:
    """Validate the inline [cite: <id>] tags in a filing against the corpus.

    Pure and deterministic. Every cited id must be a real chunk id in the built
    corpus index; an id with no chunk is reported as unresolved. `chunk_ids` lets a
    caller pass an explicit id set (a test corpus); when None, the committed index
    (floor/corpus/index.json) is read. Nothing here gates."""
    ids = chunk_ids if chunk_ids is not None else all_chunk_ids()
    result = CitationCheckResult()
    seen_cited: set[str] = set()
    seen_resolved: set[str] = set()
    seen_unresolved: set[str] = set()
    for m in _CITATION.finditer(filing_text or ""):
        cite_id = m.group(1).strip()
        if not cite_id:
            continue
        if cite_id not in seen_cited:
            seen_cited.add(cite_id)
            result.cited.append(cite_id)
        if cite_id in ids:
            if cite_id not in seen_resolved:
                seen_resolved.add(cite_id)
                result.resolved.append(cite_id)
        else:
            if cite_id not in seen_unresolved:
                seen_unresolved.add(cite_id)
                result.unresolved.append(cite_id)
    return result


def strip_corpus_citations(filing_text: str) -> str:
    """Remove the inline [cite: <id>] tags from prose for a clean human-readable
    rendering. Pure string work; leaves every other token untouched, mirroring
    grounding.strip_citations for the [field: ...] tags."""
    return re.sub(r"\s*" + _CITATION.pattern, "", filing_text or "")
