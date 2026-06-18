"""The regulation corpus + citation-accuracy spine (E3.11).

Pins five things:
  1. The corpus builds DETERMINISTICALLY: the same source files produce the same
     index.json bytes on two builds (the committed index is reproducible).
  2. Every regime's corpus_tags resolve to a real chunk in the built index (the
     "the filing cites the real article" guarantee, at the catalog level).
  3. The citation-accuracy validator FLAGS an unresolved [cite: id] and PASSES a
     resolved one (the accuracy spine catches a drifted/invented citation).
  4. SOURCES.md exists and records a source for every source-file family.
  5. The verbatim chunks carry non-empty real statutory text (a sanity bar), and
     the verbatim/summary split is honestly labelled.

None of this touches the Warden, the [CLAIMS] schema, the bound payload, or any
sealed capture: the corpus is derived reference data, never in the hashed run-log.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from floor import regcorpus
from floor.citation_check import (
    check_citations,
    strip_corpus_citations,
)
from floor.regimes import load_catalog

CORPUS_DIR = Path(regcorpus.__file__).resolve().parent / "corpus"
INDEX_PATH = CORPUS_DIR / "index.json"
SOURCES_PATH = CORPUS_DIR / "SOURCES.md"


# ---------------------------------------------------------------------------
# 1. Deterministic build.
# ---------------------------------------------------------------------------

def test_build_is_deterministic():
    # Two builds over the same source files produce byte-identical index JSON.
    first = regcorpus.index_json(regcorpus.build_index(CORPUS_DIR))
    second = regcorpus.index_json(regcorpus.build_index(CORPUS_DIR))
    assert first == second


def test_committed_index_matches_a_fresh_build():
    # The committed floor/corpus/index.json is exactly what the builder produces
    # now, so it is reproducible and inspectable, not a hand-edited artifact.
    assert INDEX_PATH.exists(), "the built index must be committed"
    committed = INDEX_PATH.read_text(encoding="utf-8")
    rebuilt = regcorpus.index_json(regcorpus.build_index(CORPUS_DIR))
    assert committed == rebuilt, (
        "floor/corpus/index.json is out of date; run scripts/build_corpus.py")


def test_index_is_sorted_by_chunk_id():
    # Determinism rests on a sorted key order; pin it directly.
    data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    ids = list(data["chunks"].keys())
    assert ids == sorted(ids)


def test_every_chunk_is_well_formed():
    chunks = regcorpus.load_index(INDEX_PATH)
    assert chunks, "the corpus must carry at least one chunk"
    for cid, chunk in chunks.items():
        assert chunk["id"] == cid
        for fieldname in ("citation", "title", "text", "regime_family"):
            assert isinstance(chunk[fieldname], str) and chunk[fieldname].strip(), \
                f"chunk {cid}: {fieldname} empty"


# ---------------------------------------------------------------------------
# 2. Catalog wiring: every regime's corpus_tags resolve.
# ---------------------------------------------------------------------------

def test_every_regime_corpus_tag_resolves_to_a_real_chunk():
    chunk_ids = regcorpus.all_chunk_ids(INDEX_PATH)
    specs = load_catalog()
    for spec in specs:
        # Every catalog regime declares at least one corpus tag.
        assert spec.corpus_tags, f"regime {spec.key} declares no corpus_tags"
        for tag in spec.corpus_tags:
            assert tag in chunk_ids, (
                f"regime {spec.key}: corpus_tag {tag!r} resolves to no chunk")


def test_corpus_tags_preserve_citation_punctuation():
    # The chunk ids carry real citation punctuation (parentheses, slashes, dots);
    # the loader must not strip or lowercase them, or a [cite: id] would not match.
    by = {s.key: s for s in load_catalog()}
    assert "NIS2-Art23(4)" in by["nis2_full"].corpus_tags
    assert "DORA-2022/2554-Art19(1)" in by["dora"].corpus_tags
    assert "GDPR-Art5(1)(c)" in by["uk_ico"].corpus_tags
    assert "SEC-Form8K-Item1.05(a)" in by["sec"].corpus_tags


# ---------------------------------------------------------------------------
# 3. The citation-accuracy validator.
# ---------------------------------------------------------------------------

def test_validator_flags_an_unresolved_citation():
    chunk_ids = regcorpus.all_chunk_ids(INDEX_PATH)
    # A real id plus an invented one: the invented one must be flagged.
    text = ("Filed under [cite: NIS2-Art23(4)] and the invented "
            "[cite: NIS2-Art99].")
    result = check_citations(text, chunk_ids)
    assert "NIS2-Art23(4)" in result.resolved
    assert "NIS2-Art99" in result.unresolved
    assert not result.all_resolved


def test_validator_passes_a_resolved_citation():
    chunk_ids = regcorpus.all_chunk_ids(INDEX_PATH)
    text = ("Filed under [cite: GDPR-Art33] and "
            "[cite: SEC-Form8K-Item1.05(a)].")
    result = check_citations(text, chunk_ids)
    assert result.all_resolved
    assert result.resolved == ["GDPR-Art33", "SEC-Form8K-Item1.05(a)"]
    assert result.unresolved == []


def test_validator_resolves_against_the_committed_index_by_default():
    # With no explicit id set, the validator reads the committed index.
    result = check_citations("Cited [cite: GDPR-Art34].")
    assert result.all_resolved
    assert result.resolved == ["GDPR-Art34"]


def test_filing_with_no_citations_trivially_passes():
    result = check_citations("A filing with no inline citation tags at all.",
                             {"GDPR-Art33"})
    assert result.cited == []
    assert result.all_resolved  # nothing unresolved


def test_a_citation_is_only_counted_once():
    # Repeating the same id does not inflate the counts.
    result = check_citations(
        "[cite: GDPR-Art33] then again [cite: GDPR-Art33].", {"GDPR-Art33"})
    assert result.cited == ["GDPR-Art33"]
    assert result.resolved == ["GDPR-Art33"]


def test_strip_corpus_citations_removes_only_the_tags():
    text = "The duty [cite: GDPR-Art33] attaches within 72 hours."
    stripped = strip_corpus_citations(text)
    assert "[cite:" not in stripped
    assert "The duty" in stripped and "within 72 hours" in stripped


# ---------------------------------------------------------------------------
# 4. SOURCES.md provenance.
# ---------------------------------------------------------------------------

def test_sources_md_exists_and_covers_every_source_file():
    assert SOURCES_PATH.exists(), "floor/corpus/SOURCES.md must exist"
    text = SOURCES_PATH.read_text(encoding="utf-8")
    # Every corpus source file is named in SOURCES.md, so each chunk family has a
    # recorded official source.
    for source_file in regcorpus.SOURCE_FILES:
        assert source_file in text, f"{source_file} not recorded in SOURCES.md"
    # The retrieval date is recorded.
    assert "2026-06-18" in text


def test_sources_md_records_a_source_url_per_family():
    text = SOURCES_PATH.read_text(encoding="utf-8")
    # Each primary-source host appears, so a reader can re-verify the text.
    for host in ("eur-lex.europa.eu", "sec.gov", "dfs.ny.gov"):
        assert host in text, f"SOURCES.md is missing the {host} source"


# ---------------------------------------------------------------------------
# 5. Verbatim sanity + honest labelling.
# ---------------------------------------------------------------------------

def test_verbatim_chunks_carry_real_non_empty_text():
    chunks = regcorpus.load_index(INDEX_PATH)
    verbatim = {cid: c for cid, c in chunks.items() if c["verbatim"]}
    # There is a meaningful body of verbatim statutory text (the EU/US core).
    assert len(verbatim) >= 10
    for cid, chunk in verbatim.items():
        # A verbatim chunk is real statute, not a stub: a sane minimum length and
        # NOT the summary prefix.
        assert len(chunk["text"]) > 60, f"verbatim chunk {cid} too short"
        assert not chunk["text"].lstrip().startswith("Summary (not verbatim")


def test_summary_chunks_are_honestly_labelled():
    chunks = regcorpus.load_index(INDEX_PATH)
    summaries = {cid: c for cid, c in chunks.items() if not c["verbatim"]}
    # Every non-verbatim chunk's text actually begins with the honest summary
    # label; the verbatim flag is derived from that prefix, never asserted blindly.
    for cid, chunk in summaries.items():
        assert chunk["text"].lstrip().startswith("Summary (not verbatim"), cid


def test_the_core_breach_articles_are_present_and_verbatim():
    chunks = regcorpus.load_index(INDEX_PATH)
    # The load-bearing breach-notification articles are present AND verbatim (these
    # are the ones a regulator judge will look up against the official text).
    for cid in ("GDPR-Art33", "GDPR-Art34", "NIS2-Art23(4)",
                "SEC-Form8K-Item1.05(a)", "NYDFS-23NYCRR500.17(a)"):
        assert cid in chunks, f"core article {cid} missing from the corpus"
        assert chunks[cid]["verbatim"], f"core article {cid} must be verbatim"


def test_gdpr_art33_text_is_the_real_statute():
    # A concrete grounding check on one verbatim chunk: the GDPR Art 33 text carries
    # the real "72 hours" duty and the unless-clause, so it is the actual statute,
    # not a paraphrase.
    chunks = regcorpus.load_index(INDEX_PATH)
    # Collapse the source line wrapping so a phrase that breaks across a newline
    # still matches: the corpus stores the statute with its original wrapping.
    art33 = " ".join(chunks["GDPR-Art33"]["text"].split())
    assert "72 hours" in art33
    assert "unlikely to result in a risk to the rights and freedoms" in art33


# ---------------------------------------------------------------------------
# Builder validation surfaces structural errors loudly.
# ---------------------------------------------------------------------------

def test_parse_rejects_a_malformed_marker(tmp_path):
    bad = "<!-- chunk: only-two | fields -->\nsome text\n"
    with pytest.raises(ValueError):
        regcorpus.parse_chunks(bad, "bad.md")


def test_parse_rejects_a_duplicate_id_within_a_file(tmp_path):
    bad = ("<!-- chunk: DUP | Cite | Title -->\nfirst\n"
           "<!-- chunk: DUP | Cite | Title -->\nsecond\n")
    with pytest.raises(ValueError):
        regcorpus.parse_chunks(bad, "bad.md")


def test_parse_rejects_an_empty_chunk(tmp_path):
    bad = ("<!-- chunk: A | Cite | Title -->\n"
           "<!-- chunk: B | Cite | Title -->\nbody\n")
    with pytest.raises(ValueError):
        regcorpus.parse_chunks(bad, "bad.md")


def test_build_rejects_a_duplicate_id_across_files(tmp_path):
    # Two files declaring the same chunk id is a hard error: a [cite: id] must
    # resolve to exactly one chunk.
    (tmp_path / "a.md").write_text(
        "<!-- chunk: SAME | Cite A | Title A -->\nbody a\n", encoding="utf-8")
    (tmp_path / "b.md").write_text(
        "<!-- chunk: SAME | Cite B | Title B -->\nbody b\n", encoding="utf-8")
    with pytest.raises(ValueError):
        regcorpus.build_index(tmp_path, source_files=("a.md", "b.md"))
