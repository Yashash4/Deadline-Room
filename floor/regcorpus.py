"""The regulation corpus: loader, chunk parser, and the built-index reader.

E3.11 builds a curated corpus of REAL public statutory text (the breach-notification
articles for the Deadline Room's regimes), chunked per article/section with STABLE
human-citation ids (NIS2-Art23(4), SEC-Form8K-Item1.05(a), GDPR-Art33, ...). This
module is the pure, no-LLM, no-network library over that corpus:

  - `parse_chunks(text, source_file)` splits one source markdown file on its
    `<!-- chunk: <id> | <citation> | <title> -->` markers into CorpusChunk records.
    The chunk id is a stable human-citation string, never a hash, so it survives
    re-chunking and reads in a packet.
  - `build_index(corpus_dir, sources)` walks the source files in sorted order and
    returns the deterministic, sorted index dict the builder writes to
    floor/corpus/index.json. Same inputs always produce byte-identical output (no
    now(), no randomness, sorted keys), so the committed index is reproducible.
  - `load_index(path)` reads the built index back for the citation-accuracy
    validator and (later) the E5.9 retriever.

This is reference data. Nothing here gates, clocks, counts, or enters the hashed
run-log, so byte-identical replay and every sealed sha are untouched. The corpus
is consumed by floor/citation_check.py (the citation-accuracy validator) and, in a
later task, by the E5.9 retriever.

The source-of-truth honesty rules (verbatim vs labelled summary, the per-chunk
source url + retrieval date) live in floor/corpus/SOURCES.md, not in code. A chunk
whose text begins with "Summary (not verbatim" is an honestly-labelled summary; a
chunk with no such prefix is reproduced verbatim from its official source.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
_INDEX_PATH = _CORPUS_DIR / "index.json"

# The corpus source files, in a fixed declared order. Each maps a regime FAMILY to
# its markdown source. The builder walks them sorted by file name for determinism,
# so this tuple's order does not affect the built index; it is the honest manifest
# of which files carry the corpus.
SOURCE_FILES = (
    "dora.md",
    "gdpr.md",
    "global.md",
    "nis2.md",
    "nydfs.md",
    "sec.md",
)

# A chunk marker: <!-- chunk: <id> | <citation> | <title> -->. The id is the stable
# human-citation string; the citation is the formal legal citation rendered for an
# examiner; the title is a short human label. Pipes separate the three fields, so a
# field may not itself contain a pipe (asserted in the builder).
_CHUNK_MARKER = re.compile(
    r"<!--\s*chunk:\s*(?P<body>.+?)\s*-->", re.DOTALL)

# A verbatim chunk's text does NOT begin with this prefix; a summary chunk does.
_SUMMARY_PREFIX = "Summary (not verbatim"


@dataclass(frozen=True)
class CorpusChunk:
    """One citeable corpus chunk: a stable id, its formal citation, a short title,
    the regime family file it came from, and the statutory text.

    `verbatim` is True when the text is reproduced verbatim from the official
    source, False when it is an honestly-labelled summary (its text begins with
    "Summary (not verbatim"). The honesty discipline (SOURCES.md) is the source of
    truth for sourcing; this flag is derived from the text so a consumer can filter
    or badge verbatim vs summary without re-reading SOURCES.md."""
    id: str
    citation: str
    title: str
    regime_family: str
    text: str

    @property
    def verbatim(self) -> bool:
        return not self.text.lstrip().startswith(_SUMMARY_PREFIX)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "citation": self.citation,
            "title": self.title,
            "regime_family": self.regime_family,
            "text": self.text,
            "verbatim": self.verbatim,
        }


def _regime_family(source_file: str) -> str:
    """The regime-family tag for a source file (its stem): 'gdpr', 'nis2', 'dora',
    'sec', 'nydfs', 'global'. This is the corpus's own grouping, distinct from the
    catalog regime key; a catalog regime points at chunk ids via corpus_tags."""
    return Path(source_file).stem


def parse_chunks(text: str, source_file: str) -> list[CorpusChunk]:
    """Split one source file's markdown into its CorpusChunk records.

    Splits on the `<!-- chunk: id | citation | title -->` markers; the text of a
    chunk is everything from the end of its marker up to the next marker (or end of
    file), stripped. Raises structurally on a malformed marker (not exactly three
    pipe-separated fields), a duplicate id within the file, or an empty chunk text,
    so a corpus error surfaces loudly rather than producing a silent bad chunk.
    """
    family = _regime_family(source_file)
    markers = list(_CHUNK_MARKER.finditer(text))
    if not markers:
        raise ValueError(f"corpus source {source_file} has no chunk markers")
    chunks: list[CorpusChunk] = []
    seen: set[str] = set()
    for i, m in enumerate(markers):
        body = m.group("body")
        parts = [p.strip() for p in body.split("|")]
        if len(parts) != 3:
            raise ValueError(
                f"corpus source {source_file}: chunk marker {body!r} must have "
                f"exactly three pipe-separated fields (id | citation | title)")
        chunk_id, citation, title = parts
        if not chunk_id or not citation or not title:
            raise ValueError(
                f"corpus source {source_file}: chunk marker {body!r} has an empty "
                f"id, citation, or title field")
        if chunk_id in seen:
            raise ValueError(
                f"corpus source {source_file}: duplicate chunk id {chunk_id!r}")
        seen.add(chunk_id)
        start = m.end()
        end = markers[i + 1].start() if i + 1 < len(markers) else len(text)
        body_text = text[start:end].strip()
        if not body_text:
            raise ValueError(
                f"corpus source {source_file}: chunk {chunk_id!r} has empty text")
        chunks.append(CorpusChunk(
            id=chunk_id, citation=citation, title=title,
            regime_family=family, text=body_text))
    return chunks


def build_index(corpus_dir: str | Path | None = None,
                source_files: tuple[str, ...] = SOURCE_FILES) -> dict:
    """Build the deterministic corpus index from the source files.

    Returns the index dict: {"chunks": {id: {...}, ...}} with chunk ids as keys.
    Deterministic and reproducible: the source files are read in sorted order, the
    chunks are inserted in sorted-by-id order, and no now()/randomness is used, so
    two builds over the same sources produce byte-identical JSON. Raises on a
    duplicate chunk id ACROSS files (the human-citation id must be globally unique
    so a [cite: id] tag resolves to exactly one chunk)."""
    base = Path(corpus_dir) if corpus_dir is not None else _CORPUS_DIR
    all_chunks: dict[str, CorpusChunk] = {}
    for source_file in sorted(source_files):
        path = base / source_file
        text = path.read_text(encoding="utf-8")
        for chunk in parse_chunks(text, source_file):
            if chunk.id in all_chunks:
                prior = all_chunks[chunk.id].regime_family
                raise ValueError(
                    f"duplicate chunk id {chunk.id!r} across files "
                    f"({prior} and {chunk.regime_family}); citation ids must be "
                    f"globally unique")
            all_chunks[chunk.id] = chunk
    chunks_out = {
        cid: all_chunks[cid].as_dict() for cid in sorted(all_chunks)
    }
    return {"chunks": chunks_out}


def index_json(index: dict) -> str:
    """Serialize the built index to the exact, byte-stable JSON string the builder
    writes to floor/corpus/index.json. sort_keys + a fixed indent + a trailing
    newline, so the committed file is deterministic and diff-friendly."""
    return json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load_index(path: str | Path | None = None) -> dict:
    """Read the built corpus index (floor/corpus/index.json) and return its chunk
    map {id: chunk_dict}. Raises if the index is missing or malformed, so a
    consumer (the citation validator, the E5.9 retriever) fails loud rather than
    treating a missing corpus as an empty one."""
    p = Path(path) if path is not None else _INDEX_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"corpus index not found at {p}; run scripts/build_corpus.py")
    data = json.loads(p.read_text(encoding="utf-8"))
    chunks = data.get("chunks") if isinstance(data, dict) else None
    if not chunks:
        raise ValueError(f"corpus index {p} has no 'chunks' map")
    return chunks


def all_chunk_ids(path: str | Path | None = None) -> set[str]:
    """The set of every citeable chunk id in the built index. Used by the
    citation-accuracy validator to resolve [cite: id] tags."""
    return set(load_index(path).keys())
