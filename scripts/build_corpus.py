"""Deterministic corpus builder: chunk the regulation source files into the
committed index, validate it, and prove every regime is grounded.

E3.11. The regulation corpus (floor/corpus/*.md) holds REAL public statutory text
chunked per article/section with stable human-citation ids. This builder:

  1. Parses every source file into chunks (floor/regcorpus.build_index), which
     fails loud on a malformed marker, a duplicate id, or an empty chunk.
  2. Validates the built corpus: every chunk has a non-empty id, citation, title,
     and text; every chunk id is globally unique and well-formed.
  3. Validates the catalog wiring: every regime in floor/regimes.yaml that declares
     corpus_tags resolves each tag to a real chunk id, and every catalog regime
     (except the non-corpus ones honestly listed) has at least one resolvable
     chunk. A corpus_tag pointing at a non-existent chunk is a hard error.
  4. Writes floor/corpus/index.json deterministically (sorted, no now(), no
     randomness) and reports whether the on-disk index changed.

It is deterministic and reproducible: running it twice over the same sources writes
byte-identical bytes, so the committed index.json is inspectable and stable. It
makes no network call and reads no clock.

  py scripts/build_corpus.py            (rebuild and write the index)
  py scripts/build_corpus.py --check    (verify the committed index is up to date,
                                         exit nonzero if a rebuild would change it,
                                         do NOT write)

Exit 0 on success; nonzero with a named locus on any validation failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.regcorpus import build_index, index_json  # noqa: E402
from floor.regimes import load_catalog  # noqa: E402

CORPUS_DIR = REPO_ROOT / "floor" / "corpus"
INDEX_PATH = CORPUS_DIR / "index.json"

# Catalog regimes that legitimately ground against NO corpus chunk of their own.
# The affected-party / GDPR Art 34 data_subject obligation is grounded by the GDPR
# Art 34 corpus chunk via its corpus_tags, so it is NOT listed here; this set is
# the honest escape hatch for any future regime that ships before its corpus does.
# Today it is empty: every catalog regime resolves at least one real chunk.
REGIMES_WITHOUT_CORPUS: frozenset[str] = frozenset()


def _validate_chunks(chunks: dict) -> list[str]:
    """Every chunk has a non-empty id, citation, title, and text. Returns the list
    of problems (empty when the corpus is well-formed)."""
    problems: list[str] = []
    for cid, chunk in sorted(chunks.items()):
        for field_name in ("id", "citation", "title", "text", "regime_family"):
            value = chunk.get(field_name)
            if not isinstance(value, str) or not value.strip():
                problems.append(
                    f"chunk {cid!r}: field {field_name!r} is empty or not a string")
        if chunk.get("id") != cid:
            problems.append(
                f"chunk keyed {cid!r} carries a mismatched id {chunk.get('id')!r}")
    return problems


def _validate_catalog_wiring(chunks: dict) -> list[str]:
    """Every regime's corpus_tags resolve to a real chunk; every catalog regime
    (except REGIMES_WITHOUT_CORPUS) resolves at least one. Returns the problems."""
    problems: list[str] = []
    chunk_ids = set(chunks.keys())
    specs = load_catalog()
    for spec in specs:
        tags = tuple(getattr(spec, "corpus_tags", ()) or ())
        bad = [t for t in tags if t not in chunk_ids]
        for t in bad:
            problems.append(
                f"regime {spec.key!r}: corpus_tag {t!r} resolves to no chunk in "
                f"the index")
        if not tags and spec.key not in REGIMES_WITHOUT_CORPUS:
            problems.append(
                f"regime {spec.key!r}: declares no corpus_tags and is not listed "
                f"in REGIMES_WITHOUT_CORPUS")
        elif tags and not [t for t in tags if t in chunk_ids] \
                and spec.key not in REGIMES_WITHOUT_CORPUS:
            problems.append(
                f"regime {spec.key!r}: none of its corpus_tags resolve to a chunk")
    return problems


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    print("=" * 72)
    print("BUILD CORPUS: chunk the regulation source files into a stable index")
    print("=" * 72)

    try:
        index = build_index(CORPUS_DIR)
    except (ValueError, FileNotFoundError) as e:
        print(f"build_corpus: corpus parse failed: {e}", file=sys.stderr)
        return 2
    chunks = index["chunks"]
    print(f"Parsed {len(chunks)} chunks from {CORPUS_DIR.name}/ source files.")

    problems = _validate_chunks(chunks)
    problems += _validate_catalog_wiring(chunks)
    if problems:
        print("\nCorpus validation FAILED:")
        for p in problems:
            print("  " + p)
        return 1

    verbatim = sum(1 for c in chunks.values() if c.get("verbatim"))
    summary = len(chunks) - verbatim
    print(f"Validation passed: {len(chunks)} chunks, {verbatim} verbatim, "
          f"{summary} labelled summaries.")
    print("Every regime's corpus_tags resolve to a real chunk.")

    new_bytes = index_json(index)
    old_bytes = INDEX_PATH.read_text(encoding="utf-8") if INDEX_PATH.exists() else ""
    changed = new_bytes != old_bytes

    if check_only:
        if changed:
            print("\n--check: the committed index.json is OUT OF DATE; rerun "
                  "scripts/build_corpus.py to rebuild it.", file=sys.stderr)
            return 1
        print("\n--check: the committed floor/corpus/index.json is up to date.")
        return 0

    INDEX_PATH.write_text(new_bytes, encoding="utf-8")
    if changed:
        print(f"\nWrote {INDEX_PATH.relative_to(REPO_ROOT)} "
              f"({len(new_bytes)} bytes).")
    else:
        print(f"\n{INDEX_PATH.relative_to(REPO_ROOT)} unchanged "
              f"(byte-identical rebuild).")
    print("Index is deterministic: a second build over the same sources writes "
          "the same bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
