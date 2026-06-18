"""Pure deterministic RAG retriever over the regulation corpus (E5.9).

The retrieval half of the RAG-grounded-filing feature whose corpus half is E3.11.
E3.11 built the curated corpus of REAL public statutory text, chunked per
article/section with stable human-citation ids (floor/corpus/index.json), and gave
each regime a `corpus_tags` list naming the chunk ids that ground it. This module
is the retriever that, given a regime and the incident fact-record, fetches the
top-k of that regime's grounding chunks so the CONTENT-producing LLM calls (the
drafter, the materiality assessor, the Challenger) can write against and cite the
real regulation text.

Three hard properties, all required because the retriever feeds drafting and the
result is rendered in the packet, while the Warden must stay byte-identical:

  1. PURE and DETERMINISTIC. retrieve(regime, fact_record, k) is a pure function of
     (corpus, regime, fact_record, k): no network, no clock, no RNG, no global
     state. Identical inputs always produce the identical ordered list. The ranking
     is a hand-rolled Okapi BM25 over the chunk text (zero non-stdlib dependency),
     with a fixed, documented tie-break so two chunks with the same score always
     order the same way.

  2. It NEVER reaches a gate. Nothing here gates, counts, clocks, releases, or
     enters the hashed run-log. Retrieval feeds only the content-producing LLM
     prompts (as injected context) and the packet renderer (as out-of-log derived
     trace), exactly like the format_profile and the grounding receipt. The Warden
     never retrieves; the gate never sees a chunk.

  3. The DEFAULT path is BM25 over the committed index. An optional
     EmbeddingRetriever reads a committed floor/corpus/embeddings.json when present,
     but it NEVER calls a live embedding API in the default or test path: a missing
     cache simply means the embedding retriever is unavailable, and the caller falls
     back to BM25. So a run with no embeddings cache is byte-identical to one built
     before this module existed.

The query for a regime is built deterministically from two sources: the regime's
own corpus_tags topic words (the citation strings and chunk titles name what the
regime is about) and the load-bearing fact-record fields (the incident's systems,
data categories, attacker, and the breach-notification vocabulary). The candidate
set is the regime's declared corpus_tags chunks: a regime retrieves over the
passages that ground IT, so "top-k for SEC returns SEC chunks" holds by
construction, and a chunk from another regime can never leak into a filing's
citations.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from floor import regcorpus, regimes

_CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
_EMBEDDINGS_PATH = _CORPUS_DIR / "embeddings.json"

# Okapi BM25 parameters, fixed so the ranking is reproducible and documented. These
# are the standard defaults; k1 controls term-frequency saturation and b controls
# the document-length normalization. They are constants, never tuned at runtime, so
# the score is a pure function of the corpus and the query.
BM25_K1 = 1.5
BM25_B = 0.75

# The default number of chunks a retrieval returns. Small on purpose: a filing
# cites a handful of clauses, and a tight context keeps the injected prompt focused
# on the load-bearing requirements rather than the whole statute.
DEFAULT_K = 4

# A token is a lowercased run of word characters. Punctuation that appears inside a
# citation id (parentheses, slashes, dots) is a token boundary for the text scorer:
# we score over the prose words, not the id punctuation. Digits are kept so a
# numeric requirement ("72 hours") tokenizes.
_TOKEN = re.compile(r"[a-z0-9]+")

# A tiny stop-list of function words that carry no retrieval signal. Kept short and
# fixed so the tokenization stays a pure, documented transform; the goal is only to
# stop the most common glue words from dominating short queries, not to do real NLP.
_STOPWORDS = frozenset({
    "the", "a", "an", "of", "to", "and", "or", "in", "on", "at", "for", "is",
    "are", "be", "by", "as", "it", "its", "that", "this", "with", "from", "shall",
    "which", "any", "all", "such", "where", "when", "not", "no",
})

# The load-bearing fact-record fields that name what the incident IS, in a fixed
# order. These seed the query so a retrieval is incident-aware (a breach of a
# customer KYC store with personal data retrieves the data-categories passages),
# without letting a noisy free-text field (a long systems list) swamp the regime's
# own topic words. Only these keys are read, and only as plain text.
_QUERY_FACT_FIELDS = (
    "systems",
    "data_categories",
    "attacker",
    "containment",
    "regulated_entity",
)

# Fixed breach-notification vocabulary added to every query so the retriever favors
# the notification/reporting clauses over, say, a definitions recital when both are
# tagged to a regime. Deterministic and regime-independent.
_NOTIFICATION_VOCAB = (
    "breach", "incident", "notification", "report", "personal", "data",
    "supervisory", "authority", "competent", "material",
)


@dataclass(frozen=True)
class RetrievedChunk:
    """One chunk returned by a retrieval: the stable citation id, the formal
    citation and title (for the packet), the statutory text (for the injected
    prompt), and the BM25 score that ranked it (for the trace and a stable
    tie-break). Frozen and hashable so a retrieval result is a value, never mutated
    in place."""
    id: str
    citation: str
    title: str
    text: str
    regime_family: str
    score: float

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "citation": self.citation,
            "title": self.title,
            "text": self.text,
            "regime_family": self.regime_family,
            "score": round(self.score, 6),
        }


def tokenize(text: str) -> list[str]:
    """Lowercase, split on non-word characters, drop stop-words. Pure and
    deterministic: the same string always yields the same token list. Digits are
    kept; one-character tokens other than a bare digit are dropped as noise."""
    out: list[str] = []
    for tok in _TOKEN.findall((text or "").lower()):
        if tok in _STOPWORDS:
            continue
        if len(tok) == 1 and not tok.isdigit():
            continue
        out.append(tok)
    return out


def _corpus_tags_for(regime: str, catalog: list[regimes.RegimeSpec] | None) -> tuple[str, ...]:
    """The corpus_tags chunk ids that ground a regime. `regime` may be the regime
    KEY (sec, nis2_full) or the regime BRANCH (sec, nis2): both are accepted so a
    caller that has only the branch label (the drafter closures key on branch) can
    retrieve without first resolving the key. Returns the empty tuple for a regime
    that declares no corpus_tags (an ungrounded regime), so the caller drafts
    exactly as before."""
    specs = catalog if catalog is not None else regimes.load_catalog()
    for spec in specs:
        if spec.key == regime:
            return spec.corpus_tags
    for spec in specs:
        if spec.branch == regime:
            return spec.corpus_tags
    return ()


def build_query(regime: str, fact_record: dict,
                tags: tuple[str, ...],
                chunks: dict[str, dict]) -> list[str]:
    """Build the deterministic retrieval query token list for a regime.

    The query mixes three fixed sources, always in the same order so the token list
    is reproducible: (1) the regime's own corpus_tags topic words, taken from each
    tagged chunk's citation and title (what the regime is about); (2) the
    load-bearing fact-record fields naming what the incident is; (3) the fixed
    breach-notification vocabulary. Pure function of its inputs."""
    parts: list[str] = []
    # (1) The regime's topic, from the citation + title of each tagged chunk.
    for tag in tags:
        chunk = chunks.get(tag)
        if chunk is None:
            continue
        parts.extend(tokenize(chunk.get("citation", "")))
        parts.extend(tokenize(chunk.get("title", "")))
    # (2) The incident facts that name what happened.
    for field in _QUERY_FACT_FIELDS:
        value = fact_record.get(field)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for v in value:
                parts.extend(tokenize(str(v)))
        else:
            parts.extend(tokenize(str(value)))
    # (3) The fixed notification vocabulary.
    parts.extend(_NOTIFICATION_VOCAB)
    return parts


def _bm25_scores(query: list[str],
                 candidates: list[tuple[str, list[str]]]) -> dict[str, float]:
    """Score every candidate chunk against the query with Okapi BM25 over the
    candidate set as the corpus. Pure function of (query, candidates).

    `candidates` is a list of (chunk_id, token_list). The IDF is computed over the
    candidate set (the regime's own grounding chunks), which is the right reference
    population: we are ranking which of THIS regime's clauses best matches the
    incident, not comparing across regimes. Returns {chunk_id: score}."""
    n = len(candidates)
    if n == 0:
        return {}
    doc_freq: dict[str, int] = {}
    lengths: dict[str, int] = {}
    term_freq: dict[str, dict[str, int]] = {}
    total_len = 0
    for cid, tokens in candidates:
        lengths[cid] = len(tokens)
        total_len += len(tokens)
        tf: dict[str, int] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1
        term_freq[cid] = tf
        for term in tf:
            doc_freq[term] = doc_freq.get(term, 0) + 1
    avg_len = total_len / n if n else 0.0
    query_terms = set(query)
    scores: dict[str, float] = {}
    for cid, tokens in candidates:
        tf = term_freq[cid]
        length = lengths[cid]
        score = 0.0
        for term in query_terms:
            f = tf.get(term, 0)
            if f == 0:
                continue
            df = doc_freq.get(term, 0)
            # Okapi BM25 idf with the +1 inside the log so it is always >= 0 (no
            # negative-idf surprise on a term present in every candidate).
            idf = math.log(1.0 + (n - df + 0.5) / (df + 0.5))
            denom = f + BM25_K1 * (1.0 - BM25_B + BM25_B * (length / avg_len if avg_len else 0.0))
            score += idf * (f * (BM25_K1 + 1.0)) / denom if denom else 0.0
        scores[cid] = score
    return scores


class Bm25Retriever:
    """The DEFAULT retriever: hand-rolled Okapi BM25 over the committed corpus index.

    Pure and deterministic, zero non-stdlib dependency. Construct it once over the
    built index (it loads floor/corpus/index.json by default) and call retrieve()
    per (regime, fact_record). A retrieval restricts the candidate set to the
    regime's declared corpus_tags chunks, scores each against the
    deterministically-built query, and returns the top-k ordered by score
    descending, then by chunk id ascending as a stable tie-break."""

    name = "bm25"

    def __init__(self, chunks: dict[str, dict] | None = None,
                 catalog: list[regimes.RegimeSpec] | None = None) -> None:
        self._chunks = chunks if chunks is not None else regcorpus.load_index()
        self._catalog = catalog

    def retrieve(self, regime: str, fact_record: dict, *,
                 k: int = DEFAULT_K) -> list[RetrievedChunk]:
        """Return the top-k grounding chunks for a regime against the fact-record.

        Pure function of (self._chunks, self._catalog, regime, fact_record, k). The
        candidate set is the regime's corpus_tags chunks; an empty tag list (an
        ungrounded regime) yields an empty result and the caller drafts ungrounded.
        Ranking is BM25 score descending, then chunk id ascending (a total order, so
        the list is byte-identical across two calls). k <= 0 returns []."""
        if k <= 0:
            return []
        tags = _corpus_tags_for(regime, self._catalog)
        candidates: list[tuple[str, list[str]]] = []
        present_tags: list[str] = []
        for tag in tags:
            chunk = self._chunks.get(tag)
            if chunk is None:
                continue
            present_tags.append(tag)
            candidates.append((tag, tokenize(chunk.get("text", ""))))
        if not candidates:
            return []
        query = build_query(regime, fact_record, tuple(present_tags), self._chunks)
        scores = _bm25_scores(query, candidates)
        # Total order: score descending, then id ascending. Both keys are pure, so
        # the ordering is identical on every call.
        ordered = sorted(present_tags, key=lambda cid: (-scores.get(cid, 0.0), cid))
        out: list[RetrievedChunk] = []
        for cid in ordered[:k]:
            chunk = self._chunks[cid]
            out.append(RetrievedChunk(
                id=cid,
                citation=chunk.get("citation", ""),
                title=chunk.get("title", ""),
                text=chunk.get("text", ""),
                regime_family=chunk.get("regime_family", ""),
                score=scores.get(cid, 0.0),
            ))
        return out


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors. Pure; returns 0.0 for a
    zero vector so a degenerate embedding never raises."""
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class EmbeddingRetriever:
    """An optional dense retriever that reads a COMMITTED embeddings cache, never a
    live embedding API in the default or test path.

    The cache (floor/corpus/embeddings.json) carries a precomputed vector per chunk
    id plus a small map of precomputed QUERY vectors keyed by regime, so a retrieval
    is a pure cosine ranking with no model call at run time. If the cache is absent
    the retriever reports unavailable() and the caller falls back to BM25, so a repo
    with no cache behaves exactly as one built before this class existed. This seam
    exists so a production deployment can swap in real embeddings by committing the
    cache, without any live call on the default path.

    The cache schema:
        {"chunks": {chunk_id: [float, ...]},
         "queries": {regime_key_or_branch: [float, ...]}}
    """

    name = "embedding"

    def __init__(self, cache_path: str | Path | None = None,
                 chunks: dict[str, dict] | None = None,
                 catalog: list[regimes.RegimeSpec] | None = None) -> None:
        self._path = Path(cache_path) if cache_path is not None else _EMBEDDINGS_PATH
        self._chunks = chunks if chunks is not None else regcorpus.load_index()
        self._catalog = catalog
        self._cache: dict | None = None
        if self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("chunks") and data.get("queries"):
                self._cache = data

    def available(self) -> bool:
        """True iff a well-formed committed embeddings cache was loaded. When False,
        the caller falls back to BM25; no live call is ever made here."""
        return self._cache is not None

    def retrieve(self, regime: str, fact_record: dict, *,
                 k: int = DEFAULT_K) -> list[RetrievedChunk]:
        """Cosine-rank the regime's corpus_tags chunks against the precomputed query
        vector for that regime, from the committed cache. Pure: no model call. Raises
        if the cache is unavailable (the caller must check available() first), so a
        missing cache never silently degrades to an empty result that looks real."""
        if self._cache is None:
            raise RuntimeError(
                "embedding cache unavailable; call available() and fall back to BM25")
        if k <= 0:
            return []
        tags = _corpus_tags_for(regime, self._catalog)
        qvecs = self._cache["queries"]
        cvecs = self._cache["chunks"]
        qvec = qvecs.get(regime)
        if qvec is None:
            # Try the branch->key fallback: the cache may key queries by regime key
            # while the caller passed a branch. Resolve via the catalog.
            specs = self._catalog if self._catalog is not None else regimes.load_catalog()
            for spec in specs:
                if spec.branch == regime and spec.key in qvecs:
                    qvec = qvecs[spec.key]
                    break
        if qvec is None:
            return []
        scored: list[tuple[str, float]] = []
        for tag in tags:
            if tag not in self._chunks or tag not in cvecs:
                continue
            scored.append((tag, _cosine(qvec, cvecs[tag])))
        ordered = sorted(scored, key=lambda pair: (-pair[1], pair[0]))
        out: list[RetrievedChunk] = []
        for cid, sim in ordered[:k]:
            chunk = self._chunks[cid]
            out.append(RetrievedChunk(
                id=cid, citation=chunk.get("citation", ""),
                title=chunk.get("title", ""), text=chunk.get("text", ""),
                regime_family=chunk.get("regime_family", ""), score=sim))
        return out


# The default retriever seam. A caller that wants dense retrieval constructs an
# EmbeddingRetriever, checks available(), and falls back to default_retriever() when
# the committed cache is absent. The default is BM25 so the no-cache path is the
# zero-dependency, byte-stable one.
_DEFAULT_RETRIEVER: Bm25Retriever | None = None


def default_retriever() -> Bm25Retriever:
    """The process-wide default BM25 retriever over the committed index, built once
    and reused. Pure: the index is read-only reference data."""
    global _DEFAULT_RETRIEVER
    if _DEFAULT_RETRIEVER is None:
        _DEFAULT_RETRIEVER = Bm25Retriever()
    return _DEFAULT_RETRIEVER


def retrieve(regime: str, fact_record: dict, *,
             k: int = DEFAULT_K,
             retriever: Bm25Retriever | EmbeddingRetriever | None = None
             ) -> list[RetrievedChunk]:
    """Module-level convenience: retrieve the top-k grounding chunks for a regime.

    Defaults to the process-wide BM25 retriever over the committed index. A caller
    may pass an explicit retriever (a test corpus, or an EmbeddingRetriever it has
    already confirmed available()). Pure and deterministic for the default BM25
    path; identical inputs always return the identical ordered list."""
    r = retriever if retriever is not None else default_retriever()
    return r.retrieve(regime, fact_record, k=k)


def render_grounding_block(chunks: list[RetrievedChunk]) -> str:
    """Render the retrieved chunks as the GROUNDING CONTEXT block injected at the
    head of a content-producing prompt. Pure string work; an empty list yields "".

    The block states it is authoritative regulation text and names each chunk by its
    stable citation id, so the model can write against the cited requirements and add
    [cite: <id>] tags. It carries no Warden control fence and states no incident
    facts, so it changes only the human-readable prose, exactly like format_profile."""
    if not chunks:
        return ""
    lines = [
        "GROUNDING CONTEXT (authoritative regulation text, cite these ids):",
        "The following are verbatim or summarized passages of the real regulation "
        "this filing must satisfy. Write against these requirements, and after a "
        "sentence that satisfies one, add a trailing tag [cite: <id>] naming the "
        "passage id below (for example [cite: GDPR-Art33]). Cite only ids that "
        "appear in this block.",
    ]
    for c in chunks:
        lines.append("")
        lines.append(f"[id: {c.id}] {c.citation} ({c.title})")
        lines.append(c.text)
    return "\n".join(lines)
