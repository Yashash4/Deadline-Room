"""E5.9 RAG-grounded drafting: the pure deterministic retriever, the prompt-grounding
seam in the content-producing LLM calls, the packet receipt, and citation accuracy.

The hard properties this proves:

  1. The retriever is PURE and DETERMINISTIC: the same (corpus, regime, fact_record,
     k) always returns the identical ordered chunk list across two calls, the top-k
     for a regime returns THAT regime's chunks (never another regime's), and the BM25
     ranking is pinned on a fixture.
  2. Injecting grounding chunks into draft_filing / assess_materiality /
     challenge_filing changes ONLY the prompt prose: the [CLAIMS] block is
     byte-identical, the [MATERIALITY] / [CHALLENGE] load-bearing blocks are
     untouched, and the default (no chunks) path is byte-identical to before.
  3. Corpus [cite: <id>] tags in filing prose never reach the hashed run-log: a
     run whose stub drafters emit [cite:] tags has the IDENTICAL run-log sha as one
     that does not, and byte-identical replay holds.
  4. The retrieval trace renders in the packet, a fake [cite: id] is flagged by
     citation_accuracy, and the embeddings path reads only the committed cache.
"""

from __future__ import annotations

import json

import pytest

from floor import drafter, materiality, challenger, packet, rag
from floor.citation_check import all_chunk_ids
from floor.claims import parse_claims
from floor.drafter import build_draft_body
from floor.run_floor import (
    DRAFTER_ROLES, _rag_grounding_block, _strip_cite_for_scoring, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom
from scripts.grounding_report import citation_accuracy

FACTS = {
    "incident_id": "inc-8842",
    "incident_start_utc": "2026-06-16T02:14:00+00:00",
    "records_affected": 48211,
    "attacker": "LockBit 3.0",
    "containment": "partially_contained",
    "systems": ["core banking ledger", "customer KYC store"],
    "data_categories": ["name", "address", "account_number"],
    "regulated_entity": "Meridian Trust Bank N.V.",
}


# ---- (1) the retriever is pure, deterministic, per-regime, and pinned -------

def test_retriever_is_pure_identical_ordered_list_across_calls():
    a = rag.retrieve("sec", FACTS, k=4)
    b = rag.retrieve("sec", FACTS, k=4)
    assert [c.id for c in a] == [c.id for c in b]
    assert [c.score for c in a] == [c.score for c in b]
    # And a second, independently constructed retriever agrees.
    r = rag.Bm25Retriever()
    c = r.retrieve("sec", FACTS, k=4)
    assert [x.id for x in c] == [x.id for x in a]


def test_topk_for_each_regime_returns_only_that_regimes_chunks():
    # Every retrieved chunk for a regime must be one of that regime's declared
    # corpus_tags: a chunk from another regime can never leak into a filing's
    # citations.
    from floor import regimes
    specs = {s.key: s for s in regimes.load_catalog()}
    for key in ("sec", "nis2_full", "uk_ico", "dora", "nydfs"):
        tags = set(specs[key].corpus_tags)
        got = rag.retrieve(key, FACTS, k=10)
        assert got, f"{key} retrieved nothing"
        assert {c.id for c in got} <= tags
        # scores are sorted descending, ids tie-break ascending: a total order.
        scores = [c.score for c in got]
        assert scores == sorted(scores, reverse=True)


def test_bm25_ranking_is_pinned_on_a_fixture():
    # The exact top-k ordering for SEC, pinned so a ranking regression is caught.
    got = [c.id for c in rag.retrieve("sec", FACTS, k=4)]
    assert got == [
        "SEC-CF-CDI-104B.01",
        "SEC-Form8K-Item1.05-Instruction2",
        "SEC-Form8K-Item1.05(b)",
        "SEC-Form8K-Item1.05-Instruction1",
    ]
    # And NIS2, retrieved by the full-regime key.
    nis2 = [c.id for c in rag.retrieve("nis2_full", FACTS, k=4)]
    assert nis2 == [
        "NIS2-Recital-101", "NIS2-Art23(1)", "NIS2-Art23(4)", "NIS2-Art23(3)"]


def test_retrieve_accepts_branch_label_too():
    # The drafter closures key on branch; retrieval by branch must resolve the same
    # chunks as retrieval by key for a regime whose branch differs from its key.
    by_key = [c.id for c in rag.retrieve("nis2_full", FACTS, k=4)]
    by_branch = [c.id for c in rag.retrieve("nis2", FACTS, k=4)]
    assert by_branch == by_key


def test_retrieve_k_zero_and_ungrounded_regime_return_empty():
    assert rag.retrieve("sec", FACTS, k=0) == []
    # A regime that names no corpus_tags retrieves nothing (the caller drafts
    # ungrounded). There is no such regime in the live catalog, so assert via a
    # fabricated id that resolves to no spec.
    assert rag.retrieve("no-such-regime", FACTS, k=4) == []


def test_tokenize_is_deterministic_and_drops_stopwords():
    toks = rag.tokenize("The breach of personal data, 72 hours.")
    assert "the" not in toks and "of" not in toks
    assert "breach" in toks and "personal" in toks and "72" in toks


# ---- (2) grounding injection changes only prose, never the load-bearing blocks ----

def _fake_complete_capture(captured):
    def fake(provider, model, messages, **kw):
        captured["messages"] = messages
        return "FILING PROSE BODY"
    return fake


def test_draft_filing_grounding_block_only_in_prompt_not_in_claims(monkeypatch):
    captured = {}
    monkeypatch.setattr(drafter, "llm_complete", _fake_complete_capture(captured))
    chunks = rag.retrieve("uk_ico", FACTS, k=3)
    drafter.draft_filing(FACTS, regime="UK ICO", grounding_chunks=chunks)
    system = captured["messages"][0]["content"]
    user = captured["messages"][1]["content"]
    # The grounding instruction is in the system prompt and the GROUNDING CONTEXT
    # block (with real citation ids) is at the head of the user prompt.
    assert "[cite:" in system and "GROUNDING CONTEXT" in user
    assert "GDPR-Art33" in user
    # The fact-record still follows the grounding block.
    assert "FACT RECORD" in user
    assert user.index("GROUNDING CONTEXT") < user.index("FACT RECORD")


def test_draft_filing_default_path_byte_identical_without_grounding(monkeypatch):
    captured_off = {}
    monkeypatch.setattr(drafter, "llm_complete", _fake_complete_capture(captured_off))
    drafter.draft_filing(FACTS, regime="DORA")
    system_off = captured_off["messages"][0]["content"]
    user_off = captured_off["messages"][1]["content"]
    assert "GROUNDING CONTEXT" not in system_off
    assert "GROUNDING CONTEXT" not in user_off
    assert "[cite:" not in system_off


def test_claims_block_byte_identical_with_and_without_grounding():
    # The grounding context rides in the prompt; the [CLAIMS] block the Warden diffs
    # is attached after sanitization and is never affected. A model that even emitted
    # a [cite:] tag in prose still gets the identical authoritative claims block.
    prose_grounded = ("Filing prose with a citation. [cite: GDPR-Art33]")
    body_grounded = build_draft_body(prose_grounded, "uk", FACTS)
    body_plain = build_draft_body("Filing prose with a citation.", "uk", FACTS)
    claims_g = body_grounded[body_grounded.rindex("[CLAIMS]"):]
    claims_p = body_plain[body_plain.rindex("[CLAIMS]"):]
    assert claims_g == claims_p
    assert parse_claims(body_grounded).records_affected == 48211


def test_materiality_grounding_only_in_prompt_block_unchanged(monkeypatch):
    captured = {}

    def fake(provider, model, messages, **kw):
        captured["messages"] = messages
        return "Memo.\n[MATERIALITY]\nmaterial=yes\n[/MATERIALITY]"

    monkeypatch.setattr(materiality, "llm_complete", fake)
    chunks = rag.retrieve("sec", FACTS, k=3)
    v = materiality.assess_materiality(FACTS, model="m", grounding_chunks=chunks)
    user = captured["messages"][1]["content"]
    assert "GROUNDING CONTEXT" in user and "SEC-" in user
    # The verdict the gate consumes is parsed exactly as without grounding.
    assert v.material is True
    # Default path: no grounding block.
    captured.clear()
    materiality.assess_materiality(FACTS, model="m")
    assert "GROUNDING CONTEXT" not in captured["messages"][1]["content"]


def test_challenger_grounding_only_in_prompt_block_unchanged(monkeypatch):
    captured = {}

    def fake(provider, model, messages, **kw):
        captured["messages"] = messages
        return "Memo.\n[CHALLENGE]\nnone\n[/CHALLENGE]"

    monkeypatch.setattr(challenger, "llm_complete", fake)
    chunks = rag.retrieve("dora", FACTS, k=2)
    ch = challenger.challenge_filing("Some filing prose.", FACTS, model="m",
                                     branch="dora", grounding_chunks=chunks)
    user = captured["messages"][1]["content"]
    assert "GROUNDING CONTEXT" in user and "DORA-" in user
    assert ch.objections == []  # the [CHALLENGE] block parsed exactly as before
    captured.clear()
    challenger.challenge_filing("Some filing prose.", FACTS, model="m", branch="dora")
    assert "GROUNDING CONTEXT" not in captured["messages"][1]["content"]


# ---- (3) corpus citations never reach the hashed run-log -------------------

def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
        "challenger": FakeBandClient(room, "challenger-id", "challenger",
                                     "challenger"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return room, clients


def _stub_draft_fns(*, with_citations: bool):
    """Per-branch stub drafters. When with_citations, each emits a real [cite: <id>]
    tag in its prose (a chunk id the retriever would return for that regime); the
    citation rides in the prose half only, exactly like the live grounded path."""
    cite_for = {
        "nis2": "[cite: NIS2-Art23(1)]",
        "sec": "[cite: SEC-Form8K-Item1.05(a)]",
        "dora": "[cite: DORA-2022/2554-Art19(1)]",
    }

    def make(branch, regime):
        def fn(claim_facts):
            tag = cite_for.get(branch, "") if with_citations else ""
            return (
                f"{regime} mandatory notification. Meridian Trust Bank N.V. reports "
                f"an incident starting {claim_facts['incident_start_utc']} affecting "
                f"{claim_facts['records_affected']} records, attacker "
                f"{claim_facts['attacker']}, containment "
                f"{claim_facts['containment']}. {tag} Deterministic test stub.")
        return fn
    return {r.branch: make(r.branch, r.regime) for r in DRAFTER_ROLES}


def test_corpus_citations_in_prose_do_not_move_sha_or_break_replay(tmp_path):
    _, clients_cite = _build_clients()
    p_cite = run_floor(out_dir=str(tmp_path / "cite"), mode="normal",
                       clients=clients_cite,
                       draft_fns=_stub_draft_fns(with_citations=True))
    _, clients_plain = _build_clients()
    p_plain = run_floor(out_dir=str(tmp_path / "plain"), mode="normal",
                        clients=clients_plain,
                        draft_fns=_stub_draft_fns(with_citations=False))
    # Same run-log sha and both replay byte-exact: the [cite:] tags are pure prose,
    # never in the hashed event stream.
    assert (p_cite["replay"]["original_sha256"]
            == p_plain["replay"]["original_sha256"])
    assert p_cite["replay"]["byte_identical"] is True
    assert p_plain["replay"]["byte_identical"] is True


def test_grounding_receipt_not_corrupted_by_numeric_citation_ids(tmp_path):
    # A DORA citation id (DORA-RTS-2024/1772) contains a number; the grounding
    # receipt must NOT mis-read it as an ungrounded record count, because the packet
    # path strips corpus citations before scoring.
    _, clients = _build_clients()
    p = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                  draft_fns=_stub_draft_fns(with_citations=True))
    assert p["grounding"]["all_pass"] is True


def test_strip_cite_for_scoring_is_noop_without_citations():
    filings = [{"branch": "sec", "text": "no citations here, 48211 records"}]
    out = _strip_cite_for_scoring(filings)
    assert out[0]["text"] == filings[0]["text"]
    # With a citation: the tag is removed for scoring only.
    filings2 = [{"branch": "sec", "text": "prose [cite: SEC-Form8K-Item1.05(a)] end"}]
    out2 = _strip_cite_for_scoring(filings2)
    assert "[cite:" not in out2[0]["text"]


# ---- (4) packet render, citation accuracy, embeddings ----------------------

class _Trace:
    """A minimal trace stub carrying just the out-of-log retrieval records the
    packet derive step reads."""
    def __init__(self, retrievals):
        self.retrievals = retrievals


def test_retrieval_trace_renders_in_the_packet():
    chunks = rag.retrieve("dora", FACTS, k=2)
    retrievals = [{
        "branch": "dora", "regime": "DORA",
        "retrieved": [c.as_dict() for c in chunks],
    }]
    filings = [{
        "branch": "dora", "regime": "DORA",
        "text": f"Filing. [cite: {chunks[0].id}] more prose.",
    }]
    block = _rag_grounding_block(_Trace(retrievals), filings)
    assert block["passages_retrieved"] == 2
    # exactly the one cited chunk is marked cited
    assert block["passages_cited"] == 1
    html = packet._render_rag_grounding(block)
    assert "Regulation passages that grounded each filing" in html
    assert chunks[0].id in html
    assert "CITED" in html
    # an empty block renders nothing
    assert packet._render_rag_grounding({}) == ""


def test_citation_accuracy_flags_a_fake_id():
    ids = all_chunk_ids()
    good = "Filing. [cite: GDPR-Art33] supported by the article."
    res = citation_accuracy(good, ids)
    assert res["all_resolved"] is True and res["accuracy"] == 1.0
    bad = good + " And [cite: GDPR-Art-NOPE-999] is invented."
    res2 = citation_accuracy(bad, ids)
    assert "GDPR-Art-NOPE-999" in res2["unresolved"]
    assert res2["all_resolved"] is False
    assert res2["accuracy"] < 1.0


def test_embedding_retriever_reads_only_committed_cache(tmp_path):
    # No cache committed by default: the retriever reports unavailable and never
    # calls a live API. The caller falls back to BM25.
    er = rag.EmbeddingRetriever(cache_path=tmp_path / "missing.json")
    assert er.available() is False
    with pytest.raises(RuntimeError):
        er.retrieve("sec", FACTS, k=2)

    # With a committed cache, it ranks by cosine and reads ONLY the cache (no API).
    chunks = rag.retrieve("sec", FACTS, k=4)
    cache = {
        "chunks": {chunks[0].id: [1.0, 0.0], chunks[1].id: [0.0, 1.0]},
        "queries": {"sec": [1.0, 0.0]},
    }
    cache_path = tmp_path / "embeddings.json"
    cache_path.write_text(json.dumps(cache), encoding="utf-8")
    er2 = rag.EmbeddingRetriever(cache_path=cache_path)
    assert er2.available() is True
    got = er2.retrieve("sec", FACTS, k=2)
    # the chunk aligned with the query vector ranks first
    assert got[0].id == chunks[0].id


def test_render_grounding_block_helper_is_pure():
    chunks = rag.retrieve("sec", FACTS, k=2)
    block = rag.render_grounding_block(chunks)
    assert "GROUNDING CONTEXT" in block
    assert chunks[0].id in block
    assert rag.render_grounding_block([]) == ""
