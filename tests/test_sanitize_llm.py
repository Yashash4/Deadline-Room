"""The Examiner Packet must stay free of em/en dashes and fancy unicode
punctuation even when a model emits them. floor.drafter.sanitize_llm_text is the
single chokepoint (every llm_complete return runs through it), so a filing can
never carry a dash into the shipped artifact."""

from __future__ import annotations

from floor.drafter import sanitize_llm_text


def test_em_and_en_dashes_removed():
    out = sanitize_llm_text("records affected — 2.1M – confirmed")
    assert "—" not in out and "–" not in out
    assert "records affected, 2.1M-confirmed" in out or "," in out


def test_unicode_hyphens_normalized():
    # GPT-5 emitted inc<U+2011>8842 with a non-breaking hyphen in a live run.
    out = sanitize_llm_text("inc‑8842 and inc‐8842")
    assert "‑" not in out and "‐" not in out
    assert "inc-8842 and inc-8842" == out


def test_smart_quotes_and_ellipsis_normalized():
    out = sanitize_llm_text("“material” ‘incident’ ongoing…")
    assert out == '"material" \'incident\' ongoing...'


def test_no_forbidden_codepoints_remain():
    sample = ("Reporting entity — Meridian – incident inc‑8842, "
              "data categories ‘name’, “address”…")
    out = sanitize_llm_text(sample)
    for cp in ("—", "–", "‒", "‑", "‐", "‘",
               "’", "“", "”", "…"):
        assert cp not in out


def test_plain_ascii_untouched():
    s = "NIS2 notification: incident inc-8842, 48,211 records (partial containment)."
    assert sanitize_llm_text(s) == s
