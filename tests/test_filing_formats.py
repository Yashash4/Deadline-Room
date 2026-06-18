"""Real per-regime filing format skeletons (PART B).

Each regime carries a FORMAT PROFILE drawn from the actual form: the LLM writes
prose INTO the real labelled slots instead of a generic structure. These tests
pin that:

  (a) each profile carries its real mandated fields and cover tag,
  (b) the profiles are tied to the regimes from the declarative catalog (every
      regime names a profile that resolves),
  (c) the drafter injects the field skeleton into the prompt when a profile is
      given, and falls back to the generic prompt when it is not,
  (d) the structured [CLAIMS] block is untouched by the format change, so the
      Warden's diff is unaffected.

These exercise the deterministic template + the prompt assembly, with no live LLM
call (the network step is the only thing not covered, by design, and it is the
same llm_complete chokepoint every other drafter test relies on).
"""

from floor import formats, regimes
from floor.claims import parse_claims
from floor.drafter import build_draft_body


def test_sec_8k_has_item_105_cover_tag_and_four_elements():
    p = formats.format_profile_for("sec_8k")
    assert "Item 1.05" in p.cover_tag
    labels = [f.label for f in p.fields]
    # The four mandated Item 1.05 content elements, broken out as the rule states
    # them: the material aspects of the NATURE, the SCOPE, and the TIMING of the
    # incident, and the MATERIAL IMPACT or reasonably likely material impact.
    assert any("Nature of the incident" in lbl for lbl in labels)
    assert any("Scope of the incident" in lbl for lbl in labels)
    assert any("Timing of the incident" in lbl for lbl in labels)
    assert any("Material impact" in lbl for lbl in labels)
    # The real EDGAR Form 8-K cover-page header fields the export renders.
    assert "Commission file number" in p.cover_fields
    assert any("Date of report" in cf for cf in p.cover_fields)


def test_nis2_early_has_unlawful_and_cross_border_flags():
    p = formats.format_profile_for("nis2_early")
    labels = " ".join(f.label for f in p.fields).lower()
    assert "unlawful or malicious" in labels
    assert "cross-border" in labels


def test_dora_fields_track_the_rts_classification_criteria():
    p = formats.format_profile_for("dora")
    labels = " ".join(f.label for f in p.fields).lower()
    assert "clients" in labels
    assert "downtime" in labels or "duration" in labels
    assert "geographical spread" in labels
    assert "economic impact" in labels or "data losses" in labels


def test_ico_art33_has_the_four_article_33_3_fields():
    p = formats.format_profile_for("ico_art33")
    labels = " ".join(f.label for f in p.fields).lower()
    assert "nature of the breach" in labels
    assert "data subjects" in labels
    assert "likely consequences" in labels
    assert "measures taken" in labels


def test_nydfs_has_50017_electronic_notice_fields():
    p = formats.format_profile_for("nydfs_50017")
    assert "500.17(a)(1)" in p.cover_tag
    labels = " ".join(f.label for f in p.fields).lower()
    assert "cybersecurity event" in labels


def test_unknown_profile_raises():
    try:
        formats.format_profile_for("does_not_exist")
    except KeyError:
        return
    raise AssertionError("expected KeyError for an unknown profile id")


def test_every_catalog_regime_names_a_resolvable_profile():
    # PART A + PART B tie: each regime in floor/regimes.yaml names a format
    # profile, and every one of those ids resolves to a real skeleton.
    for spec in regimes.load_catalog():
        assert spec.format_profile, f"{spec.key} has no format_profile"
        p = formats.format_profile_for(spec.format_profile)
        assert p.fields, f"{spec.format_profile} has no fields"


def test_prompt_for_emits_each_field_label_in_order():
    p = formats.format_profile_for("sec_8k")
    prompt = formats.prompt_for(p)
    assert p.cover_tag in prompt
    last = -1
    for f in p.fields:
        idx = prompt.find(f.label)
        assert idx != -1, f"field {f.label!r} missing from prompt"
        assert idx > last, "fields must appear in order"
        last = idx


def test_render_skeleton_lists_fields():
    p = formats.format_profile_for("ico_art33")
    skel = formats.render_skeleton(p)
    assert p.form_title in skel
    for f in p.fields:
        assert f.label in skel


def test_draft_filing_injects_profile_when_given(monkeypatch):
    # When a format profile is passed, the system + user prompt carry the real
    # field skeleton; when it is not, the generic instruction is used. We capture
    # the messages handed to llm_complete instead of making a network call.
    import floor.drafter as d

    captured = {}

    def fake_complete(provider, model, messages, **kw):
        captured["messages"] = messages
        return "FILING PROSE BODY"

    monkeypatch.setattr(d, "llm_complete", fake_complete)
    facts = {"incident_start_utc": "2026-06-16T02:14:00+00:00",
             "records_affected": 48211, "attacker": "LockBit 3.0",
             "containment": "partially_contained"}

    profile = formats.format_profile_for("sec_8k")
    d.draft_filing(facts, regime="SEC", format_profile=profile)
    joined = " ".join(m["content"] for m in captured["messages"])
    assert "Item 1.05" in joined
    assert "Nature of the incident" in joined
    assert "Material impact" in joined

    captured.clear()
    d.draft_filing(facts, regime="SEC")  # no profile -> generic path
    joined = " ".join(m["content"] for m in captured["messages"])
    assert "Item 1.05" not in joined
    assert "structure a regulator expects" in joined


def test_claims_block_unchanged_by_format_profile():
    # The load-bearing structured claims are attached by the drafter process, not
    # the model, so the format skeleton never touches them: parse round-trips the
    # exact facts regardless of the prose above the block.
    facts = {"incident_start_utc": "2026-06-16T02:14:00+00:00",
             "records_affected": 48211, "attacker": "LockBit 3.0",
             "containment": "partially_contained"}
    body = build_draft_body("Item 1.05 prose with labelled fields ...", "sec", facts)
    claims = parse_claims(body)
    assert claims.records_affected == 48211
    assert claims.attacker == "LockBit 3.0"
    assert claims.incident_start_ts == "2026-06-16T02:14:00+00:00"
