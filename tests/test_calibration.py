"""Calibration and inter-model agreement for the materiality cross-check (E5.3).

Three things are pinned here:

  1. cohen_kappa and expected_calibration_error are checked against sub-cases
     small enough to compute the expected value BY HAND, so the test is a real
     cross-check of the math, not the implementation copied.

  2. scripts/materiality_eval.py scores the committed opinion cache against the
     human-labeled corpus and reports kappa, per-model accuracy, and ECE; the
     accuracy over the corpus is asserted, and the scoring is proven keyless
     (it reads the cache, never a model).

  3. The OPTIONAL confidence add in floor/materiality.py defaults OFF, and with
     it off the request to the model and the returned verdict are byte-identical
     to the historical behavior, and the fenced [MATERIALITY] gate block is
     parsed identically whether confidence is on or off. This is the constraint
     that keeps the sealed run-log shas frozen.
"""

import json
from pathlib import Path

import pytest

from floor import materiality
from floor.eval_stats import cohen_kappa, expected_calibration_error
from floor.materiality import (
    _SYSTEM,
    _parse_confidence,
    _parse_verdict_bool,
    assess_materiality,
)
from warden.materiality import MaterialityVerdict

import scripts.materiality_eval as meval

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "tests" / "fixtures" / "materiality_corpus.json"
CACHE = REPO_ROOT / "tests" / "fixtures" / "materiality_opinions_cache.json"


def approx(value):
    return pytest.approx(value, abs=1e-9)


# --- Cohen's kappa, pinned on hand-computed sub-cases ----------------------
def test_kappa_perfect_agreement_with_label_variation():
    # Two raters that agree on every item, with both labels appearing, so the
    # chance-correction is well defined and the result is exactly 1.0.
    a = ["material", "immaterial", "material", "immaterial"]
    b = ["material", "immaterial", "material", "immaterial"]
    assert cohen_kappa(a, b) == approx(1.0)


def test_kappa_chance_level_is_zero():
    # Hand-built 2x2: n=4, each rater is material on exactly half. The agreement
    # cells are arranged so observed agreement equals chance agreement, giving
    # kappa exactly 0. a = [M, M, I, I], b = [M, I, M, I].
    #   observed agreement = 2/4 = 0.5
    #   p(material) for a = 0.5, for b = 0.5; p(immaterial) = 0.5, 0.5
    #   chance = 0.5*0.5 + 0.5*0.5 = 0.5
    #   kappa = (0.5 - 0.5) / (1 - 0.5) = 0
    a = ["material", "material", "immaterial", "immaterial"]
    b = ["material", "immaterial", "material", "immaterial"]
    assert cohen_kappa(a, b) == approx(0.0)


def test_kappa_known_partial_value():
    # A worked 10-item case. a has 6 material, b has 6 material; they agree on 8
    # of 10 items. observed = 0.8. chance = 0.6*0.6 + 0.4*0.4 = 0.36 + 0.16 = 0.52.
    # kappa = (0.8 - 0.52) / (1 - 0.52) = 0.28 / 0.48 = 0.583333...
    a = (["material"] * 6) + (["immaterial"] * 4)
    b = (["material"] * 5) + (["immaterial"] * 3) + ["material", "immaterial"]
    # Reconcile the agreement count explicitly: items 0..4 material/material (5
    # agree), items 5 material/immaterial (disagree), items 6,7 immaterial/
    # immaterial (2 agree), item 8 immaterial/material (disagree), item 9
    # immaterial/immaterial (1 agree). 8 agreements, both marginals 6 material.
    assert sum(1 for x, y in zip(a, b) if x == y) == 8
    assert a.count("material") == 6
    assert b.count("material") == 6
    assert cohen_kappa(a, b) == approx((0.8 - 0.52) / (1.0 - 0.52))


def test_kappa_less_than_chance_is_negative():
    # Systematic disagreement: the raters agree LESS than chance, so kappa < 0.
    a = ["material", "material", "immaterial", "immaterial"]
    b = ["immaterial", "immaterial", "material", "material"]
    assert cohen_kappa(a, b) < 0.0


def test_kappa_constant_label_is_one():
    # Both raters call everything material: perfect agreement on a constant, the
    # degenerate case where chance agreement is 1.0. Reported as kappa 1.0.
    a = ["material"] * 5
    b = ["material"] * 5
    assert cohen_kappa(a, b) == approx(1.0)


def test_kappa_rejects_length_mismatch_and_empty():
    with pytest.raises(ValueError):
        cohen_kappa(["material"], ["material", "immaterial"])
    with pytest.raises(ValueError):
        cohen_kappa([], [])


# --- ECE, pinned on hand-computed sub-cases --------------------------------
def test_ece_perfectly_calibrated_is_zero():
    # Every prediction at confidence 1.0 and correct: the single occupied bucket
    # has mean confidence 1.0 and accuracy 1.0, gap 0, so ECE is 0.
    conf = [1.0, 1.0, 1.0, 1.0]
    correct = [1, 1, 1, 1]
    assert expected_calibration_error(conf, correct, bins=10) == approx(0.0)


def test_ece_known_single_bucket_value():
    # All four predictions land in the same bucket (confidence 0.80 with bins=10
    # is bucket [0.8, 0.9)). Mean confidence 0.80, but only 2 of 4 are correct
    # (accuracy 0.50). ECE = |0.80 - 0.50| = 0.30 (one bucket holds everything).
    conf = [0.80, 0.80, 0.80, 0.80]
    correct = [1, 1, 0, 0]
    assert expected_calibration_error(conf, correct, bins=10) == approx(0.30)


def test_ece_two_buckets_count_weighted():
    # Bucket A: confidence 0.90 (bucket [0.9, 1.0)), 3 items, all correct ->
    # gap |0.90 - 1.0| = 0.10, weight 3/5.
    # Bucket B: confidence 0.10 (bucket [0.1, 0.2)), 2 items, none correct ->
    # gap |0.10 - 0.0| = 0.10, weight 2/5.
    # ECE = 3/5 * 0.10 + 2/5 * 0.10 = 0.10.
    conf = [0.90, 0.90, 0.90, 0.10, 0.10]
    correct = [1, 1, 1, 0, 0]
    expected = (3 / 5) * abs(0.90 - 1.0) + (2 / 5) * abs(0.10 - 0.0)
    assert expected_calibration_error(conf, correct, bins=10) == approx(expected)
    assert expected == approx(0.10)


def test_ece_one_point_zero_folds_into_top_bucket():
    # Confidence exactly 1.0 must not be dropped; it folds into the top bucket.
    conf = [1.0, 0.95]
    correct = [1, 1]
    # Both in [0.9, 1.0]; mean conf 0.975, accuracy 1.0, ECE = 0.025.
    assert expected_calibration_error(conf, correct, bins=10) == approx(0.025)


def test_ece_rejects_bad_inputs():
    with pytest.raises(ValueError):
        expected_calibration_error([0.5], [1, 0], bins=10)  # length mismatch
    with pytest.raises(ValueError):
        expected_calibration_error([], [], bins=10)  # empty
    with pytest.raises(ValueError):
        expected_calibration_error([1.5], [1], bins=10)  # conf out of range
    with pytest.raises(ValueError):
        expected_calibration_error([0.5], [2], bins=10)  # correctness not 0/1
    with pytest.raises(ValueError):
        expected_calibration_error([0.5], [1], bins=0)  # bins < 1


# --- the eval script over the committed corpus + cache (keyless) -----------
def test_corpus_has_twelve_labeled_items_with_stable_ids():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    entries = corpus["entries"]
    assert len(entries) == 12
    ids = [e["id"] for e in entries]
    assert len(set(ids)) == 12  # stable, unique ids
    for e in entries:
        assert e["label"] in ("material", "immaterial")
        assert e["rationale"].strip()
        assert isinstance(e["fact_record"], dict)


def test_cache_covers_every_corpus_item():
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cache = json.loads(CACHE.read_text(encoding="utf-8"))
    op = cache["opinions"]
    for e in corpus["entries"]:
        assert e["id"] in op
        row = op[e["id"]]
        for who in ("primary", "second"):
            assert isinstance(row[who]["material"], bool)
            assert 0.0 <= row[who]["confidence"] <= 1.0


def test_eval_score_is_keyless_and_pure():
    # The headline numbers compute from the corpus and cache with no model call,
    # and are deterministic across two runs (pure function of the fixtures).
    corpus = meval.load_corpus()
    cache = meval.load_cache()
    a = meval.score(corpus, cache)
    b = meval.score(corpus, cache)
    for key in ("kappa", "primary_accuracy", "second_accuracy",
                "primary_ece", "second_ece", "raw_agreement", "n"):
        assert a[key] == b[key]
    assert a["n"] == 12


def test_eval_accuracy_matches_hand_count_over_corpus():
    # Recompute each model's accuracy directly from the fixtures and assert the
    # script's headline number matches, so the receipt is verified, not asserted.
    corpus = meval.load_corpus()
    cache = meval.load_cache()
    op = cache["opinions"]
    truth = {e["id"]: e["label"] for e in corpus["entries"]}
    p_correct = s_correct = 0
    for item_id, label in truth.items():
        p_label = "material" if op[item_id]["primary"]["material"] else "immaterial"
        s_label = "material" if op[item_id]["second"]["material"] else "immaterial"
        p_correct += 1 if p_label == label else 0
        s_correct += 1 if s_label == label else 0
    n = len(truth)
    result = meval.score(corpus, cache)
    assert result["primary_accuracy"] == approx(p_correct / n)
    assert result["second_accuracy"] == approx(s_correct / n)
    # Both models are competent on a corpus that is mostly clear cases.
    assert result["primary_accuracy"] >= 0.75
    assert result["second_accuracy"] >= 0.6


def test_eval_kappa_matches_helper_over_corpus():
    # The script's kappa is exactly cohen_kappa over the two model label series.
    corpus = meval.load_corpus()
    cache = meval.load_cache()
    op = cache["opinions"]
    p_labels, s_labels = [], []
    for e in corpus["entries"]:
        p_labels.append("material" if op[e["id"]]["primary"]["material"]
                        else "immaterial")
        s_labels.append("material" if op[e["id"]]["second"]["material"]
                        else "immaterial")
    result = meval.score(corpus, cache)
    assert result["kappa"] == approx(cohen_kappa(p_labels, s_labels))


def test_eval_run_score_exits_clean():
    assert meval.run_score() == 0


# --- the materiality confidence add: default OFF is byte-identical ----------
# A canned model reply that carries BOTH the verdict block (with a leading memo)
# and a confidence line, so the same captured text exercises both the default
# (confidence ignored) and the emit_confidence path.
_REPLY = (
    "This incident exposed 2.1 million regulated records from a core banking "
    "system, which a reasonable investor would consider important.\n"
    "confidence=0.91\n"
    "[MATERIALITY]\nmaterial=yes\n[/MATERIALITY]"
)


class _Recorder:
    """A stand-in for llm_complete that records the messages it was handed and
    returns a fixed reply, so the test can assert the request bytes without a
    network call."""

    def __init__(self, reply):
        self.reply = reply
        self.last_messages = None

    def __call__(self, provider, model, messages, **kwargs):
        self.last_messages = messages
        return self.reply


def test_default_path_returns_bare_verdict_and_unchanged_system_prompt(monkeypatch):
    rec = _Recorder(_REPLY)
    monkeypatch.setattr(materiality, "llm_complete", rec)
    out = assess_materiality({"incident_id": "x"}, model="m", provider="p")
    # Default path returns a bare MaterialityVerdict, exactly as before E5.3.
    assert isinstance(out, MaterialityVerdict)
    assert out.material is True
    # The system prompt the model received is byte-identical to _SYSTEM: the
    # confidence suffix is NOT appended on the default path.
    system_sent = rec.last_messages[0]["content"]
    assert system_sent == _SYSTEM
    assert "confidence=" not in system_sent


def test_emit_confidence_path_returns_tuple_with_parsed_confidence(monkeypatch):
    rec = _Recorder(_REPLY)
    monkeypatch.setattr(materiality, "llm_complete", rec)
    out = assess_materiality({"incident_id": "x"}, model="m", provider="p",
                             emit_confidence=True)
    # With confidence ON the return is a (verdict, confidence) tuple.
    assert isinstance(out, tuple)
    verdict, confidence = out
    assert isinstance(verdict, MaterialityVerdict)
    # The same boolean is parsed off the unchanged [MATERIALITY] block.
    assert verdict.material is True
    assert confidence == approx(0.91)
    # The confidence suffix IS appended to the system prompt on this path.
    system_sent = rec.last_messages[0]["content"]
    assert system_sent.startswith(_SYSTEM)
    assert system_sent != _SYSTEM
    assert "confidence=" in system_sent


def test_gate_block_parse_is_identical_with_confidence_on_or_off(monkeypatch):
    # The load-bearing assertion for replay: the [MATERIALITY] block the Warden
    # gate consumes parses to the SAME boolean whether or not a confidence line
    # is present in the reply. The confidence lives outside the block.
    with_conf = _REPLY
    without_conf = (
        "This incident exposed 2.1 million regulated records.\n"
        "[MATERIALITY]\nmaterial=yes\n[/MATERIALITY]"
    )
    assert _parse_verdict_bool(with_conf) == _parse_verdict_bool(without_conf)
    assert _parse_verdict_bool(with_conf) is True


def test_parse_confidence_returns_none_when_absent():
    # The default path never sees a confidence line; the parser must return None
    # rather than inventing a value.
    no_conf = "memo only\n[MATERIALITY]\nmaterial=no\n[/MATERIALITY]"
    assert _parse_confidence(no_conf) is None


def test_parse_confidence_ignores_material_line_inside_block():
    # The confidence parser must not accidentally read the material= line: it is
    # anchored to its own 'confidence=' key and looks outside the fenced block.
    text = "[MATERIALITY]\nmaterial=yes\n[/MATERIALITY]"
    assert _parse_confidence(text) is None


def test_parse_confidence_clamps_out_of_range():
    assert _parse_confidence("confidence=1.5\n[MATERIALITY]\nmaterial=yes"
                             "\n[/MATERIALITY]") == approx(1.0)
    assert _parse_confidence("confidence=-0.2\n[MATERIALITY]\nmaterial=no"
                             "\n[/MATERIALITY]") == approx(0.0)


def test_default_verdict_bytes_match_pre_e53_construction(monkeypatch):
    # A direct byte-identity check on the returned verdict: the default path
    # builds exactly MaterialityVerdict(branch, material, memo, source) with the
    # memo being the reply minus the verdict block, identical to the historical
    # construction. We reconstruct that expected verdict here and compare.
    rec = _Recorder(_REPLY)
    monkeypatch.setattr(materiality, "llm_complete", rec)
    out = assess_materiality({"incident_id": "x"}, model="m", provider="p",
                             branch="sec")
    expected_memo = materiality._VERDICT.sub("", _REPLY).strip()
    expected = MaterialityVerdict(branch="sec", material=True,
                                  memo=expected_memo, source="p:m")
    assert out == expected
