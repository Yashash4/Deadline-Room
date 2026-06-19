"""test_portability.py -- the provider-portability check (E5.7 part 4).

scripts/portability_check.py runs the SAME draft_filing call on both providers'
equivalent models and scores each filing with the real grounding oracle. This test
exercises the KEYLESS cached path (the committed cache, honestly labeled), so it
never blocks on a live provider, and asserts the pipeline is portable: both sides
produce a grounded filing. It also confirms the live-preferring path falls back to
the cache rather than stalling when no key is present.
"""

import json

import pytest

portability_check = pytest.importorskip("scripts.portability_check")


def test_cache_fixture_is_committed_and_honest():
    cache = json.loads(portability_check.CACHE_FILE.read_text(encoding="utf-8"))
    sides = cache["sides"]
    assert set(sides) == {"featherless", "aimlapi"}
    for side in sides.values():
        # every cached side carries an honest source label and a raw response
        assert side["source"] in ("live", "illustrative")
        assert side["raw_response"].strip()


def test_cached_path_is_portable():
    """Both providers' equivalent models produce a grounded filing from the cache,
    so the pipeline is provider-portable."""
    result = portability_check.check(prefer_live=False)
    assert result["portable"] is True
    providers = {s["provider"] for s in result["sides"]}
    assert providers == {"featherless", "aimlapi"}
    for side in result["sides"]:
        assert side["produced_filing"] is True
        assert side["grounded"] is True
        assert side["grounding_score"] == pytest.approx(1.0)
        assert side["source"] in ("live", "illustrative")


def test_prefer_live_falls_back_to_cache_without_keys(monkeypatch):
    """With no provider keys set, the live draft fails fast (no stall) and each side
    falls back to the committed cache, still labeled honestly."""
    monkeypatch.delenv("FEATHERLESS_API_KEY", raising=False)
    monkeypatch.delenv("AIML_API_KEY", raising=False)
    result = portability_check.check(prefer_live=True)
    # the fall-back keeps the run portable and every side is the cached source
    assert result["portable"] is True
    for side in result["sides"]:
        assert side["source"] == "illustrative"


def test_each_side_is_a_different_provider_and_model():
    result = portability_check.check(prefer_live=False)
    models = {s["model"] for s in result["sides"]}
    assert len(models) == 2  # genuinely different models, not one proxy
    providers = {s["provider"] for s in result["sides"]}
    assert providers == {"featherless", "aimlapi"}


def test_main_cached_returns_zero(capsys):
    rc = portability_check.main(["--cached"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PORTABLE" in out
