"""test_failover.py -- draft_filing_with_failover over a real (mocked) provider
chain, and the roster fallback chain it walks (E5.7 part 1).

The HTTP layer is mocked so no network is touched. A model is made to fail with a
TERMINAL HTTP status (404) and the drafter is shown failing over to the next model
in the cross-family chain, serving the filing from there, and recording served_by /
fell_back_from OUT-OF-LOG. The default single-model path (no failover) is
unchanged.
"""

import pytest

from floor import drafter, roster
from floor.drafter import draft_filing_with_failover
from floor.model_fallback import FailoverExhausted


class _Resp:
    def __init__(self, status_code, content="a drafted filing body"):
        self.status_code = status_code
        self._content = content
        self.text = "error-body"

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class _ModelRouter:
    """Fakes requests.post, returning a per-model status so a chosen model can be
    made to fail terminally while the next one serves."""

    def __init__(self, status_by_model):
        self.status_by_model = status_by_model
        self.models_called = []

    def __call__(self, url, headers=None, json=None, timeout=None):
        model = json["model"]
        self.models_called.append(model)
        status = self.status_by_model.get(model, 200)
        return _Resp(status, content=f"filing drafted by {model}")


@pytest.fixture
def env_keys(monkeypatch):
    monkeypatch.setenv("FEATHERLESS_API_KEY", "fl-secret")
    monkeypatch.setenv("AIML_API_KEY", "aiml-secret")


# ---- the roster chain -------------------------------------------------------

def test_fallback_chain_is_cross_family_and_leads_with_primary():
    chain = roster.fallback_chain(roster.NIS2_DRAFTER, roster.PROVIDER_DEV)
    # primary first (the role's dev model), then the cross-family fallbacks
    assert chain[0] == (roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2")
    families = {m.split("/")[0] for _, m in chain}
    assert {"deepseek-ai", "MiniMaxAI", "Qwen"} <= families
    # no duplicate entries
    assert len(chain) == len(set(chain))


def test_prod_chain_leads_with_aiml_then_falls_back_to_open():
    chain = roster.fallback_chain(roster.SEC_DRAFTER, roster.PROVIDER_PROD)
    assert chain[0] == (roster.AIMLAPI, "claude-opus-4-1-20250805")
    # falls back across the open families on Featherless
    assert (roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2") in chain


# ---- draft_filing_with_failover --------------------------------------------

def test_primary_model_serves(monkeypatch, env_keys):
    rec = _ModelRouter(status_by_model={})  # everything 200
    monkeypatch.setattr(drafter.requests, "post", rec)
    chain = [(roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2"),
             (roster.FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")]
    result = draft_filing_with_failover({"incident_id": "x"}, chain=chain,
                                        regime="NIS2")
    assert "DeepSeek" in result.served_by[1]
    assert result.did_fail_over is False
    assert rec.models_called == ["deepseek-ai/DeepSeek-V3.2"]  # second never tried


def test_fails_over_when_primary_is_404(monkeypatch, env_keys):
    rec = _ModelRouter(status_by_model={"deepseek-ai/DeepSeek-V3.2": 404})
    monkeypatch.setattr(drafter.requests, "post", rec)
    chain = [(roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2"),
             (roster.FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")]
    result = draft_filing_with_failover({"incident_id": "x"}, chain=chain,
                                        regime="NIS2")
    # the SECOND model served the filing
    assert result.served_by == (roster.FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")
    assert result.fell_back_from == [(roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2")]
    assert result.did_fail_over is True
    assert "MiniMax" in result.value
    assert rec.models_called == ["deepseek-ai/DeepSeek-V3.2",
                                 "MiniMaxAI/MiniMax-M2.7"]


def test_whole_chain_down_surfaces_exhausted(monkeypatch, env_keys):
    rec = _ModelRouter(status_by_model={
        "deepseek-ai/DeepSeek-V3.2": 404, "MiniMaxAI/MiniMax-M2.7": 403})
    monkeypatch.setattr(drafter.requests, "post", rec)
    chain = [(roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2"),
             (roster.FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")]
    with pytest.raises(FailoverExhausted):
        draft_filing_with_failover({"incident_id": "x"}, chain=chain, regime="NIS2")


def test_served_filing_carries_the_authoritative_claims_unaffected(monkeypatch,
                                                                    env_keys):
    """Regardless of which model served, the drafter process attaches the SAME
    structured claims block; only the prose differs across the chain. Here we assert
    the served text is the model's prose (the claims block is attached later by the
    drafter process in build_draft_body, not by failover)."""
    rec = _ModelRouter(status_by_model={"deepseek-ai/DeepSeek-V3.2": 500})
    monkeypatch.setattr(drafter.requests, "post", rec)
    # a 500 is transient: with max_attempts=1 retry does not retry, so it surfaces
    # as a terminal _TransientDrafterError and failover steps over it.
    chain = [(roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2"),
             (roster.FEATHERLESS, "Qwen/Qwen2.5-72B-Instruct")]
    result = draft_filing_with_failover({"incident_id": "x"}, chain=chain,
                                        regime="NIS2", max_attempts=1)
    assert result.served_by[1] == "Qwen/Qwen2.5-72B-Instruct"
    assert "[CLAIMS]" not in result.value  # claims attached downstream, not here
