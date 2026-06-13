"""test_provider_split.py -- the PRODUCTION provider split that lets the floor win
both partner prizes without spending AI/ML credit during development.

Two things are pinned here, with the HTTP layer mocked so no network or LLM is
touched:

  1. The provider router (floor.drafter.llm_complete) sends each call to the right
     base URL, with Bearer auth and the right env-var key, for the named provider.
     draft_filing / draft_characterization carry a role's provider through it.

  2. The roster resolution. dev (default) keeps EVERY role on Featherless, so a dev
     run spends zero AI/ML credit. prod routes the parallel racing drafters
     (Triage, NIS2, SEC, DORA) to AI/ML API and keeps the hero open-model roles
     (Materiality, UK ICO) on Featherless.
"""

import pytest

from floor import drafter, roster


# ---------------------------------------------------------------------------
# A tiny fake for requests.post so the router can be exercised offline. It
# records the call and returns a canned OpenAI-compatible completion body.
# ---------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, status_code=200, content="ready"):
        self.status_code = status_code
        self._content = content
        self.text = "error-body"

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class _Recorder:
    def __init__(self, status_code=200, content="ready"):
        self.calls = []
        self._status = status_code
        self._content = content

    def __call__(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json,
                           "timeout": timeout})
        return _FakeResp(self._status, self._content)


@pytest.fixture
def env_keys(monkeypatch):
    monkeypatch.setenv("FEATHERLESS_API_KEY", "fl-secret")
    monkeypatch.setenv("AIML_API_KEY", "aiml-secret")


# ---- the router routes to the right base / auth / model --------------------

def test_router_featherless_base_auth_and_model(monkeypatch, env_keys):
    rec = _Recorder()
    monkeypatch.setattr(drafter.requests, "post", rec)
    out = drafter.llm_complete(
        roster.FEATHERLESS, "deepseek-ai/DeepSeek-V3.2",
        [{"role": "user", "content": "hi"}])
    assert out == "ready"
    call = rec.calls[0]
    assert call["url"] == drafter.FEATHERLESS_BASE + "/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer fl-secret"
    assert call["json"]["model"] == "deepseek-ai/DeepSeek-V3.2"


def test_router_aimlapi_base_auth_and_model(monkeypatch, env_keys):
    rec = _Recorder()
    monkeypatch.setattr(drafter.requests, "post", rec)
    out = drafter.llm_complete(
        roster.AIMLAPI, "gpt-5-chat-latest",
        [{"role": "user", "content": "hi"}])
    assert out == "ready"
    call = rec.calls[0]
    assert call["url"] == drafter.AIMLAPI_BASE + "/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer aiml-secret"
    assert call["json"]["model"] == "gpt-5-chat-latest"


def test_router_unknown_provider_raises():
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete("not-a-provider", "m", [{"role": "user", "content": "x"}])


def test_router_missing_key_raises(monkeypatch):
    monkeypatch.delenv("AIML_API_KEY", raising=False)
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete(roster.AIMLAPI, "gpt-5-chat-latest",
                             [{"role": "user", "content": "x"}])


def test_router_non_200_raises(monkeypatch, env_keys):
    monkeypatch.setattr(drafter.requests, "post", _Recorder(status_code=404))
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete(roster.AIMLAPI, "missing-model",
                             [{"role": "user", "content": "x"}])


def test_router_empty_content_raises(monkeypatch, env_keys):
    monkeypatch.setattr(drafter.requests, "post", _Recorder(content="   "))
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete(roster.FEATHERLESS, "m",
                             [{"role": "user", "content": "x"}])


# ---- draft_filing / draft_characterization carry the provider --------------

def test_draft_filing_routes_through_provider(monkeypatch, env_keys):
    rec = _Recorder(content="A tidy NIS2 filing.")
    monkeypatch.setattr(drafter.requests, "post", rec)
    drafter.draft_filing({"incident_id": "x"}, model="claude-opus-4-1-20250805",
                         provider=roster.AIMLAPI, regime="SEC")
    call = rec.calls[0]
    assert call["url"].startswith(drafter.AIMLAPI_BASE)
    assert call["json"]["model"] == "claude-opus-4-1-20250805"


def test_draft_filing_defaults_to_featherless(monkeypatch, env_keys):
    rec = _Recorder(content="A tidy filing.")
    monkeypatch.setattr(drafter.requests, "post", rec)
    drafter.draft_filing({"incident_id": "x"})
    assert rec.calls[0]["url"].startswith(drafter.FEATHERLESS_BASE)


def test_draft_characterization_routes_through_provider(monkeypatch, env_keys):
    rec = _Recorder(content="Both filings will say 2.1 million records.")
    monkeypatch.setattr(drafter.requests, "post", rec)
    out = drafter.draft_characterization(
        regime="SEC", old_records=48211, new_records=2_100_000, role="propose",
        model="gpt-5-chat-latest", provider=roster.AIMLAPI)
    assert "2.1 million" in out
    assert rec.calls[0]["url"].startswith(drafter.AIMLAPI_BASE)


# ---- roster resolution: dev all-Featherless, prod is the split -------------

def test_dev_resolves_every_drafting_role_to_featherless():
    for role in (roster.NIS2_DRAFTER, roster.SEC_DRAFTER, roster.DORA_DRAFTER,
                 roster.TRIAGE):
        provider, model = roster.resolve(role, roster.PROVIDER_DEV)
        assert provider == roster.FEATHERLESS, f"{role.name} left Featherless in dev"
        assert model == role.model


def test_prod_routes_racing_drafters_to_aimlapi():
    expected = {
        roster.TRIAGE: "gemini-3.5-flash",
        roster.NIS2_DRAFTER: "claude-sonnet-4-20250514",
        roster.DORA_DRAFTER: "gpt-5-chat-latest",
        roster.SEC_DRAFTER: "claude-opus-4-1-20250805",
    }
    for role, model in expected.items():
        provider, got = roster.resolve(role, roster.PROVIDER_PROD)
        assert provider == roster.AIMLAPI, f"{role.name} not on AI/ML in prod"
        assert got == model


def test_prod_keeps_featherless_hero_roles_on_featherless():
    heroes = roster.prod_featherless_hero_models()
    assert heroes["Materiality"] == "deepseek-ai/DeepSeek-V3.2"
    assert heroes["UK ICO Drafter"] == "MiniMaxAI/MiniMax-M2.7"
    assert roster.MATERIALITY_HERO[0] == roster.FEATHERLESS
    assert roster.UK_HERO[0] == roster.FEATHERLESS


def test_prod_aiml_validation_lists_only_aiml_models():
    models = roster.prod_aiml_validation_models()
    assert set(models) == {"Triage", "NIS2 Drafter", "DORA Drafter", "SEC Drafter"}
    # every listed model is one of the AI/ML drafter ids, none a Featherless id
    for m in models.values():
        assert "/" not in m or not m.startswith(("deepseek-ai/", "MiniMaxAI/",
                                                 "Qwen/"))


def test_resolve_rejects_unknown_provider_set():
    with pytest.raises(ValueError):
        roster.resolve(roster.NIS2_DRAFTER, "staging")


# ---- the dev floor run never touches AI/ML ---------------------------------

def test_dev_floor_run_never_calls_aimlapi(monkeypatch, tmp_path):
    """A full dev floor run with a real (mocked) provider router must send every
    completion to Featherless. If any call hits AI/ML, fail loudly. This is the
    cost guard: dev spends zero AI/ML credit."""
    from floor.run_floor import DRAFTER_ROLES, run_floor
    from floor.shell_adapter import FakeBandClient, FakeRoom

    monkeypatch.setenv("FEATHERLESS_API_KEY", "fl-secret")
    monkeypatch.setenv("AIML_API_KEY", "aiml-secret")

    seen_bases = []

    def fake_post(url, headers=None, json=None, timeout=None):
        seen_bases.append(url)
        return _FakeResp(content="A deterministic drafted filing body.")

    monkeypatch.setattr(drafter.requests, "post", fake_post)

    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")

    # No draft_fns: the floor calls the real draft_filing -> the mocked router.
    run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
              provider_set=roster.PROVIDER_DEV)

    assert seen_bases, "the dev run made no LLM calls at all"
    for url in seen_bases:
        assert url.startswith(drafter.FEATHERLESS_BASE), \
            f"dev run hit a non-Featherless endpoint: {url}"
        assert "aimlapi.com" not in url


def test_prod_floor_run_routes_drafters_to_aimlapi(monkeypatch, tmp_path):
    """Under prod, the racing drafters' completions go to AI/ML API. (Offline:
    the live availability check is skipped for fake-client runs, so this asserts
    only the drafting calls.)"""
    from floor.run_floor import DRAFTER_ROLES, run_floor
    from floor.shell_adapter import FakeBandClient, FakeRoom

    monkeypatch.setenv("FEATHERLESS_API_KEY", "fl-secret")
    monkeypatch.setenv("AIML_API_KEY", "aiml-secret")

    seen = []

    def fake_post(url, headers=None, json=None, timeout=None):
        seen.append({"url": url, "model": json["model"]})
        return _FakeResp(content="A deterministic drafted filing body.")

    monkeypatch.setattr(drafter.requests, "post", fake_post)

    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")

    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       provider_set=roster.PROVIDER_PROD)

    # every drafting call went to AI/ML, each with its named prod model
    assert seen, "the prod run made no LLM calls"
    for call in seen:
        assert call["url"].startswith(drafter.AIMLAPI_BASE)
    models = {c["model"] for c in seen}
    assert "gpt-5-chat-latest" in models  # DORA
    assert "claude-opus-4-1-20250805" in models  # SEC
    # the packet records the active provider set + the AI/ML drafter roster
    assert packet["incident"]["provider_set"] == "prod"
    assert set(packet["providers"]["aiml_drafters"]) == {
        "Triage", "NIS2 Drafter", "SEC Drafter", "DORA Drafter"}
