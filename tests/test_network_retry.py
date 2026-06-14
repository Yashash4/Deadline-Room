"""Bounded exponential-backoff retry on the two network chokepoints.

These prove the retry policy Shaktesh (the LLMOps judge) asked for, and prove it
is gated so the offline suite and byte-identical replay are unchanged:

  - the LLM chokepoint (floor.drafter.llm_complete) retries a transient 503 /
    transport error and succeeds on a later attempt;
  - it fails fast (no retry) on a terminal 4xx (400 / 403);
  - the DEFAULT path is a single attempt, so existing behavior is preserved;
  - the Band chokepoint (BandAgentShell._call) follows the same policy;
  - the recovered-retry counter feeds the additive packet receipt;
  - a clean offline floor run stays byte-identical.

No live network: every requests call is monkeypatched, and the backoff sleep is
replaced so the tests never actually wait."""

from __future__ import annotations

import pytest

import floor.retry as retry
from floor import drafter
from shell import band_agent_shell


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text else ("" if payload is None else "body")

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _ok_completion(content: str = "drafted filing body"):
    return _FakeResponse(200, {
        "choices": [{"message": {"content": content}}],
        "usage": {"total_tokens": 42},
    })


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # The backoff never actually waits in tests.
    monkeypatch.setattr(retry.time, "sleep", lambda _s: None)
    retry.COUNTER.reset()
    yield
    retry.COUNTER.reset()


# ---- LLM chokepoint --------------------------------------------------------

def test_llm_retries_transient_503_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResponse(503, text="capacity")
        return _ok_completion()

    monkeypatch.setattr(drafter.requests, "post", fake_post)
    out = drafter.llm_complete("featherless", "m", [{"role": "user", "content": "x"}],
                               api_key="k", max_attempts=3)
    assert out == "drafted filing body"
    assert calls["n"] == 2  # one failure, one success
    assert retry.COUNTER.recovered == 1  # the recovered transient is counted


def test_llm_retries_transport_error_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise drafter.requests.RequestException("connection reset")
        return _ok_completion()

    monkeypatch.setattr(drafter.requests, "post", fake_post)
    out = drafter.llm_complete("featherless", "m", [{"role": "user", "content": "x"}],
                               api_key="k", max_attempts=3)
    assert out == "drafted filing body"
    assert calls["n"] == 2
    assert retry.COUNTER.recovered == 1


def test_llm_no_retry_on_400(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        return _FakeResponse(400, text="bad request")

    monkeypatch.setattr(drafter.requests, "post", fake_post)
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete("featherless", "m", [{"role": "user", "content": "x"}],
                             api_key="k", max_attempts=3)
    assert calls["n"] == 1  # 4xx is terminal: fail fast, no retry
    assert retry.COUNTER.recovered == 0


def test_llm_no_retry_on_403(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        return _FakeResponse(403, text="forbidden")

    monkeypatch.setattr(drafter.requests, "post", fake_post)
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete("featherless", "m", [{"role": "user", "content": "x"}],
                             api_key="k", max_attempts=3)
    assert calls["n"] == 1


def test_llm_default_is_single_attempt(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        return _FakeResponse(503, text="capacity")

    monkeypatch.setattr(drafter.requests, "post", fake_post)
    # Default max_attempts is 1: a transient 503 raises after ONE attempt, exactly
    # as it did before retries existed. This is what keeps replay byte-identical.
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete("featherless", "m", [{"role": "user", "content": "x"}],
                             api_key="k")
    assert calls["n"] == 1
    assert retry.COUNTER.recovered == 0


def test_llm_exhausts_then_raises_typed_error(monkeypatch):
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        return _FakeResponse(503, text="capacity")

    monkeypatch.setattr(drafter.requests, "post", fake_post)
    # Three attempts, all transient: the typed DrafterError still surfaces (never
    # swallowed), and the recovered counter stays 0 because nothing recovered.
    with pytest.raises(drafter.DrafterError):
        drafter.llm_complete("featherless", "m", [{"role": "user", "content": "x"}],
                             api_key="k", max_attempts=3)
    assert calls["n"] == 3
    assert retry.COUNTER.recovered == 0


# ---- Band chokepoint -------------------------------------------------------

def _shell(max_attempts: int, tmp_path):
    return band_agent_shell.BandAgentShell(
        api_key="k", agent_name="t", log_dir=str(tmp_path),
        max_attempts=max_attempts)


def test_band_retries_transient_500_then_succeeds(monkeypatch, tmp_path):
    calls = {"n": 0}

    def fake_request(method, url, json=None, params=None, timeout=None, headers=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResponse(500, text="server error")
        return _FakeResponse(200, {"data": {"id": "abc"}})

    monkeypatch.setattr(band_agent_shell.requests, "request", fake_request)
    shell = _shell(3, tmp_path)
    status, data = shell._call("GET", "/agent/me")
    assert status == 200
    assert data == {"data": {"id": "abc"}}
    assert calls["n"] == 2
    assert retry.COUNTER.recovered == 1


def test_band_no_retry_on_404(monkeypatch, tmp_path):
    calls = {"n": 0}

    def fake_request(method, url, json=None, params=None, timeout=None, headers=None):
        calls["n"] += 1
        return _FakeResponse(404, {"error": "not found"})

    monkeypatch.setattr(band_agent_shell.requests, "request", fake_request)
    shell = _shell(3, tmp_path)
    status, data = shell._call("GET", "/agent/me")
    # 404 is terminal: returned (not retried) so the caller's own BandError fires.
    assert status == 404
    assert calls["n"] == 1
    assert retry.COUNTER.recovered == 0


def test_band_default_is_single_attempt(monkeypatch, tmp_path):
    calls = {"n": 0}

    def fake_request(method, url, json=None, params=None, timeout=None, headers=None):
        calls["n"] += 1
        return _FakeResponse(503, text="busy")

    monkeypatch.setattr(band_agent_shell.requests, "request", fake_request)
    shell = _shell(1, tmp_path)  # default attempts
    status, _ = shell._call("GET", "/agent/me")
    # A transient that never gets a retry: surfaced as the real status so the
    # caller raises BandError, exactly as before. One attempt, no backoff.
    assert status == 503
    assert calls["n"] == 1
    assert retry.COUNTER.recovered == 0


def test_band_exhausts_transient_surfaces_status(monkeypatch, tmp_path):
    calls = {"n": 0}

    def fake_request(method, url, json=None, params=None, timeout=None, headers=None):
        calls["n"] += 1
        return _FakeResponse(503, text="busy")

    monkeypatch.setattr(band_agent_shell.requests, "request", fake_request)
    shell = _shell(3, tmp_path)
    status, _ = shell._call("GET", "/agent/me")
    assert status == 503  # final transient surfaces so the caller's BandError fires
    assert calls["n"] == 3
    assert retry.COUNTER.recovered == 0


def test_band_transport_error_surfaces_as_503(monkeypatch, tmp_path):
    def fake_request(method, url, json=None, params=None, timeout=None, headers=None):
        raise band_agent_shell.requests.RequestException("dns failure")

    monkeypatch.setattr(band_agent_shell.requests, "request", fake_request)
    shell = _shell(2, tmp_path)
    status, data = shell._call("GET", "/agent/me")
    assert status == 503
    assert "transport_error" in data


# ---- the gate: a clean offline run is byte-identical and shows no receipt --

def test_clean_offline_floor_is_byte_identical_and_has_no_reliability_field(tmp_path):
    from floor.run_floor import DRAFTER_ROLES, run_floor
    from floor.shell_adapter import FakeBandClient, FakeRoom

    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")

    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Records "
                    f"{claim_facts['records_affected']} attacker "
                    f"{claim_facts['attacker']}. Test stub.")
        return fn

    draft_fns = {r.branch: make(r.regime) for r in DRAFTER_ROLES}
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=draft_fns)
    # The FakeBand path never touches the network, so no retry recovers and the
    # additive receipt is omitted entirely (happy path is visually unchanged).
    assert "reliability" not in packet
    assert retry.COUNTER.recovered == 0
    # Replay stays byte-identical: the retry work is outside the hashed run log.
    assert packet["replay"]["byte_identical"] is True


# ---- the receipt renders only when nonzero --------------------------------

def test_reliability_receipt_renders_only_when_nonzero():
    from floor.packet import _render_reliability
    assert _render_reliability({}) == ""
    assert _render_reliability({"recovered_retries": 0}) == ""
    out = _render_reliability({"recovered_retries": 2})
    assert "8c. Network reliability" in out
    assert "2 transient" in out
    assert "auto-recovered" in out
    # No forbidden glyphs leak into the rendered receipt.
    assert "—" not in out and "–" not in out


# ---- transient classification ---------------------------------------------

def test_transient_status_classification():
    assert retry.is_transient_status(429)
    assert retry.is_transient_status(500)
    assert retry.is_transient_status(503)
    assert retry.is_transient_status(599)
    assert not retry.is_transient_status(400)
    assert not retry.is_transient_status(401)
    assert not retry.is_transient_status(403)
    assert not retry.is_transient_status(404)
    assert not retry.is_transient_status(200)
