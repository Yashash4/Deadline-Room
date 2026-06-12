"""test_band_shell.py -- the hardened BandAgentShell speaks the LIVE Band Agent
API exactly (verified schemas in research/spikes/LIVE-API-MAP.md and the
spikes/band_spikes.py probe). We mock the transport and assert the shell sends
the right method, path, headers, and body, and parses the verified response
shapes correctly."""

import json

import pytest

from shell.band_agent_shell import BandAgentShell, BandError, strip_mention_markers


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = "" if body is None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeTransport:
    """Records every request and replies from a scripted queue keyed by
    (method, path-suffix)."""

    def __init__(self):
        self.calls = []
        self.script = {}

    def reply(self, method, path_suffix, status, body):
        self.script[(method, path_suffix)] = (status, body)

    def __call__(self, method, url, json=None, params=None, timeout=None, headers=None):
        self.calls.append({"method": method, "url": url, "json": json,
                           "params": params, "headers": headers})
        for (m, suffix), (status, body) in self.script.items():
            if m == method and url.endswith(suffix):
                return FakeResponse(status, body)
        return FakeResponse(204, None)


@pytest.fixture
def shell(monkeypatch, tmp_path):
    import shell.band_agent_shell as mod
    transport = FakeTransport()
    monkeypatch.setattr(mod.requests, "request", transport)
    s = BandAgentShell(api_key="band_a_test", agent_name="t",
                       log_dir=str(tmp_path))
    return s, transport


def test_auth_header_is_x_api_key_not_bearer(shell):
    s, t = shell
    t.reply("GET", "/agent/me", 200, {"data": {"id": "agent-1"}})
    s.whoami()
    h = t.calls[-1]["headers"]
    assert h["X-API-Key"] == "band_a_test"
    assert "Authorization" not in h


def test_whoami_parses_data_id(shell):
    s, t = shell
    t.reply("GET", "/agent/me", 200, {"data": {"id": "agent-xyz", "handle": "h"}})
    assert s.whoami() == "agent-xyz"
    assert s.agent_id == "agent-xyz"


def test_create_chat_sends_verified_body_and_parses_id(shell):
    s, t = shell
    t.reply("POST", "/agent/chats", 201, {"data": {"id": "room-9"}})
    cid = s.create_chat("Deadline Room")
    assert cid == "room-9"
    body = t.calls[-1]["json"]
    assert body == {"chat": {"title": "Deadline Room"}}


def test_add_participant_sends_verified_body(shell):
    s, t = shell
    s.join("room-9")
    t.reply("POST", "/agent/chats/room-9/participants", 201,
            {"data": {"status": "inactive"}})
    s.add_participant("agent-2")
    body = t.calls[-1]["json"]
    assert body == {"participant": {"participant_id": "agent-2"}}


def test_post_sends_message_envelope_with_mention_objects(shell):
    s, t = shell
    s.join("room-9")
    t.reply("GET", "/agent/chats/room-9/context", 200, {"data": []})
    t.reply("POST", "/agent/chats/room-9/messages", 201,
            {"data": {"id": "msg-1", "success": True}})
    s.post("hello", mentions=["agent-2"], dedup_key="k1")
    body = t.calls[-1]["json"]
    assert body["message"]["mentions"] == [{"id": "agent-2"}]
    assert "hello" in body["message"]["content"]
    assert "[dedup_key:k1]" in body["message"]["content"]


def test_post_dedup_drops_when_key_already_in_context(shell):
    s, t = shell
    s.join("room-9")
    # context already contains our dedup key -> exactly-once drop
    t.reply("GET", "/agent/chats/room-9/context", 200,
            {"data": [{"content": "old [dedup_key:k1]"}]})
    result = s.post("hello", mentions=["agent-2"], dedup_key="k1")
    assert result is None
    # no POST /messages call was made
    assert not any(c["method"] == "POST" and c["url"].endswith("/messages")
                   for c in t.calls)


def test_next_message_parses_single_object_and_204(shell):
    s, t = shell
    s.join("room-9")
    t.reply("GET", "/agent/chats/room-9/messages/next", 200,
            {"data": {"id": "msg-7", "content": "hi", "sender_id": "agent-1"}})
    m = s.next_message()
    assert m["id"] == "msg-7"
    # 204 empty -> None
    t.reply("GET", "/agent/chats/room-9/messages/next", 204, None)
    assert s.next_message() is None


def test_next_skips_already_handled_id(shell):
    s, t = shell
    s.join("room-9")
    t.reply("GET", "/agent/chats/room-9/messages/next", 200,
            {"data": {"id": "msg-7"}})
    t.reply("POST", "/agent/chats/room-9/messages/msg-7/processing", 200, {"data": {}})
    t.reply("POST", "/agent/chats/room-9/messages/msg-7/processed", 200, {"data": {}})
    assert s.next_message()["id"] == "msg-7"
    s.mark("msg-7", "processing")
    s.mark("msg-7", "processed")
    # /next re-serves the same id, but the client knows it is handled
    assert s.next_message() is None


def test_mark_lifecycle_paths_and_failed_body(shell):
    s, t = shell
    s.join("room-9")
    t.reply("POST", "/agent/chats/room-9/messages/m/processing", 200, {"data": {}})
    t.reply("POST", "/agent/chats/room-9/messages/m/processed", 200, {"data": {}})
    t.reply("POST", "/agent/chats/room-9/messages/m/failed", 200, {"data": {}})
    s.mark("m", "processing")
    assert t.calls[-1]["url"].endswith("/messages/m/processing")
    s.mark("m", "processed")
    assert t.calls[-1]["json"] == {}
    s.mark("m", "failed", error="boom")
    # failed body is {"error": <string>} (verified: 'reason' is rejected)
    assert t.calls[-1]["json"] == {"error": "boom"}


def test_error_surfaces_structurally(shell):
    s, t = shell
    t.reply("GET", "/agent/me", 401, {"error": "nope"})
    with pytest.raises(BandError):
        s.whoami()


def test_run_loop_drains_processes_and_posts_reply(shell):
    s, t = shell
    s.join("room-9")
    t.reply("GET", "/agent/chats/room-9/messages/next", 200,
            {"data": {"id": "msg-1", "content": "draft please"}})
    t.reply("POST", "/agent/chats/room-9/messages/msg-1/processing", 200, {"data": {}})
    t.reply("POST", "/agent/chats/room-9/messages/msg-1/processed", 200, {"data": {}})
    t.reply("GET", "/agent/chats/room-9/context", 200, {"data": []})
    t.reply("POST", "/agent/chats/room-9/messages", 201, {"data": {"id": "reply-1"}})

    seen = {}

    def handle(message, context):
        seen["mid"] = message["id"]
        return {"content": "ok", "mentions": ["agent-1"], "dedup_key": "r1"}

    handled = s.run(handle, poll_seconds=0, max_loops=5, idle_breaks=1)
    assert handled == 1
    assert seen["mid"] == "msg-1"
    # a reply message was posted mentioning agent-1
    posts = [c for c in t.calls if c["method"] == "POST"
             and c["url"].endswith("/messages")]
    assert posts and posts[-1]["json"]["message"]["mentions"] == [{"id": "agent-1"}]


def test_strip_mention_markers():
    raw = "@[[3aa52157-9ba6-4a9f-9304-90e5cdab875e]] hello world"
    assert strip_mention_markers(raw) == "hello world"
