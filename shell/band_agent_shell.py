"""BandAgentShell: every Band plumbing concern in one class, so each agent
(Warden, NIS2 drafter, anything) supplies ONLY a handle() function.

Concept-agnostic by design: nothing in here knows about clocks, filings,
sanctions, or keys. Windows-safe (no fcntl; per-agent JSONL, no shared locks).

Verified against the LIVE Band Agent API on 2026-06-13 (see
spikes/band_spikes.py and research/spikes/LIVE-API-MAP.md). Authoritative facts
this client encodes:

  Base:   https://app.band.ai/api/v1
  Auth:   header  X-API-Key: <agent key>   (NOT Authorization: Bearer)

  GET  /agent/me                                   -> 200 {data:{id,handle,name}}
  POST /agent/chats          {"chat":{"title": str}}                        -> 201 {data:{id}}
  POST /agent/chats/{cid}/participants  {"participant":{"participant_id": uuid}} -> 201
  POST /agent/chats/{cid}/messages  {"message":{"content": str,
                                                 "mentions":[{"id": uuid}]}} -> 201 {data:{id,recipients}}
       (mentions REQUIRED; mentioned agent MUST already be a participant; self-mention 422)
  GET  /agent/chats/{cid}/messages/next            -> 200 {data:{...one message...}} | 204 empty
       PER-CHAT drain. Returns the OLDEST not-yet-processed mentioned message,
       REPEATEDLY, until that message is marked processed (or failed). It is a
       cursor over lifecycle state, not a destructive pop.
  POST /agent/chats/{cid}/messages/{mid}/processing  (no body)              -> 200
  POST /agent/chats/{cid}/messages/{mid}/processed   (any/empty JSON body)  -> 200
       (must follow processing; processed before processing is 422)
  POST /agent/chats/{cid}/messages/{mid}/failed   {"error": <string>}       -> 200
  GET  /agent/chats/{cid}/context                  -> 200 {data:[messages...]}
  GET  /agent/peers?not_in_chat={cid}              -> 200

Exactly-once is owned by the poster via a read-then-act dedup guard
(already_posted), never by reliance on re-delivery: the message-content
carries a dedup_key the poster checks against /context before re-posting.

Usage:
    def handle(message: dict, context: list[dict]) -> dict | None:
        # framework-specific work (LLM call, graph...). Return a reply dict to
        # post, or None to post nothing. A reply dict may carry "content",
        # "mentions" ([uuid,...]), and "dedup_key".
        ...

    shell = BandAgentShell(api_key=KEY, agent_name="nis2_drafter",
                           dedup_namespace="draft:nis2")
    shell.join(chat_id)
    shell.run(handle, max_loops=20)   # drain -> processing -> handle -> post -> processed
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

import requests

BASE = os.environ.get("BAND_BASE_URL", "https://app.band.ai/api/v1")

EP = {
    "me":           "/agent/me",
    "chats":        "/agent/chats",
    "participants": "/agent/chats/{chat_id}/participants",
    "context":      "/agent/chats/{chat_id}/context",
    "messages":     "/agent/chats/{chat_id}/messages",
    "next":         "/agent/chats/{chat_id}/messages/next",
    "processing":   "/agent/chats/{chat_id}/messages/{msg_id}/processing",
    "processed":    "/agent/chats/{chat_id}/messages/{msg_id}/processed",
    "failed":       "/agent/chats/{chat_id}/messages/{msg_id}/failed",
    "peers":        "/agent/peers",
}

# The Band content channel inlines mentions as "@[[<uuid>]]" markers. Strip them
# when an agent wants the human-readable body.
_MENTION_MARKER = re.compile(r"@\[\[[0-9a-fA-F-]{36}\]\]\s*")


def strip_mention_markers(content: str) -> str:
    return _MENTION_MARKER.sub("", content or "").strip()


class BandError(RuntimeError):
    """Surfaced structurally; the run log records the status and body."""

    def __init__(self, op: str, status: int, body) -> None:
        super().__init__(f"{op} failed: HTTP {status} {body}")
        self.op = op
        self.status = status
        self.body = body


class BandAgentShell:
    def __init__(self, api_key: str, agent_name: str,
                 dedup_namespace: str = "", log_dir: str = "runlogs") -> None:
        self.key = api_key
        self.name = agent_name
        self.ns = dedup_namespace or agent_name
        self.chat_id: Optional[str] = None
        self.agent_id: Optional[str] = None
        # Client-side record of messages we have already carried through their
        # lifecycle, so a /next that re-serves the same id is a no-op for us.
        self._handled: set[str] = set()
        Path(log_dir).mkdir(exist_ok=True)
        self.log_path = Path(log_dir) / f"{agent_name}.jsonl"

    # ---- HTTP -------------------------------------------------------------
    def _call(self, method: str, path: str, body=None, params=None):
        r = requests.request(
            method, BASE + path, json=body, params=params, timeout=60,
            headers={"X-API-Key": self.key, "Content-Type": "application/json"},
        )
        if r.status_code == 204 or not r.text:
            data = {}
        else:
            try:
                data = r.json()
            except ValueError:
                data = {"raw": r.text}
        self._log("http", {"method": method, "path": path, "status": r.status_code})
        return r.status_code, data

    # ---- local mirror (the replay substrate; per-agent file, no locks) ----
    def _log(self, kind: str, payload: dict) -> None:
        entry = {"ts": time.time(), "agent": self.name, "kind": kind, **payload}
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    # ---- identity & rooms -------------------------------------------------
    def whoami(self) -> Optional[str]:
        code, data = self._call("GET", EP["me"])
        if code != 200:
            raise BandError("whoami", code, data)
        self.agent_id = (data.get("data") or {}).get("id")
        return self.agent_id

    def create_chat(self, title: str) -> str:
        code, data = self._call("POST", EP["chats"], {"chat": {"title": title}})
        if code not in (200, 201):
            raise BandError("create_chat", code, data)
        self.chat_id = (data.get("data") or {}).get("id")
        return self.chat_id

    def join(self, chat_id: str) -> None:
        self.chat_id = chat_id

    def add_participant(self, agent_id: str, chat_id: Optional[str] = None) -> dict:
        cid = chat_id or self.chat_id
        code, data = self._call(
            "POST", EP["participants"].format(chat_id=cid),
            {"participant": {"participant_id": agent_id}},
        )
        if code not in (200, 201):
            raise BandError("add_participant", code, data)
        return data

    def peers(self, not_in_chat: Optional[str] = None) -> list:
        params = {"not_in_chat": not_in_chat} if not_in_chat else None
        code, data = self._call("GET", EP["peers"], params=params)
        if code != 200:
            raise BandError("peers", code, data)
        d = data.get("data", data)
        return d if isinstance(d, list) else []

    # ---- context & the read-then-act dedup guard --------------------------
    def context(self, chat_id: Optional[str] = None) -> list:
        cid = chat_id or self.chat_id
        code, data = self._call("GET", EP["context"].format(chat_id=cid))
        if code != 200:
            return []
        if isinstance(data, list):
            return data
        for k in ("data", "messages", "context", "items"):
            if isinstance(data.get(k), list):
                return data[k]
        return []

    def already_posted(self, dedup_key: str) -> bool:
        """Crash positions A and B both resolve here: before re-posting, read
        the room and check whether our dedup_key is already present."""
        blob = json.dumps(self.context(), default=str)
        return dedup_key in blob

    # ---- posting ----------------------------------------------------------
    def post(self, content: str, mentions: Optional[list] = None,
             dedup_key: Optional[str] = None) -> Optional[dict]:
        """Post a message. mentions is a list of agent UUIDs (strings). The
        Band API requires at least one mention; the caller supplies the
        recipient (typically the Warden). dedup_key, if given, is embedded in
        the content and checked against /context for exactly-once."""
        key = dedup_key or f"{self.ns}:{uuid.uuid4().hex[:8]}"
        if dedup_key and self.already_posted(dedup_key):
            self._log("dedup_drop", {"dedup_key": dedup_key})
            return None  # exactly-once: the work already landed
        text = content if isinstance(content, str) else json.dumps(content)
        if dedup_key:
            text = f"{text}\n[dedup_key:{dedup_key}]"
        mention_objs = [{"id": m} for m in (mentions or [])]
        body = {"message": {"content": text, "mentions": mention_objs}}
        code, data = self._call(
            "POST", EP["messages"].format(chat_id=self.chat_id), body)
        self._log("post", {"dedup_key": key, "status": code})
        if code not in (200, 201):
            raise BandError("post", code, data)
        return data

    # ---- lifecycle --------------------------------------------------------
    def next_message(self) -> Optional[dict]:
        """Return the oldest mentioned message not yet carried through its
        lifecycle by this client, or None. /next re-serves the same message
        until it is marked processed/failed, so we also skip ids we have
        already handled in this process."""
        code, data = self._call(
            "GET", EP["next"].format(chat_id=self.chat_id))
        if code == 204 or not data:
            return None
        if code != 200:
            raise BandError("next", code, data)
        msg = data.get("data", data)
        if not isinstance(msg, dict) or not msg.get("id"):
            return None
        if msg["id"] in self._handled:
            return None
        return msg

    def mark(self, msg_id: str, state: str, error: str = "") -> None:
        """state in {processing, processed, failed}. processed/failed must
        follow processing. failed carries {"error": <string>}."""
        path = EP[state].format(chat_id=self.chat_id, msg_id=msg_id)
        body = {"error": error} if state == "failed" else ({} if state == "processed" else None)
        code, data = self._call("POST", path, body)
        self._log("lifecycle", {"msg_id": msg_id, "state": state, "status": code})
        if code not in (200, 201):
            raise BandError(f"mark {state}", code, data)
        if state in ("processed", "failed"):
            self._handled.add(msg_id)

    # ---- the run loop -----------------------------------------------------
    def run(self, handle: Callable[[dict, list], Optional[dict]],
            poll_seconds: float = 2.0, max_loops: Optional[int] = None,
            idle_breaks: Optional[int] = None) -> int:
        """Drain -> processing -> handle() -> post reply -> processed.
        handle() raising -> mark failed with the error as the typed reason.

        idle_breaks: stop after this many consecutive empty polls (lets a
        bounded drainer exit once its inbox is quiet). max_loops caps total
        iterations. Returns the number of messages handled."""
        loops = 0
        idle = 0
        handled = 0
        while max_loops is None or loops < max_loops:
            loops += 1
            msg = self.next_message()
            if not msg:
                idle += 1
                if idle_breaks is not None and idle >= idle_breaks:
                    break
                time.sleep(poll_seconds)
                continue
            idle = 0
            msg_id = msg["id"]
            self.mark(msg_id, "processing")
            try:
                reply = handle(msg, self.context())
                if reply is not None:
                    self.post(
                        reply.get("content", ""),
                        mentions=reply.get("mentions", []),
                        dedup_key=reply.get("dedup_key"),
                    )
                self.mark(msg_id, "processed")
                handled += 1
            except Exception as e:  # noqa: BLE001 -- typed failure, not a crash
                self.mark(msg_id, "failed", error=f"{type(e).__name__}: {e}")
        return handled
