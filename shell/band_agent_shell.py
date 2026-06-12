"""BandAgentShell: every Band plumbing concern in one class, so each agent
(M1 drafter, Two-Key approver, anything) supplies ONLY a handle() function.

Concept-agnostic by design: nothing in here knows about clocks, filings,
sanctions, or keys. Windows-safe (no fcntl; per-agent JSONL, no shared locks).

Endpoint paths live in EP — same convention as spikes.py: fix once, re-run.
After spikes run, adjust the response-shape helpers (_gid) if needed.

Usage:
    def handle(message: dict, context: list[dict]) -> dict | None:
        # framework-specific work goes here (LangGraph graph, raw LLM call...)
        # return a dict to post as a reply, or None to post nothing
        ...

    shell = BandAgentShell(api_key=KEY, agent_name="nis2_drafter",
                           dedup_namespace="draft:nis2")
    shell.join(chat_id)
    shell.run(handle)          # drain -> dedup-guard -> handle -> post -> mark
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

import requests

BASE = os.environ.get("BAND_BASE_URL", "https://api.band.ai/v1")

EP = {
    "me":           "/agent/me",
    "chats":        "/agent/chats",
    "participants": "/agent/chats/{chat_id}/participants",
    "context":      "/agent/chats/{chat_id}/context",
    "messages":     "/agent/chats/{chat_id}/messages",
    "next":         "/agent/messages/next",
    "processing":   "/agent/messages/{msg_id}/processing",
    "processed":    "/agent/messages/{msg_id}/processed",
    "failed":       "/agent/messages/{msg_id}/failed",
    "peers":        "/agent/peers",
}


def _gid(data, *keys):
    if isinstance(data, dict):
        for k in (*keys, "id", "uuid", "chat_id", "message_id", "agent_id"):
            if k in data:
                return data[k]
        for v in data.values():
            f = _gid(v, *keys)
            if f:
                return f
    if isinstance(data, list) and data:
        return _gid(data[0], *keys)
    return None


class BandAgentShell:
    def __init__(self, api_key: str, agent_name: str,
                 dedup_namespace: str = "", log_dir: str = "runlogs") -> None:
        self.key = api_key
        self.name = agent_name
        self.ns = dedup_namespace or agent_name
        self.chat_id: Optional[str] = None
        self.agent_id: Optional[str] = None
        Path(log_dir).mkdir(exist_ok=True)
        self.log_path = Path(log_dir) / f"{agent_name}.jsonl"

    # ---- HTTP -------------------------------------------------------------
    def _call(self, method: str, path: str, body=None, params=None):
        r = requests.request(method, BASE + path, json=body, params=params,
                             timeout=60,
                             headers={"Authorization": f"Bearer {self.key}",
                                      "Content-Type": "application/json"})
        try:
            data = r.json() if r.text else {}
        except ValueError:
            data = {"raw": r.text}
        self._log("http", {"method": method, "path": path,
                           "status": r.status_code})
        return r.status_code, data

    # ---- local mirror (the replay substrate; per-agent file, no locks) ----
    def _log(self, kind: str, payload: dict) -> None:
        entry = {"ts": time.time(), "agent": self.name, "kind": kind, **payload}
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    # ---- identity & rooms ---------------------------------------------------
    def whoami(self) -> Optional[str]:
        code, data = self._call("GET", EP["me"])
        self.agent_id = _gid(data) if code == 200 else None
        return self.agent_id

    def create_chat(self, name: str) -> str:
        code, data = self._call("POST", EP["chats"], {"name": name})
        if code not in (200, 201):
            raise RuntimeError(f"create_chat failed: {code} {data}")
        self.chat_id = _gid(data, "chat_id")
        return self.chat_id

    def join(self, chat_id: str) -> None:
        self.chat_id = chat_id

    def add_participant(self, agent_id: str, chat_id: Optional[str] = None):
        cid = chat_id or self.chat_id
        return self._call("POST", EP["participants"].format(chat_id=cid),
                          {"agent_id": agent_id})

    # ---- context & the read-then-act dedup guard ---------------------------
    def context(self, chat_id: Optional[str] = None) -> list:
        cid = chat_id or self.chat_id
        code, data = self._call("GET", EP["context"].format(chat_id=cid))
        if code != 200:
            return []
        if isinstance(data, list):
            return data
        for k in ("messages", "context", "items", "data"):
            if isinstance(data.get(k), list):
                return data[k]
        return []

    def already_posted(self, dedup_key: str) -> bool:
        """Crash positions A and B both resolve here: before re-posting,
        read the room and check whether our key is already present."""
        blob = json.dumps(self.context(), default=str)
        return dedup_key in blob

    # ---- posting ------------------------------------------------------------
    def post(self, content, mentions: Optional[list] = None,
             dedup_key: Optional[str] = None, meta: Optional[dict] = None):
        key = dedup_key or f"{self.ns}:{uuid.uuid4().hex[:8]}"
        if dedup_key and self.already_posted(dedup_key):
            self._log("dedup_drop", {"dedup_key": dedup_key})
            return None  # exactly-once: the work already landed
        body = {"content": (content if isinstance(content, str)
                            else json.dumps({"dedup_key": key,
                                             "meta": meta or {},
                                             "payload": content})),
                "mentions": mentions or []}
        code, data = self._call("POST",
                                EP["messages"].format(chat_id=self.chat_id),
                                body)
        self._log("post", {"dedup_key": key, "status": code})
        return data

    # ---- lifecycle ------------------------------------------------------------
    def next_message(self) -> Optional[dict]:
        code, data = self._call("GET", EP["next"])
        return data if code == 200 and data else None

    def mark(self, msg_id: str, state: str, reason: str = "") -> None:
        path = EP[state].format(msg_id=msg_id)
        body = {"reason": reason} if state == "failed" and reason else None
        self._call("POST", path, body)
        self._log("lifecycle", {"msg_id": msg_id, "state": state})

    # ---- the run loop -----------------------------------------------------------
    def run(self, handle: Callable[[dict, list], Optional[dict]],
            poll_seconds: float = 2.0, max_loops: Optional[int] = None) -> None:
        """Drain -> processing -> handle() -> post reply -> processed.
        handle() raising -> mark failed with the error as the typed reason."""
        loops = 0
        while max_loops is None or loops < max_loops:
            loops += 1
            msg = self.next_message()
            if not msg:
                time.sleep(poll_seconds)
                continue
            msg_id = _gid(msg, "message_id")
            self.mark(msg_id, "processing")
            try:
                reply = handle(msg, self.context())
                if reply is not None:
                    dk = (reply.get("dedup_key")
                          if isinstance(reply, dict) else None)
                    self.post(reply, mentions=reply.get("mentions", []),
                              dedup_key=dk)
                self.mark(msg_id, "processed")
            except Exception as e:  # noqa: BLE001 — typed failure, not a crash
                self.mark(msg_id, "failed", reason=f"{type(e).__name__}: {e}")
