"""Adapter: the live Band client the floor orchestrator drives.

LiveBand IS the hardened BandAgentShell. It exists as a named seam so tests can
substitute an in-process fake (FakeBandClient, below) implementing the same
surface: whoami, create_chat, join, add_participant, post, run. The orchestrator
depends on this surface only, never on requests, so the orchestration logic is
testable without the network while run_floor.py stays live.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Optional

_CODE = Path(__file__).resolve().parent.parent
if str(_CODE) not in sys.path:
    sys.path.insert(0, str(_CODE))

from shell.band_agent_shell import BandAgentShell  # noqa: E402


class LiveBand(BandAgentShell):
    """The production client: hardened BandAgentShell, unchanged behavior."""


class FakeRoom:
    """One shared in-memory room for the fake clients in a test, mirroring the
    live mention-delivery + lifecycle semantics that the spikes verified:
      - a message is delivered to an agent iff that agent is mentioned;
      - /next re-serves the oldest not-yet-processed mentioned message until it
        is marked processed/failed.
    """

    def __init__(self) -> None:
        self._seq = 0
        self.messages: list[dict] = []  # {id, sender, content, mentions, status_by:{agent}}
        self.participants: set[str] = set()

    def post(self, sender: str, content: str, mentions: list[str]) -> str:
        self._seq += 1
        mid = f"m{self._seq}"
        self.messages.append({
            "id": mid, "sender": sender, "content": content,
            "mentions": list(mentions), "lifecycle": {},
        })
        return mid

    def next_for(self, agent_id: str, handled: set[str]) -> Optional[dict]:
        for m in self.messages:
            if agent_id in m["mentions"] and m["id"] not in handled \
                    and m["lifecycle"].get(agent_id) not in ("processed", "failed"):
                return m
        return None

    def set_lifecycle(self, mid: str, agent_id: str, state: str) -> None:
        for m in self.messages:
            if m["id"] == mid:
                m["lifecycle"][agent_id] = state
                return


class FakeBandClient:
    """Same surface as BandAgentShell, backed by a shared FakeRoom. Used by the
    floor orchestration tests so the full run executes with no network."""

    def __init__(self, room: FakeRoom, agent_id: str, agent_name: str,
                 dedup_namespace: str = "") -> None:
        self._room = room
        self.agent_id = agent_id
        self.name = agent_name
        self.ns = dedup_namespace or agent_name
        self.chat_id: Optional[str] = None
        self._handled: set[str] = set()
        self.posted: list[dict] = []

    def whoami(self) -> str:
        return self.agent_id

    def create_chat(self, title: str) -> str:
        self.chat_id = "fake-room-1"
        self._room.participants.add(self.agent_id)
        return self.chat_id

    def join(self, chat_id: str) -> None:
        self.chat_id = chat_id

    def add_participant(self, agent_id: str, chat_id: Optional[str] = None) -> dict:
        self._room.participants.add(agent_id)
        return {"data": {"status": "inactive"}}

    def context(self, chat_id: Optional[str] = None) -> list:
        return list(self._room.messages)

    def already_posted(self, dedup_key: str) -> bool:
        return any(dedup_key in m["content"] for m in self._room.messages)

    def post(self, content: str, mentions: Optional[list] = None,
             dedup_key: Optional[str] = None) -> Optional[dict]:
        if dedup_key and self.already_posted(dedup_key):
            return None
        text = content
        if dedup_key:
            text = f"{content}\n[dedup_key:{dedup_key}]"
        mid = self._room.post(self.agent_id, text, mentions or [])
        self.posted.append({"id": mid, "content": text, "mentions": mentions or []})
        return {"data": {"id": mid, "success": True}}

    def next_message(self) -> Optional[dict]:
        m = self._room.next_for(self.agent_id, self._handled)
        return dict(m) if m else None

    def mark(self, msg_id: str, state: str, error: str = "") -> None:
        self._room.set_lifecycle(msg_id, self.agent_id, state)
        if state in ("processed", "failed"):
            self._handled.add(msg_id)

    def run(self, handle: Callable[[dict, list], Optional[dict]],
            poll_seconds: float = 0.0, max_loops: Optional[int] = 50,
            idle_breaks: Optional[int] = 2) -> int:
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
                continue
            idle = 0
            mid = msg["id"]
            self.mark(mid, "processing")
            try:
                reply = handle(msg, self.context())
                if reply is not None:
                    self.post(reply.get("content", ""),
                              mentions=reply.get("mentions", []),
                              dedup_key=reply.get("dedup_key"))
                self.mark(mid, "processed")
                handled += 1
            except Exception as e:  # noqa: BLE001
                self.mark(mid, "failed", error=f"{type(e).__name__}: {e}")
        return handled
