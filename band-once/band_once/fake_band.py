"""Fake in-memory Band: just enough lifecycle semantics to drive the
exactly-once proof and tests without the real API.

This is an in-process TEST / SIMULATION double. It only stands in for Band's
message lifecycle so the exactly-once shell and ledger are exercisable offline.
Nothing here gates or counts anything.

Mirrors the documented model:

  delivered -> processing -> processed/failed, auto-incrementing attempt
  counter on re-delivery, /messages/next drain on reconnect.

Chaos hooks:
  kill_in_flight(agent): crash positions A and B. Every PROCESSING message
      reverts to DELIVERED with attempt += 1. Whether the agent posted before
      dying (position B) is the agent's story; the lifecycle only knows the work
      was never marked done.
  kill_after_ack_lost(agent): the asymmetric lost-ack partition. The work
      SUCCEEDED and the post landed, but the processing->processed ack never came
      back. /next re-serves the SAME message WITHOUT incrementing attempt: a true
      at-least-once redelivery, identical to the first, not a fresh attempt. This
      stresses the read-then-act dedup path, not just the ledger key against a
      bumped attempt counter.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum


class Lifecycle(str, Enum):
    DELIVERED = "delivered"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


@dataclass
class FakeMessage:
    msg_id: int
    to_agent: str
    body: dict = field(default_factory=dict)
    state: Lifecycle = Lifecycle.DELIVERED
    attempt: int = 1


class FakeBand:
    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self._inbox: dict[str, list[FakeMessage]] = {}
        self.room_log: list[dict] = []  # everything posted to the room

    # --- delivery -----------------------------------------------------
    def send(self, to_agent: str, body: dict) -> FakeMessage:
        msg = FakeMessage(next(self._ids), to_agent, dict(body))
        self._inbox.setdefault(to_agent, []).append(msg)
        return msg

    def messages_next(self, agent: str) -> FakeMessage | None:
        """Drain: returns the oldest non-terminal message and flips it to processing."""
        for msg in self._inbox.get(agent, []):
            if msg.state == Lifecycle.DELIVERED:
                msg.state = Lifecycle.PROCESSING
                return msg
        return None

    def mark_processed(self, msg: FakeMessage) -> None:
        msg.state = Lifecycle.PROCESSED

    def mark_failed(self, msg: FakeMessage, reason: str) -> None:
        msg.state = Lifecycle.FAILED
        msg.body["failure_reason"] = reason

    # --- room ---------------------------------------------------------
    def post_to_room(self, author: str, body: dict) -> None:
        self.room_log.append({"author": author, **body})

    # --- chaos --------------------------------------------------------
    def kill_in_flight(self, agent: str) -> int:
        """Crash positions A and B share the same lifecycle consequence:
        every PROCESSING message reverts to DELIVERED with attempt += 1."""
        reverted = 0
        for msg in self._inbox.get(agent, []):
            if msg.state == Lifecycle.PROCESSING:
                msg.state = Lifecycle.DELIVERED
                msg.attempt += 1
                reverted += 1
        return reverted

    def kill_after_ack_lost(self, agent: str) -> int:
        """The asymmetric lost-ack partition. The post landed and the work
        SUCCEEDED, but the processing->processed ack was lost on the way back.
        Every PROCESSING message reverts to DELIVERED with the attempt counter
        UNCHANGED, so /next re-serves the SAME message (identical attempt), a
        true at-least-once redelivery rather than a fresh attempt."""
        reverted = 0
        for msg in self._inbox.get(agent, []):
            if msg.state == Lifecycle.PROCESSING:
                msg.state = Lifecycle.DELIVERED
                reverted += 1
        return reverted
