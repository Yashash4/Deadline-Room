"""Fake in-memory Band: just enough lifecycle semantics to test the Warden
without the real API.

This is an in-process TEST / SIMULATION double, NOT part of the deterministic
no-LLM trust core. The Warden's guarantees (typed transitions, exactly-once,
byte-identical replay, the statutory clocks) live in state_machine.py, ledger.py,
replay.py, chain.py, and clocks.py and hold against the real Band exactly as they
hold here; this file only stands in for Band's message lifecycle so the core is
testable offline. Nothing here gates, counts, or clocks anything.

Mirrors the documented model:

  delivered -> processing -> processed/failed, auto-incrementing attempt
  counter on re-delivery, /messages/next drain on reconnect.

Chaos hooks:
  kill_before_post(agent): crash position A. Message reverts
      processing -> delivered; nothing was posted.
  kill_after_post(agent): crash position B. The draft WAS posted, but the
      message never reached `processed`; on reconnect it is re-delivered
      and the agent will naively re-post (the ledger must catch it).
  kill_after_ack_lost(agent): the asymmetric lost-ack partition. The work
      SUCCEEDED and the post landed, but the processing->processed mark (the
      ack) never came back. /next re-serves the SAME message WITHOUT
      incrementing attempt: a true at-least-once redelivery, identical to the
      first, not a fresh attempt. This stresses the read-then-act dedup path,
      not just the ledger key against a bumped attempt counter. It is distinct
      from position B precisely because the attempt counter does NOT change, so
      a guard that leaned on attempt to tell crash-retry from new work would be
      caught here.

Day-1 spike items 1-3 validate these assumptions against the real API;
this fake encodes our current best understanding so the deterministic
core is fully testable tonight.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
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
    body: dict
    state: Lifecycle = Lifecycle.DELIVERED
    attempt: int = 1


class FakeBand:
    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self._inbox: dict[str, list[FakeMessage]] = {}
        self.room_log: list[dict] = []  # everything posted to the room

    # --- delivery -----------------------------------------------------
    def send(self, to_agent: str, body: dict) -> FakeMessage:
        msg = FakeMessage(next(self._ids), to_agent, body)
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
        every PROCESSING message reverts to DELIVERED with attempt += 1.
        Whether the agent posted before dying (position B) is the agent's
        story; the lifecycle only knows the work was never marked done."""
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
        true at-least-once redelivery rather than a fresh attempt.

        This differs from kill_in_flight on exactly one axis: the attempt
        counter does not move. That is the honest distributed failure the SRE
        review flagged, and it is what proves the read-then-act dedup (and the
        ledger key, which is the attempt-independent natural key of the work)
        catches the redelivery, not a coincidence of a bumped attempt number."""
        reverted = 0
        for msg in self._inbox.get(agent, []):
            if msg.state == Lifecycle.PROCESSING:
                msg.state = Lifecycle.DELIVERED
                reverted += 1
        return reverted
