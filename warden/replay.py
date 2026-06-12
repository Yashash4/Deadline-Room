"""Append-only JSONL run log + byte-for-byte deterministic replay.

The Warden writes every admitted transition, rejection, ledger entry,
clock event, and diff result to the log. Replay feeds the saved event
stream back into a FRESH state machine and must reproduce the identical
trace, byte for byte. The replay reads our own saved log, never Band's
24h retention window.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .state_machine import Event, ProtocolStateMachine


def _canon(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class RunLog:
    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._seq = 0

    def append(self, entry_type: str, payload: dict) -> dict:
        entry = {"seq": self._seq, "type": entry_type, "payload": payload}
        self._entries.append(entry)
        self._seq += 1
        return entry

    def entries(self) -> list[dict]:
        return list(self._entries)

    def to_jsonl(self) -> str:
        return "\n".join(_canon(e) for e in self._entries) + "\n"

    def sha256(self) -> str:
        return hashlib.sha256(self.to_jsonl().encode()).hexdigest()

    def save(self, path: str | Path) -> str:
        Path(path).write_text(self.to_jsonl())
        return self.sha256()

    @staticmethod
    def load(path: str | Path) -> "RunLog":
        log = RunLog()
        for line in Path(path).read_text().splitlines():
            if line.strip():
                e = json.loads(line)
                log._entries.append(e)
                log._seq = e["seq"] + 1
        return log


def replay(saved: RunLog) -> RunLog:
    """Feed the saved protocol events through a fresh state machine.

    Only 'protocol_event' entries are re-executed; everything else
    (ledger, clock, diff entries) is re-emitted verbatim, preserving
    interleaving. Output must be byte-identical to the original log.
    """
    fresh_sm = ProtocolStateMachine()
    out = RunLog()
    for entry in saved.entries():
        if entry["type"] == "protocol_event":
            p = entry["payload"]
            result = fresh_sm.apply(
                correlation_id=p["correlation_id"],
                event=Event(p["event"]),
                ts=p["ts"],
                actor=p.get("actor", ""),
                actor_role=p.get("actor_role"),
            )
            out.append("protocol_event", {
                **p,
                "admitted": result.admitted,
                "to_state": result.to_state.value if result.admitted else None,
                "reason": None if result.admitted else result.reason,
            })
        else:
            out.append(entry["type"], entry["payload"])
    return out
