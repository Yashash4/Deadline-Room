"""Exactly-once handoff layer (the G2 fold-in).

Dedup keys are the natural key of the unit of work, e.g.
"draft:nis2:inc-8842:round-1". A re-delivered message whose key is
already recorded is acknowledged and DROPPED, never double-counted.

Crash position A (killed before posting): the lifecycle reverts
processing -> delivered; the restarted agent re-runs; the key is not
yet recorded, so the re-run is admitted. Idempotent by re-execution.

Crash position B (killed after posting, before marked processed):
the restarted agent re-posts; the key IS recorded; the duplicate is
dropped. The Band attempt counter distinguishes crash-retry from a
genuinely new unit of work (which gets a new round in its key).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Disposition(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE_DROPPED = "duplicate_dropped"


@dataclass(frozen=True)
class LedgerEntry:
    dedup_key: str
    attempt: int
    ts: str
    disposition: Disposition


class IdempotencyLedger:
    def __init__(self) -> None:
        self._seen: dict[str, LedgerEntry] = {}
        self._log: list[LedgerEntry] = []

    def record(self, dedup_key: str, attempt: int, ts: str) -> LedgerEntry:
        if dedup_key in self._seen:
            entry = LedgerEntry(dedup_key, attempt, ts, Disposition.DUPLICATE_DROPPED)
        else:
            entry = LedgerEntry(dedup_key, attempt, ts, Disposition.ACCEPTED)
            self._seen[dedup_key] = entry
        self._log.append(entry)
        return entry

    def accepted_keys(self) -> set[str]:
        return set(self._seen.keys())

    def duplicates_dropped(self) -> int:
        return sum(1 for e in self._log if e.disposition is Disposition.DUPLICATE_DROPPED)

    def history(self) -> list[LedgerEntry]:
        return list(self._log)
