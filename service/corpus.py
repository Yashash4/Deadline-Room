"""The read layer the governance service serves: one data directory, re-derived.

A `Corpus` is a thin, STATELESS view over a single sealed-artifact directory (the
run-log JSONL files plus their per-run signature sidecars, and the declarative
intake set). It holds no mutable gate state: every accessor re-discovers and
re-folds the sealed runs from disk on each call, so a response can never drift
from the sealed record. The Warden run is the source of truth; this object only
discovers, re-verifies, and folds.

Everything served here is DERIVED from `floor/portfolio.py`, the same pure,
deterministic read layer the web panel and `scripts/attest_portfolio.py` use:

  * `portfolio()` : the signed portfolio attestation (Merkle root over the fleet's
                    chain heads, run count, cross-incident insights, SLA roll-up)
                    plus its detached portfolio signature.
  * `insights()`  : the cross-incident findings folded from the sealed logs.
  * `sla()`       : the fleet SLA / throughput roll-up.
  * `queue()`     : the intake queue + status board over the sealed runs and the
                    declarative pending set.

The directory is the durable store. There is no database, no cache, and no
in-memory gate ledger: re-reading disk is the whole contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from floor.portfolio import (
    attest_portfolio,
    cross_incident_patterns,
    insights_dict,
    load_portfolio,
    portfolio_sla,
    queue_dict,
    queue_view,
    sla_dict,
)
from warden.portfolio_signing import sign_portfolio

# The declarative intake file name inside a data directory. Each record is an
# incident that has ARRIVED but not yet run, so it sits in the board's queued
# lane. Absence of the file means an empty pending set, never an error.
INTAKE_FILE = "intake.json"


class Corpus:
    """A stateless read view over one sealed-artifact data directory.

    The service constructs exactly one `Corpus` bound to its data directory and
    serves every read through it. The object stores ONLY the directory path: it
    holds no run logs, no gate verdicts, and no cached attestation, so two
    successive reads of an unchanged corpus return identical bytes and a read
    after a new seal reflects the new run with no invalidation step. This is the
    "holds no gate state" contract the service is judged on."""

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir)

    # -- discovery -------------------------------------------------------------

    def runs(self) -> list:
        """Re-discover and re-verify every sealed run under the data directory.

        Pure read of disk via `floor.portfolio.load_portfolio`: each `run-*.jsonl`
        with a sibling signature sidecar is read LF-canonically, its sha and chain
        head recomputed, and its per-run signature re-verified. Called fresh on
        every request so the view never goes stale."""
        return load_portfolio(self.data_dir)

    def pending(self) -> list[dict]:
        """The declarative pending intake records (incidents that arrived but have
        not run), read from the data directory's intake file. A missing or
        malformed file yields an empty set rather than an error, so the queue
        still renders when nothing is staged."""
        path = self.data_dir / INTAKE_FILE
        if not path.exists():
            return []
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return []
        records = doc.get("pending", []) if isinstance(doc, dict) else []
        return [r for r in records if isinstance(r, dict)]

    # -- derived, signed roll-ups ---------------------------------------------

    def attestation(self):
        """The portfolio attestation object folded over the verified sealed runs."""
        return attest_portfolio(self.runs())

    def portfolio(self) -> dict:
        """The signed portfolio document the API serves: the canonical manifest,
        its digest, and the detached portfolio signature over the Merkle root, run
        count, insights digest, and SLA digest. Built the same way
        `scripts/attest_portfolio.py` builds the committed sidecar, so the served
        object is byte-for-byte what a verifier re-derives from disk."""
        att = self.attestation()
        signature = sign_portfolio(
            att.root, att.run_count, att.manifest_sha256,
            att.insights_sha256, att.sla_sha256)
        return {
            "manifest": att.manifest,
            "manifest_sha256": att.manifest_sha256,
            "signature": signature,
        }

    def insights(self) -> dict:
        """The canonical cross-incident findings dict folded from the sealed logs."""
        return insights_dict(cross_incident_patterns(self.runs()))

    def sla(self) -> dict:
        """The canonical fleet SLA / throughput roll-up dict folded from the sealed
        clocks and protocol entries."""
        return sla_dict(portfolio_sla(self.runs()))

    def queue(self) -> dict:
        """The canonical intake queue + status board dict over the sealed runs and
        the declarative pending set, sorted by nearest statutory deadline."""
        return queue_dict(queue_view(self.runs(), self.pending()))
