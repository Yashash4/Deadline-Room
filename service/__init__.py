"""Persistent governance service for the standing Deadline Room ops center (E6.7).

A long-running service that stays up across incidents, exposes an HTTP API,
persists the corpus, and serves the portfolio attestation, the intake queue, and
the SLA roll-up on demand. It is a TRANSPORT and ORCHESTRATOR over the sealed and
signed spine, never a second source of truth: every served object is DERIVED from
a sealed run, and the service mutates nothing in the Warden path.

  * Persistence is the sealed-artifact corpus itself: the run-log JSONL files plus
    their detached per-run signature sidecars under a data directory are the
    durable store. The service holds NO mutable gate state that could drift from
    the sealed record. It reads the corpus on every request (the Warden run is the
    source of truth) and never caches a gate verdict.
  * The read path serves floor/portfolio.py: the signed portfolio attestation, the
    cross-incident insights, the fleet SLA roll-up, and the intake queue board.
  * The write path accepts a new incident and runs the floor in an OFFLINE worker
    (the same in-process FakeBand harness web/capture_scenarios.py uses, so it
    needs no live Band room), then seals and signs the result into the corpus as a
    new run-log plus sidecar. The freshly sealed run then appears in the queue and
    is folded into the portfolio, derived from the sealed bytes like every other.

Public entry points:
  * `service.corpus.Corpus`     : the read layer over one data directory.
  * `service.worker.run_incident_offline` : the offline seal worker.
  * `service.app.create_app`    : the FastAPI application factory.
  * `service.cli.main`          : the `deadline-room` command line.
"""

from __future__ import annotations

from .corpus import Corpus
from .worker import IncidentRequest, SealedIncident, run_incident_offline

__all__ = [
    "Corpus",
    "IncidentRequest",
    "SealedIncident",
    "run_incident_offline",
]
