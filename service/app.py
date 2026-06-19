"""The FastAPI application: read the signed spine, accept and seal new incidents.

The governance service is a TRANSPORT over the sealed/signed corpus. It exposes:

  Read endpoints (everything DERIVED from a sealed run, the Warden is the truth):
    GET /healthz              liveness: the process is up.
    GET /readyz               readiness: the corpus directory is present and the
                              portfolio re-derives, so the service can serve.
    GET /portfolio            the signed portfolio attestation (manifest + signature).
    GET /insights            the cross-incident findings folded from the logs.
    GET /sla                  the fleet SLA / throughput roll-up.
    GET /queue                the intake queue + status board.

  Write endpoint (orchestrate, then seal into the corpus):
    POST /incidents           run a posted incident OFFLINE through the floor, seal
                              and sign it into the corpus, and return its sealed
                              summary. The new run then appears in /queue and is
                              folded into /portfolio, derived from the sealed bytes.

The app holds NO mutable gate state. It stores only the corpus directory path (via
a `Corpus`) and the worker callable; every read re-folds from disk, and the write
path's only durable effect is a new sealed run-log plus sidecar in the corpus. Two
identical reads of an unchanged corpus return identical bytes, and a read after a
seal reflects the new run with no cache to invalidate.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .corpus import Corpus
from .worker import ALLOWED_MODES, IncidentRequest, run_incident_offline


class IncidentPost(BaseModel):
    """The POST /incidents request body: a new incident to run and seal offline."""

    incident_id: str = Field(
        ...,
        description="Lowercase alphanumeric-with-dashes incident id (1-63 chars).")
    mode: str = Field(
        "normal",
        description=f"Offline floor beat, one of {ALLOWED_MODES}.")
    label: str = Field("", description="Optional short human title for the board.")


def create_app(data_dir: str | Path) -> FastAPI:
    """Build the governance API bound to one sealed-artifact data directory.

    The returned app is stateless beyond the directory path: it constructs one
    `Corpus` over `data_dir` and serves every read by re-folding the sealed runs on
    disk, and serves the write path by sealing into the same directory through the
    offline worker. No gate verdict is cached between requests."""
    corpus = Corpus(data_dir)
    app = FastAPI(
        title="Deadline Room governance service",
        description=(
            "A standing governance service over the sealed/signed Deadline Room "
            "corpus. Read endpoints serve the signed portfolio attestation, the "
            "cross-incident insights, the fleet SLA roll-up, and the intake queue, "
            "each derived from a sealed run. The write endpoint runs a posted "
            "incident offline through the Warden floor and seals it into the "
            "corpus. The service holds no mutable gate state."),
        version="1",
    )

    @app.get("/healthz")
    def healthz() -> dict:
        """Liveness: the process is up and serving. Asserts nothing about the
        corpus, so a fresh deployment with an empty corpus is still live."""
        return {"status": "ok", "service": "deadline-room"}

    @app.get("/readyz")
    def readyz() -> dict:
        """Readiness: the corpus directory exists and the portfolio re-derives from
        disk, so the service can answer read requests. Returns 503 (not ready)
        when the directory is missing or the fold raises, never a 500 stack."""
        directory = Path(corpus.data_dir)
        if not directory.is_dir():
            raise HTTPException(
                status_code=503,
                detail=f"corpus directory not found: {directory}")
        try:
            att = corpus.attestation()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=503,
                detail=f"corpus not ready: {exc}") from exc
        return {
            "status": "ready",
            "data_dir": str(directory),
            "run_count": att.run_count,
            "portfolio_root": att.root,
        }

    @app.get("/portfolio")
    def portfolio() -> dict:
        """The signed portfolio attestation over the whole sealed fleet, re-derived
        and re-signed from disk on every call."""
        return corpus.portfolio()

    @app.get("/insights")
    def insights() -> dict:
        """The cross-incident findings folded from the sealed logs."""
        return corpus.insights()

    @app.get("/sla")
    def sla() -> dict:
        """The fleet SLA / throughput roll-up folded from the sealed clocks."""
        return corpus.sla()

    @app.get("/queue")
    def queue() -> dict:
        """The intake queue + status board over the sealed runs and pending set."""
        return corpus.queue()

    @app.post("/incidents", status_code=201)
    def post_incident(body: IncidentPost) -> dict:
        """Run a posted incident OFFLINE through the floor, seal and sign it into
        the corpus, and return its sealed summary plus the refreshed queue.

        A malformed incident id or an unknown mode is rejected with 400 before any
        run. The only durable effect is a new sealed run-log plus sidecar; the
        service holds no gate state and re-reads the corpus for the returned
        queue."""
        request = IncidentRequest(
            incident_id=body.incident_id, mode=body.mode, label=body.label)
        try:
            request.validate()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        sealed = run_incident_offline(request, corpus.data_dir)
        return {
            "sealed": {
                "incident_id": sealed.incident_id,
                "mode": sealed.mode,
                "run_log_name": sealed.run_log_name,
                "sha256": sealed.sha256,
                "chain_head": sealed.chain_head,
                "signature_valid": sealed.signature_valid,
            },
            "queue": corpus.queue(),
        }

    return app
