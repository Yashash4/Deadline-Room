"""The product application: the governance API, the console UI, the Prometheus
metrics surface, and the compliance-officer approval screen, served as one app.

This is the E9.9 deployment front. It does NOT reimplement any service logic and
it does NOT touch the deterministic gate. It WRAPS the E6.7 governance app
(`service.app.create_app`) and decorates it with three additive surfaces a
production deployment needs:

  1. The product UI. The `web/` Incident Commander console (index.html, app.js,
     styles.css) and the approval screen (approve.html, approve.js) are served as
     static files from the running service, so the console is an application a
     CISO office reaches over HTTP rather than a file opened from disk.

  2. A Prometheus `/metrics` surface, formatted in the text exposition format from
     the E1.6 operability/SLO telemetry already folded into the signed portfolio.
     Every number is a read of the sealed corpus (margins, breaches, throughput),
     so the metrics are the same deterministic values the packet renders, never a
     live estimate. A `deadline_room_build_info` gauge and the standard process
     liveness make the scrape useful out of the box.

  3. The approval screen back end, a FRONT END over the REAL two-key release gate
     (`warden.release_gate.TwoKeyReleaseGate`). It collects two distinct human
     keys and asks the UNCHANGED gate whether a branch may release. It NEVER
     decides release itself, never fabricates a key, and never bypasses the gate:
     the gate's `decision` is the single source of truth, and the two-key
     invariant test (`tests/test_two_key_release.py`) still guards it because this
     surface holds one `TwoKeyReleaseGate` and calls its real `sign`/`decision`.

The wrapped governance app keeps its full contract: /healthz, /readyz, /portfolio,
/insights, /sla, /queue, POST /incidents are unchanged. This module only adds
routes and a static mount around it.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from service.app import create_app
from service.corpus import Corpus
from warden.release_gate import REQUIRED_ROLES, TwoKeyReleaseGate
from warden.signing import fingerprint, load_public_key_hex

# The signer fingerprint identifies the running build's signing key in the metrics
# scrape. It is public material (a short hash of the public key), so it is safe to
# publish and stable across runs of the same deployment.
_SIGNER_FINGERPRINT = fingerprint(load_public_key_hex())

WEB_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEB_DIR.parent

# The corpus the service serves. A deployment points DEADLINE_ROOM_DATA_DIR at its
# persistent volume of sealed run logs; the default is the committed web/data so a
# fresh checkout serves the four sealed captures with no configuration.
DATA_DIR = Path(os.environ.get("DEADLINE_ROOM_DATA_DIR", str(WEB_DIR / "data")))


# --- the approval screen: a front end over the REAL two-key release gate -------

class SignoffPost(BaseModel):
    """One human sign-off on one branch, collected by the approval screen.

    `correlation_id` names the branch whose lock is being turned; `role` must be
    one of the two distinct release roles the gate requires; `actor` is the human
    who signed; `ts` is the sign-off instant. The gate rejects an unknown role and
    counts the same role twice as one key, so this surface cannot manufacture a
    release the gate would not admit."""

    correlation_id: str = Field(..., description="Branch correlation id to release.")
    role: str = Field(
        ...,
        description=f"Release role, one of {sorted(REQUIRED_ROLES)}.")
    actor: str = Field(..., description="The human who signed.")
    ts: str = Field(..., description="ISO-8601 sign-off instant.")


def _gate_state(gate: TwoKeyReleaseGate, correlation_id: str) -> dict:
    """The current gate decision for a branch, read straight from the real gate.

    This is a pure read of `TwoKeyReleaseGate.decision`: the released flag, the
    keys present, and the keys still missing all come from the gate, never from
    this surface. The approval screen renders exactly what the gate reports."""
    decision = gate.decision(correlation_id)
    signoffs = gate.signoffs(correlation_id)
    return {
        "correlation_id": correlation_id,
        "released": decision.released,
        "have_roles": sorted(decision.have_roles),
        "missing_roles": sorted(decision.missing_roles),
        "required_roles": sorted(REQUIRED_ROLES),
        "reason": decision.reason,
        "signoffs": [
            {"role": s.role, "actor": s.actor, "ts": s.ts} for s in signoffs
        ],
    }


# --- Prometheus text exposition from the E1.6 telemetry / sealed portfolio -----

def _prometheus_metrics(corpus: Corpus) -> str:
    """Render the Prometheus text exposition from the sealed corpus.

    Every series is a deterministic read of the signed portfolio SLA roll-up and
    queue, the SAME numbers the operability/SLO block (floor/telemetry.py) and the
    fleet panel show. No live timing is invented: the margins and breach counts are
    the sealed clock math. A breached SLO surfaces as
    `deadline_room_breaches_total > 0`, which the alert rule (monitoring/) fires
    on. Returns the text body; the route wraps it with the Prometheus content type.
    """
    lines: list[str] = []

    def metric(name: str, help_text: str, kind: str, value, labels: str = "") -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        label_block = f"{{{labels}}}" if labels else ""
        lines.append(f"{name}{label_block} {value}")

    metric(
        "deadline_room_build_info",
        "Identity of the running service: its signing-key fingerprint (always 1).",
        "gauge", 1, labels=f'signer_fingerprint="{_SIGNER_FINGERPRINT}"')

    # SLA roll-up over the whole sealed fleet (the sla_dict canonical shape).
    sla = corpus.sla()
    metric(
        "deadline_room_filings_total",
        "Total statutory filings that landed across the fleet.",
        "gauge", sla.get("total_filings", 0))
    metric(
        "deadline_room_breaches_total",
        "Total statutory deadline breaches across the fleet (SLO: 0).",
        "gauge", sla.get("total_breaches", 0))
    metric(
        "deadline_room_drafted_total",
        "Total drafter outputs produced across the fleet.",
        "gauge", sla.get("throughput_drafted", 0))
    metric(
        "deadline_room_released_total",
        "Total branches released through the two-key gate across the fleet.",
        "gauge", sla.get("throughput_released", 0))
    metric(
        "deadline_room_suppressed_total",
        "Total branches suppressed below threshold across the fleet.",
        "gauge", sla.get("throughput_suppressed", 0))
    worst = sla.get("worst_margin_hours")
    if worst is not None:
        metric(
            "deadline_room_worst_case_margin_hours",
            "Tightest statutory margin any filing landed inside, in hours.",
            "gauge", worst)
    median = sla.get("median_margin_hours")
    if median is not None:
        metric(
            "deadline_room_median_margin_hours",
            "Median statutory margin across filed clocks, in hours.",
            "gauge", median)
    near = sla.get("near_breach_count")
    if near is not None:
        metric(
            "deadline_room_near_breach_total",
            "Filings that landed inside the near-breach margin window.",
            "gauge", near)
    metric(
        "deadline_room_ever_breached",
        "1 if the fleet ever breached a statutory deadline, else 0 (SLO: 0).",
        "gauge", 1 if sla.get("ever_breached") else 0)

    # Queue depth: how many incidents are waiting versus settled.
    queue = corpus.queue()
    counts = queue.get("counts", {})
    items = queue.get("items", [])
    metric(
        "deadline_room_queue_depth",
        "Number of incidents on the intake board.",
        "gauge", len(items))
    metric(
        "deadline_room_queue_pending",
        "Number of incidents queued and not yet running.",
        "gauge", counts.get("queued", 0))

    return "\n".join(lines) + "\n"


# --- assemble the product application ------------------------------------------

def build_app(data_dir: str | Path = DATA_DIR) -> FastAPI:
    """Build the product application around the E6.7 governance app.

    The governance app is constructed unchanged via `service.app.create_app`; this
    function adds the metrics surface, the approval-screen routes over the real
    two-key gate, and the static UI mount, then returns the same FastAPI object so
    the deployment serves one app. The gate instance lives on `app.state` so its
    sign-offs persist across requests within a process, exactly as the Warden holds
    one gate per run; it is the REAL `TwoKeyReleaseGate`, never a copy of its logic.
    """
    data_path = Path(data_dir)
    app = create_app(data_path)
    corpus = Corpus(data_path)
    # The one real release gate this front end collects keys into. It is the
    # unchanged warden gate; this surface only calls its sign/decision methods.
    app.state.release_gate = TwoKeyReleaseGate()

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> PlainTextResponse:
        """Prometheus scrape surface from the E1.6 telemetry / sealed portfolio."""
        body = _prometheus_metrics(corpus)
        return PlainTextResponse(
            body, media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/api/release/{correlation_id}")
    def release_state(correlation_id: str) -> dict:
        """Read the real gate's current decision for one branch (no mutation)."""
        return _gate_state(app.state.release_gate, correlation_id)

    @app.post("/api/release/signoff")
    def release_signoff(body: SignoffPost) -> dict:
        """Record ONE human sign-off through the REAL two-key gate and return its
        decision. This surface never decides release: it calls the gate's `sign`,
        which raises on an unknown role and counts a repeated role as one key, then
        returns whatever the gate decided. Two distinct keys, and only two distinct
        keys, turn the lock, because the gate, not this route, makes that call."""
        gate: TwoKeyReleaseGate = app.state.release_gate
        try:
            gate.sign(body.correlation_id, body.role, body.actor, body.ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _gate_state(gate, body.correlation_id)

    @app.post("/api/release/reset/{correlation_id}")
    def release_reset(correlation_id: str) -> dict:
        """Clear a branch's lock so a fresh release must collect both keys again,
        delegating to the gate's own `reset` (e.g. an amendment re-release). This
        is the gate's documented behavior, not a bypass."""
        gate: TwoKeyReleaseGate = app.state.release_gate
        gate.reset(correlation_id)
        return _gate_state(gate, correlation_id)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        """Land on the Incident Commander console."""
        return RedirectResponse(url="/ui/index.html")

    @app.get("/approve", include_in_schema=False)
    def approve() -> FileResponse:
        """The compliance-officer approve-and-release screen."""
        return FileResponse(WEB_DIR / "approve.html")

    # Serve the console and its assets as static files. Mounted last so the API and
    # health routes above take precedence; the UI lives under /ui.
    app.mount("/ui", StaticFiles(directory=str(WEB_DIR), html=True), name="ui")

    return app


# The module-level app the container entrypoint (uvicorn web.app_server:app) runs.
app = build_app()
