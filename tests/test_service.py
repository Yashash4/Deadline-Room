"""The governance service (E6.7) serves the signed spine and seals offline.

These tests exercise the standing service end to end through a FastAPI test client
(no real network bind): the read endpoints return the attested portfolio, the
intake queue, the SLA roll-up, and the cross-incident insights, each DERIVED from a
sealed run; a posted incident is run OFFLINE through the floor, sealed, signed, and
then appears in the queue and the portfolio; the health and readiness endpoints
pass; and, most importantly, the service holds NO mutable gate state: every
response re-derives from the sealed corpus on disk, so two reads of an unchanged
corpus are identical and a read after a seal reflects the new run with no cache.

The service worker uses the OFFLINE FakeBand path, so these tests need no live Band
room and no API keys. A fresh temporary corpus is seeded by COPYING the committed
sealed captures, so the tests never write into web/data/ and the four byte-frozen
run-log shas are untouched.
"""

from __future__ import annotations

import json
import shutil
import warnings
from pathlib import Path

import pytest

# Starlette 1.x prefers an `httpx2` transport for its TestClient and emits a
# StarletteDeprecationWarning when it falls back to the still-supported `httpx`
# client. `httpx2` is not yet a released package, so the fallback is the only
# available path and the warning is not actionable. Suppress it at the import
# site only, leaving every other warning live.
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        message="Using `httpx` with `starlette.testclient` is deprecated",
    )
    from fastapi.testclient import TestClient

from floor.portfolio import load_portfolio
from service.app import create_app
from service.corpus import Corpus
from service.worker import IncidentRequest, run_incident_offline

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMITTED_DATA = REPO_ROOT / "web" / "data"

# The four byte-frozen sealed run-log shas. Seeding a temp corpus from the
# committed captures must reproduce these exactly, which proves the seed copied the
# real sealed bytes and that the service reads the same frozen record.
FROZEN_SHAS = {
    "run-inc-8842-normal.jsonl": "89dae145",
    "run-inc-8842-inject_contradiction.jsonl": "f1f2223a",
    "run-inc-8842-chaos.jsonl": "303c4371",
    "run-inc-8842-amendment.jsonl": "0ca07fb0",
}


@pytest.fixture()
def corpus_dir(tmp_path: Path) -> Path:
    """A throwaway corpus seeded from the committed sealed captures.

    Copies the four frozen run logs, their signature sidecars, and the declarative
    intake set into a temp directory, so every test runs against a real sealed
    corpus without ever writing into the committed web/data/."""
    out = tmp_path / "data"
    out.mkdir()
    for name in FROZEN_SHAS:
        shutil.copy(COMMITTED_DATA / name, out / name)
        sidecar = name + ".sig.json"
        shutil.copy(COMMITTED_DATA / sidecar, out / sidecar)
    shutil.copy(COMMITTED_DATA / "intake.json", out / "intake.json")
    return out


@pytest.fixture()
def client(corpus_dir: Path) -> TestClient:
    return TestClient(create_app(corpus_dir))


def _short_sha(path: Path) -> str:
    import hashlib

    return hashlib.sha256(
        path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()[:8]


def test_seed_reproduces_the_frozen_shas(corpus_dir: Path) -> None:
    """The seeded corpus carries the exact byte-frozen captures, so the tests read
    the real sealed record and never a stub."""
    for name, expected in FROZEN_SHAS.items():
        assert _short_sha(corpus_dir / name) == expected


def test_health_and_readiness_pass(client: TestClient) -> None:
    """Liveness is always ok; readiness reports a ready corpus with a run count and
    a portfolio root re-derived from disk."""
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    ready = client.get("/readyz")
    assert ready.status_code == 200
    body = ready.json()
    assert body["status"] == "ready"
    assert body["run_count"] == len(FROZEN_SHAS)
    assert len(body["portfolio_root"]) == 64


def test_readiness_503_on_missing_corpus(tmp_path: Path) -> None:
    """Readiness fails cleanly (503, no stack) when the corpus directory is absent,
    so an orchestrator can gate traffic until the corpus is mounted."""
    missing = tmp_path / "not-there"
    app = create_app(missing)
    with TestClient(app, raise_server_exceptions=False) as probe:
        assert probe.get("/readyz").status_code == 503
        # Liveness is independent of the corpus: the process is still up.
        assert probe.get("/healthz").status_code == 200


def test_portfolio_endpoint_serves_signed_attestation(
    client: TestClient, corpus_dir: Path
) -> None:
    """GET /portfolio returns the signed manifest over the sealed fleet, and the
    served signature verifies over the served root, count, insights, and SLA."""
    from warden.portfolio_signing import verify_portfolio

    resp = client.get("/portfolio")
    assert resp.status_code == 200
    doc = resp.json()
    manifest = doc["manifest"]
    signature = doc["signature"]

    assert manifest["run_count"] == len(FROZEN_SHAS)
    assert len(manifest["portfolio_root"]) == 64
    # Every frozen run is named in the attested manifest.
    names = {r["name"] for r in manifest["runs"]}
    assert names == set(FROZEN_SHAS)

    assert verify_portfolio(
        manifest["portfolio_root"], manifest["run_count"],
        signature["insights_sha256"], signature["sla_sha256"], signature)


def test_queue_sla_insights_endpoints(client: TestClient) -> None:
    """The queue, SLA, and insights endpoints serve the canonical read-layer dicts.

    The queue lists the four sealed runs plus the three declarative pending intake
    records, and surfaces the fleet worst-case margin; the SLA carries the fleet
    aggregates; the insights carry the cross-incident groupings."""
    queue = client.get("/queue").json()
    assert queue["counts"]["queued"] == 3  # the three intake.json records
    kinds = {it["kind"] for it in queue["items"]}
    assert kinds == {"run", "pending"}
    run_items = [it for it in queue["items"] if it["kind"] == "run"]
    assert len(run_items) == len(FROZEN_SHAS)
    assert "worst_case_margin_hours" in queue

    sla = client.get("/sla").json()
    assert "total_filings" in sla
    assert "median_margin_hours" in sla
    assert len(sla["per_run"]) == len(FROZEN_SHAS)

    insights = client.get("/insights").json()
    assert "repeat_offenders" in insights
    assert "veto_field_recurrence" in insights


def test_posted_incident_runs_offline_seals_and_queues(
    client: TestClient, corpus_dir: Path
) -> None:
    """POST /incidents runs a new incident OFFLINE, seals + signs it into the
    corpus, and the new run appears in the queue and the portfolio.

    No live Band room is touched: the worker uses the in-process FakeBand path. The
    sealed run carries a valid per-run signature and a new run-log file lands in the
    corpus, raising the portfolio run count by one."""
    before = client.get("/portfolio").json()["manifest"]["run_count"]

    resp = client.post(
        "/incidents",
        json={"incident_id": "inc-9100", "mode": "normal",
              "label": "posted by the service"})
    assert resp.status_code == 201
    body = resp.json()
    sealed = body["sealed"]
    assert sealed["incident_id"] == "inc-9100"
    assert sealed["signature_valid"] is True
    assert len(sealed["sha256"]) == 64
    assert sealed["run_log_name"].startswith("run-inc-9100-normal-")

    # The sealed file is a real, signature-verifying run in the corpus.
    sealed_path = corpus_dir / sealed["run_log_name"]
    assert sealed_path.exists()
    discovered = {r.name: r for r in load_portfolio(corpus_dir)}
    assert sealed["run_log_name"] in discovered
    assert discovered[sealed["run_log_name"]].signature_valid is True

    # The new run is in the returned queue and lifts the portfolio count by one.
    queue_keys = {it["key"] for it in body["queue"]["items"]}
    assert sealed["run_log_name"] in queue_keys
    after = client.get("/portfolio").json()["manifest"]["run_count"]
    assert after == before + 1


def test_posted_incident_does_not_touch_frozen_captures(
    client: TestClient, corpus_dir: Path
) -> None:
    """Sealing a posted incident never rewrites a frozen capture: the four byte-
    frozen shas are unchanged after the write path runs."""
    client.post("/incidents", json={"incident_id": "inc-9101", "mode": "chaos"})
    for name, expected in FROZEN_SHAS.items():
        assert _short_sha(corpus_dir / name) == expected


def test_bad_incident_request_is_rejected(client: TestClient) -> None:
    """A malformed incident id or an unknown mode is rejected with 400 before any
    run, so the service never seals an ambiguous artifact."""
    assert client.post(
        "/incidents", json={"incident_id": "Bad ID!", "mode": "normal"}
    ).status_code == 400
    assert client.post(
        "/incidents", json={"incident_id": "inc-9102", "mode": "nonsense"}
    ).status_code == 400


def test_service_holds_no_gate_state(corpus_dir: Path) -> None:
    """The service holds NO mutable Warden / gate state between requests.

    Every response is derived from the sealed corpus on disk, so:
      * two reads of an unchanged corpus return byte-identical bytes (no drift, no
        accumulated counter);
      * a brand-new Corpus over the same directory yields the same portfolio root
        as the running app (no hidden in-memory state distinguishes them);
      * after a seal, a fresh Corpus over the directory reflects the new run, so the
        durable corpus, not the service, is the source of truth.
    """
    app = create_app(corpus_dir)
    with TestClient(app) as probe:
        first = probe.get("/queue").content
        second = probe.get("/queue").content
        assert first == second  # no mutable state accrued between reads

        running_root = probe.get("/portfolio").json()["manifest"]["portfolio_root"]
        # A fresh, independent Corpus over the same directory re-derives the same
        # root: the app holds nothing the directory does not.
        assert Corpus(corpus_dir).attestation().root == running_root

        # Seal a new run THROUGH THE WORKER (bypassing the app entirely), then the
        # running app reflects it on the next read, proving the app reads disk every
        # time rather than serving a cached fleet.
        run_incident_offline(
            IncidentRequest(incident_id="inc-9200", mode="normal"), corpus_dir)
        refreshed = probe.get("/portfolio").json()["manifest"]
        assert refreshed["run_count"] == len(FROZEN_SHAS) + 1
        # And a fresh Corpus agrees with the running app: one source of truth.
        assert Corpus(corpus_dir).attestation().root == refreshed["portfolio_root"]


def test_corpus_pending_tolerates_missing_intake(tmp_path: Path) -> None:
    """A corpus with no intake file yields an empty pending set, not an error, so
    the queue still renders on a fresh deployment."""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert Corpus(empty).pending() == []
    # And a malformed intake file degrades to empty rather than raising.
    (empty / "intake.json").write_text("{ not json", encoding="utf-8")
    assert Corpus(empty).pending() == []


def test_cli_replay_verifies_a_frozen_capture(capsys) -> None:
    """`deadline-room replay <log>` replays a frozen capture byte-for-byte and
    reports VALID over its committed signature, exiting 0."""
    from service.cli import main

    log = COMMITTED_DATA / "run-inc-8842-normal.jsonl"
    rc = main(["replay", str(log)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Byte-identical  : YES" in out
    assert "Signature       : VALID" in out


def test_cli_demo_seals_into_a_temp_corpus(tmp_path: Path, capsys) -> None:
    """`deadline-room demo --data-dir DIR` seals one incident offline and prints the
    queue; the sealed run lands in the given corpus."""
    from service.cli import main

    out_dir = tmp_path / "demo-corpus"
    rc = main(["demo", "--mode", "normal", "--incident-id", "inc-demo",
               "--data-dir", str(out_dir)])
    assert rc == 0
    sealed = list(out_dir.glob("run-inc-demo-normal-*.jsonl"))
    assert len(sealed) == 1
    assert sealed[0].with_suffix(sealed[0].suffix + ".sig.json").exists()
    assert "DEADLINE ROOM DEMO" in capsys.readouterr().out


def test_signature_sidecar_is_valid_json(corpus_dir: Path) -> None:
    """A sealed incident's sidecar is well-formed JSON carrying a detached ed25519
    signature record, so a downstream verifier reads it like any committed sidecar."""
    sealed = run_incident_offline(
        IncidentRequest(incident_id="inc-9300", mode="amendment"), corpus_dir)
    sidecar = corpus_dir / (sealed.run_log_name + ".sig.json")
    record = json.loads(sidecar.read_text(encoding="utf-8"))
    assert record["algorithm"] == "ed25519"
    assert record["detached"] is True
    assert len(record["signature"]) == 128
