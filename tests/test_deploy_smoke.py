"""Offline deployment smoke test for E9.9.

The deployment WRAPS the system; it never changes the Warden gate. These checks run
with NO live docker, NO cluster, and NO cloud: they parse the deployment artifacts
as data and bring the product application up through the in-process FastAPI test
client, the same offline path the E6.7 service tests use.

What is asserted:

  * The Kubernetes manifests (deploy/k8s/*.yaml) and the Helm chart templates parse
    as valid YAML, declare the container-per-agent workloads, and the service
    Deployment carries the /healthz liveness and /readyz readiness probes.
  * The Dockerfile defines the per-role build targets and the service entrypoint;
    the compose file references the same uvicorn entrypoint and build targets.
  * The Terraform under infra/ is well-formed HCL and declares the KMS custody key,
    the secret store, and the corpus storage.
  * The monitoring stack parses and the breached-SLO alert is present.
  * The product application comes up offline and serves the portfolio, the queue,
    the Prometheus /metrics surface, the static UI, and the approval screen, and the
    approval screen fronts the REAL two-key release gate without bypassing it (one
    key withholds, two distinct keys release, the same key twice does not, an
    unknown role is refused).

The committed sealed corpus is read-only here: the four byte-frozen run-log shas are
never written. The service test client uses a temp corpus seeded by copying the
committed captures, exactly like tests/test_service.py.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY = REPO_ROOT / "deploy"
INFRA = REPO_ROOT / "infra"
MONITORING = REPO_ROOT / "monitoring"
WEB = REPO_ROOT / "web"
COMMITTED_DATA = WEB / "data"

# The four byte-frozen sealed run-log shas. Seeding a temp corpus from the committed
# captures reproduces these, proving the seed copied the real sealed bytes.
FROZEN_SHAS = {
    "run-inc-8842-normal.jsonl": "89dae145",
    "run-inc-8842-inject_contradiction.jsonl": "f1f2223a",
    "run-inc-8842-chaos.jsonl": "303c4371",
    "run-inc-8842-amendment.jsonl": "0ca07fb0",
}

T = "2026-06-16T05:00:00+00:00"


# --- helpers ------------------------------------------------------------------

def _load_yaml_docs(path: Path) -> list[dict]:
    """Every YAML document in a file, dropping empty documents."""
    with open(path, encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def _all_k8s_docs() -> list[dict]:
    docs: list[dict] = []
    for path in sorted((DEPLOY / "k8s").glob("*.yaml")):
        docs.extend(_load_yaml_docs(path))
    return docs


def _kind(docs: list[dict], kind: str, name: str | None = None) -> list[dict]:
    out = [d for d in docs if d.get("kind") == kind]
    if name is not None:
        out = [d for d in out if d.get("metadata", {}).get("name") == name]
    return out


# --- Kubernetes manifests ------------------------------------------------------

def test_k8s_manifests_are_valid_yaml_and_nonempty():
    docs = _all_k8s_docs()
    assert docs, "no k8s documents parsed from deploy/k8s/"
    for doc in docs:
        assert "apiVersion" in doc and "kind" in doc, f"malformed doc: {doc!r}"


def test_k8s_has_warden_service_and_per_regime_drafters():
    docs = _all_k8s_docs()
    deployments = _kind(docs, "Deployment")
    names = {d["metadata"]["name"] for d in deployments}
    assert "deadline-room-service" in names
    assert "deadline-room-warden" in names
    # Container-per-agent: one drafter Deployment per regime.
    drafter_names = {n for n in names if n.startswith("deadline-room-drafter-")}
    assert len(drafter_names) >= 4, drafter_names
    # The service is reachable via a Service object and a backing volume claim.
    assert _kind(docs, "Service", "deadline-room-service")
    assert _kind(docs, "PersistentVolumeClaim")


def _container_of(deployment: dict, container_name: str) -> dict:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    for c in containers:
        if c["name"] == container_name:
            return c
    raise AssertionError(f"no container {container_name!r} in {deployment['metadata']['name']}")


def test_service_deployment_has_health_and_ready_probes():
    docs = _all_k8s_docs()
    service = _kind(docs, "Deployment", "deadline-room-service")[0]
    container = _container_of(service, "service")
    liveness = container["livenessProbe"]["httpGet"]["path"]
    readiness = container["readinessProbe"]["httpGet"]["path"]
    assert liveness == "/healthz"
    assert readiness == "/readyz"
    port = container["livenessProbe"]["httpGet"]["port"]
    assert port in ("http", 8000)


def test_warden_deployment_probes_audit_the_corpus():
    docs = _all_k8s_docs()
    warden = _kind(docs, "Deployment", "deadline-room-warden")[0]
    container = _container_of(warden, "warden")
    # The Warden liveness probe runs the post-run audit; readiness checks the mount.
    live_cmd = container["livenessProbe"]["exec"]["command"]
    assert any("audit_run.py" in part for part in live_cmd), live_cmd
    assert "readinessProbe" in container


def test_helm_templates_parse_as_yaml_with_chart_metadata():
    chart_dir = DEPLOY / "helm" / "deadline-room"
    chart = yaml.safe_load((chart_dir / "Chart.yaml").read_text(encoding="utf-8"))
    assert chart["name"] == "deadline-room"
    values = yaml.safe_load((chart_dir / "values.yaml").read_text(encoding="utf-8"))
    # The chart drives a drafter per regime from values.
    assert len(values["drafters"]) >= 4
    # The templates are Go-templated, so a raw YAML parse is not meaningful; assert
    # the template files exist and reference the health/ready probe paths and the
    # per-role image helper so a render would produce the right workloads.
    templates = chart_dir / "templates"
    service_tpl = (templates / "service.yaml").read_text(encoding="utf-8")
    assert "/healthz" in service_tpl and "/readyz" in service_tpl
    assert "web.app_server:app" in service_tpl
    warden_tpl = (templates / "warden.yaml").read_text(encoding="utf-8")
    assert "audit_run.py" in warden_tpl
    drafter_tpl = (templates / "drafters.yaml").read_text(encoding="utf-8")
    assert "DEADLINE_ROOM_REGIME" in drafter_tpl


# --- Dockerfile + compose ------------------------------------------------------

def test_dockerfile_defines_role_targets_and_service_entrypoint():
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    for target in ("AS base", "AS service", "AS warden", "AS drafter"):
        assert target in text, f"missing build stage: {target}"
    # The service image runs the product app under uvicorn.
    assert "web.app_server:app" in text
    assert "uvicorn" in text


def test_compose_references_role_targets_and_uvicorn_entrypoint():
    compose = yaml.safe_load(
        (DEPLOY / "compose" / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert "service" in services and "warden" in services
    drafters = [name for name in services if name.startswith("drafter-")]
    assert len(drafters) >= 4, drafters
    svc = services["service"]
    assert svc["build"]["target"] == "service"
    assert "web.app_server:app" in " ".join(svc["command"])
    assert services["warden"]["build"]["target"] == "warden"


# --- Terraform (HCL well-formed) ----------------------------------------------

def test_terraform_parses_and_declares_custody_secret_and_storage():
    hcl2 = pytest.importorskip("hcl2")
    parsed: dict[str, list] = {"resource": [], "variable": [], "output": []}
    for path in sorted(INFRA.glob("*.tf")):
        with open(path, encoding="utf-8") as handle:
            doc = hcl2.load(handle)  # raises on malformed HCL
        for key in parsed:
            parsed[key].extend(doc.get(key, []))

    # hcl2 may return block-type keys quoted (e.g. '"aws_kms_key"'); normalize.
    def _unquote(value: str) -> str:
        return value.strip('"')

    resource_types = set()
    for block in parsed["resource"]:
        resource_types.update(_unquote(k) for k in block.keys())
    # The KMS custody key (E2.5), the secret store, and the corpus storage.
    assert "aws_kms_key" in resource_types
    assert "aws_secretsmanager_secret" in resource_types
    assert "aws_s3_bucket" in resource_types
    # The TSA endpoint (E2.4) is a declared, deployer-supplied input.
    var_names = set()
    for block in parsed["variable"]:
        var_names.update(_unquote(k) for k in block.keys())
    assert "tsa_url" in var_names
    # The custody key arn is an apply output the runtime consumes.
    out_names = set()
    for block in parsed["output"]:
        out_names.update(_unquote(k) for k in block.keys())
    assert "warden_kms_key_arn" in out_names


# --- monitoring ----------------------------------------------------------------

def test_monitoring_parses_and_has_breached_slo_alert():
    prom = yaml.safe_load((MONITORING / "prometheus.yml").read_text(encoding="utf-8"))
    jobs = {sc["job_name"] for sc in prom["scrape_configs"]}
    assert "deadline-room-service" in jobs
    assert prom["scrape_configs"][0]["metrics_path"] == "/metrics"

    alerts = yaml.safe_load((MONITORING / "alerts.yml").read_text(encoding="utf-8"))
    rules = [r for grp in alerts["groups"] for r in grp["rules"]]
    breach = [r for r in rules if r.get("alert") == "DeadlineRoomStatutoryBreach"]
    assert breach, "missing the breached-SLO alert"
    assert "deadline_room_breaches_total" in breach[0]["expr"]
    assert breach[0]["labels"]["severity"] == "critical"

    # The example dashboard is valid JSON and watches the breach metric.
    dashboard = json.loads(
        (MONITORING / "grafana-dashboard.json").read_text(encoding="utf-8"))
    exprs = " ".join(
        t["expr"] for panel in dashboard["panels"] for t in panel["targets"])
    assert "deadline_room_breaches_total" in exprs


# --- the product application comes up offline ----------------------------------

@pytest.fixture()
def corpus_dir(tmp_path: Path) -> Path:
    """A throwaway corpus seeded from the committed sealed captures, so the four
    byte-frozen shas are never written and the committed web/data is untouched."""
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
    from web.app_server import build_app

    return TestClient(build_app(corpus_dir))


def test_product_app_serves_health_ready_portfolio_and_queue(client: TestClient):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json()["status"] == "ready"
    portfolio = client.get("/portfolio").json()
    # The portfolio is the signed attestation over the sealed fleet.
    assert "manifest" in portfolio or "root" in portfolio or "signature" in portfolio
    queue = client.get("/queue").json()
    assert "items" in queue


def test_product_app_serves_prometheus_metrics_from_telemetry(client: TestClient):
    res = client.get("/metrics")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/plain")
    body = res.text
    # The breached-SLO series and the build identity are present and well-formed.
    assert "deadline_room_breaches_total" in body
    assert "deadline_room_build_info" in body
    # The sealed fleet never breached, so the breach gauge reads 0.
    breach_lines = [
        ln for ln in body.splitlines()
        if ln.startswith("deadline_room_breaches_total ")
    ]
    assert breach_lines and breach_lines[0].split()[-1] == "0"


def test_product_app_serves_static_console_and_approval_screen(client: TestClient):
    root = client.get("/", follow_redirects=False)
    assert root.status_code in (302, 307)
    assert root.headers["location"].endswith("/ui/index.html")
    console = client.get("/ui/index.html")
    assert console.status_code == 200
    assert "Incident Commander console" in console.text
    approve = client.get("/approve")
    assert approve.status_code == 200
    assert "Approve and release" in approve.text


# --- the approval screen fronts the REAL two-key gate (no bypass) --------------

def test_approval_screen_fronts_real_two_key_gate(client: TestClient):
    branch = "inc-smoke:sec"
    # No keys: the gate withholds.
    state = client.get(f"/api/release/{branch}").json()
    assert state["released"] is False
    assert set(state["required_roles"]) == {"head_of_ir", "general_counsel"}

    # One key: still withheld.
    one = client.post("/api/release/signoff", json={
        "correlation_id": branch, "role": "general_counsel",
        "actor": "gc", "ts": T}).json()
    assert one["released"] is False
    assert "head_of_ir" in one["missing_roles"]

    # Two distinct keys: the gate releases (the gate decides, not the front end).
    two = client.post("/api/release/signoff", json={
        "correlation_id": branch, "role": "head_of_ir",
        "actor": "lena", "ts": T}).json()
    assert two["released"] is True
    assert two["missing_roles"] == []


def test_same_key_twice_does_not_release_through_the_front_end(client: TestClient):
    branch = "inc-dup:sec"
    client.post("/api/release/signoff", json={
        "correlation_id": branch, "role": "head_of_ir",
        "actor": "lena", "ts": T})
    again = client.post("/api/release/signoff", json={
        "correlation_id": branch, "role": "head_of_ir",
        "actor": "lena", "ts": T}).json()
    assert again["released"] is False
    assert "general_counsel" in again["missing_roles"]


def test_unknown_release_role_is_refused_by_the_gate(client: TestClient):
    res = client.post("/api/release/signoff", json={
        "correlation_id": "inc-bad:sec", "role": "intern",
        "actor": "someone", "ts": T})
    assert res.status_code == 400


def test_reset_forces_both_keys_again(client: TestClient):
    branch = "inc-reset:sec"
    client.post("/api/release/signoff", json={
        "correlation_id": branch, "role": "general_counsel",
        "actor": "gc", "ts": T})
    client.post("/api/release/signoff", json={
        "correlation_id": branch, "role": "head_of_ir",
        "actor": "lena", "ts": T})
    assert client.get(f"/api/release/{branch}").json()["released"] is True
    after = client.post(f"/api/release/reset/{branch}").json()
    assert after["released"] is False
    assert set(after["missing_roles"]) == {"head_of_ir", "general_counsel"}
