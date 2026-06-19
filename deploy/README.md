# Deadline Room: Kubernetes deployment

Container-per-agent topology for the regulated breach-reporting war room. Each Band
agent owns a single WebSocket connection (last connection wins), so every agent runs
in its own container behind its own Deployment.

## Layout

- `k8s/` plain manifests, applied with `kubectl apply -f deploy/k8s/`. These are the
  authoritative declarative spec the smoke test (`tests/test_deploy_smoke.py`)
  parses and probe-checks offline.
- `helm/deadline-room/` a Helm chart that renders the same set with configurable
  image tags, replica counts, the data-volume claim, and the corpus path.

## What runs

| Workload | Image target | Role |
|---|---|---|
| `deadline-room-service` | `service` | the standing governance API + product UI + `/metrics` + the approval screen, fronting the real two-key release gate |
| `deadline-room-warden` | `warden` | the deterministic no-LLM gate process |
| `deadline-room-drafter-{nis2,dora,sec,uk_ico}` | `drafter` | one LLM drafter per regime, each its own Band agent |

The service Deployment carries the liveness and readiness probes the cluster uses:
`/healthz` for liveness (the process is up) and `/readyz` for readiness (the sealed
corpus re-derives, so the service can serve). The Service object exposes port 8000.

## Apply

```
kubectl apply -f deploy/k8s/
# or, with Helm and your own registry / data volume:
helm install deadline-room deploy/helm/deadline-room \
  --set image.repository=registry.example.com/deadline-room \
  --set image.tag=v1
```

Secrets (the Band and model API keys, and the signing-key custody handle) are
provisioned by Terraform in `infra/` and surfaced as a Kubernetes Secret named
`deadline-room-secrets`; the manifests reference it by name and never inline a
credential.
