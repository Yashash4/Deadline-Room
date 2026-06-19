# Deadline Room: monitoring

The standing service exposes the E1.6 operability/SLO telemetry as Prometheus text
at `/metrics`. Every series is a deterministic read of the sealed corpus, so the
monitoring stack reflects the signed record rather than a live estimate.

## Files

- `prometheus.yml` scrape config (the service `/metrics` endpoint, 30s interval).
- `alerts.yml` alerting rules, led by `DeadlineRoomStatutoryBreach`, which fires the
  moment `deadline_room_breaches_total > 0` (the headline SLO: no statutory deadline
  is ever breached). Also a near-breach warning, a thin-margin warning, and a
  service-down alert.
- `grafana-dashboard.json` an example dashboard: breaches, worst-case and median
  margin, ever-breached, throughput, and queue depth.

## Metrics exposed at /metrics

| Series | Meaning |
|---|---|
| `deadline_room_build_info` | identity gauge labelled with the signing-key fingerprint |
| `deadline_room_filings_total` | total filings landed across the fleet |
| `deadline_room_breaches_total` | total statutory breaches (SLO: 0) |
| `deadline_room_drafted_total` | total drafter outputs |
| `deadline_room_released_total` | total branches released through the two-key gate |
| `deadline_room_suppressed_total` | total branches suppressed below threshold |
| `deadline_room_worst_case_margin_hours` | tightest margin any filing landed inside |
| `deadline_room_median_margin_hours` | median statutory margin |
| `deadline_room_near_breach_total` | filings inside the near-breach window |
| `deadline_room_ever_breached` | 1 if the fleet ever breached, else 0 |
| `deadline_room_queue_depth` / `deadline_room_queue_pending` | intake board depth |

## Run locally

```
prometheus --config.file=monitoring/prometheus.yml
```

The scrape target is the service from `deploy/compose/docker-compose.yml`
(`service:8000`); point it at your cluster Service for a Kubernetes deployment.
