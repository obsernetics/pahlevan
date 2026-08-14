# Monitoring

Two things ship here: a Prometheus Operator `ServiceMonitor` pair that scrapes
the agent and the operator, and a Grafana dashboard built on those metrics.

## What the dashboard shows

Every panel is backed by a metric that is recorded by running code. The panels
are grouped the way the questions arrive:

- **Is enforcement on?** Containers by phase, and the share that reached
  enforcing. A fleet stuck at zero means learning windows are not elapsing or
  no policy is set to `Blocking`.
- **Is it biting?** In-kernel denials by signal, and the denial rate against
  total events. A rate that spikes right after a transition is the signature of
  a bad baseline, which is what self-healing rolls back.
- **Is it healing?** Rollbacks and self-healing actions. Sustained rollbacks
  mean learning windows are too short for the workload.
- **What did it cost?** Ring-buffer decode errors, agent CPU and memory.

## Cardinality

The dashboard only uses the default (`--metrics-detail=basic`) series. The
per-container series behind `--metrics-detail=high` are deliberately not
graphed: they are keyed by container id crossed with a syscall or a path, so a
dashboard over them would break at fleet scale. Query them ad hoc when
debugging one workload.

## Install

With the Prometheus Operator present:

```bash
kubectl apply -f deploy/monitoring/servicemonitor.yaml
```

Import `deploy/monitoring/grafana-dashboard.json` into Grafana, or mount it via
a sidecar-labelled ConfigMap:

```bash
kubectl create configmap pahlevan-dashboard -n monitoring \
  --from-file=deploy/monitoring/grafana-dashboard.json
kubectl label configmap pahlevan-dashboard -n monitoring grafana_dashboard=1
```

Without the Prometheus Operator, scrape `:8080/metrics` on the agent DaemonSet
and the operator Deployment directly.
