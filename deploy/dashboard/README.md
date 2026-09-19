# Optional dashboard manifests

Raw manifests for the optional Pahlevan dashboard. It is off by default and
absent from `install.yaml`, so applying this directory is the only way these
objects reach a cluster from the raw manifests:

```bash
kubectl apply -k deploy/base       # the agent and the operator, as usual
kubectl create secret tls pahlevan-dashboard-tls \
  --cert=dashboard.crt --key=dashboard.key -n pahlevan-system
kubectl apply -k deploy/dashboard
```

Helm users set `dashboard.enabled=true` instead; the chart renders the same
shapes.

| File | What it is |
|---|---|
| `serviceaccount.yaml` | The dashboard's own identity, separate from the operator's. |
| `rbac.yaml` | The entire grant: create on the two reviews, read on the three CRDs. |
| `rbac-namespaced.yaml` | Not applied by default - the single-namespace alternative to the cluster-wide read binding. |
| `deployment.yaml` | The server. No privilege, no host access, TLS required. |
| `service.yaml` | `ClusterIP` only. |
| `networkpolicy.yaml` | Default-deny, with the ingress controller's namespace and the kubelet's probes let through. |

Nothing here exposes the dashboard outside the cluster. That is the operator's
deliberate act through their own ingress. The full picture - what it is, the
auth flow, TLS, and how to expose it safely - is in
[docs/dashboard.md](../../docs/dashboard.md).
