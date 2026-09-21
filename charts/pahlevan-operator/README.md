# Pahlevan Helm chart

Installs the two Pahlevan components:

- **agent** - a privileged DaemonSet on every node. This is the eBPF data
  plane: it loads and attaches the programs, learns each container's syscall,
  file, network and exec behaviour, and enforces the learned baseline in the
  kernel.
- **operator** - a leader-elected Deployment. This is the control plane. It
  owns the policy CRDs and holds no host access, no eBPF and no privilege.

An optional read-only **dashboard** ships with the chart and is off by
default. Read `docs/dashboard.md` before turning it on; it needs a TLS pair
and exposing it is your own deliberate act through your own ingress.

## Requirements

- Kubernetes 1.24+ (`policy/v1` PodDisruptionBudget, `admissionregistration.k8s.io/v1`
  ValidatingAdmissionPolicy)
- Linux kernel 5.8+ with BPF; BPF LSM (`lsm=bpf` on the kernel command line)
  for blocking enforcement rather than observation only
- Helm 3.8+

The agent namespace must allow privileged pods. `helm install --create-namespace`
creates the namespace without Pod Security Admission labels, so on a cluster
whose default is `restricted` the agent's pods are rejected with no hint that
a label is the cause. Create it yourself first:

```bash
kubectl create namespace pahlevan-system
kubectl label namespace pahlevan-system pod-security.kubernetes.io/enforce=privileged
```

## Install

```bash
helm install pahlevan charts/pahlevan-operator --namespace pahlevan-system
```

The three CRDs (`PahlevanPolicy`, `ContainerProfile`, `AttackSurface`) live in
`crds/` and are installed with the release. Helm does **not** upgrade files in
`crds/`, so after a release that changes the API, apply them yourself:

```bash
kubectl apply -f https://raw.githubusercontent.com/obsernetics/pahlevan/main/config/crd/
```

## Values

Only the keys below exist. Anything else passed with `--set` is accepted by
Helm and silently ignored, so a typo looks exactly like a setting that did not
take effect.

### Image and release-wide

| Key | Default | What it does |
|---|---|---|
| `nameOverride` / `fullnameOverride` | `""` | Object name prefix. |
| `image.repository` | `ghcr.io/obsernetics/pahlevan` | Image for both components. |
| `image.tag` | `""` | Defaults to the chart `appVersion`. |
| `image.pullPolicy` | `IfNotPresent` | |
| `image.pullSecrets` | `[]` | |
| `crds.install` | `true` | |
| `rbac.create` | `true` | |
| `serviceAccount.create` | `true` | |
| `serviceAccount.agentName` / `.operatorName` | `""` | Default to `<fullname>-agent` / `-operator`. |
| `observability.exports` | `prometheus,otel` | |
| `metrics.port` | `8080` | |
| `health.port` | `8081` | |

### Agent (DaemonSet)

| Key | Default | What it does |
|---|---|---|
| `agent.enabled` | `true` | |
| `agent.learningWindow` | `5m` | How long a container is observed before enforcement. |
| `agent.enforcementDelay` | `30s` | Grace after the window closes. |
| `agent.capabilities` | `[BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]` | All dropped first, then these added back. `BPF`+`PERFMON` is enough on kernel 5.8+; the rest cover older kernels. |
| `agent.resources` | 200m/256Mi, 1/1Gi | BPF maps are charged to this container's memory cgroup on kernel 5.11+, so the limit has to cover them as well as the Go heap. |
| `agent.priorityClassName` | `system-node-critical` | Stops the kubelet evicting the agent ahead of the pods it protects. |
| `agent.terminationGracePeriodSeconds` | `60` | Covers a 30s manager shutdown, the eBPF link detach and the 5s observability flush. |
| `agent.startupProbe.periodSeconds` / `.failureThreshold` | `5` / `30` | The budget for loading and attaching eBPF. Nothing listens on the health port until that finishes; too small a budget is a permanent crash loop on slow nodes. |
| `agent.seccomp.generate` | `true` | Write generated seccomp profiles under the kubelet's seccomp root, where a `localhostProfile` reference can resolve. |
| `agent.seccomp.root` / `.dir` | `/var/lib/kubelet/seccomp` / `.../pahlevan` | |
| `agent.tolerations` | `[{operator: Exists}]` | Tolerates everything, so tainted and control-plane nodes are covered too. |
| `agent.nodeSelector` | `{kubernetes.io/os: linux}` | |
| `agent.podAnnotations` | `{}` | |

### Operator (Deployment)

| Key | Default | What it does |
|---|---|---|
| `operator.enabled` | `true` | |
| `operator.replicaCount` | `2` | One is active; the rest stand by on the lease. |
| `operator.leaderElect` | `true` | |
| `operator.hostUsers` | `false` | Runs in a user namespace (KEP-127). Set `true` on clusters without it. |
| `operator.resources` | 100m/128Mi, 500m/512Mi | The cache covers the whole cluster's pods and workloads, so memory tracks object count. |
| `operator.priorityClassName` | `system-cluster-critical` | Set `""` on a cluster that restricts the built-in system priority classes. |
| `operator.terminationGracePeriodSeconds` | `45` | A SIGKILL before the manager stops also skips the leader-election release. |
| `operator.startupProbe.periodSeconds` / `.failureThreshold` | `2` / `30` | |
| `operator.podDisruptionBudget.enabled` | `true` | Without it a node drain can evict both replicas at once. |
| `operator.podDisruptionBudget.maxUnavailable` | `1` | `maxUnavailable`, not `minAvailable`: at `replicaCount: 1` a `minAvailable: 1` budget permits no disruption and blocks every drain of that node forever. |
| `operator.tolerations` | control-plane `NoSchedule` | |
| `operator.nodeSelector` | `{}` | |
| `operator.podAnnotations` | `{}` | |

### Dashboard (optional, off)

See `deploy/dashboard/README.md` and `docs/dashboard.md`. The keys are
`dashboard.enabled`, `.replicaCount`, `.image.*`, `.serviceAccountName`,
`.rbac.create`, `.service.port`, `.tls.secretName`, `.networkPolicy.*`,
`.audiences`, `.hostUsers`, `.resources`, `.nodeSelector`, `.tolerations` and
`.podAnnotations`.

## Monitoring

`deploy/monitoring/` holds a `ServiceMonitor` pair and a `PrometheusRule` with
the alerts that matter, including the ones that fire when the agent itself is
not running - every enforcement rule is built on series the agent produces, so
a crash-looping agent makes them all silently return no data.

## Uninstall

```bash
helm uninstall pahlevan --namespace pahlevan-system

# CRDs are not removed with the release. Deleting them deletes every
# PahlevanPolicy, ContainerProfile and AttackSurface in the cluster.
kubectl delete crd pahlevanpolicies.policy.pahlevan.io \
                  containerprofiles.policy.pahlevan.io \
                  attacksurfaces.policy.pahlevan.io
```
