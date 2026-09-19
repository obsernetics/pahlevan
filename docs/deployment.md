# Deployment Guide

This guide covers running Pahlevan in production: what actually gets deployed,
how it is sized and configured, how enforcement is rolled out without taking a
workload down, and how the events reach the people who need them.

Everything below is a flag, a chart value or a manifest that exists in this
repository. Where a capability has no configuration surface yet, this page says
so rather than inventing one.

For a first install in a scratch cluster, start with the
[quick start](quick-start.md) instead.

## Before you install

Two things gate whether the agent can do its job, and neither is visible from
inside a pod that has not started yet.

**Kernel version.** The floor to run at all is Linux 5.8, set by the ring buffer
the syscall monitor needs - and the syscall monitor is the only program whose
load failure stops the agent. Above that floor the kernel version decides how
much of Pahlevan works rather than whether it starts:

| Kernel | What is available |
|---|---|
| 5.8 | Syscall, network, capability and shell monitors |
| 5.10 | Adds the file monitor (`bpf_d_path`) |
| 5.11 | Adds exec and credential monitors. The first kernel on which every detector `pahlevan coverage` lists is present |
| 5.15 | Adds ad-hoc kernel probes (`bpf_get_attach_cookie`) |

A program below its floor costs its own observations and leaves the rest of the
agent running, with a log line naming the helper it could not use. That is a
survivable state to be in deliberately and a bad one to be in by accident, which
is why it is worth checking the fleet before the install rather than reading it
out of agent logs afterwards.

All eight objects are CO-RE, so each node must also expose kernel BTF at
`/sys/kernel/btf/vmlinux`, and cgroup v2 is required for attribution.

```bash
kubectl get nodes -o custom-columns=\
NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion,OS:.status.nodeInfo.operatingSystem
```

**The BPF LSM.** In-kernel enforcement needs `CONFIG_BPF_LSM=y` and `bpf` in the
kernel's active LSM list, which most distributions do not set by default.
Without it the agent still loads, still learns and still reports, but it cannot
refuse anything: enforcement degrades to monitoring rather than failing. That is a survivable state to be in by accident for a week
and a bad one to discover during an incident, so check it deliberately. See
[`lsm-support.md`](lsm-support.md) for how each distribution enables it and
[`system-requirements.md`](system-requirements.md) for the full matrix.

After the agent is running, `pahlevan debug` reports what it found on each
node, including an inferred BPF LSM state per node:

```bash
pahlevan debug
pahlevan debug -o json --file pahlevan-debug.json   # attach this to an issue
```

The bundle covers component pods, node kernels, CRD availability, recent
Kubernetes Events and the `pahlevan_*` metric highlights. It never reads
Secrets, ServiceAccount tokens or container environment variables, so it is
safe to hand to somebody outside your organisation.

## What gets deployed

A standard install creates:

| Object | Purpose |
|---|---|
| `pahlevan-agent` DaemonSet | The eBPF data plane. One pod per Linux node, `system-node-critical`, tolerating everything so it lands on tainted nodes too. |
| `pahlevan-operator` Deployment | The control plane. Leader-elected, two replicas by default, no host access. |
| Three CRDs | `PahlevanPolicy`, `ContainerProfile`, `AttackSurface`. |
| RBAC | A ClusterRole and binding per component, plus a namespaced Role for leader election. |
| Two Services | Fronting the `:8080` metrics port of each component. |

The agent is **not** `privileged: true`, but it is privileged in every way that
matters and the DaemonSet does not claim otherwise. It adds `CAP_BPF`,
`CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE` and `CAP_NET_ADMIN`, drops
everything else, runs with a read-only root filesystem, and runs with
`hostPID: true` because kernel events carry host PIDs that cannot be resolved
from inside a PID namespace. `CAP_BPF` and `CAP_PERFMON` were split out of
`CAP_SYS_ADMIN` in Linux 5.8, the same release as the agent's floor;
`CAP_SYS_ADMIN` is requested alongside them for the kernels and container
runtimes where the finer-grained pair is not enough on its own. If your
environment forbids `CAP_SYS_ADMIN`, trim `agent.capabilities` and expect
programs that need it to fail to load - the agent will say which.

`pahlevan-system` is therefore labelled
`pod-security.kubernetes.io/enforce: privileged`. The workloads Pahlevan
protects live in their own namespaces and keep whatever Pod Security level they
already run at.

One thing is created at runtime rather than installed: the operator creates the
CEL `ValidatingAdmissionPolicy` `pahlevan-pod-hardening` and its binding when it
starts. There is no admission webhook and therefore no certificate to rotate and
no webhook to be unavailable. On a cluster that does not serve
`admissionregistration.k8s.io/v1` the operator starts without it.

`pahlevan status` reports whether each of these is present.

## Installing

### Helm

The chart is `pahlevan-operator`, and it installs both components despite the
name.

```bash
helm repo add pahlevan https://obsernetics.github.io/pahlevan/charts
helm repo update

helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system --create-namespace \
  --values values-production.yaml
```

Pin the image for anything you care about. The chart defaults `image.tag` to its
own `appVersion`, which moves when you upgrade the chart:

```yaml
image:
  repository: ghcr.io/obsernetics/pahlevan
  tag: v3.3.3
  pullPolicy: IfNotPresent
```

See [`packages.md`](packages.md) for pinning by digest instead, which is what an
air-gapped or regulated environment usually wants.

### Single manifest

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml
```

`install.yaml` is generated from the Kustomize bases in `deploy/`, and CI fails
if the two drift. It has no values: if you need to change anything, use the
chart, or use `deploy/base` as a Kustomize base and patch it.

## Configuration

These are the chart's values. Anything not listed here is not a value, and the
sections below say what to do in that case.

### The agent

```yaml
agent:
  enabled: true
  learningWindow: 5m        # --learning-window
  enforcementDelay: 30s     # --enforcement-delay
  capabilities: [BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits:   {cpu: 500m, memory: 512Mi}
  priorityClassName: system-node-critical
  tolerations: [{operator: Exists}]
  nodeSelector: {kubernetes.io/os: linux}
  podAnnotations: {}
```

`learningWindow` is the agent-wide default. A `PahlevanPolicy` overrides it per
workload with `learningConfig.duration`, and that is the knob you should reach
for: five minutes is right for a stateless web tier and badly wrong for a
workload whose interesting code paths run at month end.

The agent's resources are a Helm value set at install or upgrade time, not
something patched into a ConfigMap afterward. Actual usage tracks event volume,
which is highest during a learning window and drops once enforcement is on and
in-kernel deduplication is suppressing repeats.

Keep `priorityClassName: system-node-critical` and the blanket toleration unless
you have a specific reason not to. A DaemonSet that is evicted under memory
pressure, or that skips tainted nodes, produces nodes with no data plane on
them - and nothing in the cluster will tell you those nodes are unprotected
except the absence of events you were not expecting anyway.

### The operator

```yaml
operator:
  enabled: true
  replicaCount: 2
  leaderElect: true
  hostUsers: false          # user namespaces, KEP-127
  resources:
    requests: {cpu: 50m, memory: 64Mi}
    limits:   {cpu: 200m, memory: 256Mi}
  tolerations:
    - key: node-role.kubernetes.io/control-plane
      operator: Exists
      effect: NoSchedule
```

Leader election means extra replicas are standby, not extra throughput: exactly
one operator reconciles at a time. Two replicas buys a faster recovery from a
node failure, not more capacity.

`hostUsers: false` maps the operator's in-container root to an unprivileged host
UID. It needs a Kubernetes version serving user namespaces; set it `true` on
older clusters, where the operator still has no host mounts and no privilege
worth taking.

### Other values

```yaml
crds:
  install: true             # set false if CRDs are managed separately
rbac:
  create: true
serviceAccount:
  create: true
  agentName: ""             # defaults to <fullname>-agent
  operatorName: ""
observability:
  exports: "prometheus,otel"  # prometheus, otel, datadog
metrics:
  port: 8080
health:
  port: 8081
```

The chart does not template arbitrary agent flags. Several agent capabilities
below - the gRPC stream, the file sink, the notifiers, shell capture - therefore
need a patch to the DaemonSet rather than a value. The honest way to do that is
a Kustomize overlay over `deploy/base`, or a post-render patch on the Helm
release; both keep the change in version control instead of in somebody's shell
history.

## Rolling enforcement out

The failure mode that matters is not a missed detection. It is a policy built
from a baseline that was incomplete, denying something the workload needed, at
3am. The sequence below exists to make that discoverable before it is load
bearing.

**1. Learn in `Monitoring`.** Nothing is refused. The allow-sets fill.

```yaml
spec:
  learningConfig:
    duration: 30m
    autoTransition: false
  enforcementConfig:
    mode: Monitoring
```

Quote `Off` if you use it. Unquoted, `mode: Off` is a YAML 1.1 boolean, arrives
as `false`, and used to silently become `Monitoring` - the opposite of switching
a policy off. The CRD now carries an enum, so the API server rejects it, but the
habit is worth keeping.

**2. Read what was learned.** The baseline is on one `ContainerProfile` per
container, not on the policy:

```bash
pahlevan profile list -A
pahlevan profile get <container-profile> -n <namespace> -o yaml
```

**3. Check what the policy translates to.** `pahlevan policy explain` reads a
file offline and names every part of it the data plane cannot represent - a CIDR
wider than a single host, a glob, a DNS name, an ingress rule. Those parts are
dropped silently at runtime and reported on the policy's status, which is a
place people look after the fact rather than before.

```bash
pahlevan policy explain -f policy.yaml
pahlevan policy explain -f policy.yaml --strict    # exits non-zero in CI
```

Run the `--strict` form in the pipeline that ships your policies. A policy with
warnings is doing less than it says, and the gap is invisible from
`kubectl get`.

**4. Switch to `Blocking`.** Unlearned behavior is now refused in-kernel with
`EPERM`, before the operation completes.

```bash
kubectl patch pahlevanpolicy <name> --type=merge \
  -p '{"spec":{"enforcementConfig":{"mode":"Blocking","blockUnknown":true}}}'
```

`enforcementConfig.gracePeriod` delays strict enforcement after the transition.
`blockUnknown` left unset defaults to true under `Blocking`, because default-deny
of unlearned behavior is the only enforcement the data plane performs and a
`Blocking` policy without it would enforce nothing. Setting it explicitly false
downgrades the policy to monitoring.

**5. Watch the first hour.**

```bash
pahlevan logs --component agent --follow | grep DENIED
pahlevan metrics --component agent --filter pahlevan_enforcement_actions_total
pahlevan ui --grpc localhost:9090          # if the stream is enabled
```

### Self-healing

```yaml
spec:
  selfHealing:
    enabled: true
    rollbackThreshold: 3
    rollbackWindow: 5m
    recoveryStrategy: Rollback     # or Relax, or Maintenance
```

The operator watches violation rate and workload health after a transition. When
enforcement correlates with disruption it relaxes the policy, and if that does
not recover the workload it rolls back to monitoring and can restart learning.

Turn it off (`enabled: false`) when you would rather have a hard failure than an
automatic rollback - a compliance workload where silently returning to
monitoring is worse than an outage. Sustained rollbacks across a fleet are not a
self-healing problem; they mean the learning windows are too short for the
workloads, and the fix is upstream of the rollback.

## Metrics and alerting

Both components serve Prometheus-format metrics on `:8080/metrics` and health
probes on `:8081`. Neither the chart nor `install.yaml` installs a
`ServiceMonitor`, because that would require the Prometheus Operator CRDs to be
present and fail the install where they are not.

With the Prometheus Operator:

```bash
kubectl apply -f deploy/monitoring/servicemonitor.yaml
kubectl apply -f deploy/monitoring/alerts.yaml
```

The ServiceMonitor pair relabels the agent's series with the node name, which is
what makes a denial spike attributable to one kernel rather than to the fleet.
Without the Prometheus Operator, scrape the pods directly using the
`prometheus.io/*` annotations they already carry.

The rules in `alerts.yaml` alert on ring-buffer decode errors, container
breakout detections, event handler errors, denial-rate spikes, repeated
rollbacks, and a fleet where nothing reached enforcement. A Grafana dashboard
built on the same metrics is in
[`deploy/monitoring/`](../deploy/monitoring/README.md).

To check what a component is actually reporting, without Prometheus in the way:

```bash
pahlevan metrics --component agent
pahlevan metrics --component agent --filter pahlevan_enforcement --watch
```

### Cardinality

The agent's `--metrics-detail` flag defaults to `basic`, which emits aggregate
series. Setting it to `high` adds per-container, per-syscall and per-path
series. Those are useful for debugging one workload and expensive across a
fleet: they are keyed by container id crossed with a syscall or a path, so the
series count grows with your workload count times your path count. The shipped
dashboard deliberately graphs only the `basic` series. Query the high-detail
ones ad hoc.

## Getting events off the node

A counter tells you a denial happened and nothing about what was denied. The
agent has four ways to say what, and they are independent - the flags that
enable them are on the agent binary, not in the chart's values.

### The file sink

```
--export-file=/var/log/pahlevan/events.json   (or PAHLEVAN_EXPORT_FILE)
--export-denials-only=true                    (the default)
```

One JSON document per line, rotated, which is what `pahlevan events` reads and
what a log shipper tails. `--export-denials-only=false` exports every
observation instead, which is a much larger volume and rarely what you want in
production.

### The gRPC event stream

```
--grpc-bind-address=:9090
--grpc-tls-cert=... --grpc-tls-key=...
--grpc-client-ca=...        (mTLS: without it TLS encrypts but authenticates nobody)
--grpc-token=...            (bearer token; requires TLS, or it is sent in cleartext)
--grpc-insecure             (permit plaintext and unauthenticated - see below)
```

Empty `--grpc-bind-address` disables the stream, which is the default, so
`pahlevan ui --grpc` and `pahlevan events --grpc` have nothing to connect to
until you enable it.

The listener **refuses to start plaintext and unauthenticated** unless you pass
`--grpc-insecure`. That is not caution for its own sake: the stream carries every
denial on the node, which is a map of what your workloads do and where their
secrets are read from.

There is a real tension here. Both CLI subscribers dial in plaintext, so an
agent serving the stream over TLS cannot be read by `pahlevan ui --grpc` or
`pahlevan events --grpc` directly. Until the CLI learns to present credentials,
the workable arrangements are a plaintext listener on an address that is not
reachable off the node plus `--grpc-insecure`, or TLS terminated by something
in front of it. Do not reach for `--grpc-insecure` on a listener bound to a
routable address.

### OpenTelemetry

```
--otlp-endpoint=otel-collector:4317   (or OTEL_EXPORTER_OTLP_ENDPOINT)
--otlp-insecure=true                  (default; suits an in-cluster collector)
--pod-namespace=... --pod-name=... --node-name=...
```

Events are exported as OTLP logs using OpenTelemetry semantic conventions,
which is how they reach Loki in an LGTM stack. The three identity flags become
resource attributes. They matter more than they look: Grafana joins logs,
traces and metrics on shared labels, so if the metrics say `node=X` and the logs
say `host=X` the join silently produces nothing. The chart already wires
`PAHLEVAN_NODE_NAME` and `PAHLEVAN_POD_NAME` from the downward API;
`--pod-namespace` is not wired and without it every agent in the DaemonSet
collapses into one series.

### Notifications

Formatted delivery to where people already look, rather than a raw event
envelope into a webhook that nobody reads:

```
--notify-slack-webhook=...       (or PAHLEVAN_SLACK_WEBHOOK)
--notify-pagerduty-key=...       (or PAHLEVAN_PAGERDUTY_KEY)
--notify-pagerduty-severity=error    (critical, error, warning, info)
--notify-template-url=...
--notify-template='...'
--notify-all-events=false        (the default)
--notify-dedupe-window=5m
```

**Slack** posts one formatted message per batch of denials, grouped and
deduplicated. **PagerDuty** uses the Events API v2 and raises one incident per
distinct finding, keyed so the same problem re-triggers an existing incident
rather than opening a second one - the difference between a page and a pager
storm.

**The template notifier** is for everything else: a Go `text/template` rendered
into the body POSTed to `--notify-template-url`. It is rendered with the source
(normally the node name), the events in the delivery, how many were denied, and
a one-line summary, and it can call `summary`, `workload`, `subject`, `json`,
`truncate`, `upper`, `lower` and `join`. Use `json` for anything interpolated
into a JSON body; a naive template gets that wrong the first time a path
contains a quote. The template is parsed at startup, so a syntax error is a
startup failure naming the mistake rather than notifications that silently never
arrive.

Two defaults are doing real work. `--notify-all-events` is off, so only denials
are sent: a channel receiving one message per file open is a channel that gets
muted, and a muted channel is worse than no channel. And `--notify-dedupe-window`
suppresses a repeat of an identical finding for five minutes, because a crash
loop retrying the same denied `open` a hundred times a second is one finding,
not a hundred.

Both webhook URLs and the PagerDuty key are credentials. Put them in a Secret
and inject them as the environment variables above rather than as flags in the
pod spec, where they show up in `kubectl get daemonset -o yaml` for anyone with
read access. `--notify-template-url` has no environment-variable fallback.

### Shell capture

```
--trace-shell-commands=false     (the default)
```

Captures commands typed at interactive shell prompts inside governed containers,
via a uretprobe on `readline` - the builtins that produce no exec, no open and
no connect and are otherwise invisible. It is off by default because recording
what a person types is a decision an operator should make deliberately, and
often one with a works-council or legal dimension. Shells without readline
(dash, busybox) cannot be probed and are unaffected, so this is not a complete
record of shell activity and should not be described to anyone as one.

The `shell_monitor.c` program loads whether or not this flag is set - it is the
attachment to a container's shell binary that the flag gates - so an agent with
the program loaded and the flag unset captures nothing, which is the intended
default.

## Upgrades

```bash
helm repo update
helm upgrade pahlevan pahlevan/pahlevan-operator \
  -n pahlevan-system --values values-production.yaml --wait --timeout 10m

kubectl rollout status daemonset/pahlevan-agent -n pahlevan-system
kubectl rollout status deployment/pahlevan-operator -n pahlevan-system
```

Two things to know about an agent upgrade. The DaemonSet rolls node by node, and
while a node's agent pod is restarting that node has no data plane: programs are
detached and re-attached, and enforcement on that node resumes when the new pod
has loaded and re-seeded its maps. Learned baselines survive, because they are
persisted on `ContainerProfile` resources rather than held only in BPF maps.

Helm does not upgrade CRDs in a `crds/` directory on `helm upgrade`. If a
release changes the CRD schema, apply the new CRDs yourself before upgrading:

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/download/<tag>/install.yaml
```

To roll back:

```bash
helm rollback pahlevan -n pahlevan-system
```

Rolling the operator back does not relax enforcement on its own. If an upgrade
is denying something it should not, change the policy's mode to `Monitoring`
first and investigate second - it takes effect as a map update rather than a
restart, so it is the fastest lever you have.

## Backup

Policies and learned baselines are both Kubernetes objects, so they back up the
way everything else does:

```bash
kubectl get pahlevanpolicy      -A -o yaml > pahlevan-policies.yaml
kubectl get containerprofile    -A -o yaml > pahlevan-profiles.yaml
kubectl get attacksurface       -A -o yaml > pahlevan-attacksurfaces.yaml
```

The policies are the part worth restoring. `ContainerProfile` baselines are
rebuilt by learning, and a profile restored into a cluster running a different
version of a workload is a baseline that no longer matches what the workload
does - which is exactly how you get a denial at 3am. Restore policies, let
learning run again.

## Verifying a deployment

```bash
pahlevan status                                  # components, CRDs, admission policy
pahlevan debug                                   # per-node kernel and LSM state
pahlevan policy list -A                          # what is applied where
pahlevan attack-surface analyze -A               # what remains reachable
pahlevan metrics --component agent --filter pahlevan_containers
```

A deployment is working when agents are ready on every node, the CRDs are
served, policies report an `Enforcing` phase, and
`pahlevan_containers_enforced` is non-zero. A fleet stuck at zero enforced
containers usually means learning windows are not elapsing or no policy is set
to `Blocking`.

## Uninstalling

```bash
helm uninstall pahlevan -n pahlevan-system
# or
kubectl delete -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml
```

Removing the agent removes enforcement immediately: the eBPF programs are
detached when the process exits, and the kernel stops consulting them. Seccomp
profiles you applied to workloads with `pahlevan profile patch` are **not**
removed, because they live in your workload manifests now. Remove them from
those manifests, or the workloads keep running under a baseline nothing is
maintaining.

Helm does not delete CRDs it installed from a `crds/` directory, which also
means it does not delete your `PahlevanPolicy`, `ContainerProfile` and
`AttackSurface` objects. Delete them explicitly when you mean to.

## Related reading

- [Architecture](architecture.md) - what the components do and why they are split
- [Policy reference](policy-reference.md) - every policy field
- [API reference](api-reference.md) - generated from the CRD types
- [LSM support](lsm-support.md) - per-distribution BPF LSM state
- [Troubleshooting](troubleshooting.md) - when the above did not work
