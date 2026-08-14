# Architecture

Pahlevan splits a **privileged per-node data plane** from an **unprivileged,
leader-elected control plane**. The agent owns everything that touches the
kernel; the operator owns everything that touches the Kubernetes API. This is
the same node-instrumentation shape as Falco and Tetragon, with an operator
driving a `selector -> learn -> enforce` lifecycle on top.

![Pahlevan architecture](assets/architecture.svg)

## Components

### Agent (DaemonSet, one per node)

The agent runs on every node and owns the eBPF data plane:

- Loads and attaches the CO-RE eBPF programs at startup, degrading gracefully
  when a hook is unavailable (for example, no BPF LSM means observation only).
- Resolves cgroup ids to Kubernetes pods and containers so every event carries
  real workload identity.
- Builds per-container baselines during the learning window and writes the
  resulting allow-sets into BPF maps.
- Enforces locally in the kernel. No user-space round trip sits on the hot path,
  so a denial is a verdict returned by the LSM hook itself.
- Exposes Prometheus metrics on `:8080` and health probes on `:8081`.

It does **not** run with `privileged: true`. It requests the capability set the
work actually needs (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`,
`CAP_SYS_RESOURCE`, `CAP_NET_ADMIN`) with `readOnlyRootFilesystem: true` and
`drop: ALL` for everything else. `CAP_BPF` and `CAP_PERFMON` are the modern
least-privilege pair on kernel 5.8 and newer; `CAP_SYS_ADMIN` and
`CAP_SYS_RESOURCE` cover older kernels and map operations.

### Operator (Deployment, leader-elected)

The operator is an ordinary controller-runtime manager. It needs no host access
at all, so it runs in a **user namespace** (`hostUsers: false`, Kubernetes 1.30+),
which maps in-container root to an unprivileged host UID. It handles:

- Reconciling `PahlevanPolicy` resources and driving phase transitions.
- Aggregating learning and enforcement status from every node agent.
- Maintaining `ContainerProfile` and `AttackSurface` resources.
- Admission, via a CEL `ValidatingAdmissionPolicy`. There is no admission
  webhook, so there is no certificate rotation, no webhook availability risk,
  and no extra network path in the API server's critical path.

### Custom resources

| Kind | Scope | Purpose |
|---|---|---|
| `PahlevanPolicy` | Namespaced | Selects workloads and configures the learning window, enforcement mode, and self-healing. |
| `ContainerProfile` | Namespaced | The learned baseline for a container: syscalls, file paths, and egress destinations, persisted so restarts do not relearn from zero. |
| `AttackSurface` | Namespaced | Aggregated posture and risk view derived from the observed and learned data. |

## eBPF programs

All programs are CO-RE (compile once, run everywhere): they are compiled during
the build, the objects and bpf2go bindings are committed to the tree, and no
per-node compilation or kernel headers are required at runtime.

| Program | Hook | Role |
|---|---|---|
| `syscall_monitor.c` | `raw_tracepoint/sys_enter` | Observes every syscall, deduplicated in-kernel per `(cgroup, syscall)` so the ring buffer sees each pair once. |
| `file_monitor.c` | `lsm/file_open` | Observes opens with paths resolved in-kernel via `bpf_d_path()`; denies unlearned paths with `EPERM` under enforcement. |
| `network_monitor.c` | `lsm/socket_connect` | Observes egress; denies connections to destinations outside the learned allow-set. |
| `exec_monitor.c` | `lsm/bprm_check_security` | Observes process execution; denies unlearned binaries. |
| `lsm_monitor.c` | `lsm/task_alloc`, `lsm/socket_create`, `lsm/ptrace_access_check`, `lsm/capable`, `lsm/bprm_check_security` | Broader security-event surface for posture analysis. |

Each enforcing program is driven by two map families: a `*_mode` map that says
whether the cgroup is off, monitoring, or blocking, and a `*_allowed` map that
holds the learned allow-set. Flipping a policy to enforcement is a map update,
not a program reload.

Every program passes the kernel verifier before it can attach, runs in the eBPF
virtual machine with bounded loops and bounded memory, and is subject to the
agent's resource limits.

## Learn to enforce

1. **Select.** A `PahlevanPolicy` selector matches target pods. The agent
   identifies their cgroups with `bpf_get_current_cgroup_id()` and resolves those
   ids back to pod and container names.
2. **Learn.** During the learning window every file the container opens (path
   resolved with `bpf_d_path()`), every egress destination it dials, and every
   binary it executes is added to that cgroup's allow-set. Syscalls are observed
   in parallel and deduplicated per `(cgroup, syscall)`.
3. **Transition.** On `learningConfig.autoTransition`, or when you flip
   `enforcementConfig.mode` by hand, the policy moves to enforcement and a
   seccomp profile is generated from the learned syscall set.
4. **Enforce.** An open of an unlearned path, an egress to an unlearned
   destination, or an exec of an unlearned binary is **denied in-kernel with
   `EPERM`** by the LSM hook, before the operation completes. A detection tool
   can only tell you it already happened.

`enforcementConfig.mode` accepts `Off`, `Monitoring`, and `Blocking`. Start in
`Monitoring`, review the learned profile, then move to `Blocking`.

### Verification

The flow is verified in a VM on Linux 6.8 with the BPF LSM enabled
(`hack/vm/up.sh`, then `make vm-test`). Representative output from the
enforcement test:

```text
learned 28 (cgroup,path) allow-set entries
learned /etc/hostname allowed under enforcement
DENIED in-kernel as expected: cat /etc/os-release -> exit status 1
```

The demo GIF in the README is a scripted replay of exactly this behavior.

## Self-healing

Enforcement built from a learned baseline can be wrong when the baseline was
incomplete: a workload path exercised only at month end was never seen during a
five-minute window. Self-healing exists so that failure mode degrades
availability as little as possible.

The operator watches violation rate and workload health after a transition. When
enforcement correlates with disruption it relaxes the policy, and if relaxation
does not recover the workload it rolls back to monitoring and can restart the
learning phase. Set `selfHealing.enabled: false` if you would rather have a hard
failure than an automatic rollback.

## Security model

- **Blast radius is split.** The component with kernel privilege has no cluster
  API power beyond its own node's status reporting; the component with
  cluster-wide API power runs in a user namespace with no host access.
- **No admission webhook.** Policy validation is a CEL
  `ValidatingAdmissionPolicy` evaluated by the API server itself.
- **Namespace scoping.** Policies are namespaced and enforced through Kubernetes
  RBAC. The `pahlevan-system` namespace is labelled
  `pod-security.kubernetes.io/enforce: privileged` because the agent needs eBPF
  capabilities; protected workloads live in their own namespaces and keep
  whatever Pod Security level you already run.
- **Verifier-gated code.** Nothing reaches the kernel that the verifier has not
  accepted.

## Kernel requirements

| Capability | Requirement |
|---|---|
| Syscall, file, network, and exec observation | Linux 5.8+ (CO-RE, ring buffer, `CAP_BPF`) |
| In-kernel enforcement (`EPERM` denials) | Linux 5.7+ with `CONFIG_BPF_LSM=y` and `bpf` in the active `lsm=` list |
| User-namespace operator | Kubernetes 1.30+ |

Without the BPF LSM the agent still loads, still learns, and still reports:
enforcement degrades to monitoring rather than failing. See
[`lsm-support.md`](lsm-support.md) for per-distribution details and
[`system-requirements.md`](system-requirements.md) for the full matrix.

## Resource profile

Defaults per node agent are `100m` CPU and `128Mi` memory requested, with
`500m` / `512Mi` limits. The operator requests `50m` / `64Mi` with `200m` /
`256Mi` limits. Actual usage
tracks event volume: a chatty workload during its learning window costs more
than the same workload once enforcement is on and the ring buffer has gone
quiet, because in-kernel deduplication suppresses repeats.

Measured resident memory from the 2026-08-14 benchmark run was roughly 327 MiB
for the Pahlevan agent with debug logging enabled, against 106 MiB for Falco and
67 MiB for Tetragon. That gap is a known tuning target and is reported in full in
[`benchmarks/results.md`](benchmarks/results.md).

## Scalability

- **Containers per node**: hundreds, bounded by kernel eBPF map resources.
- **Policies per cluster**: bounded by etcd and operator reconcile capacity, not
  by the data plane.
- **Events per second**: bounded by ring buffer sizing; in-kernel deduplication
  keeps steady-state volume far below raw syscall rate.
- **Learning window**: configurable, typically 5 to 30 minutes depending on how
  much of the workload's behavior a window is likely to cover.

## Observability

The agent and operator both export Prometheus metrics, including enforcement and
violation counters. OpenTelemetry export is available for traces, and
`AttackSurface` data can be exported for dashboards. See
[`deployment.md`](deployment.md) for wiring these into an existing monitoring
stack.
