# Troubleshooting

This guide is organised by what you see, not by what the code is called. Each
entry quotes the text the binaries actually produce, so searching your logs for
the message in front of you should land you in the right section.

## Start here

```bash
pahlevan debug
```

`pahlevan debug` collects, in one command, the state a problem report needs:
every component pod with its phase, readiness, restart count, image and age;
every node with its kernel version, OS image, container runtime and whether the
BPF LSM looks active there; whether each of the three CRDs is served and how
many objects it holds; recent Kubernetes Events involving Pahlevan objects; and
the `pahlevan_*` metric highlights scraped from each component. It never reads
Secrets, ServiceAccount tokens or container environment variables.

```bash
# Save a JSON bundle to attach to an issue
pahlevan debug -o json --file pahlevan-debug.json

# Only the agent, without reading logs
pahlevan debug --component agent --skip-logs
```

The BPF LSM column is inferential, because the kernel does not expose its LSM
list through the Kubernetes API. A node reads `Disabled` when its agent logged
an LSM attach failure, `Unsupported kernel` when the kernel predates
`CONFIG_BPF_LSM` (5.7), and `Likely enabled` when a ready agent on a new enough
kernel logged no attach failure in the inspected window.

If the command exits with `kubernetes clients are not initialized; check your
kubeconfig and cluster connectivity`, it never reached the cluster. Commands
that read a file or print a constant (`pahlevan version`, `pahlevan policy
explain`, `pahlevan coverage`, `pahlevan ui`, `pahlevan completion`) work
without a kubeconfig; everything else needs one.

The rest of the standard survey:

```bash
kubectl get pods -n pahlevan-system
kubectl get crd | grep pahlevan
kubectl get pahlevanpolicy --all-namespaces
kubectl logs -n pahlevan-system daemonset/pahlevan-agent --tail=200
```

The agent is a DaemonSet (`pahlevan-agent`) and the operator is a Deployment
(`pahlevan-operator`), both in `pahlevan-system` in a standard install. The
agent is the half that touches the kernel, so nearly every entry below is about
its logs.

## Nothing is ever denied, and the agent looks healthy

This is the most common report, and the cause is almost always the same: the
node was not booted with the BPF LSM active.

Four of Pahlevan's eBPF programs can refuse an operation, and all four are LSM
programs:

| Program | Hook | Enforces |
|---|---|---|
| `file_monitor.c` | `lsm/file_open` | File opens |
| `network_monitor.c` | `lsm/socket_connect` | Egress connects |
| `exec_monitor.c` | `lsm/bprm_check_security` | Execs |
| `capability_monitor.c` | `lsm/capable` | Capability checks |

The rest attach to a tracepoint (`syscall_monitor.c`), kprobes
(`cred_monitor.c`, `generic_kprobe.c`) or a uretprobe (`shell_monitor.c`), which
need no boot parameter. None of them can refuse an operation, because they run
alongside the kernel's decision rather than in place of it; the only lever they
have is `bpf_send_signal`, which kills the task after the fact rather than
preventing anything.

So a node without the BPF LSM runs the agent, reports syscalls and credential
changes, and refuses nothing. That degradation is deliberate: failing the whole
data plane would lose the observation too. See
[`lsm-support.md`](lsm-support.md) for exactly what a node in that state still
sees.

### What it looks like

One or more of these at agent startup, at the default log level:

```
lsm/file_open attach failed; file enforcement/observation disabled (enable with lsm=...,bpf)
lsm/socket_connect attach failed; network observation/enforcement disabled
lsm/bprm_check_security attach failed; exec observation/enforcement disabled
lsm/capable attach failed; capability observation disabled
```

Later, when a policy tries to flip a container to enforcing, the transition
aborts on the first hook it cannot configure, which is the file one:

```
failed to enable file enforcement
```

carrying `file monitor not loaded (bpf LSM unavailable?)` as its cause. The
container stays in learning, so a policy in this state shows `Enforcing` with
`enforcingContainers` well below `totalContainers`.

If the file hook attached and one of the others did not, the transition
continues and logs the missing hooks at `-v 1` instead, as `network enforcement
unavailable`, `exec enforcement unavailable` or `capability enforcement
unavailable`. That is the partial case: files are enforced on that node and the
rest of the policy is not.

### Confirming it on the node

```bash
# The active LSM list. "bpf" must appear.
cat /sys/kernel/security/lsm

# What the kernel was booted with.
cat /proc/cmdline

# The kernel must have been built with it at all.
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```

### Fixing it

`CONFIG_BPF_LSM=y` is necessary but not sufficient: the BPF LSM also has to be
enabled on the kernel command line, because it is not in the default list on
most distributions. Add `bpf` to the existing `lsm=` list rather than replacing
it, since dropping the distribution's other modules from that list disables
them.

```bash
# Read the current list first, then append bpf to it.
cat /sys/kernel/security/lsm
# e.g. lsm=lockdown,capability,landlock,yama,apparmor,bpf
```

Set it in the bootloader configuration and reboot the node. On managed
Kubernetes this usually means a node-image or node-pool setting rather than
something you can change in place. See [`lsm-support.md`](lsm-support.md) for
the kernel side in more detail.

Until the node is rebooted, the useful posture is `enforcementConfig.mode:
Monitoring`: the profiles that accumulate are exactly the ones enforcement will
be built from once the LSM is available, so the time is not wasted.

## The agent will not start

The agent fails fast only for the things that make the whole data plane
impossible. Everything else degrades.

### `failed to remove memory limit`

The agent could not raise `RLIMIT_MEMLOCK`, so no BPF map can be created. This
is a missing capability, not a kernel feature. The agent needs `CAP_BPF` and
`CAP_PERFMON` on kernel 5.8 and newer, plus `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`
and `CAP_NET_ADMIN` for older kernels and map operations. The shipped DaemonSet
requests exactly that set with `privileged: false`, `readOnlyRootFilesystem:
true` and `drop: ALL` for everything else:

```yaml
securityContext:
  privileged: false
  runAsUser: 0
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: true
  capabilities:
    add: [BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE, NET_ADMIN]
    drop: ["ALL"]
```

If you have edited the chart's `agent.capabilities`, or an admission controller
is stripping capabilities from the pod, restore them. Pod Security Admission is
the usual culprit: a `baseline` or `restricted` enforce label on
`pahlevan-system` rejects a pod asking for these capabilities outright, so the
agent never schedules rather than failing at startup. The shipped namespace
manifest labels the namespace
`pod-security.kubernetes.io/enforce: privileged` for exactly this reason;
workload namespaces are unaffected by that label.

### `eBPF support check failed: eBPF is not supported on this system`

`bpf(2)` is unavailable or refused. Either the kernel lacks `CONFIG_BPF_SYSCALL`
or the process has no capability to call it, which brings you back to the
previous entry. Check both:

```bash
grep -E 'CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_BPF_JIT=' /boot/config-$(uname -r)
```

### `syscall monitoring requires tracepoint support which is not available on this system. Please ensure debugfs is mounted and kernel has tracepoint support`

The syscall monitor is the one program the agent refuses to run without, because
it is the core observation path. The DaemonSet mounts `/sys/kernel/debug` from
the host for this; if that volume is missing or the node does not mount debugfs,
the check fails.

```bash
mount | grep debugfs
grep -E 'CONFIG_TRACEPOINTS=|CONFIG_FTRACE=' /boot/config-$(uname -r)
ls /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter
```

### `failed to create syscall collection:` followed by verifier output

The kernel verifier rejected a program at load time. The wrapped error is
`cilium/ebpf`'s verifier log, which names the instruction and the constraint,
for example `the register R0 has unknown scalar value should have been in
[-4095, 0]`. A rejection here is a bug rather than a configuration problem: the
committed objects are compiled at build time and verified in a VM on Linux 6.8
as part of `make vm-test`, so a rejection means your kernel's verifier differs
from the one the objects were validated against. Capture the whole log, the
kernel version and the architecture, and open an issue. There is no workaround
to apply on the node.

The same message for the other programs is not fatal, because they are
best-effort:

```
file monitor unavailable; continuing without file observation
network monitor unavailable; continuing without network observation
capability monitor unavailable; continuing without capability observation
credential monitor unavailable; continuing without escalation detection
shell monitor unavailable; continuing without interactive command capture
exec monitor unavailable; continuing without exec observation
generic kprobe unavailable; user-defined kernel probes disabled
```

Each of these means that one signal is gone and the rest of the agent is
running. Which signal you lost tells you what stopped working: no file
observation means no file allow-set and therefore no file enforcement, and so on
down the table in the previous section.

## A policy applies cleanly and does nothing

The API server prunes unknown fields in a custom resource rather than rejecting
them, so a policy written against field names that do not exist applies without
error and does a fraction of what it says. There is no error anywhere to find.

Check the policy against the schema before blaming the data plane:

```bash
pahlevan policy explain -f policy.yaml
```

It unmarshals strictly, so a field the CRD does not have is an error, and it
prints what the policy translates to plus every part that cannot be enforced.
`--strict` exits non-zero, which is what you want in CI. The three mistakes it
catches most often:

- **`learning:` and `enforcement:` instead of `learningConfig:` and
  `enforcementConfig:`.** Older hand-written documentation described an API that
  never existed. A policy using those names selects workloads and then learns and
  enforces nothing, because both blocks were pruned on the way in.
- **`mode: Off` unquoted.** In YAML 1.1 that is a boolean, so it arrives as
  `false`. The API server now rejects it because `mode` is an enum, but an object
  stored before that validation existed, or a cluster whose CRD has not been
  upgraded, will still carry it. The agent warns
  `enforcementConfig.mode is "false", which is what YAML turns an unquoted Off or
  On into; write mode: "Off" in quotes. Treated as Monitoring`.
- **A misspelled selector operator.** `mode` is the only enumerated field in the
  whole CRD, so `operator: exists` is accepted by the API server and treated by
  the agent as "does not match". The policy governs nothing and says nothing.

In a running cluster the same warnings appear in the agent log once per policy
generation, under `policy rule is not fully representable`. Grep for it:

```bash
kubectl logs -n pahlevan-system daemonset/pahlevan-agent | grep "not fully representable"
```

### Fields that are accepted and do nothing

Some fields exist in the CRD, pass validation and are acted on by nothing. They
are documented rather than hidden, because finding one in a cluster and not
knowing is worse than being told:

- `observabilityConfig` in its entirety. Telemetry is configured by the agent's
  flags, per node rather than per policy.
- `learningConfig.windowSize` and `learningConfig.lifecycleAware`.
- `filePolicy.defaultAction`, `syscallPolicy.defaultAction` and
  `networkPolicy.defaultAction`. Default-deny is what enforcement is, so the
  field cannot express a third thing.
- `filePolicy.executableFilter.requireSignature`. Nothing verifies executable
  signatures.

`pahlevan policy explain` names every one present in a given policy.

## A policy governs more workloads than intended

The node agent lists `PahlevanPolicy` objects across the whole cluster and
applies the first one whose selector matches the pod, regardless of which
namespace the policy lives in. A policy in `default` selecting `app: web` with
no `namespaceSelector` will govern an `app: web` pod in `payments` too, and the
ordering among several matching policies is the API server's list order.

An empty selector matches everything, so a selector lost to a typo is the
worst case of this: one policy governing the cluster.

Scope with `namespaceSelector`, which matches the namespace's own labels.
Kubernetes stamps every namespace with `kubernetes.io/metadata.name`, so
selecting by name needs no extra labelling:

```yaml
spec:
  selector:
    matchLabels:
      app: web
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: payments
```

If scoped policies suddenly match nothing, look for this in the agent log. It is
logged at `-v 1`, so raise the verbosity to see it:

```
cannot list namespaces; namespaceSelector will not match
```

The agent needs `list` on namespaces to resolve namespace labels. Without it, it
degrades rather than failing: unscoped policies keep working, and every scoped
one stops matching.

## Containers never reach enforcing

Read `status.enforcementStatus` first. `enforcingContainers` and
`totalContainers` say how many of the containers the policy selects have
actually reached enforcement, which is the number that matters when the phase
says `Enforcing` and a workload is not being enforced.

```bash
kubectl get pahlevanpolicy <name> -o jsonpath='{.status.enforcementStatus}' | jq
pahlevan profile list -n <namespace>
```

Work through the causes in this order.

**The policy does not ask for enforcement.** `mode: Monitoring` learns and never
denies. So does `mode: Blocking` with `alertOnly: true`, and so does `mode:
Blocking` with an explicit `blockUnknown: false`, because default-deny of
unlearned behaviour is the only enforcement the data plane performs and a
`Blocking` policy that opts out of it would enforce nothing. Both downgrade to
`Monitoring` by design.

**The window has not elapsed.** A container becomes eligible
`learningConfig.duration + enforcementConfig.gracePeriod` after its learning
window opened. Check both values are what you think.

**The container has used up its enforcement attempts.** After three attempts it
stays in learning permanently:

```
enforcement attempt cap reached; container stays in learning (monitor only)
```

The log line carries `lastRollbackReason`, which is the actual problem. Fix
that, then delete the pod so its replacement starts with a fresh cgroup and a
fresh attempt count.

**The container is in a post-rollback cooldown.** The cooldown is 10 minutes
multiplied by the rollback count, so a container that has rolled back three
times waits half an hour before the next attempt.

**The BPF LSM is not available.** See the first section. A successful
transition logs:

```
container transitioned to enforcing
```

with the cgroup, the pod, the attempt number and the size of each learned set.
Its absence is the signal.

## Containers keep rolling back out of enforcing

```bash
kubectl get events --field-selector reason=EnforcementRolledBack -A
```

Each rollback writes a `Warning` Event on the pod with reason
`EnforcementRolledBack` and a message naming the trigger, plus an agent log line
`rolled back enforcement to learning`.

Rollback fires only inside the observation window immediately after the enforce
transition, 5 minutes by default. Past it the baseline is treated as settled, so
a container that runs fine for an hour and is then legitimately denied is not
un-enforced by an attacker's noise. Inside the window, two things trigger it:

- **Denial rate.** 10 in-kernel denials by default, configurable with
  `selfHealing.rollbackThreshold`. The message reads `N in-kernel denials within
  M of enforcement (threshold T)`.
- **Pod distress**, measured against a baseline captured at the instant
  enforcement began: `container "x" entered CrashLoopBackOff after enforcement
  began`, `container "x" restarted after enforcement began (1 -> 2)`, or
  `container "x" became not ready after enforcement began`. Judging against a
  captured baseline is what keeps a pod that was already crash-looping from
  being blamed on enforcement.

A rollback is almost always telling you the learning window was too short for
the workload, not that enforcement is broken. Three responses, in order of
preference:

1. Lengthen `learningConfig.duration` so the window covers the behaviour that
   was missed. Look at the denials in the events or in
   `pahlevan_ebpf_denials_total` to see what was missing.
2. Add the missing behaviour as an `enforcementConfig.exceptions` entry, which
   seeds the allow-set with something that never occurred during learning.
3. Raise `selfHealing.rollbackThreshold` only when you have established that the
   denials are expected and harmless. Raising it to silence a real breakage
   converts a rollback into an outage.

`selfHealing.enabled: false` disables rollback entirely: the container stays
enforcing whatever happens. That is a deliberate choice for a workload where a
half-enforced state is worse than a broken one, not a default to reach for.

`selfHealing.recoveryStrategy` accepts `Relax` and `Maintenance`, but only
`Rollback` is implemented. The others are reported as unimplemented rather than
silently behaving like `Rollback`:

```
selfHealing.recoveryStrategy "Relax" is not implemented; the only recovery is Rollback, which returns the container to learning
```

## A workload breaks under Blocking

Find out what was denied before changing anything:

```bash
# In-kernel denials by signal kind, from the agent on the affected node.
curl -s localhost:8080/metrics | grep pahlevan_ebpf_denials_total

# The denial events themselves. This reads the JSON-lines log the agent's file
# sink writes (/var/log/pahlevan/events.json by default), so it has to run
# where that file is, or against a copy of it. It needs the agent to have been
# started with --export-file.
pahlevan events --denials-only --tail=50

# Or subscribe to the agent's gRPC stream instead of reading the file.
pahlevan events --grpc <node>:<port> --denials-only --follow
```

The per-container `ContainerProfile` carries `deniedFiles`, `deniedNetwork`,
`deniedExecs` and `deniedCapabilities`, which narrows it to a signal before you
go reading event streams.

To lift enforcement from containers that are already enforcing, set the
governing policy to `mode: "Off"`. That is the only mode change the agent acts
on retroactively: on its next reconcile it clears every enforcement bit for
those containers and stops tracking them, which is also what makes the change
take effect without restarting the agent. Quote it, or YAML turns it into
`false`.

```bash
kubectl patch pahlevanpolicy <name> -n <ns> --type=merge \
  -p '{"spec":{"enforcementConfig":{"mode":"Off"}}}'
```

`mode: Monitoring` is the gentler change but it is not a rescue: it stops new
containers from ever being flipped to enforcing, and leaves containers that are
already enforcing exactly as they are. They come out of enforcement when the pod
restarts, because the replacement gets a new cgroup id and starts again in
learning, or when self-healing rolls them back. If the workload is broken right
now, use `Off` or delete the pod.

`Off` costs the in-memory baseline: the agent drops the learned set for those
containers, so re-enabling the policy relearns from zero. That is the price of
the retroactive lift, and it is usually the right trade when a workload is
down.

The four most common reasons a real workload is denied something legitimate:

- **A path that only appears sometimes.** Log rotation, a certificate renewal, a
  month-end code path. Lengthen the window or add a `File` exception.
- **A read that was learned but a write that was not.** Reads and writes are
  separate entries in the allow-set on purpose, so learning a read of
  `/etc/passwd` does not permit writing it. Use `writeAllowedPaths` for a path
  the workload genuinely writes.
- **A wildcard that was written as a wildcard.** The allow-set is a hash of the
  exact resolved path, so `/var/log/*` matches a file literally named `*` and
  nothing else. `pahlevan policy explain` warns about this.
- **A symlink.** Enforcement keys on the path the kernel resolves, which follows
  symlinks, so allowing `/etc/os-release` grants nothing where it links to
  `/usr/lib/os-release`. Name the target.

## Syscalls are not being blocked, and `blockedSyscalls` is zero

This is expected, and the field is documented as always zero.

Syscalls are not confined by a BPF map. The eBPF syscall program observes and
cannot refuse: seccomp is installed at exec, so an already-running process
cannot be retroactively filtered. Pahlevan's syscall enforcement is delivered as
a generated seccomp profile instead, which means:

- The agent must run with `--seccomp-dir` set, or no profile is written at all.
- The profile confines new pods that reference it as a `localhostProfile`, not
  the pod it was learned from.
- The kernel does not report seccomp denials back to the agent, so there is no
  counter for them. `status.enforcementStatus.blockedSyscalls` stays zero and is
  kept only for API compatibility.

The generated profile is default-deny (`SCMP_ACT_ERRNO`) over the learned
syscalls plus a small safety baseline (`exit`, `exit_group`, `rt_sigreturn`,
`restart_syscall`, `brk`, `mmap`, `munmap`, `mprotect`, `futex`, `nanosleep`,
`clock_nanosleep`, `sched_yield`) so a confined process can start, sleep, take
signals and exit cleanly. `syscallPolicy.deniedSyscalls` is applied last and
wins over everything including that baseline, which is a real way to break a
workload if you deny something like `futex` by accident. Neither list is
validated against the syscall table, so a typo is applied literally.

`status.seccomp` on the `ContainerProfile` carries the generated profile's path,
its `localhostProfile` value, how many syscalls it allows, and how many learned
syscall numbers had no name and were skipped.

## Network rules are not doing what the policy says

The egress allow-set is a hash of the exact `(address, port)` pair, and most
surprises follow from that. `pahlevan policy explain -f policy.yaml` names every
one of these against your file before you apply it.

- **`ingressRules` are ignored.** The `lsm/socket_connect` hook governs egress
  only. The warning reads `networkPolicy.ingressRules are ignored: the
  socket_connect LSM hook governs egress only`.
- **A CIDR wider than a single host seeds nothing.** Only `/32` and `/128` are
  representable. `egressRules[0].ipBlock.cidr "10.0.0.0/8" covers 16777216
  addresses; the kernel allow-set is a hash of the exact destination and cannot
  express a prefix`.
- **`podSelector` and `namespaceSelector` peers cannot be resolved** to a fixed
  address at translation time. Use an `ipBlock`.
- **DNS names are not accepted** in `Network` exceptions, for the same reason:
  `does not name an IP address; DNS names cannot be resolved to a stable
  allow-set key`.
- **A rule with no ports seeds nothing**, because there is no key without a port.
- **A port range wider than 1024 ports is refused**, because it would insert one
  entry per port per address into an LRU map and evict the learned baseline.

DNS and loopback are per-cgroup flags rather than allow-set entries, because
they name a class of destination rather than an address. If a workload cannot
resolve names under enforcement, set `networkPolicy.allowDNS: true` rather than
trying to enumerate resolver addresses.

If the whole network signal is missing rather than misbehaving, check for
`lsm/socket_connect attach failed` at startup: that is the BPF LSM case, not a
policy problem.

## Events are not reaching my collector

Enforcement happens in the kernel and is unaffected by an export failure, so the
denial counters keep climbing normally while an export file, webhook or gRPC
subscriber quietly receives nothing. That is exactly the failure this metric
exists to make visible:

```bash
curl -s localhost:8080/metrics | grep -E 'pahlevan_ebpf_(handler|decode|read)_errors_total'
```

- `pahlevan_ebpf_handler_errors_total` is the one to alert on if you export
  events: a handler returning errors is an export that is not delivering.
- `pahlevan_ebpf_read_errors_total` means a ring buffer reader is failing, which
  otherwise looks exactly like a quiet node.
- `pahlevan_ebpf_decode_errors_total` means records arrived and could not be
  decoded, which usually means the kernel and userspace halves of an event
  struct have drifted.

If the gRPC stream refuses to start, the message says why:

```
the grpc listener would be plaintext and unauthenticated, and it serves every
denial on this node. Configure --grpc-tls-cert and --grpc-tls-key, add
--grpc-client-ca for mTLS or --grpc-token for a bearer token, or pass
--grpc-insecure if this listener is genuinely unreachable
```

That stream carries every denial on the node: which pods exist, which paths they
read, which destinations they dial, the full command line of every exec. Pass
`--grpc-insecure` only when the listener is genuinely unreachable. A bearer
token without TLS is refused separately, because a token sent in cleartext on
every call protects nothing.

A notification template that fails to parse is a startup error naming the
mistake, rather than an error logged once per batch while notifications silently
never arrive.

## Metrics are missing

Both components expose Prometheus metrics on `:8080` and health probes on
`:8081`. No `ServiceMonitor` is installed by the shipped manifests, so if you
run the Prometheus Operator you have to wire one up yourself.

The quickest way to see them is `pahlevan metrics`, which scrapes through the
API server's pod proxy, so it needs no port-forward, no Service and no node
access, and groups the results per pod because the agent's counters are per
node:

```bash
pahlevan metrics
pahlevan metrics --component agent --node worker-2 --filter blocked --watch
pahlevan metrics --component operator -o raw
```

If you would rather go straight at an endpoint:

```bash
pod=$(kubectl get pod -n pahlevan-system -l app.kubernetes.io/name=pahlevan-agent \
  -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n pahlevan-system "$pod" 8080:8080
curl -s localhost:8080/metrics | grep pahlevan_
```

The data-plane series, all labelled by event `kind` (`syscall`, `network`,
`file`, `exec`, `capability`, `cred`, `shell`, `kprobe`):

| Metric | Meaning |
|---|---|
| `pahlevan_ebpf_events_total` | Events decoded from the ring buffers. |
| `pahlevan_ebpf_denials_total` | Operations denied in-kernel. |
| `pahlevan_ebpf_would_deny_total` | Operations the `Audit` action reported and allowed. |
| `pahlevan_ebpf_read_errors_total` | Ring buffer reads that failed. |
| `pahlevan_ebpf_decode_errors_total` | Records that could not be decoded. |
| `pahlevan_ebpf_handler_errors_total` | Event handlers that returned an error. |
| `pahlevan_ebpf_escalations_total` | Credential changes that gained privilege with no execve underway. |
| `pahlevan_ebpf_breakouts_total` | Execs whose working directory was outside the process's own mount namespace. |

`pahlevan_ebpf_would_deny_total` is kept out of the denial series deliberately:
an `Audit` rollout produces one of these for every operation outside the
baseline, and folding them into denials would make a planned dry run fire the
same alerts as an outage.

The control-plane series: `pahlevan_containers_tracked`,
`pahlevan_containers_learning`, `pahlevan_containers_enforced`,
`pahlevan_policy_violations_total`, `pahlevan_enforcement_actions_total`,
`pahlevan_learning_progress_ratio` and `pahlevan_policy_quality_score`.

A node whose agent is running but whose counters are all zero is a node that is
seeing no traffic or a node whose programs did not attach. Compare
`pahlevan_ebpf_events_total` across nodes; one node at zero while others climb
is the signal to go read that node's startup log.

## Resource usage

The shipped agent requests 100m CPU and 128Mi memory with limits of 500m and
512Mi. The BPF maps are preallocated by the kernel, so the agent's resident
memory is determined largely by their sizing rather than by Go allocation: an
LRU hash costs roughly 60 bytes per entry, and the defaults are sized for a
typical node. The learned-state maps hold 8192 cgroups, 131072 file allow-set
entries, 32768 network entries and 8192 exec entries per node, with 256 KiB ring
buffers per program.

Those sizes are compiled in. There is no ConfigMap, flag or policy field that
changes them today: `MapSizing` exists in `pkg/ebpf` and nothing calls it. On a
node dense enough to evict learned entries from an LRU map the symptom is
denials of behaviour that was definitely learned, appearing under load rather
than consistently. If you see that, say so in an issue with the node's pod count
and `pahlevan_ebpf_events_total` by kind; it is the case the sizing needs to be
made configurable for.

If the agent is OOMKilled, raise the memory limit rather than trying to shrink
the maps, and set `GOMEMLIMIT` a little under the container limit so the Go heap
backs off before the kernel kills the process:

```yaml
env:
- name: GOMEMLIMIT
  value: "400MiB"
```

## Recovering a cluster in a hurry

There is no `pahlevan debug clear-programs` and nothing that unloads programs
from outside the agent. Recovery is done through the policies and the DaemonSet.

```bash
# 1. Lift enforcement everywhere. Off is the mode the agent applies
#    retroactively, so containers that are already enforcing stop being
#    enforced on the next reconcile. Note the quotes: unquoted Off is a YAML
#    boolean and would be rejected by the enum.
kubectl get pahlevanpolicy -A \
  -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' |
while IFS=/ read -r ns name; do
  kubectl patch pahlevanpolicy "$name" -n "$ns" --type=merge \
    -p '{"spec":{"enforcementConfig":{"mode":"Off"}}}'
done

# 2. Last resort: remove the data plane. Detaching the programs stops every
#    denial on every node immediately.
kubectl delete daemonset pahlevan-agent -n pahlevan-system
```

Step 1 is reversible and is enough in almost every case. What it costs is the
in-memory baselines, which the agent drops along with the tracking, so the
workloads relearn from zero when the policies go back to `Monitoring` or
`Blocking`. Do not reach for `Monitoring` here: it stops new containers being
flipped to enforcing but leaves the ones already enforcing exactly as they are,
which is the opposite of what an outage needs.

## Reporting a problem

```bash
pahlevan debug -o json --file pahlevan-debug.json
pahlevan version
kubectl logs -n pahlevan-system daemonset/pahlevan-agent --tail=1000 > agent.log
kubectl logs -n pahlevan-system deployment/pahlevan-operator --tail=1000 > operator.log
kubectl get pahlevanpolicy -A -o yaml > policies.yaml
kubectl get containerprofile -A -o yaml > profiles.yaml
```

Include the kernel version and architecture of the affected node, the output of
`cat /sys/kernel/security/lsm` from it, and the policy that was in effect. For
anything to do with a policy not behaving as written, attach the output of
`pahlevan policy explain -f policy.yaml`: it answers the first question a
maintainer will ask, which is whether the policy says what its author thought it
said.
