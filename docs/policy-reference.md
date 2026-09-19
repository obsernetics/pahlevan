# Policy reference

A `PahlevanPolicy` says which workloads Pahlevan governs, how long it watches
them before it decides what normal looks like, and what the kernel does with an
operation that falls outside that baseline. This document explains what each
block means and what it costs to get wrong.

The authoritative list of fields is [`api-reference.md`](api-reference.md),
which is generated from `pkg/apis/policy/v1alpha1/types.go` and therefore cannot
describe a field that does not exist. This document is the prose companion: what
the fields do, which combinations contradict each other, and which are accepted
by the API server and acted on by nothing.

One thing to internalise before reading any example, here or elsewhere. The
Kubernetes API server does not reject an unknown field in a custom resource; it
prunes it. A policy written against the wrong field names applies cleanly,
reports no error, shows a green status, and enforces a fraction of what it says.
The blocks are `learningConfig` and `enforcementConfig`, not `learning` and
`enforcement`. Run `pahlevan policy explain -f policy.yaml` before applying
anything: it unmarshals strictly, so a field the CRD does not have is an error
there rather than silence in the cluster.

## The shape of a policy

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: web-frontend
  namespace: default
spec:
  selector:
    matchLabels:
      app: web
    matchExpressions:
    - key: tier
      operator: In
      values: ["frontend"]
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: default

  learningConfig:
    duration: "10m"
    minSamples: 100
    autoTransition: true

  enforcementConfig:
    mode: Blocking
    gracePeriod: "2m"
    alertOnly: false
    blockUnknown: true
    exceptions:
    - type: File
      patterns: ["/var/run/secrets/kubernetes.io/serviceaccount/token"]
      reason: "rotated after the learning window closes"

  filePolicy:
    deniedPaths: ["/etc/shadow"]
    readOnlyPaths: ["/etc/nginx/nginx.conf"]

  syscallPolicy:
    deniedSyscalls: ["ptrace", "process_vm_readv"]

  networkPolicy:
    allowDNS: true
    egressRules:
    - ports:
      - port: 5432
      peers:
      - ipBlock:
          cidr: 10.43.12.7/32

  selfHealing:
    enabled: true
    rollbackThreshold: 5
    rollbackWindow: "5m"
```

Working policies for several shapes of workload live in
[`examples/policies/`](../examples/policies): a web application, a database, a
CI runner, a set of microservices, a process-filter example, and batch jobs,
which need a different pattern because a job exits before a learning window
closes.

## Selecting workloads

`spec.selector` decides which pods a policy governs. It carries `matchLabels`,
`matchExpressions` and `namespaceSelector`, and a pod must satisfy all three.

An empty selector matches everything. That is worth saying out loud, because a
policy whose selector was pruned by a typo becomes a policy that governs the
entire cluster rather than one that governs nothing.

`matchExpressions` supports four operators: `In`, `NotIn`, `Exists` and
`DoesNotExist`. The CRD does not constrain the value: `operator` is a plain
string, and `mode` is the only enumerated field in the whole schema. The node
agent treats an operator it does not recognise as "does not match", so a
misspelled `exists` produces a policy that quietly governs no pods at all. There
is no error to find; the symptom is a workload with no `ContainerProfile`.

`namespaceSelector` matches against the namespace's own labels, not the pod's.
Kubernetes stamps every namespace with `kubernetes.io/metadata.name`, so
selecting a namespace by name works through `matchLabels` without labelling
anything by hand. It is a distinct type from the pod selector and carries only
`matchLabels` and `matchExpressions`, because a namespace selector that itself
carried a namespace selector would be meaningless.

Scoping matters more than it looks. The node agent lists `PahlevanPolicy`
objects across the whole cluster and applies the first one whose selector matches
the pod, regardless of which namespace the policy lives in. A policy in
`default` that selects `app: web` and sets no `namespaceSelector` will govern an
`app: web` pod in `payments` too, and the ordering among several matching
policies is the API server's list order rather than anything you control. If a
policy is meant to apply to one namespace, say so with `namespaceSelector`.

Namespace scoping fails closed in both directions. A pod in a namespace the
agent has no labels for does not match a scoped policy, and an agent that cannot
list namespaces logs `cannot list namespaces; namespaceSelector will not match`
and stops matching every scoped policy while continuing to apply the unscoped
ones.

## Learning

```yaml
learningConfig:
  duration: "10m"
  minSamples: 100
  autoTransition: true
```

`duration` is the learning window. During it, the agent records, per cgroup,
every file the container opens (with the path resolved in-kernel, and reads kept
separate from writes), every egress destination it dials, every binary it
executes, every capability it exercises and every syscall it makes. That
recording is the baseline; nothing is written by hand.

`duration` is also the clock the node agent's per-container transition runs on.
A container becomes eligible for enforcement `duration + enforcementConfig.gracePeriod`
after its learning window opened. A `Blocking` policy that omits `duration`
therefore has a zero-length window, and its containers are flipped to enforcing
as soon as the grace period elapses, against whatever baseline happened to exist
by then. Set it deliberately.

`minSamples` and `autoTransition` drive the policy's own status phase, which is
a separate thing from the per-container transition above. `autoTransition`
allows the policy to leave `Learning` before `duration` has elapsed, and
`minSamples` is the floor that makes that safe: the phase advances early only
when at least `minSamples` samples have been collected and learning progress has
reached 80 percent.

Two fields in this block are accepted and do nothing. `windowSize` is read only
by a sampling-window learner that the agent and the operator never construct, so
it has no effect in any deployment. `lifecycleAware` is stored and displayed and
nothing acts on it; a restarted container gets a new cgroup id and therefore a
new baseline whether it is set or not. Both are reported by
`pahlevan policy explain`.

## Enforcement

```yaml
enforcementConfig:
  mode: Blocking
  gracePeriod: "2m"
  alertOnly: false
  blockUnknown: true
```

`mode` is the only field in the CRD with an enum, and the enum is load-bearing.
Without it the API server accepts any string, and the agent maps anything it
does not recognise onto `Monitoring`, so a typo produces a policy that looks
applied and enforces nothing. The trap that made this an enum: `mode: Off`
unquoted is a YAML 1.1 boolean, arrives as `false`, and used to become
`Monitoring` silently, which is the opposite of switching a policy off. Write
`mode: "Off"` in quotes, or the API server will tell you.

- `Off` means the workload is not governed at all. No learning, no
  `ContainerProfile`, no enforcement. It is the operator saying "ignore this",
  and it must not cost a profile.
- `Monitoring` learns and reports but never flips the kernel to denying. This is
  the safe starting point for a workload you do not fully understand.
- `Blocking` learns, then denies anything outside the baseline in-kernel.

Changing the mode of a live policy is not symmetrical, which matters when you
are undoing something. `Off` is applied retroactively: on its next reconcile the
agent clears every enforcement bit for the containers that policy governs and
stops tracking them, dropping their in-memory baselines with it. Moving from
`Blocking` to `Monitoring` is not retroactive: it stops further containers being
flipped to enforcing and leaves the ones already enforcing exactly as they are,
until their pods restart onto new cgroups or self-healing rolls them back.

`gracePeriod` is held after the learning window closes and before enforcement
begins, so a workload whose startup behaviour differs from its steady state is
observed in both before anything is refused.

`alertOnly` and `blockUnknown` both interact with `mode`, and both resolve
downwards rather than upwards. `alertOnly: true` downgrades `Blocking` to
`Monitoring`. `blockUnknown` is a pointer precisely so that unset and false mean
different things: unset means "the default for the mode", which under `Blocking`
is true, while an explicit `blockUnknown: false` downgrades `Blocking` to
`Monitoring`. Default-deny of unlearned behaviour is the only enforcement the
kernel data plane performs, so a `Blocking` policy that does not block unknown
behaviour would enforce nothing, and pretending otherwise would be worse than
saying so.

Negative durations are not errors. `learningConfig.duration` and
`enforcementConfig.gracePeriod` below zero are treated as zero, with a warning.

### Exceptions

```yaml
enforcementConfig:
  exceptions:
  - type: File
    patterns: ["/var/log/app/current"]
    reason: "opened only during the nightly roll"
  - type: Network
    patterns: ["10.43.12.7:5432"]
  - type: Syscall
    patterns: ["mount"]
    temporary: true
    expiresAt: "2026-10-01T00:00:00Z"
```

An exception widens the allow-set with behaviour that never occurred during the
learning window. `type` is `File`, `Network` or `Syscall`; anything else is
reported and skipped.

The pattern format differs per type, because each one is keyed differently in
the kernel. `File` patterns are exact resolved paths and grant both read and
write. `Network` patterns are `host:port` with a literal IP address, because a
DNS name has no stable allow-set key. `Syscall` patterns are syscall names and
reach the generated seccomp profile rather than a BPF map.

`temporary` with `expiresAt` is applied until that moment and reported as
expired afterwards, so a temporary decision cannot become a permanent hole.
`temporary` without `expiresAt` never expires, and says so in a warning.

## What the kernel does with a violation

Under the hood the data plane does not have an on/off switch. Each governed
cgroup carries a packed action in a per-hook mode map: bits 0 to 7 the action,
bits 8 to 15 a signal number, bits 16 to 31 an errno. One 32-bit value, one map
lookup on the hot path, and an absent entry reads as zero, which is `Learn`. The
kernel half is `bpf/enforce.h` and the userspace half is `pkg/ebpf/action.go`;
the two move together.

There are five actions:

| Action | Refuses | Learns | What it does |
|---|:---:|:---:|---|
| `Learn` | no | yes | Observes and widens the allow-set. |
| `Deny` | yes | no | Refuses with the configured errno, `EPERM` by default. |
| `Kill` | yes | no | Refuses and sends `SIGKILL` to the task that tried. |
| `Audit` | no | no | Reports what would have been refused, and allows it. |
| `Signal` | yes | no | Refuses and sends a configured signal. |

`Audit` is the one worth understanding in detail, because it is the only action
that reports a violation and lets it through. That is what makes it useful for a
rollout: somebody switching a workload they do not fully own needs to know what
*would* be denied before anything is. Learning mode is not a substitute, because
it widens the allow-set as it goes, so the very operation that would have been
denied is absorbed into the baseline instead of reported. `Audit` deliberately
does not learn, for the same reason: an audit pass that quietly added everything
it reported would report each violation once and never again. Its events carry a
would-deny flag rather than a denied flag, and it counts into
`pahlevan_ebpf_would_deny_total` rather than `pahlevan_ebpf_denials_total`, so a
planned dry run does not fire the alerts an outage fires.

`Signal` exists because of `SIGSTOP`. Freezing a process leaves its memory, its
open descriptors and its thread state intact for somebody to examine, where
`SIGKILL` destroys exactly the evidence an incident responder wants.

The errno is configurable for the same class of reason: a workload that copes
with `ENOENT` and treats `EPERM` as fatal is better served by the errno it can
handle. Zero means `EPERM`. An errno above 4095 is rejected before it is written,
because a value in that range is one the kernel reads as a pointer rather than
as an error, which turns a denial into undefined behaviour.

What a `PahlevanPolicy` can select today is the `Learn` and `Deny` ends of that
range: `Monitoring` installs `Learn`, `Blocking` installs `Deny` with `EPERM`,
and `Off` does not govern the container at all. `Kill`, `Audit` and `Signal` are
implemented in the kernel programs and in `pkg/ebpf`, and are reachable through
that Go API and through kernel probes, but no field in this CRD selects them yet.
They are documented here because their behaviour is what the counters and the
event flags already describe, and because a reader looking at
`pahlevan_ebpf_would_deny_total` deserves to know what produces it.

Every hook that can refuse an operation is an LSM hook: `lsm/file_open`,
`lsm/socket_connect`, `lsm/bprm_check_security` and `lsm/capable`. All four need
the BPF LSM active on the node. Without it the agent still runs and still
observes through the tracepoint, kprobe and uretprobe programs, but no policy on
that node refuses anything. See
[troubleshooting](troubleshooting.md) for how to tell, and
[`lsm-support.md`](lsm-support.md) for the kernel side.

## File policy

```yaml
filePolicy:
  allowedPaths: ["/app/data/current"]
  deniedPaths: ["/etc/shadow"]
  readOnlyPaths: ["/etc/nginx/nginx.conf"]
  writeAllowedPaths: ["/var/log/app/current"]
  executableFilter:
    allowedExecutables: ["/usr/sbin/nginx"]
    deniedExecutables: ["/bin/sh"]
```

Paths are exact and fully resolved. Enforcement keys on the path the kernel
resolves, which follows symlinks, so `/etc/os-release` grants nothing on a
distribution where it links to `/usr/lib/os-release`. Wildcards are not
supported: the allow-set is a hash of the exact path, so `*` is matched
literally and the rule never fires. A pattern containing `*`, `?` or `[` is
reported as such rather than silently doing nothing.

Reads and writes are separate entries in the allow-set, which is what makes the
four list fields distinct rather than decorative:

- `allowedPaths` grants both. An operator naming a path without qualification
  means the workload may use it.
- `deniedPaths` revokes both, and removes the path from the learned baseline, so
  a denial cannot be sidestepped by opening the path the other way.
- `readOnlyPaths` grants the read and revokes the write.
- `writeAllowedPaths` grants both.

That split is not theoretical. A web server reads `/etc/passwd` at startup, so
it lands in the baseline; keying on the path alone would have let anything
inside the container append a root-equivalent account to it afterwards.

`executableFilter` seeds and revokes entries in the exec allow-set, which is
enforced at `bprm_check_security`.

Two fields here are inert. `defaultAction` cannot express a third thing:
default-deny of unlearned behaviour is what `Blocking` already is, and `Allow`
is what `Monitoring` already means. `executableFilter.requireSignature` has no
effect because nothing verifies executable signatures and the kernel hook has no
way to.

## Syscall policy

```yaml
syscallPolicy:
  allowedSyscalls: ["mount"]
  deniedSyscalls: ["ptrace", "process_vm_readv"]
  capabilityFilter: ["CAP_NET_BIND_SERVICE"]
  processFilter:
    commands: ["/usr/sbin/nginx"]
    users: ["101"]
    parentProcesses: ["nginx"]
```

Syscalls are confined by a generated seccomp profile, not by a BPF map. The
eBPF syscall program observes every syscall and cannot refuse one: seccomp is
installed at exec, so an already-running process cannot be retroactively
filtered. What Pahlevan does instead is emit, from the learned syscall set, a
default-deny profile (`SCMP_ACT_ERRNO`) that allows the learned syscalls plus a
small safety baseline of `exit`, `exit_group`, `rt_sigreturn`,
`restart_syscall`, `brk`, `mmap`, `munmap`, `mprotect`, `futex`, `nanosleep`,
`clock_nanosleep` and `sched_yield`, so a confined process can still start,
sleep, take signals and exit cleanly.

`allowedSyscalls` is unioned into that profile and `deniedSyscalls` is applied
last, so a denial wins over the learned set, over an explicit allow, and over
the safety baseline. An operator who explicitly denies a syscall meant it, and
quietly keeping it would make the profile misrepresent what the workload can
call. Neither list is validated against the syscall table: a typo is applied
literally rather than rejected.

The profile is only written when the agent runs with `--seccomp-dir`, and it
takes effect when a pod references it as a `localhostProfile`. Because seccomp
is installed at exec, that confinement applies to new pods of the workload, not
to the pod that was learned from. This is why
`status.enforcementStatus.blockedSyscalls` is always zero: the kernel does not
report seccomp denials back to the agent.

`capabilityFilter` names capabilities that may be exercised, written either as
`CAP_NET_BIND_SERVICE` or `net_bind_service`. A name that is not a capability is
reported rather than guessed at.

`processFilter` answers a different question from the allow-sets. The allow-set
answers "has this container run this binary"; the filter answers "is this
process allowed to run it". Both are enforced in `bprm_check_security`.

- `commands` names binaries, which the exec allow-set already governs, so it is
  folded into that rather than becoming a fourth filter dimension. Entries must
  be absolute paths, because the kernel matches the resolved binary path; a
  relative entry is reported and ignored.
- `users` and `groups` are numeric. The kernel sees uids, not names: it has no
  view of the container's `/etc/passwd`, and resolving a name on the node would
  resolve it against the wrong file entirely. A non-numeric entry is reported
  and ignored.
- `parentProcesses` is matched against the kernel's `comm` field, which is
  `TASK_COMM_LEN` bytes, so only the first 15 characters are compared. A longer
  name is accepted with a warning saying so.

`syscallPolicy.defaultAction` is inert, for the same reason as the file one.

## Network policy

```yaml
networkPolicy:
  allowLoopback: true
  allowDNS: true
  egressRules:
  - ports:
    - port: 5432
    peers:
    - ipBlock:
        cidr: 10.43.12.7/32
    action: Allow
```

Enforcement happens at `lsm/socket_connect`, which governs egress only.
`ingressRules` are accepted by the API and ignored, with a warning that says why.

The egress allow-set is a hash of the exact `(address, port)` pair, and
everything that follows is a consequence of that:

- A CIDR must be a single host, `/32` or `/128`. Anything wider has no
  representation in a hash map and is reported with the number of addresses it
  would have needed. `ipBlock.except` is ignored, because a single-host block
  has nothing to except.
- `podSelector` and `namespaceSelector` peers cannot be resolved to a fixed
  address at translation time and are reported rather than half-applied.
- A rule with no ports seeds nothing, because there is no key without a port.
- A port range is enumerated entry by entry, so it is capped at 1024 ports per
  rule. A rule spanning the whole port space would insert 65535 entries per
  address into an LRU map and evict the learned baseline, which would break the
  workload in a way that looks nothing like the rule that caused it.

`allowLoopback` and `allowDNS` are per-cgroup flags checked ahead of the
allow-set rather than allow-set entries, because they name a class of
destination rather than an address. Seeding a guessed set of loopback addresses
would be both incomplete and impossible to withdraw.

`egressRules[].action` selects whether the rule's destinations are added to the
allow-set or removed from it. `networkPolicy.defaultAction` is inert.

## Self-healing

```yaml
selfHealing:
  enabled: true
  rollbackThreshold: 5
  rollbackWindow: "5m"
```

Enforcement built from a learned baseline can be wrong when the baseline was
incomplete, and a container that starts failing immediately after Pahlevan flips
it to enforcing is, far more often than not, failing because of that. Rollback
returns it to learning.

Only the window immediately after the enforce transition is examined. Past it
the baseline is treated as settled, so a container that runs fine for an hour and
then legitimately gets denied is not un-enforced by an attacker's noise.

- `enabled: false` means the container stays enforcing whatever happens, which
  is what turning self-healing off asks for.
- `rollbackThreshold` is the number of in-kernel denials inside the window that
  triggers a rollback. Because the count is bounded by the window, it is a rate.
  The default is 10.
- `rollbackWindow` is that window. The default is 5 minutes.

Pod distress triggers a rollback independently of the denial count: entering
`CrashLoopBackOff`, restarting, or going from ready to not ready, each measured
against a baseline captured at the instant enforcement began, so a pod that was
already crash-looping before Pahlevan touched it is not blamed on enforcement.

A rollback clears every enforcement bit, restarts the learning window, writes a
`Warning` Event on the pod with reason `EnforcementRolledBack` saying which
signal fired, and imposes a cooldown of 10 minutes multiplied by the rollback
count, so a container that keeps failing backs off instead of flapping. After
three enforcement attempts the container stays in learning permanently and the
agent logs `enforcement attempt cap reached; container stays in learning (monitor only)`.

`recoveryStrategy` accepts `Rollback`, `Relax` and `Maintenance`; only
`Rollback` is implemented, and the other two are reported as unimplemented
rather than silently behaving like `Rollback`.

## Observability

`spec.observabilityConfig`, with all of its `metrics`, `tracing`, `logging` and
`visualization` sub-blocks, is inert in its entirety. Telemetry is configured by
the agent's flags (`--observability-exports`, `--otlp-endpoint`,
`--metrics-detail` and the export and notification flags documented in
[`api-reference.md`](api-reference.md)) and applies to the whole node rather
than per policy. Setting anything in this block produces a warning and changes
nothing.

## Status

The status is written by the node agents and rolled up from the per-container
`ContainerProfile` resources.

```yaml
status:
  phase: Enforcing
  conditions:
  - type: Ready
    status: "True"
    reason: Initialized
  learningStatus:
    startTime: "2026-09-19T10:00:00Z"
    samplesCollected: 15420
    syscallsLearned: 62
    filePathsLearned: 128
    networkFlowsLearned: 4
    progress: 100
  enforcementStatus:
    blockedTotal: 3
    blockedFileAccess: 2
    blockedExecs: 1
    enforcingContainers: 4
    totalContainers: 5
  lastUpdated: "2026-09-19T10:30:00Z"
```

`phase` is one of `Initializing`, `Learning`, `Transition`, `Enforcing`,
`Failed` or `RollingBack`. Condition types are `Ready`, `Learning`,
`Enforcing`, `Healthy` and `Error`.

`enforcementStatus` counts in-kernel denials by kind: `blockedFileAccess`,
`blockedNetworkConnections`, `blockedExecs` and `blockedCapabilities`, with
`blockedTotal` as their sum across every container the policy governs.
`blockedSyscalls` is always zero and is kept for API compatibility, for the
seccomp reason given above. `enforcingContainers` and `totalContainers` say how
many of the selected containers have actually reached enforcement, which is the
number to look at when a policy says `Enforcing` and a workload is not being
enforced.

`kubectl get pahlevanpolicy` prints `Phase`, `Learning` (the learning progress
percentage), `Blocked` (`blockedTotal`) and `Age`.

The learned baseline itself lives in `ContainerProfile`, one per container, with
the learned syscalls, file paths, egress destinations, executables and
capabilities, the rollback history, and a reference to the generated seccomp
profile. `pahlevan profile list` and `pahlevan profile get` read them.

## Checking a policy before applying it

```bash
pahlevan policy explain -f policy.yaml
pahlevan policy explain -f policy.yaml --strict
```

This translates the policy offline, with no cluster, prints what will be written
into the kernel allow-sets, and names every part that will not be enforced: an
ingress rule, a CIDR wider than a host, a glob, a DNS name, an over-wide port
range, an expired exception, an inert field. It also rejects a field the CRD does
not have, which the API server would otherwise prune without a word. `--strict`
exits non-zero, so a policy that quietly does less than it says can fail a CI
gate rather than a production incident.

In a running cluster the same warnings are logged once per policy generation by
the agent, under `policy rule is not fully representable`.
