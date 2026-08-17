# Roadmap

This roadmap is derived from what is actually in the tree, not from what would
look good in a proposal. Anything marked **Done** you can point at in the code
today. Anything marked **Planned** does not exist yet, and saying otherwise
would waste the time of anyone evaluating this project.

Companion reading: [`docs/benchmarks/`](docs/benchmarks) is where the
performance numbers come from, and nothing here quotes a figure that a run did
not produce.

There are no dates. The project has one maintainer, so a date would be a guess.
The ordering within each section is roughly the intended order of work.

## Legend

| Mark | Meaning |
|---|---|
| **Done** | Implemented and in a release |
| **In progress** | Code is in the tree, not yet released, and in some cases not yet fully wired |
| **Planned** | Not implemented. No code exists |
| **Exploring** | We are not sure it is the right thing to build |

## Done

Shipped in `v2.0.0`. See [CHANGELOG.md](CHANGELOG.md) for the full entry.

### Architecture
- Split data plane and control plane: a privileged per-node `pahlevan-agent`
  DaemonSet and an unprivileged leader-elected `pahlevan-operator` Deployment.
- Operator runs with `hostUsers: false` and no host access at all.
- Agent runs with a specific capability set rather than `privileged: true`, with
  a read-only root filesystem.

### eBPF data plane
- CO-RE programs throughout, compiled at build time, with the objects and
  bpf2go bindings committed so a clean checkout builds without clang.
- Syscall observation on `raw_tracepoint/sys_enter` with in-kernel dedup per
  `(cgroup, syscall)`.
- File observation and **in-kernel enforcement** on `lsm/file_open`, with paths
  resolved in-kernel by `bpf_d_path()`.
- IPv4 egress observation and **in-kernel enforcement** on `lsm/socket_connect`.
- Exec observation and **in-kernel enforcement** on `lsm/bprm_check_security`.
- Graceful degradation: without the BPF LSM the agent still loads, still
  observes, and reports rather than failing.

### Learn to enforce
- Per-cgroup allow-sets built during a learning window, written into BPF maps.
- Autonomous transition from learning to enforcement, or manual by flipping
  `enforcementConfig.mode`.
- Seccomp profile generation from the learned syscall set.

### Kubernetes integration
- Three CRDs: `PahlevanPolicy`, `ContainerProfile` (the persisted learned
  baseline), and `AttackSurface`.
- cgroup id to pod and container attribution, including systemd and cgroupfs
  drivers and the containerd, CRI-O, and Docker id prefixes.
- CEL `ValidatingAdmissionPolicy` for pod hardening, with no admission webhook,
  no certificates, and no new failure path in the API server.
- Helm chart, `install.yaml` attached to every release, distroless image
  carrying the agent, operator, and CLI.

### Tooling
- `pahlevan` CLI: `policy` (list, get, describe, create, delete, update,
  status), `status`, `version`, `completion`.
- Four Prometheus counters exposed on the served registry: syscall, network, and
  file event totals, and enforcement actions.
- `hack/vm/`: a reproducible QEMU/KVM harness that boots a kernel with the BPF
  LSM enabled, for eBPF load, attach, observe, and enforce testing.
- `test/benchmark/`: a reproducible harness measuring detection, prevention and
  overhead, with a no-agent control pass.

## In progress

Code is in the tree and has not shipped in a release. Some of it is not yet
wired end to end, and each item says which.

- **Capability monitoring and enforcement.** An `lsm/capable` program
  (`bpf/capability_monitor.c`), learned per `(cgroup, capability)`, enforced
  with `EPERM`. Loaded, attached, and driven from the learn-to-enforce loop.
  Still needs a VM verification run and a benchmark scenario before it can be
  called done.
- **Structured JSON event export.** `pkg/export` defines a versioned envelope
  (`pahlevan.io/v1alpha1`), stdout and file sinks with rotation, a bounded
  non-blocking queue that drops rather than stall the ring-buffer readers, and
  drop counters on the correct registry. **It is not yet imported by any
  binary**, so the agent still emits log lines only. Wiring it into the agent,
  adding the Kubernetes enrichment callback, and adding the webhook sink are the
  remaining work. A `pahlevan events` CLI consumer for the envelope is being
  written alongside it.
- **Immediate-parent process ancestry.** Exec events now carry parent tgid and
  parent comm. This is one hop, on exec only, and is not the ancestry work
  described under near-term below.
- **Broadened benchmark suite.** The scenario set has grown from 4 to more than
  20, covering service account token access, `/proc` enumeration, private key
  search, interpreter abuse, persistence, setuid abuse, log clearing,
  timestomping, DNS egress, the Docker socket, mount attempts, and host path
  reads. The published results file still reflects the original four-scenario
  run and must be regenerated.
- **Refreshed benchmark run.** The published results predate the egress and exec
  enforcement paths and still say they are unwired. That is now wrong in
  Pahlevan's favour in one place and against it in another, and the run needs
  redoing rather than editing.

## Near term

The next one or two releases. These are the items that most affect whether
Pahlevan is usable by someone other than its author.

### Event API and integrations

- **Planned: gRPC event API.** A streaming event service on the agent, with the
  same envelope `pkg/export` defines, so that `pahlevan logs` can stream events
  the way `tetra getevents` does, and so that external consumers have a stable
  interface. This is the single largest functional gap against both comparators.
- **Planned: webhook and HTTP sink**, so events can reach an existing collector
  without a custom consumer.
- **Planned: Kubernetes audit-log style integration.** Two distinct pieces: emit
  denials as Kubernetes `Event` objects on the target pod, so a denial shows up
  in `kubectl describe` where an operator will actually find it, and emit a
  structured, append-only audit record suitable for shipping to a SIEM. This
  item is about Pahlevan's own denials being auditable, which is the part that
  matters for a preventive tool.
- **Planned: wire the export path into the agent** and populate the `kubernetes`
  block of the envelope from the existing attribution resolver.

### Process ancestry

- **Planned: full ancestor chain.** A process cache in the agent keyed by a
  stable execution id, populated from exec and exit events, so any event can be
  resolved to its full lineage rather than one parent. This requires exit
  tracking, which does not exist today.
- **Planned: ancestry on non-exec events.** File, network, and capability events
  currently carry pid, comm, and cgroup with no parent at all.
- **Planned: command-line arguments** on exec events.

### Reducing agent memory

An early measurement put the agent at roughly 327 MiB. BPF map preallocation
dominated that and is now 37.7 MiB; the rest has not been re-measured. Three
known contributors, in order of expected payoff:

- **Planned: right-size the BPF maps.** `file_allowed` is provisioned at 2^17
  entries and the ring buffers at 256 KiB each. The `MapSizing` hook already
  exists in the loader; the work is choosing defaults that fit a realistic node
  and exposing them as agent flags.
- **Planned: remove the per-syscall debug logging** that inflated the measured
  CPU figure, and replace it with sampled or counter-based reporting.
- **Planned: reduce Go heap churn** in the event decode path, and measure with
  a heap profile rather than by guessing.

Target: under 128 MiB steady state on a node running a normal workload mix, with
the number published in a refreshed benchmark rather than asserted here.

### ARM64 support and verification

Pahlevan is amd64 only today, and the arm64 build does not merely go untested,
it does not compile. Three concrete blockers:

- **Planned: an arm64 syscall table.** `pkg/seccomp` has only
  `syscalls_linux_amd64.go`, and because `internal/adaptive` imports the
  package, an arm64 build of the agent fails outright. This is the first thing
  to fix.
- **Planned: arm64 eBPF objects.** Every `go:generate` line hardcodes
  `-D__TARGET_ARCH_x86`, and the committed `vmlinux.h` came from an x86_64
  kernel. Both the objects and the generation flow need an arm64 variant.
- **Planned: multi-arch image and CI.** `docker-buildx` already lists arm64 in
  `PLATFORMS` but CI never calls it, and the published image is single-arch.

Not done until an arm64 VM has run `make vm-test` and a benchmark scenario has
been executed on arm64 hardware. "It compiles" is not verification for a project
that loads code into the kernel.

### Making the policy do what it says

Several `PahlevanPolicy` fields are accepted by the API server and ignored by
the agent. A field that silently does nothing is a correctness bug and a trust
problem, so these are near-term rather than later.

- **Planned: distinguish `Off` from `Monitoring`** at the data plane. Today the
  agent collapses the mode to a single boolean and the two behave identically.
- **Planned: honour `enforcementConfig.exceptions`**, so an operator can carve
  out a path or destination without abandoning enforcement.
- **Planned: honour `blockUnknown` and `gracePeriod`.**
- **Planned: honour the `syscallPolicy`, `networkPolicy`, and `filePolicy`
  blocks**, or remove them from the API. Either is acceptable; leaving them as
  decoration is not.
- **Planned: read versus write distinction** in file enforcement, which the CRD
  already implies with `readOnlyPaths` and `writeAllowedPaths`.

### Correctness and coverage gaps

- **Planned: govern IPv6 egress.** The network program returns early for
  anything that is not `AF_INET`, so IPv6 egress is allowed even in blocking
  mode. This is a bypass, not a missing feature.
- **Planned: include protocol in the network allow-set key**, which currently
  holds destination address and port only and reports TCP unconditionally.
- **Planned: detect BPF LSM availability properly.** The capability probe checks
  tracepoint, kprobe, TC, and cgroup support and does not check the one thing
  that determines whether enforcement works. The agent should report
  unambiguously, in status and in a metric, whether it can enforce on this node.
- **Planned: real self-healing.** The rollback path sets a phase and a condition
  and restores nothing, and its trigger depends on status counters that are
  never incremented. Either wire the existing implementation in `pkg/policies`
  into the agent or replace it with something smaller that actually reverts the
  BPF maps to learning mode.
- **Planned: increment the enforcement status counters** so
  `status.enforcementStatus.blocked*` reflects reality, and so that self-healing
  has an input.
- **Planned: consolidate metrics.** More than thirty metric names in
  `pkg/metrics` live on a registry that is never served and are never recorded.
  Move the ones worth keeping onto the served registry and delete the rest.
- **Planned: handle a workload that started before the agent.** Today the agent
  misses the events of an already-running workload and the cgroup never
  transitions, which the benchmark run hit and worked around by recreating the
  pod.

### Testing and CI

- **Planned: run `make test` in CI.** The unit suite exists and CI does not
  invoke it. This is embarrassing and cheap to fix.
- **Planned: automate the VM eBPF tests** on pull requests that touch `bpf/` or
  `pkg/ebpf/`, using a nested-virtualization or self-hosted runner.
- **Planned: a kernel matrix**, so that the claimed 5.7 and 5.8 floors are
  tested rather than asserted.
- **Planned: publish the benchmark from CI** rather than from a maintainer's
  laptop, so results cannot drift from the harness.

### Documentation and supply chain

- **Planned: ship all three CRDs in the Helm chart.** It currently ships only
  `PahlevanPolicy`, so chart-only installs are missing `ContainerProfile` and
  `AttackSurface`.
- **Planned: signed releases and provenance.** Sigstore signing of images,
  SLSA provenance attestations, and a published SBOM.
- **Planned: a documented upgrade path** between minor versions, including what
  happens to learned profiles.
- **Planned: complete the CLI stubs.** `attack-surface`, `logs`, `metrics`, and
  `debug` print "to be implemented" today. `logs` depends on the gRPC event API;
  the others do not and should not wait for it.
- **Planned: a troubleshooting bundle command**, equivalent to `tetra bugtool`,
  because diagnosing an eBPF attach failure over a GitHub issue is otherwise
  painful.

## Later

Worth doing, not next.

- **Planned: close the seccomp loop.** Profiles are generated and written to the
  node and nothing applies them. Applying one means setting
  `securityContext.seccompProfile.localhostProfile` at admission, distributing
  the profile to the right node before the pod schedules, and deciding what
  happens when the profile is wrong. Worth comparing against the
  [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
  before building it, since that project already solves the distribution half
  and integrating may beat reimplementing.
- **Planned: more enforcement actions.** `EPERM` is the only action today. An
  audit action that records a would-be denial without enforcing it, and a kill
  action, are both plausible. The exec program already contains an unexposed
  in-kernel `SIGKILL` mode. A past benchmark run froze a whole node with an
  unscoped kill policy, which is the cautionary note here: any kill action must
  be cgroup scoped by construction.
- **Planned: profile review and approval.** A learned baseline currently takes
  effect with nobody having looked at it. A workflow where a `ContainerProfile`
  must be approved, or diffed against the previous one, before it can enforce
  would address the biggest honest criticism of the learned model.
- **Planned: profile portability.** Learn on one node or in staging, apply
  elsewhere. This needs a stable, node-independent profile representation,
  since the current allow-sets are keyed by cgroup id.
- **Planned: cluster-scoped policy**, since `PahlevanPolicy` is namespaced only.
- **Planned: image and pod label enrichment** on events, and populating the
  `workload` and `policyRef` fields that `ContainerProfile` already declares.
- **Planned: file operation coverage beyond open**, such as rename, unlink, and
  chmod.
- **Planned: a real OpenTelemetry path**, or removal of the current wiring. A
  `TracerProvider` with zero span processors and no span ever started is worse
  than nothing, because it implies a capability that is absent.
- **Planned: exercised security process.** A tabletop run of
  [SECURITY.md](SECURITY.md) end to end, so the first real report is not the
  first time the process is used.

## Exploring

Not committed to. Feedback on any of these is welcome in an issue.

- **Non-Kubernetes deployment.** The learning model is tied to cgroups rather
  than to Kubernetes, so a plain-host mode is technically plausible. Whether it
  is worth the maintenance is another question.
- **Anomaly scoring on top of the learned baseline**, rather than a binary
  in-set or out-of-set decision.
- **Learned network policy generation**, emitting a Kubernetes `NetworkPolicy`
  or a Cilium policy from the observed egress set, so the allow-list is enforced
  by the CNI as well as by the LSM hook.
- **Sharing anonymised baselines** for common images, so a new deployment starts
  from a community profile rather than from nothing. This has obvious supply
  chain implications and would need a trust model before any code.

## Explicit non-goals

Saying no is part of a roadmap.

- **Pahlevan will not become a rule-based detection engine.** The entire premise
  is that the workload writes its own policy by running. Shipping a rule library
  would abandon it, and a rule library is only as good as the person maintaining
  it against attacks nobody has seen yet.
- **Pahlevan will not replace a CNI or NetworkPolicy.** The egress allow-set is
  a last-resort backstop at the socket layer, not a network policy engine.
- **Pahlevan will not attempt agentless operation.** In-kernel enforcement
  requires code in the kernel.
- **Pahlevan will not add a plugin framework** for arbitrary event sources. The
  project's scope is kernel-observed workload behavior.

## Community and project goals

Not features, but the honest bottleneck.

- **Grow past one maintainer.** [GOVERNANCE.md](GOVERNANCE.md) documents the
  path to reviewer and maintainer. A single maintainer is a real risk to anyone
  depending on this project, and reducing it matters more than any feature on
  this page.
- **Find and record real adopters**, at any stage, in
  [ADOPTERS.md](ADOPTERS.md). Even an evaluation that ended in "we did not adopt
  it, here is why" is valuable, and there is currently nothing.
- **CNCF Sandbox.** Submit a proposal and address whatever the TAG raises,
  including the gaps documented here.
- **Get someone other than the maintainer to run the benchmark** and reproduce
  or contradict the published numbers.

## How to influence this

Open an issue. Roadmap items are not fixed, and a concrete use case from someone
running real workloads will reorder this list faster than anything else. If you
want to work on an item, say so in an issue first so nobody duplicates the work,
then see [CONTRIBUTING.md](CONTRIBUTING.md).
