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

Shipped through `v3.0.0`. See [CHANGELOG.md](CHANGELOG.md) for the full entries.

### Architecture
- Split data plane and control plane: a privileged per-node `pahlevan-agent`
  DaemonSet and an unprivileged leader-elected `pahlevan-operator` Deployment.
- Three CRDs: `PahlevanPolicy`, `ContainerProfile`, `AttackSurface`, with the
  operator driving a `selector -> learn -> enforce` lifecycle.

### eBPF data plane
- Seven CO-RE programs, all scoped per cgroup: `lsm/file_open`,
  `lsm/socket_connect`, `lsm/bprm_check_security`, `lsm/capable`,
  `tracepoint/raw_syscalls/sys_enter`, `kprobe/commit_creds` and
  `uretprobe/readline`. The last two need no BPF LSM, so they work on stock
  kernels.
- Syscall arguments on every syscall event, with a watch set of escalation
  primitives that bypass the in-kernel deduplication and report every
  occurrence rather than only the first.
- Privilege-escalation detection at `commit_creds`, discriminated by
  `task->in_execve`, so a credential change with no execve to explain it is
  separable from a setuid binary doing its job.
- Interactive shell capture, for the builtins that produce no exec, no open and
  no connect.
- Container-breakout detection by comparing the working directory's mount
  namespace with the task's, refused in every mode including learning.
- Command-line arguments, working directory and four levels of ancestry on exec
  events; the immediate parent on file, network and capability events.
- Read versus write as separate allow-set entries, so a learned read does not
  grant a write.
- IPv6 egress governed, and the protocol mixed into the network allow-set key.
- Per-arch objects for amd64 and arm64, with a test that parses both ELFs and
  asserts the same programs, attach points, maps and key/value sizes.

### Enforcement
- Five actions rather than two: `Learn`, `Deny`, `Kill`, `Audit` and `Signal`,
  with a configurable errno and signal number, packed into one `__u32` per
  cgroup so the hot path costs one map lookup. `Audit` reports what would have
  been refused and refuses nothing, and deliberately does not learn.
- Every `PahlevanPolicy` spec block is consulted: `syscallPolicy`,
  `networkPolicy`, `filePolicy`, `enforcementConfig.exceptions`,
  `blockUnknown`, `gracePeriod`, `processFilter`, `allowDNS` and
  `allowLoopback`. What a rule cannot express says so with a warning naming the
  field and the reason.
- Right-sized BPF maps through `MapSizing`, so the agent's resident memory is a
  deployment choice rather than a compiled-in constant.

### Export and integration
- A gRPC streaming event API, which requires TLS, mTLS or a bearer token: it
  refuses to start plaintext and unauthenticated unless told to with
  `--grpc-insecure`.
- Structured JSON export to a file with rotation, an HTTP webhook, and OTLP
  logs using OpenTelemetry semantic conventions, all behind a bounded queue
  that drops and counts rather than stalling the ring-buffer readers.
- Destination naming from Services, pods and nodes, so a denial reads
  `prod/postgres:5432` rather than an address.
- Kubernetes attribution on every event: namespace, pod, container, image,
  workload, node, QoS class and pod labels.

### Tooling and CI
- `pahlevan policy explain -f`, which translates a policy offline and names the
  fields that do not reach the kernel.
- `pahlevan coverage`, which maps the seven eBPF programs to the MITRE ATT&CK
  techniques their observations can help an analyst confirm or rule out - the
  shared taxonomy this page used to say nothing provided.
- Generated artifacts with drift guards: `docs/api-reference.md` from the Go
  types, `install.yaml` from the Kustomize bases, the demo GIF from its tape,
  the README diagrams from their sources, and the Pages site from the facts it
  borrows.
- Unit tests, `-race`, gofmt, coverage, an arm64 cross-build, CodeQL, Trivy and
  govulncheck all run in CI on every pull request, and a multi-arch image is
  built and pushed to GHCR.
- A commit-msg hook that rejects assistant attribution trailers.

## Near term

The honest list of what Pahlevan still cannot do. Each is written in Pahlevan's
own terms rather than as a comparison, and each is a real gap rather than a
polish item.

- **Planned: formatted delivery of findings.** OTLP, a file and an HTTP webhook
  all exist, and OTLP reaches anything a collector exports to. What is missing
  is the formatted, per-destination half: a Slack message, a PagerDuty
  incident, a template you fill in yourself. Getting a denial into a human's
  chat client is still something you build.
- **Planned: DNS and L7 parsing.** Destinations inside the cluster are named
  from Services, pods and nodes, which costs no DNS query. Destinations
  *outside* the cluster, which are the ones that matter in an exfiltration,
  are reported as an address and nothing else.
- **Planned: ancestry matchable at any depth.** Exec events carry four levels,
  and `processFilter.parentProcesses` enforces on the first hop only. A policy
  cannot say "denied if any ancestor was a shell". A process cache keyed by a
  stable execution id would lift both limits.
- **Planned: enforcement without the BPF LSM.** The four LSM programs need
  `lsm=bpf` on the kernel command line, which most distributions do not set.
  The `commit_creds` kprobe and the syscall tracepoint already work without it;
  a kprobe-based enforcement path for the rest would remove the boot-parameter
  requirement.
- **Planned: apply the generated seccomp profile.** Profiles are generated,
  honour the policy's syscall lists, are reported on `ContainerProfile`,
  materialised on every node, and rendered as a ready-to-apply patch by
  `pahlevan profile patch`. Nothing applies them: a pod's `seccompProfile`
  cannot be changed after admission and the operator deliberately runs without
  a mutating webhook.
- **Planned: a review step before a learned profile enforces.** Learning is
  trust on first use. A workload already compromised when learning starts has
  its malicious behaviour baselined. Deny lists and exceptions let an operator
  correct the edges, but nothing requires anyone to look first.
- **Planned: automate the VM eBPF tests.** The unit suite, `-race`, gofmt,
  coverage and an arm64 cross-build all run in CI. The kernel tests need a VM
  with `lsm=bpf` and are still run by hand, which means a verifier rejection
  reaches CI only if somebody remembers.
- **Planned: load the arm64 objects on an arm64 kernel.** Both objects are
  built, and a test asserts they expose the same programs and maps. What none
  of that proves is that an arm64 verifier accepts them: the VM harness is
  amd64 and no arm64 kernel has ever loaded them.
- **Planned: re-measure the footprint.** BPF map preallocation, which dominated
  an early 327 MiB figure, is 37.7 MiB across all seven programs on Linux 6.8.
  End-to-end agent memory has not been measured since, so no figure is quoted.
- **Planned: more tracing.** The OpenTelemetry pipeline is real - exporters for
  metrics, traces and logs, one shared resource, a deployable collector - but
  very little of the codebase calls `StartSpan`, so a trace shows the reconcile
  boundaries and almost nothing inside them.
- **Planned: graduate the API past `v1alpha1`**, with a conversion path, once
  the CRD shape has stopped moving.

## Later

Worth doing, not next.

- **Planned: close the seccomp loop** (the Near term entry above covers why it
  is not done; this is the shape a solution would take). Profiles are generated
  and written to the node and nothing applies them. Applying one means setting
  `securityContext.seccompProfile.localhostProfile` at admission, distributing
  the profile to the right node before the pod schedules, and deciding what
  happens when the profile is wrong. Worth comparing against the
  [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
  before building it, since that project already solves the distribution half
  and integrating may beat reimplementing.
- **Planned: profile portability.** Learn on one node or in staging, apply
  elsewhere. This needs a stable, node-independent profile representation,
  since the current allow-sets are keyed by cgroup id.
- **Planned: cluster-scoped policy**, since `PahlevanPolicy` is namespaced only.
- **Planned: populate the `policyRef` field** that `ContainerProfile` declares.
  The image, pod labels and owning workload are already on every event.
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
