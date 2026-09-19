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

### Kernel probes
- A generic kprobe an operator points at any kernel function by name, with no
  rebuild. One pre-compiled program serves every probe: each attachment carries
  an attach cookie holding the probe id, so forty probes are forty links over
  one program rather than forty copies of it. Up to five arguments are captured
  and up to four selectors are ANDed against them, or against the calling uid,
  gid or pid. Actions are report, audit, kill and signal - a kprobe fires
  alongside the function rather than in place of it, so it cannot refuse the
  call, and a policy asking it to is refused at load rather than quietly
  downgraded.

### Export and integration
- Formatted delivery to where people look: a Slack incoming webhook, PagerDuty
  Events API v2, and a Go template for everything else. Denials only by default,
  deduplicated per finding over a window, and grouped one message per batch.
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
- The kernel tests run in CI. A pull request touching `bpf/`, `pkg/ebpf/` or
  the VM harness boots a guest with `lsm=bpf` under KVM and loads all seven
  programs through a real verifier, and a nightly run catches a break arriving
  from outside those paths. A test asserts the workflow's path filters cover
  every file a kernel decides about, so the job cannot go on reporting success
  by never running.
- A commit-msg hook that rejects assistant attribution trailers.

## Version 4

The 3.x line is complete in the sense that matters: the data plane observes and
enforces, and every claim on this page can be pointed at in the tree. What it
is not is *operable*. Everything Pahlevan knows is reachable through `kubectl
get -o yaml`, a Prometheus scrape, or a log line, and a learned profile is a
YAML status block that nobody reads until something is denied.

Version 4 is about that, plus the two things that have to break to stop being
temporary.

### What makes it a major

Semver majors need breaking changes, not just big ones. These are the two:

- **The API graduates to `v1beta1`.** `v1alpha1` has meant "the shape may move"
  since the first commit, and it has moved. Graduating means committing to the
  shape, shipping a conversion path, and serving both versions for a deprecation
  window. Anything reading the CRDs by version string breaks.
- **Enforcement no longer requires `lsm=bpf` on the kernel command line.** Today
  an agent on a stock distribution loads the syscall tracepoint, the
  `commit_creds` kprobe and the `readline` uretprobe, and silently cannot refuse
  a file open, a connect or an exec. Once a kprobe-based path exists, those
  clusters start enforcing where they previously only observed. That is the
  behaviour change people will feel, and it needs a release that says so rather
  than arriving in a patch.

Everything else in 4.0 is additive. If the two above slip, the rest ships as
3.x and the major waits, because a major cut for a feature list is a major
nobody can reason about.

### Workstreams

**1. An interactive CLI.** `pahlevan` is a set of one-shot commands that print
and exit. Watching a workload learn means running `status --watch` and reading
a redrawn line; comparing what was learned against what is enforced means two
commands and a mental diff; the side-by-side in the README's recording is drawn
by a shell script, not by the tool. A terminal UI built on Bubble Tea, with
Lip Gloss for layout and Bubbles for the list and viewport widgets, would make
the learned surface something an operator can move around in: a live event
stream, a per-workload learned-versus-enforcing panel, a profile diff, the
ATT&CK coverage table, and a policy explain view, all against the gRPC
streaming API that already exists.

The constraint that decides the design: **it must not break scripts.** Every
existing command keeps its exact non-interactive output, the TUI is opt-in
(`pahlevan ui`, or a bare `pahlevan` on a TTY), and anything that detects a
non-TTY, `--no-tui`, `NO_COLOR` or a `CI` environment falls back to the plain
path. A tool that renders escape codes into a pipe is worse than one with no
interface at all.

**2. An optional dashboard.** Something a team can deploy and point a browser
at, showing what each workload does: the process tree, the learned file,
network and syscall surface, the flow from learning to enforcement, and what
was denied and why. Diagrams and flows rather than another table of rows,
because the thing worth seeing is the shape of a workload's behaviour.

**Optional means optional.** It is not in `install.yaml`, not in the default
Helm values, and a cluster that never enables it runs exactly the bytes it runs
today. It is a separate Deployment with its own image, off unless asked for.

**Secure means it does not become the soft target.** A security tool that
ships a dashboard with a cluster-admin service account and a bespoke login page
has handed an attacker a better primitive than the one it defends against. So:

- Authentication and authorisation are delegated to Kubernetes. The browser
  presents a token, the dashboard calls `TokenReview` to establish who that is
  and `SubjectAccessReview` for every read, so a viewer sees exactly the
  namespaces their own RBAC allows and nothing else. No user database, no
  session secret to leak, no separate permission model to get wrong.
- Read-only by default. Changing a policy or a mode from the browser is a
  separate, explicitly enabled capability, and it is off unless someone turns
  it on.
- The service account is not cluster-admin. It needs `TokenReview`,
  `SubjectAccessReview`, and read on the three CRDs. That is the whole list.
- TLS only, `ClusterIP` only, with a `NetworkPolicy` shipped alongside. No
  `NodePort`, no `LoadBalancer`, no `hostNetwork` in anything the project
  ships; exposing it is the operator's deliberate act through their own
  ingress.
- A strict Content-Security-Policy with no inline script and no external
  origin. Assets are served from the image. A dashboard that pulls a charting
  library from a CDN at runtime has made every viewer's browser trust a third
  party, which is not a trade this project gets to make on a user's behalf.
- The agent stays the only privileged component. The dashboard reads the same
  gRPC API and CRDs any other client reads, and it gets no path into the
  kernel.

Threat model, test coverage and a `SECURITY.md` section land with the code, not
after it.

**3. The two breaking changes above**, plus the Near term items that are ready
when 4.0 is cut. Nothing here is a reason to hold the major.

## Near term

The honest list of what Pahlevan still cannot do. Each is written in Pahlevan's
own terms rather than as a comparison, and each is a real gap rather than a
polish item.

- **In progress: an interactive CLI (4.0).** `pahlevan ui` is in the tree: a
  Bubble Tea view over the existing gRPC stream, with a live event list,
  per-workload observed-versus-refused counts, a workload detail pane, and the
  coverage table read from `pkg/coverage`. It is a reader and changes nothing.
  Every existing command keeps its exact output, and a non-TTY, `--no-tui`,
  `NO_COLOR`, `TERM=dumb` or `CI` gets a plain summary instead of a drawn
  screen. Still to come: a learned-versus-enforcing diff sourced from
  `ContainerProfile` rather than inferred from the event stream, and a policy
  explain view. See [Version 4](#version-4).
- **Planned: an optional dashboard (4.0).** A deployable web view of what each
  workload does - process tree, learned file, network and syscall surface, the
  learning-to-enforcement flow, and what was denied and why - drawn as diagrams
  rather than more tables. Optional in the real sense: absent from
  `install.yaml` and the default Helm values, a separate Deployment, off unless
  asked for. Authentication and authorisation delegated to Kubernetes through
  `TokenReview` and a `SubjectAccessReview` per read, so a viewer sees only what
  their own RBAC allows; read-only by default; no cluster-admin service account;
  TLS and `ClusterIP` only with a `NetworkPolicy` alongside; a strict CSP with
  no inline script and no external origin, because a security tool whose
  dashboard loads a chart library from a CDN has made every viewer's browser
  trust a third party. See [Version 4](#version-4).
- **Planned: fail loudly when a merged release is never tagged.** The scheduled
  maintenance agent runs as the GitHub App, which cannot create tag refs, so it
  merges a release PR and the tag never appears: no tag, no release, no image,
  while `CHANGELOG.md` and the website both announce the version as current.
  This has now happened three times - `v3.1.0` sat untagged for five days, and
  `v3.3.1` and `v3.3.3` were each announced as released while nothing could
  install them. Rewriting the agent's prompt did not stop it, twice. A check
  that compares the `VERSION` in `main`'s Makefile against the pushed tags and
  fails once a release has been merged without one would, because it does not
  depend on anyone remembering.
- **Planned: Kubernetes audit-log ingestion.** Pahlevan sees what happens on a
  node and nothing of what happens at the API server, so a `kubectl exec`, a
  role binding granted, or a secret read through the API is invisible to it.
  Ingesting the Kubernetes audit stream and correlating it with the node events
  a policy already produces would close the gap between "somebody did this to
  the cluster" and "this happened inside the container".
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
