# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-08-31

Two hundred and twenty-five commits since 2.0.0. The theme, unintentionally, is
honesty: a large share of this release is the discovery and removal of things
that looked like they worked and did not. Where a feature could be implemented
it was; where it could not, it now says so.

This is a major release for two reasons, both listed under Breaking changes:
the gRPC event stream will not start unauthenticated any more, and the module
now requires Go 1.26.

### Breaking changes

- **The gRPC event stream refuses to start plaintext and unauthenticated.**

  If you run the agent with `--grpc-bind-address` and no transport security,
  it now exits at startup instead of serving. The stream carries every denial
  on the node - which pods exist, which paths they read, which destinations
  they dial, the full command line of every exec - and that is a
  reconnaissance report.

  Previously it started anyway and logged a warning. The person who forgets the
  certificate and the person who reads the startup log are rarely the same
  person, so the warning was not a control.

  To upgrade, pick one:

  ```yaml
  # mTLS, the right answer in a cluster. cert-manager can issue the pair.
  - --grpc-tls-cert=/etc/pahlevan/tls/tls.crt
  - --grpc-tls-key=/etc/pahlevan/tls/tls.key
  - --grpc-client-ca=/etc/pahlevan/tls/ca.crt
  ```

  ```yaml
  # TLS plus a bearer token, for a collector that cannot present a certificate.
  - --grpc-tls-cert=/etc/pahlevan/tls/tls.crt
  - --grpc-tls-key=/etc/pahlevan/tls/tls.key
  - --grpc-token=$(PAHLEVAN_GRPC_TOKEN)
  ```

  ```yaml
  # Or say explicitly that this listener is unreachable and you accept it.
  - --grpc-insecure
  ```

  A bearer token without TLS is still refused: in cleartext it is a token you
  have published. If you do not set `--grpc-bind-address` at all, nothing
  changes for you - the listener is off by default and always was.

- **The module requires Go 1.26.**

  `go.mod` declares `go 1.26.0`, so anything importing
  `github.com/obsernetics/pahlevan` needs Go 1.26 or newer to build. This came
  from `k8s.io/cli-runtime` 0.36.3, which requires it, and which in turn forced
  `controller-runtime` to 0.24.1.

  Running the published container image is unaffected - it ships compiled
  binaries and needs no toolchain.

### Added

- **Kernel-enforced `processFilter`.** Constrains the parent process comm, the
  effective uid and the effective gid at `bprm_check_security`. The learned
  allow-set asks whether a container has ever run a binary; this asks whether
  the process running it is allowed to. That distinction is what covers the
  interpreter already in the image, which the allow-set cannot.
- **Container-breakout detection.** An exec whose working directory belongs to
  a different mount namespace from the process is the invariant the runC
  breakout class violates (CVE-2024-21626 and its successors). Detected during
  learning as well as under enforcement, never added to the allow-set, and
  reported with its own flag, counter, alert and OTLP severity.
- **Destination naming.** A denial reads `prod/postgres:5432`, resolved from
  Services, pods and nodes the agent already caches. An address the cluster
  does not know is tagged `external`, which separates a misconfiguration from
  exfiltration. No DNS query is made.
- **OTLP export for security events**, using OpenTelemetry semantic-convention
  attribute names, plus one shared resource across metrics, traces and events
  so Grafana can join them. `examples/observability/lgtm-stack.yaml` deploys
  the collector and datasources.
- **`pahlevan policy explain -f`**, which translates a policy offline and names
  every part the data plane will not enforce. `--strict` fails a CI gate.
- **gRPC TLS, mTLS and bearer-token authentication** for the event stream, with
  the security posture printed at startup. The default is still plaintext.
- **`allowDNS` and `allowLoopback` are enforced**, as a per-cgroup flag checked
  ahead of the allow-set.

- **Syscall arguments on every syscall event.** The monitor moved from
  `raw_tracepoint/sys_enter` to `tracepoint/raw_syscalls/sys_enter`, whose
  format already carries the six arguments extracted, identically on both
  architectures. A watch set of escalation primitives - `ptrace`, `unshare`,
  `setns`, `bpf`, `mount`, `io_uring_setup` and the rest - bypasses the
  in-kernel deduplication, so they report every occurrence rather than only the
  first. The first `ptrace` a process makes is usually a debugger attaching at
  startup; the interesting one is the fourteenth.
- **Privilege-escalation detection at `kprobe/commit_creds`.** Every other
  monitor watches a request; this one watches the result. `commit_creds` is the
  single function through which any task's credentials change, so a local-root
  exploit that overwrites a `cred` struct and calls it directly lands here
  having made no syscall at all. The discriminator is `task->in_execve`: a
  setuid binary gains privilege inside `execve` and `sudo` does it all day,
  while privilege gained with none underway has no other explanation. Needs no
  BPF LSM.
- **Interactive shell capture at `uretprobe/readline`.** `cd`, `export` and
  `history -c` are shell builtins: they produce no exec, no open and no
  connect, so an exec-based monitor watches somebody work through them and
  reports nothing but the shell's own process. Attached per container through
  `/proc/<pid>/root` when a shell execs, and off by default behind
  `--trace-shell-commands`, because recording what a person types is a decision
  an operator makes deliberately.
- **Five enforcement actions instead of two.** `Learn`, `Deny`, `Kill`,
  `Audit` and `Signal`, with a configurable errno and signal number, packed
  into one `__u32` per cgroup so the hot path still costs one map lookup.
  `Audit` reports what would have been refused and refuses nothing, and
  deliberately does not learn - an audit pass that quietly added everything it
  reported would report each violation once and never again. `Signal` exists
  for `SIGSTOP`: freezing a process leaves its memory for an incident
  responder, where `SIGKILL` destroys exactly that.

### Fixed

- **`ContainerProfile` status was silently discarded on every write.** The
  resource has a status subresource, so a server-side apply to the main
  resource does not write status - a real API server drops it. Profiles were
  reaching the cluster with no counts, no learned syscalls, files, destinations
  or capabilities, no phase and no rollback history. The object existed and
  looked healthy. Found only when `controller-runtime` 0.24 started modelling
  the real server in its fake client.
- **Export formats returned canned strings.** `exportToMermaid` returned the
  literal `"graph TD"` for every cluster; GraphQL and Cytoscape returned `{}`.
- **The metrics provider was built with no readers**, so every recorded metric
  was silently discarded while `--observability-exports` reported the exporter
  as configured.
- **Nine metric recorders discarded their labels**, so per-policy questions had
  no answer and the gauges were last-writer-wins across containers.
- **Event-handler errors were discarded**, making a broken export pipeline
  indistinguishable from a quiet cluster.
- **An unbounded no-op event handler** was registered on the ring-buffer hot
  path on every reconcile, racing on a stale pointer.
- **Observability shutdown was unbounded**, hanging the agent on every rollout
  while a collector was down.
- **Four `GaugeVec`s were named `_total`**, so `rate()` over them was nonsense.
- **`mode: Off` did the opposite of what it says** - unquoted `Off` is a YAML
  1.1 boolean, and there was no enum, so it silently became Monitoring. The
  field is now validated at admission.
- **`pahlevan version` required a Kubernetes cluster**, and the Dockerfile
  injected build metadata into variables that do not exist, so every shipped
  binary reported an unknown commit and date.
- **Seccomp profiles were written world-readable** into a world-readable
  directory.
- Two goroutines ticking hourly to call empty functions; three unreachable
  vendor exporters guarded on fields nothing assigned; a test double compiled
  into every binary; and the two CLI columns that printed `N/A` over data one
  dereference away.

### Changed

- **Dependencies**: `cilium/ebpf` to 0.22.0, `prometheus/client_golang` to
  1.24.1, `go-logr` to 1.4.4, the OpenTelemetry family to 1.45.0 (log and its
  exporters to 0.21.0), `k8s.io/cli-runtime` to 0.36.3 and `controller-runtime`
  to 0.24.1. `otel/log` 0.21 removed its own `Value` and `KeyValue` types in
  favour of the ones in `go.opentelemetry.io/otel/attribute`, so a log record's
  attributes are now the same type as a span's and a metric's.
- **The README's diagrams are rendered images**, authored as HTML under
  `docs/assets/diagrams/` and regenerated by `hack/render-diagrams.sh`, rather
  than ASCII art whose box borders did not line up.
- **Commit messages are checked by a hook.** `.githooks/commit-msg` rejects
  assistant attribution trailers; `scripts/setup-hooks.sh` enables it.
- **Every policy example was invalid against the CRD** and has been rewritten.
  About twenty-five invented keys were being silently pruned by the API server,
  so the examples applied cleanly and did a fraction of what they said. A
  strict-decode test now fails the build.
- **`docs/api-reference.md` is generated from the Go types.** The hand-written
  version described an API that had never existed.
- **`install.yaml`, the Pages site and the demo GIF are all kept in step
  automatically** - each had drifted, and each now has a check that fails when
  it does.
- **Seven CRD fields are documented as inert** rather than left to look
  functional.
- `make vm-test` runs every VM test. It filtered on `TestVMLoad`, so nineteen
  tests written for the VM had never run there.

## [2.0.0] - 2026-08-14

Pahlevan 2.0.0 is a redesign. The single all-in-one operator is replaced by a
privileged per-node agent plus an unprivileged, leader-elected control plane,
and the eBPF data plane moved from placeholder code to real CO-RE programs that
observe and deny in the kernel.

### Added
- **Two-workload architecture**: `pahlevan-agent` (privileged DaemonSet, owns the
  eBPF data plane) and `pahlevan-operator` (leader-elected Deployment, no host
  access, runs with `hostUsers: false`).
- **CO-RE syscall monitor**: `raw_tracepoint/sys_enter` with a ring buffer and
  in-kernel deduplication per `(cgroup, syscall)`.
- **CO-RE file monitor** on `lsm/file_open` with path resolution via
  `bpf_d_path()` and graceful degradation when the BPF LSM is unavailable.
- **In-kernel file enforcement**: unlearned opens are denied with `EPERM`.
- **In-kernel network egress enforcement** via `lsm/socket_connect`, preceded by
  a CO-RE `kprobe/tcp_connect` network monitor for observation.
- **Process/exec monitoring and enforcement** via `lsm/bprm_check_security`.
- **Adaptive learn to enforce loop**: per-cgroup allow-sets are built during the
  learning window and the agent transitions to enforcement autonomously.
- **Seccomp profile generation** from the learned syscall set.
- **CEL `ValidatingAdmissionPolicy`** hardening for `PahlevanPolicy` resources.
- **`ContainerProfile` CRD** with profile persistence, a metrics endpoint, and an
  enforcement counter.
- **`AttackSurface` CRD** for cluster-wide posture aggregation.
- **Container attribution**: cgroup id to Kubernetes pod/container resolver.
- **`hack/vm/`**: reproducible QEMU/KVM harness that provisions a kernel with the
  BPF LSM enabled for eBPF load, attach, observe, and enforce tests.
- **Benchmark harness** measuring detection, prevention and overhead, with a
  no-agent control pass (`test/benchmark/`, `docs/benchmarks/`).
- **GitHub Pages site** (`pages/`) with a deploy workflow, published Helm chart,
  install and benchmark sections.
- **Committed bpf2go bindings and eBPF objects** so the tree builds from a clean
  checkout without clang on the build host.
- **Documentation and demo**: README with badges, an animated demo GIF, and an
  architecture diagram.

### Changed
- Helm chart and `install.yaml` rewritten for the agent plus operator split.
- Build produces three binaries: `pahlevan-agent`, `pahlevan-operator`, and the
  `pahlevan` CLI; the container image is a minimal distroless runtime.
- Go toolchain moved to 1.25 across `go.mod`, the Makefile, and the Dockerfile.
- Dependency bumps, including Kubernetes libraries to 0.35.0,
  `sigs.k8s.io/controller-runtime` to 0.22.4, `github.com/cilium/ebpf` to 0.20.0,
  `github.com/spf13/cobra` to 1.10.1, Ginkgo/Gomega, OpenTelemetry, `go-logr`,
  and `prometheus/client_golang`.
- Substantially expanded test coverage across the controller, learner, policies,
  CLI, APIs, observability, metrics, attribution, and visualization packages,
  plus decode round-trip tests and benchmarks for the eBPF event parsers.
- CI restructured into a build, push, then test flow with dependency caching;
  security workflows consolidated.
- Documentation cleaned of em dashes project-wide and the architecture SVG
  redrawn with clean connectors.

### Fixed
- Agent crash loop caused by a double eBPF attach and a duplicate controller name.
- Syscall monitor silently disabled by default because of ARRAY map zero
  initialization.
- Panic in the metrics path.
- `go.sum` inconsistency from an unused `golang.org/x/exp` dependency.
- Site layout overflow and horizontal scrolling in long code blocks.
- CodeQL and vulnerability workflows failing because eBPF bindings were not
  generated before the build.
- Reachable CVEs patched; `govulncheck` clean.

### Removed
- Admission webhook package and its integration wiring, replaced by the CEL
  `ValidatingAdmissionPolicy`.
- Dead code: the `pkg/events` package, an orphaned eBPF `mock.go`, and an unused
  eBPF manager.
- Placeholder and stubbed subsystems, replaced by working implementations.

## [1.0.0] - 2025-09-25

### Added
- First public release of Pahlevan: an eBPF-based Kubernetes security operator
  with the `PahlevanPolicy` CRD, a learning phase, enforcement modes, self-healing,
  observability, and Helm plus manifest based installation.

[Unreleased]: https://github.com/obsernetics/pahlevan/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/obsernetics/pahlevan/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/obsernetics/pahlevan/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/obsernetics/pahlevan/releases/tag/v1.0.0
