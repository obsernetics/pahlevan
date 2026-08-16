# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-08-16

Ninety-eight commits since 2.0.0. The theme, unintentionally, is honesty: a
large share of this release is the discovery and removal of things that looked
like they worked and did not. Where a feature could be implemented it was;
where it could not, it now says so.

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

### Fixed

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

[Unreleased]: https://github.com/obsernetics/pahlevan/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/obsernetics/pahlevan/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/obsernetics/pahlevan/releases/tag/v1.0.0
