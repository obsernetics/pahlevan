# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Refreshed benchmark run to cover the `lsm/socket_connect` egress and
  `lsm/bprm_check_security` exec enforcement paths, which landed after the
  2026-08-14 measurement.

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
- **Competitive benchmark harness** and the first measured results against Falco
  and Tetragon (`docs/benchmarks/`).
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
