<div align="center">

<h1>Pahlevan</h1>

<p><b>eBPF-powered runtime security for Kubernetes.</b><br/>
Self-learning workload baselines, enforced <i>in-kernel</i> — no hand-written rules.</p>

<p>
  <a href="https://github.com/obsernetics/pahlevan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/obsernetics/pahlevan/ci.yml?branch=main&label=CI&logo=github" alt="CI" /></a>
  <a href="https://goreportcard.com/report/github.com/obsernetics/pahlevan"><img src="https://goreportcard.com/badge/github.com/obsernetics/pahlevan" alt="Go Report Card" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white" alt="Go 1.25" /></a>
  <a href="https://github.com/obsernetics/pahlevan/releases"><img src="https://img.shields.io/github/v/release/obsernetics/pahlevan?sort=semver&color=success" alt="Latest release" /></a>
  <a href="https://github.com/obsernetics/pahlevan/stargazers"><img src="https://img.shields.io/github/stars/obsernetics/pahlevan?style=flat&logo=github&color=yellow" alt="GitHub stars" /></a>
  <br/>
  <img src="https://img.shields.io/badge/Kubernetes-1.24%2B-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes 1.24+" />
  <img src="https://img.shields.io/badge/eBPF-CO--RE-FF6600?logo=linux&logoColor=white" alt="eBPF CO-RE" />
  <img src="https://img.shields.io/badge/LSM-BPF%20enforcement-8A2BE2?logo=linux&logoColor=white" alt="LSM BPF enforcement" />
  <a href="#contributing"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome" /></a>
</p>

<img src="docs/assets/demo.gif" alt="Pahlevan learn-then-enforce demo: a workload is profiled during a learning window, then an attacker's read of /etc/shadow is denied in-kernel with EPERM" width="820" />

</div>

---

## Why Pahlevan?

Kubernetes workloads face **runtime attacks** that slip past image scanning and
perimeter defenses. Most runtime tools either *watch* (alert-only) or make you
*write the rules yourself*. Pahlevan does neither: it **learns** what each workload
normally does, then **blocks the rest in-kernel** the moment enforcement is on.

- **Auto-learning, not manual rules.** Files a container opens during a learning
  window are added to a per-cgroup allow-set automatically. No `TracingPolicy`,
  no Falco rule language.
- **Real in-kernel enforcement.** Under enforcement, an open of an unlearned path
  is denied with `EPERM` by an `lsm/file_open` BPF program — the syscall never
  succeeds. Detection tools can only tell you it already happened.
- **Accurate attribution.** Events are tied to the real container via
  `bpf_get_current_cgroup_id()`, and file paths are resolved in-kernel with
  `bpf_d_path()`.

| | **Pahlevan** | Falco | Tetragon | Cilium |
| --- | --- | --- | --- | --- |
| Primary model | Adaptive policy operator | Threat detection | Observability + tracing | Network security |
| Learns behavior | **Auto (per-cgroup)** | Manual rules | Manual `TracingPolicy` | Static policy |
| File access enforcement | **Blocks in-kernel (LSM BPF)** | Alert only | Possible, hand-written | — |
| Rules to author | **None (learned)** | Many | Per-policy | Network rules |
| Attribution | cgroup id + `d_path` | container context | cgroup/process | endpoint/identity |
| Coverage | Syscalls, files *(net/seccomp roadmap)* | Runtime events | Kernel tracing | L3–L7 traffic |

> Falco and Tetragon are excellent observability tools. Pahlevan's distinct claim is
> **closing the loop**: learn the baseline, then *prevent* the deviation in the kernel.

---

## Features

- **Adaptive learning** — per-cgroup allow-sets built from observed file opens during a learning window.
- **In-kernel file enforcement** — `lsm/file_open` denies unlearned opens with `EPERM` (requires BPF LSM).
- **Full syscall observation** — a `raw_tracepoint/sys_enter` sees every syscall, deduplicated in-kernel per `(cgroup, syscall)`.
- **CO-RE eBPF** — compile-once/run-everywhere programs; portable across kernels without per-node compilation.
- **Kubernetes-native** — a `PahlevanPolicy` CRD drives a `selector → learn → enforce` lifecycle.
- **Self-healing** — automatic policy rollback when enforcement disrupts a workload.
- **Least-privilege control plane** — the operator runs with `hostUsers: false` (user namespace) and needs no host access.
- **Roadmap** — network egress/ingress enforcement and seccomp syscall enforcement (the CRD already models them; kernel enforcement is in progress).

---

## Architecture

Pahlevan splits the **data plane** (per-node, privileged) from the **control plane**
(cluster-wide, unprivileged) — the same node-instrumentation model as Falco and
Tetragon, but with a leader-elected operator driving policy.

```mermaid
flowchart TB
  subgraph CP["Control plane"]
    OP["Operator (Deployment, leader-elected)<br/>hostUsers: false / user namespace<br/>policy lifecycle • status aggregation • admission"]
    CRD["PahlevanPolicy CRD"]
  end

  subgraph Node["Each node"]
    AG["Agent (privileged DaemonSet)<br/>loads & attaches eBPF • per-cgroup baselines • local enforcement"]
    subgraph K["Linux kernel (eBPF data plane)"]
      TP["raw_tracepoint/sys_enter<br/>observe all syscalls<br/>(dedup per cgroup,syscall)"]
      LSM["lsm/file_open<br/>observe + DENY opens<br/>bpf_d_path • cgroup id"]
    end
    AG --> TP
    AG --> LSM
  end

  CRD --> OP
  OP -- "desired policy" --> AG
  AG -- "learning/enforcement status" --> OP
```

- **Agent** — a privileged **DaemonSet** on every node. It owns the eBPF data plane:
  loading and attaching programs, building per-container baselines, and enforcing
  locally in the kernel.
- **Operator** — a leader-elected **Deployment** control plane. It requires no host
  access and runs in a **user namespace** (`hostUsers: false`), handling policy
  lifecycle, cluster-wide status aggregation, and admission.

See [`docs/architecture.md`](docs/architecture.md) for details.

---

## Quick Start

```bash
# 1. Install CRDs, RBAC, the operator, and the node agents
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# 2. Deploy a sample workload
kubectl create deployment nginx --image=nginx
kubectl label deployment nginx app=nginx

# 3. Apply an adaptive policy
cat <<'EOF' | kubectl apply -f -
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: nginx-security
spec:
  selector:
    matchLabels:
      app: nginx
  learningConfig:
    duration: 5m          # observe normal behavior for 5 minutes
    autoTransition: true  # then switch to enforcement automatically
  enforcementConfig:
    mode: Monitoring      # start in Monitoring; use Blocking to deny in-kernel
  selfHealing:
    enabled: true         # roll back if enforcement breaks the workload
EOF

# 4. Watch it learn, then enforce
kubectl get pahlevanpolicy nginx-security -w
```

Set `enforcementConfig.mode: Blocking` once you trust the learned baseline to have
denials enforced in the kernel. More examples live in [`examples/`](examples).

> **Helm:**
> ```bash
> helm repo add pahlevan https://obsernetics.github.io/pahlevan-charts
> helm install pahlevan pahlevan/pahlevan-operator -n pahlevan-system --create-namespace
> ```

---

## How it works: learn → enforce

1. **Select.** A `PahlevanPolicy` selector matches target pods; the agent identifies
   their cgroups via `bpf_get_current_cgroup_id()`.
2. **Learn.** During the learning window, every file a container opens is recorded
   (path resolved in-kernel with `bpf_d_path`) and added to that cgroup's allow-set.
   Syscalls are observed in parallel and deduplicated per `(cgroup, syscall)`.
3. **Transition.** On `autoTransition` (or when you flip the mode), the policy moves
   to enforcement.
4. **Enforce.** An open of a path that was **not** learned is **denied in-kernel with
   `EPERM`** by the `lsm/file_open` hook — before the operation completes.

This flow is verified in a VM on Linux 6.8 with the BPF LSM enabled. Representative
output from the enforcement test:

```text
learned 28 (cgroup,path) allow-set entries
learned /etc/hostname allowed under enforcement
DENIED in-kernel as expected: cat /etc/os-release -> exit status 1
```

The demo at the top of this page is a scripted replay of exactly this behavior.

---

## Requirements

- **Kubernetes v1.24+** (the user-namespace operator needs **v1.30+**).
- **Linux kernel 5.8+** for observation (CO-RE, ring buffer, `CAP_BPF`).
- **Kernel 5.7+ with `CONFIG_BPF_LSM` and `lsm=bpf`** for in-kernel enforcement.
  Monitoring-only mode works without the BPF LSM.
- **~256MB memory / 100m CPU** per node agent (baseline).

See [`docs/system-requirements.md`](docs/system-requirements.md) and
[`docs/lsm-support.md`](docs/lsm-support.md).

---

## Benchmarks

Pahlevan ships a reproducible competitive benchmark harness (vs. Falco and
Tetragon) built from real attack scenarios in
[`test/benchmark/`](test/benchmark). Because enforcement requires the BPF LSM, the
harness runs inside an eBPF-capable VM:

```bash
make test-benchmark
```

Methodology and results live in **[`docs/benchmarks/`](docs/benchmarks/)**. Results
are **generated by the harness, not hand-written** — no numbers are published here
until a run is committed.

---

## Development

```bash
make build          # build the agent, operator, and CLI binaries
make test           # unit tests (with generated CRDs/manifests, fmt, vet)
make lint           # golangci-lint + yamllint
make manifests      # regenerate CRDs and RBAC from Go types
make ebpf-build     # regenerate CO-RE eBPF objects + Go bindings (needs clang + libbpf-dev)
```

**eBPF work runs in a VM** — never load or attach programs on your host. The
[`hack/vm/`](hack/vm) helpers provision a kernel with the BPF LSM enabled:

```bash
hack/vm/up.sh       # bring up the eBPF-capable VM
make vm-test        # run the eBPF load/observe/enforce tests inside it
hack/vm/down.sh     # tear it down
```

Run `make help` for the full target list.

---

## Contributing

Contributions are welcome. Please open an issue to discuss substantial changes
first, run `make test lint` before submitting, and keep eBPF changes verifiable via
`make vm-test`. See [`docs/`](docs) for architecture, policy reference, and
troubleshooting guides.

---

## License

Licensed under the [Apache License 2.0](LICENSE).
