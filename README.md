<div align="center">

<h1>Pahlevan</h1>

<p><b>Your workload writes its own security policy. The kernel enforces it.</b></p>

<p>
  <a href="https://github.com/obsernetics/pahlevan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/obsernetics/pahlevan/ci.yml?branch=main&label=CI&logo=github" alt="CI" /></a>
  <a href="https://goreportcard.com/report/github.com/obsernetics/pahlevan"><img src="https://goreportcard.com/badge/github.com/obsernetics/pahlevan" alt="Go Report Card" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26" /></a>
  <a href="https://github.com/obsernetics/pahlevan/releases"><img src="https://img.shields.io/github/v/release/obsernetics/pahlevan?sort=semver&color=success" alt="Latest release" /></a>
  <a href="https://github.com/obsernetics/pahlevan/stargazers"><img src="https://img.shields.io/github/stars/obsernetics/pahlevan?style=flat&logo=github&color=yellow" alt="GitHub stars" /></a>
  <br/>
  <img src="https://img.shields.io/badge/Kubernetes-1.24%2B-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes 1.24+" />
  <img src="https://img.shields.io/badge/eBPF-CO--RE-FF6600?logo=linux&logoColor=white" alt="eBPF CO-RE" />
  <img src="https://img.shields.io/badge/LSM-BPF%20enforcement-8A2BE2?logo=linux&logoColor=white" alt="LSM BPF enforcement" />
  <a href="#contributing"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome" /></a>
</p>

<img src="docs/assets/demo.gif" alt="Pahlevan learn-then-enforce demo: a workload is profiled during a learning window, then an attacker's read of /etc/shadow, exec of nc, and IPv6 egress are each denied in-kernel with EPERM" width="880" />

</div>

## The idea

A container is the most predictable thing in your infrastructure. It runs one
program. It opens the same files every time. It dials the same handful of
destinations. It uses maybe sixty of the kernel's four hundred syscalls, and it
will use exactly those sixty for as long as the image is deployed.

Pahlevan watches a container do all of that, once, and then refuses everything
else — in the kernel, at the moment of the attempt, with `EPERM`.

Nobody writes a rule. There is no rule to write. The container already told you
what it does; the only question was whether anything was listening.

```
  learning window                        enforcement
 ┌─────────────────────┐               ┌──────────────────────────┐
 │ open /etc/nginx/*   │──┐            │ open /etc/nginx/*     ok  │
 │ open /var/log/*     │  │  becomes   │ open /var/log/*       ok  │
 │ connect 10.0.1.7:5432│ ├───────────▶│ connect 10.0.1.7:5432 ok  │
 │ exec nginx          │  │  the       │ ─────────────────────────│
 │ 61 syscalls         │──┘  allow-set │ open /etc/shadow    EPERM │
 └─────────────────────┘               │ exec /tmp/xmrig     EPERM │
                                       │ connect 45.9.1.4:80 EPERM │
                                       └──────────────────────────┘
```

## What that buys you

**An attacker inherits your baseline, not root.** A command-injection bug in a
Python service gets an attacker `python3` — because the service runs `python3`
constantly and it is in the allow-set. What it does not get them is
`/etc/shadow`, an egress to an address the workload never dialed, a binary
dropped in `/tmp`, or `CAP_SYS_ADMIN`. Every one of those is refused before the
syscall returns.

**The policy is never out of date.** A learned baseline describes the image that
is actually running. Redeploy with a new dependency and the next learning window
picks it up. There is no rule set to review, no detection content to subscribe
to, and no gap between "we deployed something new" and "somebody updated the
rules".

**A denial is a fact, not a score.** There is no threshold, no anomaly model, no
confidence percentage. The kernel either found the path in a hash map or it did
not. When Pahlevan says a container tried to read `/etc/shadow`, it did, and it
did not succeed.

## The trade, stated plainly

A baseline narrow enough to stop an attacker is narrow enough to stop you.

If you `kubectl exec` into a production pod and run `curl`, Pahlevan will deny
it, because the workload never ran `curl` and Pahlevan cannot tell your hands
from someone else's. That is not a bug being worked around — it is the same
mechanism working correctly, and every honest evaluation of this tool has to
start there.

Three things exist because of it: `Monitoring` mode, which learns and reports
without ever denying; self-healing, which returns a container to learning if
enforcement breaks it; and policy exceptions, which let you widen the set
deliberately and in writing. Use the first one until you believe the baseline.

## What it watches

Seven eBPF programs, all CO-RE, all scoped to a single cgroup so nothing leaks
across containers or reaches the rest of the node.

| Program | Sees | Does |
|---|---|---|
| `lsm/file_open` | Every open, path resolved in-kernel by `bpf_d_path` | Refuses an unlearned path |
| `lsm/socket_connect` | Every connect, IPv4 and IPv6, named against cluster Services | Refuses an unlearned destination |
| `lsm/bprm_check_security` | Every exec: binary, argv, cwd, four levels of ancestry | Refuses an unlearned binary, or one its parent may not launch |
| `lsm/capable` | Every capability check, plus the task's effective/permitted/inheritable sets | Refuses a capability never exercised |
| `kprobe/commit_creds` | The moment privilege actually changes | Reports it; kills the task if you ask it to |
| `tracepoint/raw_syscalls/sys_enter` | Every syscall, with its six arguments | Becomes the generated seccomp profile |
| `uretprobe/readline` | Commands typed at an interactive prompt | Records what somebody with a shell actually did |

"Refuses" is five choices, not one. Per workload you pick **Deny** (`EPERM`, or
an errno you name), **Kill**, **Signal** (`SIGSTOP` freezes the process with its
memory intact, which `SIGKILL` destroys), **Audit** (report it and let it
through), or **Learn**. Audit is the one to roll out with: it reports every
operation that *would* have been refused without refusing any of them, and
unlike learning mode it does not widen the baseline as it goes.

Two of those are worth pointing at directly.

**`commit_creds`** is the single function through which any task's credentials
change. A local-root exploit that overwrites a `cred` struct and calls it
directly makes no syscall a syscall monitor could see — but it lands here, and
it lands with no `execve` underway to explain it, which is what separates it
from `sudo` doing its job. It reports by default and kills only for workloads
you have explicitly marked as never legitimately escalating, because the only
response available at that site is a signal and a false positive there ends a
process rather than denying one operation.

**`readline`** catches what the kernel cannot. `cd /root`, `export
KUBECONFIG=…`, `history -c` are shell builtins: they change what a session is
doing and produce no exec, no open, no connect. An exec-based monitor watches
somebody work through them and reports nothing but the shell's own process.

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="Pahlevan architecture: a leader-elected operator and the PahlevanPolicy/ContainerProfile/AttackSurface CRDs drive per-node agents that load eBPF programs which observe and deny in-kernel" width="900" />
</p>

A per-node **agent** DaemonSet owns the eBPF data plane and enforces locally in
the kernel. A leader-elected **operator** Deployment drives the policy
lifecycle, status aggregation and CEL admission, with no host access and no
mutating webhook. If the operator is down, enforcement already installed in the
kernel keeps working. Detail: [`docs/architecture.md`](docs/architecture.md).

## Quick start

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml
```

Point a policy at a labelled workload:

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: nginx-security
spec:
  selector:
    matchLabels:
      app: nginx
  learningConfig:
    duration: 5m          # watch normal behaviour
    autoTransition: true  # then enforce, automatically
  enforcementConfig:
    mode: Monitoring      # Blocking denies in-kernel; start here
  selfHealing:
    enabled: true         # return to learning if enforcement breaks the workload
```

```bash
kubectl get pahlevanpolicy nginx-security -w
```

Before you switch to `Blocking`, read what the baseline actually says:

```bash
pahlevan policy explain -f nginx-security.yaml   # no cluster needed
pahlevan profile list -n default                 # what has been learned so far
pahlevan profile get pod-<uid> -o yaml           # one container's learned profile
```

`policy explain` is the one to run first, and it is the only one of the three
that needs no cluster. It tells you which fields of a policy translate into
kernel state and which are ignored — including the ones that look like they
work. More in [`examples/`](examples) and
[`docs/policy-reference.md`](docs/policy-reference.md).

## Measured, not asserted

Every number Pahlevan publishes comes from
[`test/benchmark/run.sh`](test/benchmark/run.sh), run inside a kernel-isolated
VM, twice: once with no agent installed at all, then with Pahlevan learning and
enforcing.

The control pass is the part that makes the rest mean anything. Without it, a
scenario that silently failed to execute is indistinguishable from one that was
prevented, and a CPU figure has no idle node to subtract from it. Scenarios are
mapped to MITRE ATT&CK for Containers techniques and committed alongside the
harness. Methodology and recorded runs:
[`docs/benchmarks/`](docs/benchmarks).

eBPF is never loaded on a developer machine. `hack/vm/` provisions a kernel with
the BPF LSM active, and that is where every load, attach and enforcement test
runs.

## Requirements

- **Kubernetes 1.24+** — the user-namespace operator needs 1.30+.
- **Linux 5.8+** for observation: CO-RE, ring buffer, `CAP_BPF`.
- **Go 1.26+** to build from source. Running the published image needs nothing.
- **`CONFIG_BPF_LSM` with `lsm=bpf`** on the kernel command line for in-kernel
  enforcement. Without it, the LSM hooks do not attach and Pahlevan runs as an
  observability tool; the `commit_creds` kprobe and the syscall tracepoint still
  work, because kprobes need no boot parameter.

Details: [`docs/system-requirements.md`](docs/system-requirements.md),
[`docs/lsm-support.md`](docs/lsm-support.md).

## Install

```bash
helm repo add pahlevan https://obsernetics.github.io/pahlevan/charts
helm install pahlevan pahlevan/pahlevan-operator -n pahlevan-system --create-namespace
```

The distroless image `ghcr.io/obsernetics/pahlevan` ships the agent, operator
and CLI. Tags, chart usage and manifest pinning:
[`docs/packages.md`](docs/packages.md). Release notes:
[`CHANGELOG.md`](CHANGELOG.md).

## Development

```bash
make build          # agent, operator and CLI binaries
make test           # unit tests, generated CRDs and manifests, fmt, vet
make lint           # golangci-lint + yamllint
make ebpf-build     # regenerate CO-RE objects and Go bindings (needs clang)
hack/vm/up.sh       # bring up the eBPF-capable VM, then: make vm-test
```

Any change to `bpf/*.c`, to the loader, or to a map layout needs a `make
vm-test` run: the verifier accepts or rejects a program at attach time, and a
change that passes `go build` can still fail to load. `make help` lists every
target.

## Honest status

One maintainer. A `v1alpha1` API. No public production adopters yet. The
learning model has a conceptual limit no amount of engineering removes — a
workload that is already compromised when learning begins gets its malicious
behaviour baselined along with everything else.

[`ROADMAP.md`](ROADMAP.md) says what exists, what is in progress, and what is
merely planned, and marks each one. Nothing in this README describes something
that is not in the tree.

## Contributing

Contributions are welcome. Open an issue for substantial changes, run `make test
lint` before submitting, and keep eBPF changes verifiable with `make vm-test`.
See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
