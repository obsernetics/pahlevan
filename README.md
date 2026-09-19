<div align="center">

<h1>Pahlevan</h1>

<p><b>Your workload writes its own security policy. The kernel enforces it.</b></p>

<p>
  <a href="https://github.com/obsernetics/pahlevan/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/obsernetics/pahlevan/ci.yml?branch=main&label=CI&logo=github" alt="CI" /></a> <a href="https://goreportcard.com/report/github.com/obsernetics/pahlevan"><img src="https://goreportcard.com/badge/github.com/obsernetics/pahlevan" alt="Go Report Card" /></a> <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a> <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26" /></a> <a href="https://github.com/obsernetics/pahlevan/releases"><img src="https://img.shields.io/github/v/release/obsernetics/pahlevan?sort=semver&color=success" alt="Latest release" /></a> <a href="https://github.com/obsernetics/pahlevan/stargazers"><img src="https://img.shields.io/github/stars/obsernetics/pahlevan?style=flat&logo=github&color=yellow" alt="GitHub stars" /></a>
  <br/>
  <img src="https://img.shields.io/badge/Kubernetes-1.24%2B-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes 1.24+" /> <img src="https://img.shields.io/badge/eBPF-CO--RE-FF6600?logo=linux&logoColor=white" alt="eBPF CO-RE" /> <img src="https://img.shields.io/badge/LSM-BPF%20enforcement-8A2BE2?logo=linux&logoColor=white" alt="LSM BPF enforcement" /> <a href="#contributing"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs welcome" /></a>
</p>

<img src="docs/assets/demo.gif" alt="Pahlevan learn-then-enforce demo: a workload is profiled during a learning window, the learned surface is shown beside the enforced one, and then an attacker's read of /etc/shadow, exec of a miner, egress to an unlearned address, CAP_SYS_ADMIN, a ptrace of pid 1 and a setuid to root are each denied, killed or recorded in-kernel" width="880" />

</div>

## The idea

A container runs one program, opens the same files, dials the same few
destinations and uses about sixty of the kernel's four hundred syscalls.
Pahlevan watches it do that once, then refuses everything else in the kernel
with `EPERM`. Nobody writes a rule, and an attacker inherits the baseline
instead of root.

<p align="center">
  <img src="docs/assets/learn-then-enforce.png" width="920"
       alt="Two panels. On the left, a learning window listing what an nginx container actually did: opened /etc/nginx/* and /var/log/*, connected to 10.0.1.7:5432, executed nginx, and used 61 of roughly 400 syscalls. An arrow labelled 'becomes the allow-set' leads to the right panel, enforcement, where those same three entries are marked ok and three that were never learned are refused with EPERM: /etc/shadow, /tmp/xmrig, and 45.9.1.4:80." />
</p>

## The console

Run `pahlevan` to see policies, workloads, live events and ATT&CK coverage in
one place. It only reads, so it cannot turn enforcement off.

## The trade

A baseline narrow enough to stop an attacker is narrow enough to stop you:
`kubectl exec` into a pod and run `curl`, and it is denied. Start in
`Monitoring`, which reports without denying, and use self-healing and policy
exceptions to widen the set deliberately.

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="Pahlevan architecture: a leader-elected operator and the PahlevanPolicy/ContainerProfile/AttackSurface CRDs drive per-node agents that load eBPF programs which observe and deny in-kernel" width="900" />
</p>

A per-node **agent** enforces in the kernel. A leader-elected **operator**
drives the policy lifecycle with no host access; if it is down, enforcement
keeps working.

## Quick start

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml
```

```yaml
apiVersion: policy.pahlevan.io/v1beta1
kind: PahlevanPolicy
metadata: {name: nginx}
spec:
  selector: {matchLabels: {app: nginx}}
  learningConfig: {duration: 5m, autoTransition: true}
  enforcementConfig: {mode: Monitoring}   # Blocking denies in-kernel
```

`pahlevan policy explain -f policy.yaml` shows what a policy will enforce, with
no cluster. More in [`docs/quick-start.md`](docs/quick-start.md).

## Requirements

| | |
|---|---|
| Kubernetes | 1.24+ |
| Linux | 5.8+ to observe |
| Enforcement | `lsm=bpf` on the kernel command line |

Without the BPF LSM, Pahlevan observes but cannot refuse. See
[`docs/system-requirements.md`](docs/system-requirements.md).

## Status

One maintainer, no public production adopters yet. A workload already
compromised when learning starts has that behaviour baselined too.
[`ROADMAP.md`](ROADMAP.md) says what exists and what does not.

## Contributing

Run `make test lint`. eBPF changes must pass `make vm-test`, which loads the
programs in a VM, never on your machine. See
[`CONTRIBUTING.md`](CONTRIBUTING.md). Apache 2.0.
