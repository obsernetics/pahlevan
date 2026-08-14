# Contributing to Pahlevan

Thanks for considering a contribution. Pahlevan is a small project, so a good
pull request has real leverage here.

Before you start, please read the [Code of Conduct](CODE_OF_CONDUCT.md) and
[GOVERNANCE.md](GOVERNANCE.md). If you are reporting a security vulnerability,
stop and follow [SECURITY.md](SECURITY.md) instead: do not open a public issue.

## Contents

- [Before you write code](#before-you-write-code)
- [Developer Certificate of Origin](#developer-certificate-of-origin)
- [Setting up](#setting-up)
- [Building](#building)
- [Testing](#testing)
- [Testing eBPF changes: use a VM](#testing-ebpf-changes-use-a-vm)
- [Running the benchmark harness](#running-the-benchmark-harness)
- [Code layout](#code-layout)
- [Pull request expectations](#pull-request-expectations)
- [Style](#style)
- [Releases](#releases)

## Before you write code

- **Small fixes**: just send the pull request. Typos, broken links, obvious
  bugs, and missing tests do not need an issue first.
- **Anything substantial**: open an issue describing the problem before writing
  code. This is not bureaucracy, it is so you do not spend a weekend on
  something a maintainer would have to reject. [GOVERNANCE.md](GOVERNANCE.md#substantial-changes)
  lists the categories that always need an issue first, including anything that
  changes the agent's privileges, the enforcement semantics, or the CRD API.
- **Not sure**: open an issue and ask.

## Developer Certificate of Origin

Pahlevan requires the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) on every commit. The DCO is a lightweight statement that you wrote the
contribution, or otherwise have the right to submit it under the project's
Apache 2.0 license. There is no CLA to sign.

You certify it by signing off your commits:

```bash
git commit -s -m "ebpf: deny IPv6 egress in enforce mode"
```

`-s` appends a trailer with the name and email from your git config:

```text
Signed-off-by: Your Name <you@example.com>
```

The name and email must be real and must match your git author identity. Sign
off every commit in the pull request, not just the last one.

**Forgot to sign off?**

```bash
# the most recent commit
git commit --amend -s --no-edit && git push --force-with-lease

# every commit on the branch, against main
git rebase --signoff main && git push --force-with-lease
```

To never forget again, add a commit template or an alias:

```bash
git config alias.ci "commit -s"
```

CI enforces this: [`.github/workflows/dco.yml`](.github/workflows/dco.yml) runs on
every pull request and fails if any commit in the branch is missing a
`Signed-off-by` trailer matching its author. The check output names the offending
commits.

## Setting up

You need:

| Tool | Version | Needed for |
|---|---|---|
| Go | 1.25 or newer | Everything |
| `make` | any | Everything |
| Docker or Podman | any | Image builds |
| `clang` and `llvm`, `libbpf-dev` | clang 14+ | Only if you change `bpf/*.c` |
| QEMU with KVM | any | Only if you run the eBPF or benchmark tests |

```bash
git clone https://github.com/obsernetics/pahlevan.git
cd pahlevan
make build
```

You do **not** need clang for a normal build. The eBPF objects and their bpf2go
Go bindings are committed to the tree, so a clean checkout builds without a
kernel toolchain. You only regenerate them when you change the C.

`make help` lists every target.

## Building

```bash
make build          # pahlevan-agent, pahlevan-operator, and the pahlevan CLI into bin/
make docker-build   # container image
make manifests      # regenerate CRDs and RBAC from the Go types
make generate       # regenerate deepcopy functions
```

`make build` runs `manifests`, `generate`, `fmt`, and `vet` first. If it changes
generated files, **commit them**: CI checks that the tree is clean after
generation, so a stale `config/crd` or `zz_generated.deepcopy.go` fails the
build.

If you change anything under `bpf/`:

```bash
make ebpf-build     # compile the CO-RE objects and regenerate the Go bindings
```

This needs clang and `libbpf-dev` (`make ebpf-deps` installs them on Debian and
Ubuntu). The regenerated `pkg/ebpf/*_bpfel.go`, `*_bpfeb.go`, and `*.o` files are
committed artifacts and must be included in your pull request, otherwise the C
and the Go bindings drift apart and the loaded program is not the one you wrote.

## Testing

```bash
make test           # the full suite: manifests, generate, fmt, vet, then go test ./...
make test-unit      # just the unit tests, with -race
make lint           # golangci-lint
make test-coverage  # coverage report
```

`make test` is the one CI runs. Run it before you push.

The unit suite does not load eBPF. It exercises the loader's error paths, the
event decoders, the controllers, the CRD types, and the CLI against fakes, so it
runs anywhere, including in a container. Anything that actually touches the
kernel is guarded and skipped outside the VM.

Integration and end-to-end suites are behind build tags and need a cluster:

```bash
make test-integration   # -tags=integration
make test-e2e           # -tags=e2e, needs a working kubeconfig
```

## Testing eBPF changes: use a VM

**Never load Pahlevan's eBPF programs on your development host.** Attaching an
LSM enforcement hook on the machine you are working on can deny your own shell's
file opens and wedge the box. It is also usually pointless: most distributions
do not ship `bpf` in the active LSM list, so enforcement would not attach
anyway.

The repository ships a reproducible VM for exactly this. It boots Ubuntu 24.04
headless under QEMU/KVM with `lsm=...,bpf` forced on the guest kernel command
line, and provisions clang, libbpf, and Go inside:

```bash
hack/vm/up.sh       # boot the VM (idempotent; first run downloads the image)
make vm-test        # ship the tree into the VM and run the eBPF load tests there
hack/vm/down.sh     # shut it down
```

`make vm-test` archives `HEAD`, copies it in, and runs the load, attach, and
enforce tests (`go test ./pkg/ebpf/ -run TestVMLoad -v` with
`PAHLEVAN_EBPF_VM_TEST=1`). Note that it archives **committed** state, so commit
your work before running it.

To poke around interactively:

```bash
hack/vm/run.sh 'uname -r'
hack/vm/run.sh 'cat /sys/kernel/security/lsm'   # should include "bpf"
```

Any change to `bpf/*.c`, to the loader in `pkg/ebpf/`, or to the map layouts
must come with a `make vm-test` run, and the pull request should say so. The
verifier accepts or rejects a program at attach time, and a change that passes
`go build` can still fail to load.

## Running the benchmark harness

The numbers in [`docs/benchmarks/`](docs/benchmarks) are produced by
[`test/benchmark/run.sh`](test/benchmark/run.sh), never written by hand. It runs
Pahlevan, Falco, and Tetragon against the same workload and the same attack
scenarios inside the same VM, one tool at a time, and records what each one
detected and what it actually blocked.

```bash
hack/vm/up.sh                    # boot the VM first
test/benchmark/run.sh pahlevan   # build, deploy, learn, enforce, attack
test/benchmark/run.sh falco      # Falco with vendor defaults
test/benchmark/run.sh tetragon   # Tetragon with vendor defaults
test/benchmark/run.sh all        # cluster setup, then all three in sequence
```

It installs k3s and Helm inside the VM if they are missing, deploys an
`nginx:1.27` target, and injects each scenario from
`test/benchmark/scenarios/*.sh` with `kubectl exec`.

Rules for benchmark contributions, because a benchmark that flatters us is worse
than no benchmark:

- Compare against **vendor defaults** for the other tools, and say so. If you
  tune Falco's or Tetragon's configuration, tune it in the other direction too
  and report both.
- Commit the scenario script alongside any new result.
- Record what could **not** be measured, and why. The existing results file does
  this and the habit is deliberate.
- Never edit a results file by hand to change a number. Re-run and replace.
- A scenario that Pahlevan fails is a valuable contribution. Do not remove it.

## Code layout

```text
bpf/                      CO-RE eBPF C programs (syscall, file, network, exec, capability)
pkg/ebpf/                 Loader and manager, generated bpf2go bindings, committed .o objects,
                          event decoders
pkg/apis/policy/v1alpha1/ CRD Go types: PahlevanPolicy, ContainerProfile, AttackSurface
internal/controller/      controller-runtime reconcilers for the CRDs
internal/adaptive/        The learn to enforce loop: baselines, transitions, map programming
internal/learner/         Syscall learning
internal/admission/       Policy validation logic behind the CEL ValidatingAdmissionPolicy
pkg/policies/             Enforcement engine, lifecycle manager, self-healing
pkg/learner/              Learning types shared across packages
pkg/attribution/          cgroup id to Kubernetes pod and container resolution
pkg/seccomp/              Seccomp profile generation from the learned syscall set
pkg/metrics/              Prometheus metrics
pkg/observability/        Logging, OpenTelemetry wiring
pkg/discovery/            Container tracking
pkg/visualization/        Attack surface analysis
pkg/cli/                  Output formatting and scheme registration for the CLI
cmd/pahlevan-agent/       The privileged per-node DaemonSet binary
cmd/pahlevan-operator/    The unprivileged leader-elected control plane binary
cmd/pahlevan/             The pahlevan CLI
config/, deploy/          Kustomize bases for CRDs, RBAC, manager
charts/                   Helm chart
install.yaml              Generated single-file install manifest
hack/vm/                  QEMU/KVM harness with the BPF LSM enabled
test/benchmark/           Falco and Tetragon comparison harness and scenarios
test/integration/, test/e2e/
docs/                     Architecture, policy reference, benchmarks, comparison
examples/                 Example policies
pages/                    GitHub Pages site
```

The split that matters: **the agent is the only component with kernel
privilege**, and **the operator is the only component with cluster-wide API
power**. Keep it that way. A change that gives the operator host access, or the
agent broad cluster API rights, needs a very good argument in an issue first.
See [`docs/architecture.md`](docs/architecture.md).

## Pull request expectations

A pull request is ready when:

1. **CI is green.** All checks, including the DCO check. Do not ask for review
   on a red build unless you are stuck and say what you are stuck on.
2. **Every commit is signed off.** See [above](#developer-certificate-of-origin).
3. **New behavior has tests.** A bug fix comes with a test that fails before the
   fix. A new feature comes with tests for the success path and at least the
   interesting failure path. "Tested manually" is not sufficient for anything in
   `pkg/` or `internal/`.
4. **eBPF changes were run in the VM**, with the `make vm-test` output or a
   summary of it in the description.
5. **Generated files are regenerated and committed** if you touched the API
   types or the eBPF C.
6. **The description says what and why.** What the change does, why it is
   needed, and how you verified it. Link the issue. A reviewer should not have
   to reconstruct your reasoning from the diff.
7. **User-visible changes update the docs**, and anything that changes
   enforcement behavior updates [`CHANGELOG.md`](CHANGELOG.md) under
   `[Unreleased]`.

Other things worth knowing:

- Keep pull requests focused. A refactor bundled with a behavior change is hard
  to review and hard to revert. Split them.
- Rebase rather than merge `main` into your branch. Force push with
  `--force-with-lease`.
- Review comments are about the code, never the person. If a comment reads
  harshly, assume brevity rather than hostility, and say so if it lands badly.
- Maintainers may ask for changes, or say no. When we say no, we will say why.
- Draft pull requests are welcome for early feedback. Mark them draft rather
  than apologising in the description.

## Style

- **Go**: standard `gofmt`. `make lint` runs `golangci-lint` with the config in
  [`.golangci.yml`](.golangci.yml). Errors are wrapped with `%w` and handled, not
  logged and swallowed.
- **eBPF C**: keep programs verifier friendly. Bounded loops, bounded reads, and
  explicit size checks. Comment anything the verifier forced you to write in an
  unnatural way, because the next person will otherwise "clean it up" and break
  the load.
- **No em dashes or en dashes.** Anywhere: prose, comments, docs, commit
  messages, code. Use a plain hyphen, a comma, or a new sentence. The project has
  been scrubbed of them once already and `make lint` is not going to catch a
  regression, so this one is on you.
- **No AI or assistant attribution** in commit messages, commit trailers, pull
  request descriptions, or code comments.
- **Commit messages**: a short imperative subject line, prefixed with the area
  where it helps (`ebpf:`, `operator:`, `docs:`, `chart:`). A body explaining
  why, if the subject is not self-evident. Then the `Signed-off-by` trailer.
- **Documentation**: plain, specific, and honest. Say what the code does, not
  what it aspires to do. If something is planned rather than implemented, write
  "planned". Reviewers of this project check.

## Releases

Releases follow [semantic versioning](https://semver.org/spec/v2.0.0.html) and
are cut from tags (`vX.Y.Z`), which trigger the image push and the GitHub
release with `install.yaml` attached. Changes are recorded in
[`CHANGELOG.md`](CHANGELOG.md) following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Add your entry under
`[Unreleased]` as part of your pull request rather than leaving it for the
release.

## Getting help

Open a [GitHub issue](https://github.com/obsernetics/pahlevan/issues). Questions
are fine as issues; there is no separate forum yet. If the docs did not answer
your question, that is a documentation bug and worth reporting on its own.
