# System Requirements

Pahlevan runs in the kernel, so what it can do on a given node is decided by
that node's kernel, not by the chart you installed. This page states the floors
that can be justified from the code in this repository, and says where a claim
would need testing this project has not done. An agent that loads on a kernel
it should not have, or refuses one it should have accepted, is a bug in this
page as much as in the loader.

## Kernel version

The agent loads eight eBPF objects, and each one has its own floor because each
uses a different set of BPF helpers. A helper the running kernel does not know
is rejected by the verifier at load time, which takes out the whole object that
calls it and nothing else. The floors below are the first kernel release that
carries every helper the program calls, read out of `bpf/*.c`. The hook and the
BPF LSM column come from `pkg/coverage/coverage.go`, which is the table
`pahlevan coverage` prints, so they cannot drift from the code.

| Program | Kernel hook | Needs `lsm=bpf` | Kernel floor | What sets the floor |
|---|---|---|---|---|
| `bpf/syscall_monitor.c` | `tracepoint/raw_syscalls/sys_enter` | No | **5.8** | `BPF_MAP_TYPE_RINGBUF` (5.8) |
| `bpf/network_monitor.c` | `lsm/socket_connect` | Yes | **5.8** | `BPF_PROG_TYPE_LSM` (5.7), ring buffer (5.8) |
| `bpf/capability_monitor.c` | `lsm/capable` | Yes | **5.8** | `BPF_PROG_TYPE_LSM` (5.7), ring buffer (5.8) |
| `bpf/shell_monitor.c` | `uretprobe/readline` | No | **5.8** | `bpf_probe_read_user_str` (5.5), ring buffer (5.8) |
| `bpf/file_monitor.c` | `lsm/file_open` | Yes | **5.10** | `bpf_d_path` (5.10) |
| `bpf/exec_monitor.c` | `lsm/bprm_check_security` | Yes | **5.11** | `bpf_d_path` (5.10), `bpf_get_current_task_btf` (5.11) |
| `bpf/cred_monitor.c` | `kprobe/commit_creds` | No | **5.11** | `bpf_send_signal` (5.3), `bpf_get_current_task_btf` (5.11) |
| `bpf/generic_kprobe.c` | `kprobe/<symbol>`, attached on request | No | **5.15** | `bpf_get_attach_cookie` (5.15) |

Every one of those helper versions is the release that merged the helper into
mainline, cross-checked against the kernel feature table in
[iovisor/bcc](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md).
All eight objects are CO-RE, so the kernel must also expose its own BTF at
`/sys/kernel/btf/vmlinux`, which arrived in 5.5 and needs
`CONFIG_DEBUG_INFO_BTF=y`. That is below every floor in the table, so it never
decides the answer on its own, but a kernel built without BTF fails everything
at once.

**The floor to run at all is 5.8.** The syscall monitor is the only program
whose load failure stops the agent, because behavioural learning is built on
it. Everything else is best effort: a program that will not load costs its own
observations and leaves the rest of the agent running, with one log line saying
so. On a 5.8 node the syscall, network, capability and shell programs load and
the file, exec, credential and generic-kprobe objects do not; 5.10 adds file;
5.11 adds exec and credential changes, which is the first kernel where every
detector `pahlevan coverage` lists is present; 5.15 adds the ad-hoc kernel
probes. Whether the four LSM programs in that set then attach is a separate
question, below.

**The floor to enforce anything is higher than a version number.** The four
LSM-hooked programs also need the kernel booted with `bpf` in its active LSM
list, which most distributions do not set. That is the single most consequential
requirement on this page and it has its own:
[`lsm-support.md`](lsm-support.md).

## Kernel configuration

The agent checks part of this itself at startup and logs what is missing, so an
unhappy node is diagnosable from `kubectl logs`. The checks that matter:

```bash
# eBPF, the BPF JIT and kernel BTF. Distribution kernels since 5.8 set all of
# these; a custom or minimal kernel may not.
grep -E 'CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_BPF_JIT=|CONFIG_BPF_EVENTS=|CONFIG_KPROBES=|CONFIG_DEBUG_INFO_BTF=|CONFIG_BPF_LSM=' /boot/config-$(uname -r)

# Kernel BTF must actually be exposed, not only compiled in. The agent mounts
# this path with hostPath type Directory, so a node without it cannot even
# start the pod.
ls -l /sys/kernel/btf/vmlinux

# cgroup v2. Every allow-set in the data plane is keyed on the cgroup v2 id
# returned by bpf_get_current_cgroup_id, and attribution resolves that id back
# to a pod through the unified hierarchy. A cgroup v1 node is not supported.
test -f /sys/fs/cgroup/cgroup.controllers && echo "cgroup v2"

# The active LSM list decides whether the four LSM programs can attach.
cat /sys/kernel/security/lsm
```

The agent refuses to start if it cannot load the syscall tracepoint, and the
error names debugfs and tracepoint support, because that is the usual cause on
a node where `/sys/kernel/debug` is not mounted.

## CPU architecture

Objects are built for both amd64 and arm64, and a test parses both ELFs to
assert they expose the same programs and maps. Only amd64 has ever been loaded
by a kernel. The VM harness that runs in CI boots an amd64 guest, so an arm64
verifier has never seen these programs, and a verifier rejection is exactly the
class of failure that a structural comparison of two ELF files cannot find.
Treat arm64 as built and unproven until that changes; [`../ROADMAP.md`](../ROADMAP.md)
tracks it.

## Node privileges

The agent is a DaemonSet, runs on every node, and needs real privilege in the
init namespace. [`../deploy/base/daemonset-agent.yaml`](../deploy/base/daemonset-agent.yaml)
is the authoritative version of what follows.

- **`CAP_BPF` and `CAP_PERFMON`.** `CAP_BPF` allows the `bpf()` syscall
  operations that create maps and load programs; `CAP_PERFMON` covers the
  tracing attachments. Both were split out of `CAP_SYS_ADMIN` in Linux 5.8,
  which is the same release as the agent's floor.
- **`CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE` and `CAP_NET_ADMIN`** are requested
  alongside them. They are what makes the agent work on kernels and container
  runtimes where the finer-grained pair is not enough on its own, and they are
  why the DaemonSet does not claim to be least-privilege.
- **`hostPID: true`.** Kernel events carry host PIDs. Without the host PID
  namespace the agent cannot resolve them, and the shell monitor cannot reach
  `/proc/<pid>/root` to find the shell binary inside a container's filesystem
  and attach a uprobe to its inode.
- **Host mounts.** `/sys/fs/bpf` (bidirectional, for pinned objects),
  `/sys/kernel/btf` and `/sys/fs/cgroup` read-only, `/sys/kernel/debug`, the
  host `/proc` at `/host/proc` read-only,
  and a writable `/var/lib/kubelet/seccomp/pahlevan` so generated seccomp
  profiles land where the kubelet can resolve them as a `localhostProfile`.
- **Pod Security Admission.** `pahlevan-system` is labelled
  `pod-security.kubernetes.io/enforce: privileged`. Workloads Pahlevan protects
  live in their own namespaces and keep whatever level they already run at.
- The container does **not** set `privileged: true`, and it cannot run in a
  user namespace. The operator, which has no kernel privilege at all, does:
  it runs with `hostUsers: false`.

## Kubernetes

| Requirement | Version | Why |
|---|---|---|
| Cluster | 1.24+ | The Helm chart declares `kubeVersion: ">=1.24.0"`. |
| `hostUsers: false` on the operator | 1.30+ | User namespaces for pods are beta from 1.30 and on by default from 1.33. On an older cluster the operator still runs, without the user namespace. |
| `ValidatingAdmissionPolicy` | 1.30+ | Policy validation is a CEL admission policy rather than a webhook. `pahlevan status` reports the API as unavailable on older clusters instead of failing. |

## Container runtime and cgroups

Attribution parses the cgroup v2 path of a container to recover the pod UID and
container id, and recognises the scope shapes that containerd, CRI-O and Docker
produce, along with the `containerd://`, `cri-o://` and `docker://` prefixes on
the container ids reported by the Kubernetes API. A runtime that writes neither
shape leaves events attributed to a cgroup id and no pod, which is a
degradation rather than a failure.

cgroup v2 is required, as above. No runtime version floor is stated here,
because nothing in the code checks one and this project has not tested a matrix
of runtime versions.

## Resources

The DaemonSet requests `100m` CPU and `128Mi` memory per node with `500m` and
`512Mi` limits; the operator requests `50m` and `64Mi` with `200m` and `256Mi`.
Those are the values in the shipped manifests, chosen to be enough for the
workloads the benchmark harness exercises, and they are the number to revisit
first when an agent is being OOM-killed on a busy node.

BPF maps are preallocated by the kernel, so map sizing is resident memory that
exists from the moment the programs load, whether or not any event arrives.
Across the programs that measures 37.7 MiB on Linux 6.8. Each program carries
its own ring buffer, 256 KiB where events are deduplicated in the kernel and
1 MiB where they are not, and the allow-sets are sized for 8192 governed cgroups
and 131,072 file paths per node.

End-to-end agent memory under load has not been measured since the map-sizing
fix that produced the figure above, so no total is quoted here.
[`benchmarks/README.md`](benchmarks/README.md) holds the methodology and the
recorded runs.

## Checking a node before you install

This is the whole check, and every line of it reads something the agent
actually depends on:

```bash
#!/usr/bin/env bash
# Run on the node, not in the agent pod: the agent image is distroless and has
# no shell, and it does not mount securityfs.

echo "kernel:      $(uname -r)"
echo "arch:        $(uname -m)"

if [ -e /sys/kernel/btf/vmlinux ]; then
  echo "BTF:         present"
else
  echo "BTF:         MISSING - no CO-RE program can load, and the agent pod will not start"
fi

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  echo "cgroup:      v2"
else
  echo "cgroup:      NOT v2 - attribution and every allow-set key depend on cgroup v2"
fi

if [ -d /sys/kernel/debug/tracing ]; then
  echo "tracefs:     present"
else
  echo "tracefs:     MISSING - the syscall monitor cannot attach, and its failure is fatal"
fi

lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "unreadable")
echo "active LSMs: ${lsm}"
case "${lsm}" in
  *bpf*) echo "             bpf is active: file, network, exec and capability enforcement are available" ;;
  *)     echo "             bpf is NOT active: see docs/lsm-support.md, Pahlevan will observe but not enforce" ;;
esac
```

Once Pahlevan is installed, `pahlevan debug` collects the same picture for
every node in the cluster through the Kubernetes API, including a per-node
verdict on the BPF LSM inferred from the agent's own logs, and `pahlevan
coverage` prints which detectors exist and which of them need the BPF LSM.

## What this page does not say

There is no table here of cloud providers, node images, CNI plugins or
instance types. Pahlevan's kernel tests run against one kernel, the Ubuntu
24.04 cloud image booted by [`../hack/vm/up.sh`](../hack/vm/up.sh) with
`lsm=bpf`, in CI
on every change to `bpf/`, `pkg/ebpf/` or the harness itself, and nightly. Any
per-provider compatibility claim would be a guess, and a requirements document
that guesses is worse than one that is silent: the checks above answer the
question for whatever node you actually have.

## Related

- [`lsm-support.md`](lsm-support.md) for the BPF LSM and the boot parameter it
  needs.
- [`architecture.md`](architecture.md) for how the agent and operator are split.
- [`troubleshooting.md`](troubleshooting.md) for what to do when a node fails
  one of these checks.
