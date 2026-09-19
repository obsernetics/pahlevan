# The BPF LSM

Four of Pahlevan's eight eBPF programs attach to BPF LSM hooks, and those hooks
are the only place the data plane can refuse a request before it takes effect.
A BPF LSM program attaches only on a kernel booted with `bpf` in its active LSM
list, and most distributions do not put it there. That one boot parameter is
the difference between Pahlevan denying a file open, an outbound connection, an
exec and a capability check, and Pahlevan reporting on syscalls, credential
changes and shell commands while those four decisions are never made at all.

This page is about that parameter: which programs depend on it, how to tell
whether a node has it, how to turn it on, and exactly what a node without it
still does.

## Which programs need it

`pkg/coverage/coverage.go` carries the hook and the `NeedsLSM` flag for every
detector, and `pahlevan coverage` prints that table straight out of the binary,
so what follows is the code's own answer rather than a second copy of it that
can drift:

| Program | Kernel hook | Needs `lsm=bpf` | What a node without it loses |
|---|---|---|---|
| `bpf/file_monitor.c` | `lsm/file_open` | Yes | All per-path file observation and the read/write allow-set. No file denial is possible. |
| `bpf/network_monitor.c` | `lsm/socket_connect` | Yes | All egress connect observation and the per-destination allow-set. No connection is refused. |
| `bpf/exec_monitor.c` | `lsm/bprm_check_security` | Yes | Every exec event: binary, argv, ancestry and the container-breakout signal. No exec is refused. |
| `bpf/capability_monitor.c` | `lsm/capable` | Yes | Every capability check and the effective, permitted and inheritable sets recorded with it. |
| `bpf/syscall_monitor.c` | `tracepoint/raw_syscalls/sys_enter` | No | Nothing. Tracepoints need no boot parameter. |
| `bpf/cred_monitor.c` | `kprobe/commit_creds` | No | Nothing. Kprobes need no boot parameter. |
| `bpf/shell_monitor.c` | `uretprobe/readline` | No | Nothing directly, but see the caveat below. |
| `bpf/generic_kprobe.c` | `kprobe/<symbol>`, attached on request | No | Nothing. Kprobes need no boot parameter. |

The kernel version each of these needs is a separate question from the boot
parameter, and it is answered in
[`system-requirements.md`](system-requirements.md).

### The caveat on the shell monitor

The `readline` uretprobe attaches to a shell binary, not to an LSM hook, so it
works on a stock kernel. What arms it does not. The agent attaches the probe
when it sees an interactive shell exec, and exec events come from
`lsm/bprm_check_security`. On a node without the BPF LSM the agent never learns
that a shell started, so in practice interactive command capture depends on the
BPF LSM even though the probe itself does not. Shell capture is also off unless
the agent is started with `--trace-shell-commands`, because recording what a
person types at a prompt is a decision an operator should make deliberately.

## What enforcement means without the BPF LSM

The LSM hooks return `-EPERM` and the operation does not happen. The two
kprobes cannot do that: they run after the kernel has decided, and the only
lever they have is `bpf_send_signal`. `bpf/cred_monitor.c` uses it to kill a
task whose credentials changed with no `execve` to explain it, before the new
credentials are used, and only for cgroups a policy has placed in kill mode.
That is a real control, but it is a kill rather than a refusal, and it covers
privilege escalation only.

So a node without `lsm=bpf` learns syscall sets, detects credential
escalation, can kill on it, and reports nothing about files, destinations,
execs or capabilities. Removing that boot-parameter requirement by building a
kprobe-based enforcement path is planned work, not shipped work; see
[`../ROADMAP.md`](../ROADMAP.md).

## The two different failures

They produce different symptoms, and confusing them wastes an afternoon.

**The kernel has no BPF LSM at all** (older than 5.7, or built with
`CONFIG_BPF_LSM=n`). The programs do not load. `ebpf.NewCollection` fails for
the whole object, so the exec monitor loses its `execve` argv tracepoints along
with its LSM program. The agent logs one line per monitor and carries on:

```text
file monitor unavailable; continuing without file observation
network monitor unavailable; continuing without network observation
capability monitor unavailable; continuing without capability observation
```

**The kernel has `CONFIG_BPF_LSM=y` but was not booted with `bpf` in its LSM
list.** This is the common case. The programs load fine and the attach fails:

```text
lsm/file_open attach failed; file enforcement/observation disabled (enable with lsm=...,bpf)
lsm/socket_connect attach failed; network observation/enforcement disabled
lsm/bprm_check_security attach failed; exec observation/enforcement disabled
lsm/capable attach failed; capability observation disabled
```

Neither failure stops the agent. The syscall monitor is the one program whose
absence is fatal, because it is what the learner is built on. Everything else
is best effort by design, on the argument that a degraded agent reporting what
it can see beats a crash loop reporting nothing.

## Checking a node

Ask the kernel which LSMs are active:

```bash
cat /sys/kernel/security/lsm
# e.g. capability,landlock,yama,apparmor,bpf
```

`bpf` must appear in that list. Run this on the node itself, over SSH or
through a debug pod with a shell: the agent container does not mount
securityfs, and the image is distroless, so there is no shell to `kubectl exec`
into and no `/sys/kernel/security` inside it if there were.

If `bpf` is missing, check whether the kernel can do it at all before touching
the bootloader:

```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# CONFIG_BPF_LSM=y
```

Across a cluster, `pahlevan debug` reports a per-node verdict without any node
access. It cannot read `/sys/kernel/security/lsm` through the Kubernetes API,
so the verdict is inferential: a node is `Unsupported kernel` when its kernel
version predates 5.7, `Disabled` when its agent logged an LSM attach failure,
and `Likely enabled` when a ready agent on a new enough kernel logged no such
failure in the window that was read.

## Turning it on

The LSM list is a kernel command-line parameter, so this is a bootloader change
and a reboot, per node. The important part is that `lsm=` **replaces** the
list rather than adding to it: passing `lsm=bpf` alone disables AppArmor,
SELinux, Yama and Landlock on that machine. Start from the list the node is
already running and append `bpf` to it.

The VM harness in [`../hack/vm/up.sh`](../hack/vm/up.sh) does exactly this and
is a known-working reference. It drops a GRUB fragment into the guest:

```bash
# /etc/default/grub.d/99-bpf-lsm.cfg
GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} lsm=capability,landlock,yama,apparmor,bpf"
```

then `update-grub` and reboot. That list is the Ubuntu 24.04 default with `bpf`
appended; on another distribution, read `/sys/kernel/security/lsm` first and
append to what you find there.

After the reboot, `/sys/kernel/security/lsm` should contain `bpf` and the agent
should stop logging attach failures. The harness fails loudly if it does not,
which is the same check worth making by hand:

```bash
cat /proc/cmdline                  # the lsm= parameter should be present
cat /sys/kernel/security/lsm       # bpf should be in the list
```

On a managed Kubernetes service the node kernel command line is set by the node
image and may not be editable. Whether a given provider's image can enable the
BPF LSM is decided per image, and Pahlevan's CI has only ever tested the Ubuntu
24.04 cloud image kernel that `hack/vm/` boots, so this page makes no claim
about any provider.

## Related

- [`system-requirements.md`](system-requirements.md) for kernel version floors,
  capabilities and the rest of the deployment requirements.
- [`architecture.md`](architecture.md) for where these programs sit in the
  agent.
- [`../ROADMAP.md`](../ROADMAP.md) for the planned kprobe enforcement path that
  would make this boot parameter optional.
