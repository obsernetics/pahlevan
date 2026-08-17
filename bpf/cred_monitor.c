//go:build ignore

/*
 * Credential-change monitoring (CO-RE) via a kprobe on commit_creds.
 *
 * Every other monitor in Pahlevan watches a request: a file being opened, a
 * socket connecting, a program being executed, a capability being checked.
 * This one watches the outcome. commit_creds is the single kernel function
 * through which a task's credentials change - every setuid, every capability
 * grant, every successful privilege escalation, whatever route it took to get
 * there.
 *
 * That "whatever route" is the point. A syscall monitor sees setuid(0) and a
 * seccomp profile can forbid it, but neither sees a kernel exploit that
 * overwrites a cred struct and calls commit_creds directly - which is what the
 * overwhelming majority of local-root exploits do, because it is the shortest
 * path from an arbitrary write to a root shell. From here that exploit is not
 * subtle at all: a task's euid becomes 0, or its effective capability set
 * gains bits, and no execve is in progress to explain it.
 *
 * That last clause is the discriminator. A setuid binary legitimately gains
 * privilege, and it does so inside execve, where task->in_execve is set. A
 * process that gains root without an execve underway either called a setuid
 * syscall - which the syscall monitor already reports with its arguments - or
 * did something the kernel has no other name for.
 *
 * A kprobe cannot refuse the change: commit_creds returns void and is called
 * past the point of no return. It can, however, kill the process that made it,
 * before the new credentials are used for anything. That is the only
 * enforcement available at this site and it is worth having, because there is
 * no LSM hook here.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"

/* bpf_tracing.h casts a kprobe's context to struct user_pt_regs on arm64, and
 * vmlinux.h is generated from whichever kernel built the image - in practice
 * an x86 one, which has no such type. Declaring it here is safe: it is a UAPI
 * structure, so its layout is a stable kernel ABI and cannot drift. Without
 * this the arm64 object does not compile at all, which is how the previous
 * attempt at reading syscall arguments was lost. */
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MODE_OBSERVE 0
#define MODE_KILL    1

/* Flags on the event. */
#define CRED_GAINED_ROOT  0x01 /* euid became 0 and was not 0 before */
#define CRED_GAINED_CAPS  0x02 /* the effective capability set grew */
#define CRED_IN_EXECVE    0x04 /* an execve is underway; a setuid binary explains it */
#define CRED_KILLED       0x08 /* the task was sent SIGKILL */
#define CRED_LOST_ROOT    0x10 /* euid stopped being 0 - a daemon dropping privilege */

struct cred_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u64 old_caps; /* cap_effective before */
	__u64 new_caps; /* cap_effective after */
	__u32 pid;      /* tgid */
	__u32 tid;
	__u32 old_uid;
	__u32 new_uid;
	__u32 old_euid;
	__u32 new_euid;
	__u32 flags;
	__u8  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} cred_events SEC(".maps");

/* key 0: enabled, key 1: mode, key 2: kill even inside execve */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4);
} cred_config SEC(".maps");

/* Cgroups whose credential changes are governed. Empty means every cgroup is
 * observed and none is killed, which is the safe default for a monitor that
 * can only respond with a signal. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32); /* mode for this cgroup */
	__uint(max_entries, 8192);
} cred_governed SEC(".maps");

static __always_inline __u32 cfg(__u32 key)
{
	__u32 *v = bpf_map_lookup_elem(&cred_config, &key);
	return v ? *v : 0;
}

/* The effective capability set, read in a way that survives the kernel 6.3
 * change of representation.
 *
 * Before 6.3 a kernel_cap_t was __u32 cap[2]; from 6.3 it is a single __u64
 * val. Both occupy the same eight bytes and, on the little-endian
 * architectures BPF targets here, cap[0] is the low half of val - so one
 * eight-byte read produces the same number either way, and no CO-RE branch on
 * the field name is needed. Only the offset of cap_effective within struct
 * cred is relocated, and that field exists under that name in both. */
static __always_inline __u64 effective_caps(const struct cred *c)
{
	__u64 caps = 0;
	bpf_core_read(&caps, sizeof(caps), &c->cap_effective);
	return caps;
}

/* Whether an execve is underway for the current task.
 *
 * in_execve is a bitfield, so it needs the bitfield-aware CO-RE read rather
 * than an ordinary one. If a kernel ever drops the field the read fails
 * closed - reporting "no execve underway", which makes a legitimate setuid
 * binary look like an escalation. That is the right direction to fail in: a
 * false report is investigated, a missed one is not. */
static __always_inline int in_execve(struct task_struct *task)
{
	if (!bpf_core_field_exists(task->in_execve))
		return 0;
	return BPF_CORE_READ_BITFIELD_PROBED(task, in_execve) != 0;
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(handle_commit_creds, struct cred *new)
{
	if (!cfg(0))
		return 0;
	if (!new)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	if (!task)
		return 0;

	/* real_cred rather than cred: at this point cred is still the old one for
	 * the duration of the call, and real_cred is what the task was actually
	 * running as. They differ only while a task is temporarily assuming
	 * another's credentials, which is itself worth reporting accurately. */
	const struct cred *old = BPF_CORE_READ(task, real_cred);
	if (!old)
		return 0;

	__u32 old_uid = BPF_CORE_READ(old, uid.val);
	__u32 old_euid = BPF_CORE_READ(old, euid.val);
	__u64 old_caps = effective_caps(old);

	__u32 new_uid = BPF_CORE_READ(new, uid.val);
	__u32 new_euid = BPF_CORE_READ(new, euid.val);
	__u64 new_caps = effective_caps(new);

	__u32 flags = 0;
	if (new_euid == 0 && old_euid != 0)
		flags |= CRED_GAINED_ROOT;
	if (old_euid == 0 && new_euid != 0)
		flags |= CRED_LOST_ROOT;
	/* Gained, not merely changed: a task dropping capabilities is the
	 * hardening pattern every well-behaved daemon follows at startup, and
	 * reporting it would bury the one case that matters. */
	if (new_caps & ~old_caps)
		flags |= CRED_GAINED_CAPS;

	/* Nothing was gained. Credential changes that only drop privilege are the
	 * common case by a wide margin and are dropped here, before the cgroup
	 * lookup, so the hot path stays short. */
	if (!(flags & (CRED_GAINED_ROOT | CRED_GAINED_CAPS)))
		return 0;

	if (in_execve(task))
		flags |= CRED_IN_EXECVE;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	/* Enforcement: kill the task before the new credentials are used.
	 *
	 * Only for governed cgroups, and by default only when no execve explains
	 * the change - killing every setuid binary in a container would break sudo,
	 * ping and passwd, which is not a security posture anybody asked for. */
	__u32 mode = MODE_OBSERVE;
	__u32 *gm = bpf_map_lookup_elem(&cred_governed, &cgroup_id);
	if (gm)
		mode = *gm;

	if (mode == MODE_KILL) {
		int execve_exempt = (flags & CRED_IN_EXECVE) && !cfg(2);
		if (!execve_exempt) {
			if (bpf_send_signal(9) == 0)
				flags |= CRED_KILLED;
		}
	}

	struct cred_event *e = bpf_ringbuf_reserve(&cred_events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->old_caps = old_caps;
	e->new_caps = new_caps;
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->old_uid = old_uid;
	e->new_uid = new_uid;
	e->old_euid = old_euid;
	e->new_euid = new_euid;
	e->flags = flags;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
