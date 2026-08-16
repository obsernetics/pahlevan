//go:build ignore

/*
 * Capability monitoring + enforcement (CO-RE) via the BPF LSM capable hook.
 *
 * Every privileged operation in the kernel funnels through a capability check,
 * so this hook shows exactly which capabilities a container actually exercises.
 * Following the same learn-then-enforce model as the file, network, and exec
 * monitors, the learned set becomes the allow-list and an unlearned capability
 * request is denied with -EPERM under enforcement.
 *
 * This is the signal behind "your container asked for CAP_SYS_ADMIN once, at
 * 03:00, three weeks after you deployed it".
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "enforce.h"

char LICENSE[] SEC("license") = "GPL";

#define EV_DENIED 0x80000000u
#define EV_KILLED 0x40000000u

struct cap_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	/* The task's capability sets at the time of the check. Seeing only the
	 * capability being checked answers "what did it want"; the sets answer
	 * "what could it have done", which is the question that decides whether a
	 * container is over-privileged. Both comparators report these. */
	__u64 cap_effective;
	__u64 cap_permitted;
	__u64 cap_inheritable;
	__u32 pid; /* tgid */
	__u32 cap; /* capability number, e.g. CAP_SYS_ADMIN = 21 */
	__u32 flags; /* bit 0x80000000 => denied */
	__u32 pad;
	__u8  comm[16];
	__u32 ppid;       /* parent tgid, so a denial names who caused it */
	__u32 pad2;
	__u8  pcomm[16];  /* parent comm */
};

/* fill_cap_sets reads the current task's credentials. kernel_cap_t is a struct
 * wrapping a u64 on modern kernels; BPF_CORE_READ resolves the field through
 * BTF, so a layout change is handled by relocation rather than by breaking. */
static __always_inline void fill_cap_sets(struct cap_event *e)
{
	e->cap_effective = 0;
	e->cap_permitted = 0;
	e->cap_inheritable = 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;
	const struct cred *cred = BPF_CORE_READ(task, cred);
	if (!cred)
		return;
	e->cap_effective = BPF_CORE_READ(cred, cap_effective.val);
	e->cap_permitted = BPF_CORE_READ(cred, cap_permitted.val);
	e->cap_inheritable = BPF_CORE_READ(cred, cap_inheritable.val);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB; events are deduped in-kernel */
} cap_events SEC(".maps");

/* Learned allow-set: key = (cgroup_id << 8) | capability. There are only 64
 * capabilities, so this stays tiny even across many cgroups. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 13);
} cap_allowed SEC(".maps");

/* Per-cgroup enforcement action, packed: see bpf/enforce.h. Absent or zero is
 * ACT_LEARN. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 1 << 13);
} cap_mode SEC(".maps");


/* Parent identity, for tracing a denial back to whoever caused it.
 *
 * These events are deduplicated in-kernel, so this runs once per new path,
 * destination or capability rather than on every operation, which is what
 * makes the two credential reads affordable here. Exec events carry a full
 * lineage; one hop is what the other signals need to stop being anonymous. */
static __always_inline void fill_parent(__u32 *ppid, __u8 *pcomm, int pcomm_sz)
{
	*ppid = 0;
	pcomm[0] = 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (!parent)
		return;
	*ppid = BPF_CORE_READ(parent, tgid);
	bpf_probe_read_kernel_str(pcomm, pcomm_sz, BPF_CORE_READ(parent, comm));
}

SEC("lsm/capable")
int BPF_PROG(capable_check, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts, int ret)
{
	/* Respect a prior denial in the LSM chain. */
	if (ret != 0)
		return ret;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0; /* kernel threads are not container workloads */

	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u64 key = (cgroup_id << 8) | ((__u64)cap & 0xff);

	__u32 *specp = bpf_map_lookup_elem(&cap_mode, &cgroup_id);
	__u32 spec = specp ? *specp : 0;
	__u8 action = ENFORCE_ACTION(spec);
	__u8 *known = bpf_map_lookup_elem(&cap_allowed, &key);

	if (!action_learns(action)) {
		if (known)
			return 0; /* learned capability: permit */

		__u32 flags = 0;
		int ret = enforce_apply(spec, &flags, EV_DENIED, EV_KILLED);

		struct cap_event *e = bpf_ringbuf_reserve(&cap_events, sizeof(*e), 0);
		if (e) {
			e->cgroup_id = cgroup_id;
			e->timestamp_ns = bpf_ktime_get_ns();
			e->pid = tgid;
			e->cap = (__u32)cap;
			e->flags = flags;
			e->pad = 0;
			e->pad2 = 0;
			fill_cap_sets(e);
			fill_parent(&e->ppid, e->pcomm, sizeof(e->pcomm));
			bpf_get_current_comm(&e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
		return ret;
	}

	/* Learning: record the capability, emit the first observation only. */
	if (known)
		return 0;
	__u8 one = 1;
	bpf_map_update_elem(&cap_allowed, &key, &one, BPF_ANY);

	struct cap_event *e = bpf_ringbuf_reserve(&cap_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	e->cap = (__u32)cap;
	e->flags = 0;
	e->pad = 0;
	e->pad2 = 0;
	fill_cap_sets(e);
	fill_parent(&e->ppid, e->pcomm, sizeof(e->pcomm));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
