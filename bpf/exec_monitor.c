//go:build ignore

/*
 * Process execution monitoring + enforcement (CO-RE) via the BPF LSM
 * bprm_check_security hook, which fires on execve with the resolved binary.
 *
 * Like the file and network monitors, it learns the set of executables a
 * container runs during the learning window and, under enforcement, denies
 * exec of any unlearned binary with -EPERM - stopping reverse shells, dropped
 * miners, and other unexpected processes at the moment they try to start.
 * Requires a kernel with the bpf LSM active.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_MAX_LEN 128
#define MODE_LEARN 0
#define MODE_ENFORCE 1

/* Depth of the recorded process lineage, not counting the execing process
 * itself. Four is enough for the chains that matter in a container -
 * entrypoint -> shell -> tool -> child - and the walk has to be a bounded loop
 * for the verifier anyway. Each level costs 20 bytes in the event. */
#define ANCESTRY_DEPTH 4

struct ancestor {
	__u32 pid;      /* tgid; 0 marks the end of the chain */
	__u8  comm[16];
};

struct exec_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid;  /* tgid */
	__u32 ppid; /* parent tgid: kept as its own field so existing consumers
		     * do not have to understand the ancestry array. Equal to
		     * ancestry[0].pid. */
	__u32 uid;
	__u32 flags; /* bit 0x80000000 => denied, 0x40000000 => killed */
	__u8  comm[16];
	__u8  pcomm[16]; /* parent comm; equal to ancestry[0].comm */
	/* Full lineage, nearest ancestor first. A denial is far more actionable
	 * as "nginx -> sh -> curl" than as "curl was denied". */
	struct ancestor ancestry[ANCESTRY_DEPTH];
	__u8  filename[PATH_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB; events are deduped in-kernel */
} exec_events SEC(".maps");

/* Learned allow-set: key = cgroup_id ^ FNV(filename). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	/* Containers execute few distinct binaries; LRU evicts the tail. */
	__uint(max_entries, 1 << 13);
} exec_allowed SEC(".maps");

/* Per-cgroup mode: absent/0 = learning, 1 = enforcing, 2 = enforcing + kill.
 * Mode 2 also sends SIGKILL to the offending task, matching Tetragon's Sigkill
 * action, for operators who want the process terminated and not merely refused. */
#define MODE_ENFORCE_KILL 2
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 13); /* cgroups under policy on one node */
} exec_mode SEC(".maps");

static __always_inline __u64 hash_name(const __u8 *p, int n)
{
	__u64 h = 1469598103934665603ULL;
	for (int i = 0; i < n; i++) {
		if (p[i] == 0)
			break;
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm, int ret)
{
	/* Respect a prior LSM denial in the chain. */
	if (ret != 0)
		return ret;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->flags = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Process ancestry: walk real_parent so a denial identifies the whole
	 * chain that led to it, not just the doomed child. The loop is bounded and
	 * fully unrolled, which is what the verifier requires. */
	e->ppid = 0;
	e->pcomm[0] = 0;
	__builtin_memset(e->ancestry, 0, sizeof(e->ancestry));
	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
#pragma unroll
		for (int i = 0; i < ANCESTRY_DEPTH; i++) {
			if (!task)
				break;
			struct task_struct *parent = BPF_CORE_READ(task, real_parent);
			if (!parent)
				break;
			__u32 ptgid = BPF_CORE_READ(parent, tgid);
			/* pid 0 is the idle task and every chain terminates at pid 1;
			 * recording past that is noise, and a task that is its own
			 * parent would otherwise spin out the unrolled loop. */
			if (ptgid == 0 || parent == task)
				break;
			e->ancestry[i].pid = ptgid;
			BPF_CORE_READ_STR_INTO(&e->ancestry[i].comm, parent, comm);
			if (i == 0) {
				e->ppid = ptgid;
				BPF_CORE_READ_STR_INTO(&e->pcomm, parent, comm);
			}
			if (ptgid == 1)
				break;
			task = parent;
		}
	}

	/* The binary being executed. */
	const char *fname = BPF_CORE_READ(bprm, filename);
	e->filename[0] = 0;
	if (fname)
		bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

	__u64 key = cgroup_id ^ hash_name(e->filename, sizeof(e->filename));

	__u8 *modep = bpf_map_lookup_elem(&exec_mode, &cgroup_id);
	__u8 mode = modep ? *modep : MODE_LEARN;
	__u8 *known = bpf_map_lookup_elem(&exec_allowed, &key);

	if (mode == MODE_ENFORCE || mode == MODE_ENFORCE_KILL) {
		if (known) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		e->flags |= 0x80000000; /* denied */
		if (mode == MODE_ENFORCE_KILL) {
			e->flags |= 0x40000000; /* killed */
			bpf_send_signal(9);     /* SIGKILL the offending task */
		}
		bpf_ringbuf_submit(e, 0);
		return -1; /* -EPERM: execve fails */
	}

	if (known) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	__u8 one = 1;
	bpf_map_update_elem(&exec_allowed, &key, &one, BPF_ANY);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
