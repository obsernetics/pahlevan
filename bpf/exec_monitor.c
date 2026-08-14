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

struct exec_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid; /* tgid */
	__u32 uid;
	__u32 flags; /* bit 0x80000000 => denied */
	__u8  comm[16];
	__u8  filename[PATH_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} exec_events SEC(".maps");

/* Learned allow-set: key = cgroup_id ^ FNV(filename). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 20);
} exec_allowed SEC(".maps");

/* Per-cgroup mode: absent/0 = learning, 1 = enforcing. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 16);
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

	/* The binary being executed. */
	const char *fname = BPF_CORE_READ(bprm, filename);
	e->filename[0] = 0;
	if (fname)
		bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

	__u64 key = cgroup_id ^ hash_name(e->filename, sizeof(e->filename));

	__u8 *modep = bpf_map_lookup_elem(&exec_mode, &cgroup_id);
	__u8 mode = modep ? *modep : MODE_LEARN;
	__u8 *known = bpf_map_lookup_elem(&exec_allowed, &key);

	if (mode == MODE_ENFORCE) {
		if (known) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		e->flags |= 0x80000000; /* denied */
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
