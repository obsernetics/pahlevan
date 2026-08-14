//go:build ignore

/*
 * File access monitoring (CO-RE) via the BPF LSM file_open hook.
 *
 * The LSM hook sees every file open with the resolved struct file, which lets us
 * capture the full path (bpf_d_path) and - in enforcement mode later - DENY by
 * returning -EPERM. That is strictly stronger than tracepoints, which cannot
 * block. Requires a kernel with BPF LSM active (lsm=...,bpf).
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_MAX_LEN 128

struct file_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid; /* tgid */
	__u32 uid;
	__u32 gid;
	__u32 flags; /* file->f_flags */
	__u8  comm[16];
	__u8  path[PATH_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB; events are deduped in-kernel */
} file_events SEC(".maps");

/* The learned allow-set: key = cgroup_id ^ FNV(path). During learning this is
 * auto-populated by the kernel; during enforcement, an open whose (cgroup, path)
 * is absent is denied. This IS the adaptive policy - no hand-written rules. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	/* Working set of (cgroup, path) pairs on a node. LRU evicts the tail, so
	 * this bounds memory instead of preallocating ~60 MiB. */
	__uint(max_entries, 1 << 17);
} file_allowed SEC(".maps");

/* Per-cgroup enforcement mode: absent/0 = learning, 1 = enforcing. Userspace
 * flips a cgroup to enforcing when its learning window closes. */
#define MODE_LEARN   0
#define MODE_ENFORCE 1
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 13); /* cgroups under policy on one node */
} file_mode SEC(".maps");

struct fconfig {
	__u8 disabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fconfig);
	__uint(max_entries, 1);
} file_config SEC(".maps");

static __always_inline int enabled(void)
{
	__u32 k = 0;
	struct fconfig *c = bpf_map_lookup_elem(&file_config, &k);
	return !c || c->disabled == 0;
}

/* FNV-1a over the path for the dedup key. */
static __always_inline __u64 hash_path(const __u8 *p, int n)
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

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
	if (!enabled())
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = (__u32)uid_gid;
	e->gid = (__u32)(uid_gid >> 32);
	e->flags = BPF_CORE_READ(file, f_flags);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Resolve the path. bpf_d_path is permitted on security_file_open. */
	long n = bpf_d_path((struct path *)&file->f_path, (char *)e->path, sizeof(e->path));
	if (n < 0)
		e->path[0] = 0;

	__u64 phash = hash_path(e->path, sizeof(e->path));
	__u64 key = cgroup_id ^ phash;

	/* Enforcement mode for this cgroup (default: learning). */
	__u8 *modep = bpf_map_lookup_elem(&file_mode, &cgroup_id);
	__u8 mode = modep ? *modep : MODE_LEARN;

	__u8 *known = bpf_map_lookup_elem(&file_allowed, &key);

	if (mode == MODE_ENFORCE) {
		if (known) {
			/* In the learned allow-set: permit silently. */
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		/* Not learned -> DENY in-kernel and report the violation. */
		e->flags |= 0x80000000; /* denied marker for userspace */
		bpf_ringbuf_submit(e, 0);
		return -1; /* -EPERM: the open fails */
	}

	/* Learning mode: record the path in the allow-set; emit only the first time
	 * each (cgroup, path) is seen so userspace learns the file set cheaply. */
	if (known) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	__u8 one = 1;
	bpf_map_update_elem(&file_allowed, &key, &one, BPF_ANY);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
