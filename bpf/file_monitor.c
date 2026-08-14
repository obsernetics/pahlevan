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

/* Bits userspace reads off file_event.flags, above the O_* range that
 * f_flags occupies. */
#define EV_DENIED 0x80000000u
/* EV_WRITE marks an open that requested write access. It is derived from
 * f_mode, the same source the allow-set key uses, so what userspace sees and
 * what the kernel keyed on can never disagree. */
#define EV_WRITE  0x40000000u

/* FMODE_WRITE from include/linux/fs.h. Not in vmlinux.h, which carries types
 * rather than macros. */
#define FMODE_WRITE 0x2

struct file_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid; /* tgid */
	__u32 uid;
	__u32 gid;
	__u32 flags; /* file->f_flags, plus EV_DENIED and EV_WRITE below */
	__u8  comm[16];
	__u8  path[PATH_MAX_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB; events are deduped in-kernel */
} file_events SEC(".maps");

/* The learned allow-set: key = cgroup_id ^ FNV(path) ^ write_mix. During learning this is
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

/* A container runtime must write /proc/<pid>/oom_score_adj to enter an
 * already-running container: runc's nsexec does it during `kubectl exec`, and
 * so does an exec liveness probe. Under enforcement that write is denied,
 * because bpf_d_path resolves /proc/self to /proc/<pid> and no fixed path can
 * be seeded to match a pid that changes every time.
 *
 * The result was that enforcing a policy made the workload undebuggable and
 * broke exec probes, which is the kind of operational cost that gets a security
 * tool switched off.
 *
 * oom_score_adj is a per-process OOM-killer hint. It is not a privilege
 * boundary and grants no access to anything, so exempting exactly this basename
 * is a much smaller concession than the alternative. Nothing else under /proc
 * is exempted; /proc/<pid>/mem and friends stay governed.
 */
static __always_inline int is_oom_score_adj(const __u8 *p, int n)
{
	static const char suffix[] = "/oom_score_adj";
	const int slen = sizeof(suffix) - 1; /* 14, excluding the NUL */

	if (n < slen + 6)
		return 0;
	if (p[0] != '/' || p[1] != 'p' || p[2] != 'r' ||
	    p[3] != 'o' || p[4] != 'c' || p[5] != '/')
		return 0;

	int len = 0;
	for (int i = 0; i < n; i++) {
		if (p[i] == 0)
			break;
		len = i + 1;
	}
	if (len < slen)
		return 0;

	int off = len - slen;
	/* Clamp so the verifier can prove every index below is in range. */
	if (off < 0 || off > n - slen)
		return 0;
	off &= (PATH_MAX_LEN - 1);

	for (int i = 0; i < slen; i++) {
		int idx = (off + i) & (PATH_MAX_LEN - 1);
		if (p[idx] != (__u8)suffix[i])
			return 0;
	}
	return 1;
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

	/* Write intent is part of the allow-set identity, not just a detail of the
	 * event. Keying on the path alone meant that learning nginx's startup READ
	 * of /etc/passwd also permitted an attacker to WRITE it later and append a
	 * root-equivalent account, which is exactly the escalation enforcement is
	 * supposed to stop. */
	__u32 fmode = (__u32)BPF_CORE_READ(file, f_mode);
	__u8 write = (fmode & FMODE_WRITE) ? 1 : 0;
	if (write)
		e->flags |= EV_WRITE;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Resolve the path. bpf_d_path is permitted on security_file_open. */
	long n = bpf_d_path((struct path *)&file->f_path, (char *)e->path, sizeof(e->path));
	if (n < 0)
		e->path[0] = 0;

	__u64 phash = hash_path(e->path, sizeof(e->path));
	/* Mixed multiplicatively by the 64-bit golden ratio rather than set as a
	 * bit, so the write dimension cannot alias with a path hash that happens
	 * to have that bit set. */
	__u64 key = cgroup_id ^ phash ^ ((__u64)write * 0x9E3779B97F4A7C15ULL);

	/* Enforcement mode for this cgroup (default: learning). */
	__u8 *modep = bpf_map_lookup_elem(&file_mode, &cgroup_id);
	__u8 mode = modep ? *modep : MODE_LEARN;

	/* Let the container runtime in. See is_oom_score_adj. */
	if (is_oom_score_adj(e->path, sizeof(e->path))) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	__u8 *known = bpf_map_lookup_elem(&file_allowed, &key);

	if (mode == MODE_ENFORCE) {
		if (known) {
			/* In the learned allow-set: permit silently. */
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		/* Not learned -> DENY in-kernel and report the violation. */
		e->flags |= EV_DENIED; /* denied marker for userspace */
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
