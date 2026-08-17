//go:build ignore

/*
 * Syscall monitoring (CO-RE).
 *
 * A single raw tracepoint on sys_enter observes EVERY syscall (not a hand-picked
 * few), which is what behavioural learning needs. To keep userspace volume sane
 * we emit only the FIRST time a given (cgroup, syscall) pair is seen - that is
 * exactly the signal the learner wants (the syscall set of a workload), and it
 * also naturally surfaces a NEW syscall appearing after the learning window.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Event reported to userspace. Field order/size is the wire format decoded by
 * pkg/ebpf; keep it in sync with the Go SyscallEvent binary layout. */
struct syscall_event {
	__u64 cgroup_id;    /* real attribution key (bpf_get_current_cgroup_id) */
	__u64 timestamp_ns;
	__u64 syscall_nr;
	__u32 pid;          /* tgid (userspace PID) */
	__u32 tid;          /* kernel thread id */
	__u32 uid;
	__u32 gid;
	__u8  comm[16];
	/* The syscall's arguments, as the kernel received them.
	 *
	 * Without them a whole class of question is unanswerable: ptrace and
	 * ptrace(PTRACE_ATTACH) are the same event, and so are unshare and
	 * unshare(CLONE_NEWUSER). Those are the escalation primitives, and the
	 * argument is the entire signal.
	 *
	 * Reading them is why this program moved from raw_tracepoint/sys_enter to
	 * tracepoint/raw_syscalls/sys_enter. The raw variant hands over a
	 * struct pt_regs, and extracting arguments from it needs
	 * PT_REGS_PARM*_CORE_SYSCALL, which casts to struct user_pt_regs - a type
	 * an x86-derived vmlinux.h does not have, and the exact construct that
	 * broke the arm64 build once before. The ordinary tracepoint has already
	 * extracted them into an array, identically on both architectures. */
	__u64 args[6];
};

/* Ring buffer of syscall_event. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB: events are deduped in-kernel, so
				       * userspace volume is low and a large ring only
				       * wastes preallocated memory. */
} events SEC(".maps");

/* Dedup and counting: key = (cgroup_id << 16) | (syscall_nr & 0xffff) -> count.
 *
 * The event is emitted only the first time a (cgroup, syscall) pair is seen,
 * which is what bounds userspace volume, but the counter keeps incrementing.
 * That gives the frequency of each syscall for free: no extra events, no extra
 * map, and it answers "which syscalls does this workload actually lean on",
 * which the learned set alone cannot. Userspace reads the map on demand. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u64);
	/* ~400 syscall numbers per cgroup; a node's working set fits easily and
	 * the LRU evicts the tail. 1M entries preallocated ~60 MiB for nothing. */
	__uint(max_entries, 1 << 14);
} syscall_seen SEC(".maps");

/* Optional runtime knobs (single element). ARRAY maps are pre-populated with
 * zeroed entries, so the gate uses a `disabled` flag: zero (the default) means
 * enabled, and userspace sets it to 1 to turn the program off. */
struct config {
	__u8 disabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config);
	__uint(max_entries, 1);
} config_map SEC(".maps");

/* Syscalls that bypass deduplication and report every occurrence.
 *
 * Populated from userspace with the escalation primitives for the running
 * architecture - ptrace, unshare, setns, mount, bpf, io_uring_setup and the
 * rest. Empty by default, so a deployment that does not want them pays
 * nothing beyond one map lookup per syscall. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 64);
} syscall_watch SEC(".maps");

static __always_inline int enabled(void)
{
	__u32 k = 0;
	struct config *c = bpf_map_lookup_elem(&config_map, &k);
	return !c || c->disabled == 0;
}

/* The tracepoint's own layout: eight bytes of common fields, the syscall
 * number, then the six arguments. Declared here rather than taken from
 * vmlinux.h because the generated header does not describe tracepoint formats.
 */
struct sys_enter_ctx {
	__u64 __pad_common;
	__s64 id;
	__u64 args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_ctx *ctx)
{
	if (!enabled())
		return 0;

	__u64 syscall_nr = (__u64)ctx->id;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	/* Skip kernel threads (no user pid). */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	/* Count every occurrence; emit only the first - except for the watched
	 * set, which emits every time.
	 *
	 * Deduplication is what keeps this program cheap, and for a learned
	 * baseline it loses nothing: the question is which syscalls a workload
	 * uses, and the first occurrence answers it. For an escalation primitive
	 * the question is the opposite. The first ptrace a workload makes is
	 * usually a debugger attaching to itself at startup; the interesting one
	 * is the fourteenth, an hour later, with PTRACE_ATTACH and somebody else's
	 * pid. Deduplicating that away is deduplicating away the attack.
	 *
	 * The set is populated from userspace, because syscall numbers differ by
	 * architecture and the kernel side has no table. Keeping the numbers in Go
	 * means this program stays arch-neutral. */
	__u64 watched_key = syscall_nr;
	__u8 *watched = bpf_map_lookup_elem(&syscall_watch, &watched_key);

	__u64 key = (cgroup_id << 16) | (syscall_nr & 0xffff);
	__u64 *count = bpf_map_lookup_elem(&syscall_seen, &key);
	if (count) {
		/* Not atomic: an exact count is not worth a contended atomic on the
		 * hottest path in the program. A lost increment under concurrency
		 * changes a frequency ranking by one, which nothing acts on. */
		(*count)++;
		if (!watched)
			return 0;
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&syscall_seen, &key, &one, BPF_ANY);
	}

	struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 uid_gid = bpf_get_current_uid_gid();
	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->syscall_nr = syscall_nr;
	e->pid = tgid;
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	e->gid = (__u32)(uid_gid >> 32);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
#pragma unroll
	for (int i = 0; i < 6; i++)
		e->args[i] = ctx->args[i];

	bpf_ringbuf_submit(e, 0);
	return 0;
}
