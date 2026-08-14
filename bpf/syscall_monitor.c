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
};

/* Ring buffer of syscall_event. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB: events are deduped in-kernel, so
				       * userspace volume is low and a large ring only
				       * wastes preallocated memory. */
} events SEC(".maps");

/* Dedup: key = (cgroup_id << 16) | (syscall_nr & 0xffff) -> seen flag.
 * Bounds userspace event volume to one event per (cgroup, syscall). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
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

static __always_inline int enabled(void)
{
	__u32 k = 0;
	struct config *c = bpf_map_lookup_elem(&config_map, &k);
	return !c || c->disabled == 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	if (!enabled())
		return 0;

	/* raw_tp/sys_enter args: [0]=struct pt_regs *, [1]=long syscall id */
	__u64 syscall_nr = (__u64)ctx->args[1];

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	/* Skip kernel threads (no user pid). */
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	/* Dedup per (cgroup, syscall). */
	__u64 key = (cgroup_id << 16) | (syscall_nr & 0xffff);
	__u8 *seen = bpf_map_lookup_elem(&syscall_seen, &key);
	if (seen)
		return 0;
	__u8 one = 1;
	bpf_map_update_elem(&syscall_seen, &key, &one, BPF_ANY);

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

	bpf_ringbuf_submit(e, 0);
	return 0;
}
