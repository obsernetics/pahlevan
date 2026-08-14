//go:build ignore

/*
 * Network monitoring (CO-RE).
 *
 * A kprobe on tcp_connect captures outbound TCP connection attempts with the
 * destination address/port and cgroup attribution. This is the security-relevant
 * signal (egress to C2/exfil) and works per-cgroup like the other monitors, which
 * XDP/TC (per-interface, no cgroup context) does not. Events are deduped in-kernel
 * per (cgroup, daddr, dport) so learning sees each destination once.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2

struct network_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid; /* tgid */
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  protocol; /* IPPROTO_TCP */
	__u8  direction; /* 0 = egress */
	__u8  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} network_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 20);
} network_seen SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return 0; /* IPv4 only for now */

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	__u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	__u16 dport = (dport_be >> 8) | (dport_be << 8); /* ntohs */
	__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num); /* host order */

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	/* Dedup per (cgroup, daddr, dport). */
	__u64 key = cgroup_id ^ ((__u64)daddr << 16) ^ (__u64)dport;
	if (bpf_map_lookup_elem(&network_seen, &key))
		return 0;
	__u8 one = 1;
	bpf_map_update_elem(&network_seen, &key, &one, BPF_ANY);

	struct network_event *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	e->saddr = saddr;
	e->daddr = daddr;
	e->sport = sport;
	e->dport = dport;
	e->protocol = 6; /* IPPROTO_TCP */
	e->direction = 0; /* egress */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
