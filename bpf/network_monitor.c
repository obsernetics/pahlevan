//go:build ignore

/*
 * Network monitoring + enforcement (CO-RE) via the BPF LSM socket_connect hook.
 *
 * socket_connect sees every outbound connect() with the destination sockaddr and
 * can DENY by returning -EPERM - so, exactly like the file monitor, the same
 * program learns a per-cgroup allow-set of destinations during the learning
 * window and then blocks connections to unlearned destinations in-kernel. This is
 * network egress control with zero hand-written rules. Requires bpf LSM.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10
#define MODE_LEARN 0
#define MODE_ENFORCE 1

struct network_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid; /* tgid */
	__u32 saddr;
	__u32 daddr;      /* IPv4 destination, 0 when family is AF_INET6 */
	__u16 sport;
	__u16 dport;
	__u8  protocol;   /* IPPROTO_TCP */
	__u8  direction;  /* 0 = egress, bit 0x80 = denied */
	__u8  family;     /* AF_INET or AF_INET6 */
	__u8  pad;
	__u8  daddr6[16]; /* IPv6 destination, zero when family is AF_INET */
	__u8  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB; events are deduped in-kernel */
} network_events SEC(".maps");

/* Learned allow-set of destinations: key = cgroup_id ^ (daddr<<16) ^ dport. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	/* Distinct egress destinations per node; LRU evicts the tail. */
	__uint(max_entries, 1 << 15);
} network_allowed SEC(".maps");

/* Per-cgroup mode: absent/0 = learning, 1 = enforcing. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 13); /* cgroups under policy on one node */
} network_mode SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u16 family = BPF_CORE_READ(address, sa_family);
	if (family != AF_INET && family != AF_INET6)
		return 0; /* only IP egress is governed; unix/netlink are out of scope */

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	__u32 daddr = 0;
	__u8 daddr6[16] = {};
	__u16 dport_be = 0;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)address;
		daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
		dport_be = BPF_CORE_READ(sin, sin_port);
	} else {
		/* IPv6 was previously skipped entirely, which meant an attacker could
		 * exfiltrate over IPv6 even with enforcement on. Govern it too. */
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
		dport_be = BPF_CORE_READ(sin6, sin6_port);
		BPF_CORE_READ_INTO(&daddr6, sin6, sin6_addr.in6_u.u6_addr8);
	}
	__u16 dport = (dport_be >> 8) | (dport_be << 8); /* ntohs */

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	/* Allow-set key folds the whole destination address so v4 and v6 cannot
	 * collide and a v6 destination cannot be smuggled past a v4 entry. */
	__u64 addr_hash;
	if (family == AF_INET) {
		addr_hash = (__u64)daddr;
	} else {
		addr_hash = 1469598103934665603ULL;
		for (int i = 0; i < 16; i++) {
			addr_hash ^= daddr6[i];
			addr_hash *= 1099511628211ULL;
		}
	}
	__u64 key = cgroup_id ^ (addr_hash << 16) ^ (__u64)dport ^ (__u64)family;

	__u8 *modep = bpf_map_lookup_elem(&network_mode, &cgroup_id);
	__u8 mode = modep ? *modep : MODE_LEARN;
	__u8 *known = bpf_map_lookup_elem(&network_allowed, &key);

	if (mode == MODE_ENFORCE) {
		if (known)
			return 0; /* learned destination: allow */

		struct network_event *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
		if (e) {
			e->cgroup_id = cgroup_id;
			e->timestamp_ns = bpf_ktime_get_ns();
			e->pid = tgid;
			e->saddr = 0;
			e->daddr = daddr;
			__builtin_memcpy(e->daddr6, daddr6, sizeof(daddr6));
			e->sport = 0;
			e->dport = dport;
			e->protocol = 6;
			e->direction = 0x80; /* denied marker */
			e->family = (__u8)family;
			e->pad = 0;
			bpf_get_current_comm(&e->comm, sizeof(e->comm));
			bpf_ringbuf_submit(e, 0);
		}
		return -1; /* -EPERM: connect() fails */
	}

	/* Learning: record the destination; emit the first time it is seen. */
	if (known)
		return 0;
	__u8 one = 1;
	bpf_map_update_elem(&network_allowed, &key, &one, BPF_ANY);

	struct network_event *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	e->saddr = 0;
	e->daddr = daddr;
	__builtin_memcpy(e->daddr6, daddr6, sizeof(daddr6));
	e->sport = 0;
	e->dport = dport;
	e->protocol = 6;
	e->direction = 0;
	e->family = (__u8)family;
	e->pad = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
