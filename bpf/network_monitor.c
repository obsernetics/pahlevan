//go:build ignore

/*
 * Network Flow Monitoring eBPF Program
 *
 * Copyright 2025.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* --------------------------------------------------------------------------
 * Data Structures
 * -------------------------------------------------------------------------- */

/* Network flow event metadata */
struct network_flow_event {
    __u32 src_ip;          /* Source IPv4 address (host byte order) */
    __u32 dst_ip;          /* Destination IPv4 address (host byte order) */
    __u16 src_port;        /* Source port */
    __u16 dst_port;        /* Destination port */
    __u8  protocol;        /* IP protocol (TCP/UDP/ICMP/etc.) */
    __u32 container_id;    /* Simplified container identifier */
    __u64 timestamp_ns;    /* Nanosecond timestamp */
    __u64 bytes;           /* Payload length (if available) */
    __u64 packets;         /* Number of packets (aggregated in TC hook) */
};

/* Per-container connection policy */
struct connection_policy {
    __u32 container_id;        /* Container identifier */
    __u32 allowed_destinations[256]; /* Whitelisted destinations (simplified) */
    __u16 allowed_ports[64];        /* Whitelisted ports */
    __u32 learning_mode;            /* 1 = learning, 0 = enforcement */
    __u64 last_update_ns;           /* Last update timestamp */
};

/* --------------------------------------------------------------------------
 * Maps
 * -------------------------------------------------------------------------- */

/* Container → network connection policy */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct connection_policy);
    __uint(max_entries, 10000);
} connection_policies SEC(".maps");

/* Perf event array for sending flow events to user space */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} network_events SEC(".maps");

/* --------------------------------------------------------------------------
 * Helper Functions
 * -------------------------------------------------------------------------- */

/**
 * Resolve container identifier from current process context.
 * For network monitoring, we use the current task's namespace information.
 */
static __always_inline __u32 get_container_id_from_skb(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        // Fallback to PID-based approach when task is unavailable
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        return pid % 65536;
    }

    // Get PID namespace ID as container identifier
    __u32 pid_ns_inum = 0;
    struct pid_namespace *pid_ns = task->nsproxy ? task->nsproxy->pid_ns_for_children : NULL;
    if (pid_ns) {
        pid_ns_inum = pid_ns->ns.inum;
    }

    // Fallback to enhanced PID-based approach if namespace unavailable
    if (pid_ns_inum == 0) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

        // Better hash combining PID and TGID
        __u32 hash = pid ^ (tgid << 16);
        return hash % 65536;
    }

    return pid_ns_inum;
}

/* --------------------------------------------------------------------------
 * XDP Program: Ingress Monitoring
 * -------------------------------------------------------------------------- */

/**
 * Monitor ingress traffic at XDP hook.
 */
SEC("xdp")
int xdp_monitor_network(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only handle IPv4 */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct network_flow_event flow = {};
    flow.src_ip       = bpf_ntohl(ip->saddr);
    flow.dst_ip       = bpf_ntohl(ip->daddr);
    flow.protocol     = ip->protocol;
    flow.timestamp_ns = bpf_ktime_get_ns();
    flow.container_id = get_container_id_from_skb();

    /* Extract L4 headers */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        flow.src_port = bpf_ntohs(tcp->source);
        flow.dst_port = bpf_ntohs(tcp->dest);

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        flow.src_port = bpf_ntohs(udp->source);
        flow.dst_port = bpf_ntohs(udp->dest);
    }

    /* Emit event to user space */
    bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, &flow, sizeof(flow));

    return XDP_PASS;
}

/* --------------------------------------------------------------------------
 * TC Program: Egress Monitoring
 * -------------------------------------------------------------------------- */

/**
 * Monitor egress traffic at TC hook.
 */
SEC("tc")
int tc_monitor_egress(struct __sk_buff *skb) {
    struct network_flow_event flow = {};
    flow.timestamp_ns = bpf_ktime_get_ns();
    flow.container_id = get_container_id_from_skb();
    flow.bytes        = skb->len;
    flow.packets      = 1;

    bpf_perf_event_output(skb, &network_events, BPF_F_CURRENT_CPU, &flow, sizeof(flow));
    return 0;
}

/* --------------------------------------------------------------------------
 * License
 * -------------------------------------------------------------------------- */

char _license[] SEC("license") = "GPL";
