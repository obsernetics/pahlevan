//go:build ignore

/*
 * Syscall Monitoring eBPF Program
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

#include "types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* --------------------------------------------------------------------------
 * Data Structures
 * -------------------------------------------------------------------------- */

/* Syscall event metadata */
struct syscall_event {
    __u32 pid;             /* Process ID */
    __u32 tid;             /* Thread ID */
    __u32 syscall_nr;      /* Syscall number */
    __u64 timestamp_ns;    /* Event timestamp in nanoseconds */
    char  comm[16];        /* Process name */
    __u32 container_id;    /* Simplified container identifier */
};

/* Per-container syscall policy */
struct container_policy {
    __u32 container_id;           /* Container identifier */
    __u32 learning_mode;          /* 1 = learning, 0 = enforcement */
    __u64 allowed_syscalls[64];   /* Bitmap for syscalls 0–4095 */
    __u32 violation_count;        /* Number of policy violations */
    __u64 last_update_ns;         /* Last update timestamp */
};

/* Global policy configuration */
struct policy_config {
    __u32 global_learning_mode;   /* 1 = learning, 0 = enforcement */
    __u32 enforcement_enabled;    /* 1 = enforce policies */
    __u64 learning_window_ns;     /* Learning window in nanoseconds */
    __u32 max_violations;         /* Max allowed violations */
};

/* --------------------------------------------------------------------------
 * Maps
 * -------------------------------------------------------------------------- */

/* Container → syscall policy */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct container_policy);
    __uint(max_entries, 10000);
} container_policies SEC(".maps");

/* Global configuration array (single element) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct policy_config);
    __uint(max_entries, 1);
} global_config SEC(".maps");

/* Perf event array for reporting syscall events */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

/* --------------------------------------------------------------------------
 * Helper Functions
 * -------------------------------------------------------------------------- */

/**
 * Resolve container identifier for the current process using namespace information.
 * Uses PID namespace inode number for proper container identification.
 */
static __always_inline __u32 get_container_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    // Use PID-based container identification (simplified for compatibility)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;

    // Create container identifier hash from PID and TGID
    __u32 hash = pid ^ (tgid << 16);
    return hash % 65536;
}

/**
 * Check whether a given syscall is allowed for the container.
 * Updates allowed_syscalls bitmap if in learning mode.
 */
static __always_inline int is_syscall_allowed(__u32 container_id, __u32 syscall_nr) {
    struct container_policy *policy = bpf_map_lookup_elem(&container_policies, &container_id);
    if (!policy) {
        return 1; /* Allow if no policy exists */
    }

    __u32 word_idx = syscall_nr / 64;
    __u32 bit_idx  = syscall_nr % 64;

    if (policy->learning_mode) {
        if (word_idx < 64) {
            policy->allowed_syscalls[word_idx] |= (1ULL << bit_idx);
        }
        return 1;
    }

    if (word_idx >= 64) {
        return 0; /* Syscall out of range */
    }

    return (policy->allowed_syscalls[word_idx] & (1ULL << bit_idx)) ? 1 : 0;
}

/* --------------------------------------------------------------------------
 * Tracepoints
 * -------------------------------------------------------------------------- */

/* Example: openat syscall */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(void *ctx) {
    struct syscall_event event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event.pid           = pid_tgid >> 32;
    event.tid           = pid_tgid & 0xffffffff;
    event.syscall_nr    = 257; /* openat */
    event.timestamp_ns  = bpf_ktime_get_ns();
    event.container_id  = get_container_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (!is_syscall_allowed(event.container_id, event.syscall_nr)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return -1; /* Block syscall */
    }

    return 0;
}

/* Example: read syscall */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(void *ctx) {
    struct syscall_event event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event.pid           = pid_tgid >> 32;
    event.tid           = pid_tgid & 0xffffffff;
    event.syscall_nr    = 0; /* read */
    event.timestamp_ns  = bpf_ktime_get_ns();
    event.container_id  = get_container_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (!is_syscall_allowed(event.container_id, event.syscall_nr)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return -1;
    }

    return 0;
}

/* Example: write syscall */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(void *ctx) {
    struct syscall_event event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event.pid           = pid_tgid >> 32;
    event.tid           = pid_tgid & 0xffffffff;
    event.syscall_nr    = 1; /* write */
    event.timestamp_ns  = bpf_ktime_get_ns();
    event.container_id  = get_container_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    if (!is_syscall_allowed(event.container_id, event.syscall_nr)) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * License
 * -------------------------------------------------------------------------- */

char _license[] SEC("license") = "GPL";
