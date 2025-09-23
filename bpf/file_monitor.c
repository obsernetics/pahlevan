//go:build ignore

/*
 * File Access Monitoring eBPF Program
 *
 * Copyright 2025.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* --------------------------------------------------------------------------
 * Data Structures
 * -------------------------------------------------------------------------- */

/* File access event metadata */
struct file_access_event {
    __u32 pid;              /* Process ID */
    __u32 tid;              /* Thread ID */
    __u32 operation;        /* 0 = read, 1 = write, 2 = open, 3 = close */
    char  filename[256];    /* Target filename (simplified) */
    __u32 container_id;     /* Simplified container identifier */
    __u64 timestamp_ns;     /* Nanosecond timestamp */
    __u32 access_mode;      /* Access mode flags (if available) */
};

/* File access policy per container */
struct file_access_policy {
    __u32 container_id;     /* Container identifier */
    __u32 learning_mode;    /* 1 = learning mode, 0 = enforcement */
    char  allowed_paths[1024][64]; /* Whitelisted paths (simplified) */
    __u32 path_count;       /* Number of valid entries in allowed_paths */
    __u64 last_update_ns;   /* Last update timestamp */
};

/* --------------------------------------------------------------------------
 * Maps
 * -------------------------------------------------------------------------- */

/* Container → file access policy */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct file_access_policy);
    __uint(max_entries, 10000);
} file_policies SEC(".maps");

/* Perf event array for user-space notification */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} file_events SEC(".maps");

/* --------------------------------------------------------------------------
 * Helper Functions
 * -------------------------------------------------------------------------- */

/**
 * Resolve a simplified container identifier for the current process.
 * NOTE: This is a placeholder hash, not suitable for production.
 */
static __always_inline __u32 get_container_id(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return pid % 1000; /* Very naive hashing for demonstration */
}

/**
 * Determine whether a file access is permitted under the current policy.
 *
 * @param container_id Container identifier
 * @param path         Path being accessed
 * @return 1 if access is allowed, 0 if denied
 */
static __always_inline int is_file_access_allowed(__u32 container_id, const char *path) {
    struct file_access_policy *policy = bpf_map_lookup_elem(&file_policies, &container_id);
    if (!policy) {
        return 1; /* Allow when no policy is defined */
    }

    if (policy->learning_mode) {
        /* Learning mode: record activity, always allow */
        return 1;
    }

    /* Enforcement mode: placeholder logic (always allow in demo) */
    return 1;
}

/* --------------------------------------------------------------------------
 * Probes
 * -------------------------------------------------------------------------- */

/* Kprobe: file open */
SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_openat2(struct pt_regs *ctx) {
    struct file_access_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.operation    = 2; /* open */
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    __builtin_memset(evt.filename, 0, sizeof(evt.filename));
    bpf_probe_read_str(evt.filename, sizeof(evt.filename), "unknown");

    if (!is_file_access_allowed(evt.container_id, evt.filename)) {
        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -1; /* Block */
    }

    return 0;
}

/* Kprobe: file read */
SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx) {
    struct file_access_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.operation    = 0; /* read */
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    __builtin_memset(evt.filename, 0, sizeof(evt.filename));
    bpf_probe_read_str(evt.filename, sizeof(evt.filename), "file");

    if (!is_file_access_allowed(evt.container_id, evt.filename)) {
        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -1;
    }

    return 0;
}

/* Kprobe: file write */
SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx) {
    struct file_access_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.operation    = 1; /* write */
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    __builtin_memset(evt.filename, 0, sizeof(evt.filename));
    bpf_probe_read_str(evt.filename, sizeof(evt.filename), "file");

    if (!is_file_access_allowed(evt.container_id, evt.filename)) {
        bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * License
 * -------------------------------------------------------------------------- */

char _license[] SEC("license") = "GPL";
