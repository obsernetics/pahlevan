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
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* File access permission masks */
#define MAY_EXEC    0x00000001
#define MAY_WRITE   0x00000002
#define MAY_READ    0x00000004
#define MAY_APPEND  0x00000008
#define MAY_ACCESS  0x00000010
#define MAY_OPEN    0x00000020
#define MAY_CHDIR   0x00000040

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
 * Resolve container identifier for the current process using cgroup information.
 * Uses a combination of PID namespace and cgroup hash for better uniqueness.
 */
static __always_inline __u32 get_container_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    // Get PID namespace ID as primary identifier
    __u32 pid_ns_inum = 0;
    struct pid_namespace *pid_ns = task->nsproxy ? task->nsproxy->pid_ns_for_children : NULL;
    if (pid_ns) {
        pid_ns_inum = pid_ns->ns.inum;
    }

    // If we can't get namespace info, fall back to PID-based approach
    if (pid_ns_inum == 0) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

        // Create a better hash using both PID and TGID
        __u32 hash = pid ^ (tgid << 16);
        return hash % 65536;  // Expanded range for better distribution
    }

    // Use namespace inode number as container ID
    return pid_ns_inum;
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

    /* Enforcement mode: check if file path is allowed */
    char current_path[256];
    bpf_d_path(&file->f_path, current_path, sizeof(current_path));

    /* Check against allowed paths */
    for (int i = 0; i < policy->path_count && i < 1024; i++) {
        if (bpf_strncmp(current_path, policy->allowed_paths[i], 64) == 0) {
            return 1; /* Allow access */
        }

        /* Check for directory prefix match */
        int path_len = bpf_strlen(policy->allowed_paths[i]);
        if (path_len > 0 && policy->allowed_paths[i][path_len-1] == '/') {
            if (bpf_strncmp(current_path, policy->allowed_paths[i], path_len) == 0) {
                return 1; /* Allow access to files in allowed directory */
            }
        }
    }

    /* Default: deny access */
    return 0;
}

/* --------------------------------------------------------------------------
 * LSM Hooks (Linux Security Module)
 * -------------------------------------------------------------------------- */

/**
 * LSM hook: file_open
 * Monitors file open operations at the security layer
 */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    struct file_access_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.operation    = 2; /* open */
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    __builtin_memset(evt.filename, 0, sizeof(evt.filename));
    if (file && file->f_path.dentry && file->f_path.dentry->d_name.name) {
        bpf_probe_read_str(evt.filename, sizeof(evt.filename),
                          file->f_path.dentry->d_name.name);
    } else {
        bpf_probe_read_str(evt.filename, sizeof(evt.filename), "unknown");
    }

    if (!is_file_access_allowed(evt.container_id, evt.filename)) {
        bpf_perf_event_output(file, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -EACCES; /* Access denied */
    }

    /* Record file access for learning */
    bpf_perf_event_output(file, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

/**
 * LSM hook: file_permission
 * Monitors file permission checks
 */
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask) {
    struct file_access_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.operation    = (mask & MAY_WRITE) ? 1 : 0; /* write : read */
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();
    evt.access_mode  = mask;

    __builtin_memset(evt.filename, 0, sizeof(evt.filename));
    if (file && file->f_path.dentry && file->f_path.dentry->d_name.name) {
        bpf_probe_read_str(evt.filename, sizeof(evt.filename),
                          file->f_path.dentry->d_name.name);
    } else {
        bpf_probe_read_str(evt.filename, sizeof(evt.filename), "unknown");
    }

    if (!is_file_access_allowed(evt.container_id, evt.filename)) {
        bpf_perf_event_output(file, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -EACCES;
    }

    /* Record permission check for learning */
    bpf_perf_event_output(file, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

/**
 * LSM hook: inode_permission
 * Monitors inode-level permission checks
 */
SEC("lsm/inode_permission")
int BPF_PROG(lsm_inode_permission, struct inode *inode, int mask) {
    struct file_access_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.operation    = (mask & MAY_WRITE) ? 1 : 0;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();
    evt.access_mode  = mask;

    __builtin_memset(evt.filename, 0, sizeof(evt.filename));
    bpf_probe_read_str(evt.filename, sizeof(evt.filename), "inode");

    if (!is_file_access_allowed(evt.container_id, evt.filename)) {
        bpf_perf_event_output(inode, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -EACCES;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Kprobe Fallback Probes (for compatibility)
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
