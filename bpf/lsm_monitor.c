//go:build ignore

/*
 * LSM-based Security Monitoring eBPF Program
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
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* --------------------------------------------------------------------------
 * Data Structures
 * -------------------------------------------------------------------------- */

/* Security event metadata */
struct security_event {
    __u32 pid;              /* Process ID */
    __u32 tid;              /* Thread ID */
    __u32 uid;              /* User ID */
    __u32 gid;              /* Group ID */
    __u32 event_type;       /* 0=process, 1=socket, 2=ptrace, 3=capability */
    __u32 action;           /* Specific action taken */
    __u32 container_id;     /* Container identifier */
    __u64 timestamp_ns;     /* Nanosecond timestamp */
    __u32 result;           /* 0=allowed, 1=denied */
    char comm[16];          /* Command name */
};

/* Security policy per container */
struct security_policy {
    __u32 container_id;     /* Container identifier */
    __u32 learning_mode;    /* 1 = learning mode, 0 = enforcement */
    __u32 allow_ptrace;     /* Allow ptrace operations */
    __u32 allow_networking; /* Allow network operations */
    __u32 allowed_caps;     /* Bitmask of allowed capabilities */
    __u64 last_update_ns;   /* Last update timestamp */
};

/* --------------------------------------------------------------------------
 * Maps
 * -------------------------------------------------------------------------- */

/* Container → security policy */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct security_policy);
    __uint(max_entries, 10000);
} security_policies SEC(".maps");

/* Perf event array for user-space notification */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} security_events SEC(".maps");

/* --------------------------------------------------------------------------
 * Helper Functions
 * -------------------------------------------------------------------------- */

/**
 * Get container identifier for the current process using namespace information.
 * Uses PID namespace inode number for proper container identification.
 */
static __always_inline __u32 get_container_id(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
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

/**
 * Check if an action is allowed under the current security policy
 */
static __always_inline int is_action_allowed(__u32 container_id, __u32 event_type, __u32 action) {
    struct security_policy *policy = bpf_map_lookup_elem(&security_policies, &container_id);
    if (!policy) {
        return 1; /* Allow when no policy is defined */
    }

    if (policy->learning_mode) {
        return 1; /* Learning mode: always allow, just record */
    }

    /* Basic enforcement logic */
    switch (event_type) {
        case 1: /* socket */
            return policy->allow_networking;
        case 2: /* ptrace */
            return policy->allow_ptrace;
        case 3: /* capability */
            return (policy->allowed_caps & (1 << action)) != 0;
        default:
            return 1; /* Allow unknown event types */
    }
}

/* --------------------------------------------------------------------------
 * LSM Hooks
 * -------------------------------------------------------------------------- */

/**
 * LSM hook: task_alloc
 * Monitors process/task creation
 */
SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_alloc, struct task_struct *task, unsigned long clone_flags) {
    struct security_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.event_type   = 0; /* process */
    evt.action       = clone_flags;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    /* Get current credentials */
    const struct cred *cred = bpf_get_current_cred();
    if (cred) {
        evt.uid = cred->uid.val;
        evt.gid = cred->gid.val;
    }

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    evt.result = is_action_allowed(evt.container_id, evt.event_type, evt.action) ? 0 : 1;

    /* Always record for learning/monitoring */
    bpf_perf_event_output(task, &security_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return evt.result ? -EACCES : 0;
}

/**
 * LSM hook: socket_create
 * Monitors network socket creation
 */
SEC("lsm/socket_create")
int BPF_PROG(lsm_socket_create, int family, int type, int protocol, int kern) {
    struct security_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.event_type   = 1; /* socket */
    evt.action       = (family << 16) | (type << 8) | protocol;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    const struct cred *cred = bpf_get_current_cred();
    if (cred) {
        evt.uid = cred->uid.val;
        evt.gid = cred->gid.val;
    }

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    evt.result = is_action_allowed(evt.container_id, evt.event_type, evt.action) ? 0 : 1;

    bpf_perf_event_output(&family, &security_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return evt.result ? -EACCES : 0;
}

/**
 * LSM hook: ptrace_access_check
 * Monitors ptrace operations for debugging/injection protection
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child, unsigned int mode) {
    struct security_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.event_type   = 2; /* ptrace */
    evt.action       = mode;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    const struct cred *cred = bpf_get_current_cred();
    if (cred) {
        evt.uid = cred->uid.val;
        evt.gid = cred->gid.val;
    }

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    evt.result = is_action_allowed(evt.container_id, evt.event_type, evt.action) ? 0 : 1;

    bpf_perf_event_output(child, &security_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return evt.result ? -EACCES : 0;
}

/**
 * LSM hook: capable
 * Monitors capability checks
 */
SEC("lsm/capable")
int BPF_PROG(lsm_capable, const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts) {
    struct security_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.event_type   = 3; /* capability */
    evt.action       = cap;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    if (cred) {
        evt.uid = cred->uid.val;
        evt.gid = cred->gid.val;
    }

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    evt.result = is_action_allowed(evt.container_id, evt.event_type, evt.action) ? 0 : 1;

    bpf_perf_event_output(cred, &security_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return evt.result ? -EACCES : 0;
}

/**
 * LSM hook: bprm_check_security
 * Monitors program execution
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm) {
    struct security_event evt = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.pid          = pid_tgid >> 32;
    evt.tid          = pid_tgid & 0xffffffff;
    evt.event_type   = 0; /* process */
    evt.action       = 1; /* exec */
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.container_id = get_container_id();

    const struct cred *cred = bpf_get_current_cred();
    if (cred) {
        evt.uid = cred->uid.val;
        evt.gid = cred->gid.val;
    }

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    /* Always allow process execution, just monitor */
    evt.result = 0;

    bpf_perf_event_output(bprm, &security_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return 0;
}

/* --------------------------------------------------------------------------
 * License
 * -------------------------------------------------------------------------- */

char _license[] SEC("license") = "GPL";