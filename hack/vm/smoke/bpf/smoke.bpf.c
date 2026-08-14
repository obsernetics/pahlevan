// SPDX-License-Identifier: GPL-2.0
//
// smoke.bpf.c - Minimal CO-RE eBPF smoke test for the pahlevan test VM.
//
// It carries two programs whose successful load+attach proves the VM can do
// real eBPF work that the HOST is intentionally not allowed to do:
//
//   1. A raw tracepoint on sys_enter_execve  -> ordinary eBPF load/attach.
//   2. An LSM hook on file_open              -> requires the *bpf* LSM to be
//      active in the running kernel (lsm=...,bpf). Loading + attaching an
//      lsm/ program is impossible unless /sys/kernel/security/lsm includes
//      "bpf", so this is the decisive proof that BPF-LSM enforcement works.
//
// Both increment a counter so the userspace loader can show they actually ran.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define IDX_EXECVE 0
#define IDX_LSM    1

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// Ordinary eBPF: fires on every execve.
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    bump(IDX_EXECVE);
    return 0;
}

// BPF-LSM: fires on every file_open MAC check. Returning 0 = allow, so the
// system keeps working; a negative return would DENY, which is exactly the
// enforcement primitive pahlevan relies on. Attaching this at all requires the
// bpf LSM to be enabled in the kernel cmdline.
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    bump(IDX_LSM);
    return 0; // allow
}
