//go:build ignore

/*
 * Interactive shell command capture (uretprobe on readline).
 *
 * Everything else Pahlevan watches happens in the kernel, which means it only
 * sees a shell command once the shell turns it into a syscall. Most commands
 * do: `cat /etc/shadow` becomes an execve and an open. Plenty do not.
 * `cd /root`, `export KUBECONFIG=...`, `echo payload > /tmp/x`, `read -r line`,
 * `history -c`, a for-loop over a variable - all of those are shell builtins.
 * They change what the session is doing and they produce no exec event
 * whatsoever, so an exec-based monitor watches an attacker work and sees
 * nothing but the shell's own process.
 *
 * A uretprobe on readline() closes that gap by reading the command where it is
 * written: at the prompt. The return value of readline is the line the user
 * typed, in the shell's own address space, before the shell has parsed it.
 * Builtins, pipelines, quoting, typos and all.
 *
 * This is the highest-value thing a uprobe can do for a container runtime
 * security tool, because an interactive shell inside a production container is
 * already the anomaly. The command is what turns "somebody has a shell in
 * payments-api" into a description of what they did with it.
 *
 * Scope, deliberately: only shells the agent is told to trace, only the line
 * as typed, and nothing about any other userspace function. This is not a
 * general-purpose userspace tap.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"

/* See bpf/cred_monitor.c for why this declaration is here: bpf_tracing.h needs
 * struct user_pt_regs to read a probe's registers on arm64, and an x86-derived
 * vmlinux.h does not carry it. It is UAPI, so the layout is fixed. */
#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* 232 bytes of command line.
 *
 * Long enough for the overwhelming majority of typed commands and for the
 * beginning of a pasted one, which is the part that says what it is. Truncated
 * lines are marked rather than silently cut, so a reader can tell the
 * difference between a short command and the front of a long one. */
#define LINE_LEN 232

#define SHELL_TRUNCATED 0x01
#define SHELL_EMPTY     0x02

struct shell_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid; /* tgid */
	__u32 tid;
	__u32 uid;
	__u32 flags;
	__u8  comm[16];
	__u8  line[LINE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} shell_events SEC(".maps");

/* key 0: enabled */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4);
} shell_config SEC(".maps");

/* The event is far too large for the 512-byte stack, so it is assembled in a
 * per-CPU scratch buffer and copied into the ring buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct shell_event);
	__uint(max_entries, 1);
} shell_scratch SEC(".maps");

SEC("uretprobe/readline")
int BPF_KRETPROBE(handle_readline, const char *line)
{
	__u32 zero = 0;
	__u32 *enabled = bpf_map_lookup_elem(&shell_config, &zero);
	if (!enabled || !*enabled)
		return 0;

	/* readline returns NULL at end of input - the user pressed Ctrl-D. There
	 * is no command to report. */
	if (!line)
		return 0;

	struct shell_event *e = bpf_map_lookup_elem(&shell_scratch, &zero);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->cgroup_id = bpf_get_current_cgroup_id();
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	e->flags = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* The line lives in the shell's address space, so this is a user read.
	 * bpf_probe_read_user_str returns the length including the terminator, or
	 * a negative errno if the page is not resident - which can happen and is
	 * not an error worth reporting, just a line that cannot be read. */
	long n = bpf_probe_read_user_str(e->line, LINE_LEN, line);
	if (n < 0)
		return 0;
	if (n <= 1) {
		/* An empty line: the user pressed return at the prompt. Reported
		 * rather than dropped, because a session's shape - how many prompts,
		 * how far apart - is itself evidence, and it costs one event per
		 * keystroke a human made. */
		e->flags |= SHELL_EMPTY;
	}
	if (n == LINE_LEN)
		e->flags |= SHELL_TRUNCATED;

	bpf_ringbuf_output(&shell_events, e, sizeof(*e), 0);
	return 0;
}
