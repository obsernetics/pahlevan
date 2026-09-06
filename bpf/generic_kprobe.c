//go:build ignore

/*
 * A kprobe the operator points at any kernel function, without rebuilding.
 *
 * Pahlevan's other six programs each watch one thing and were chosen because
 * they answer the questions a learned baseline needs: which files, which
 * destinations, which binaries, which capabilities, which syscalls, and the
 * moment credentials change. That covers the model well and covers everything
 * else not at all. A kernel function outside that set - a filesystem hook, a
 * module load path, a driver ioctl, whatever tomorrow's advisory names - was
 * unreachable without writing C, recompiling, and shipping a new agent.
 *
 * This is one program, compiled once, that userspace attaches to any symbol a
 * policy names. It carries no knowledge of what it is attached to. Everything
 * that varies - which arguments to compare, against what, and what to do about
 * a match - lives in a map, keyed by the attachment.
 *
 * The key is the attach cookie. Every kprobe link is created with a cookie set
 * to the probe's id, and bpf_get_attach_cookie returns it here, so one program
 * attached to forty functions knows which of the forty is running. Without it
 * every attachment would need its own copy of the program, which is how you run
 * out of kernel memory.
 *
 * WHAT THIS CANNOT DO: refuse the call. A kprobe fires alongside the function,
 * not in place of it, and denying needs bpf_override_return, which requires
 * CONFIG_BPF_KPROBE_OVERRIDE and a target the kernel has marked error
 * injectable - a short list that does not include most of what anyone wants to
 * watch. So the actions here are report, audit, and signal. The signal is real
 * enforcement, delivered before the task returns to userspace, and it is the
 * same trade bpf/cred_monitor.c makes at commit_creds for the same reason.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"

/* bpf_tracing.h reads a kprobe's registers through struct user_pt_regs on
 * arm64, and a vmlinux.h generated from an x86 kernel does not carry that type.
 * It is UAPI, so the layout is a stable ABI. See bpf/cred_monitor.c. */
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
#include "enforce.h"

char LICENSE[] SEC("license") = "GPL";

/* How many arguments are captured and how many selectors one probe may carry.
 *
 * Five arguments because that is what the calling convention exposes through
 * PT_REGS_PARM on every architecture this builds for; a sixth is not portably
 * reachable. Four selectors because they are evaluated in an unrolled loop and
 * the verifier's instruction budget is not free - four is enough to say "this
 * argument, that flag set, from this uid" and stop. */
#define KP_ARGS      5
#define KP_SELECTORS 4

/* Selector operators. Ordered so the numeric ones are contiguous. */
#define KP_OP_ANY   0 /* unused slot */
#define KP_OP_EQ    1
#define KP_OP_NE    2
#define KP_OP_LT    3
#define KP_OP_GT    4
#define KP_OP_MASK  5 /* (arg & value) != 0  - any of these bits set */
#define KP_OP_NMASK 6 /* (arg & value) == 0  - none of these bits set */

/* Which value a selector compares. Arguments are the point, but a probe that
 * can only look at arguments cannot say "when root does it", and that is most
 * of what makes a probe interesting. */
#define KP_SRC_ARG  0 /* args[sel.arg] */
#define KP_SRC_UID  1
#define KP_SRC_GID  2
#define KP_SRC_PID  3

struct kp_selector {
	__u8  src;   /* KP_SRC_* */
	__u8  arg;   /* index into args, when src is KP_SRC_ARG */
	__u8  op;    /* KP_OP_* */
	__u8  pad;
	__u32 pad2;
	__u64 value;
};

struct kp_config {
	/* Packed enforcement action; see bpf/enforce.h. Deny is not available
	 * here (a kprobe cannot refuse the call), so userspace rejects it and the
	 * program treats anything that denies as report-only rather than
	 * pretending. */
	__u32 action;
	__u8  nselectors;
	__u8  scoped;   /* 1: only fire for cgroups in kp_governed */
	__u16 pad;
	struct kp_selector sel[KP_SELECTORS];
};

/* Keyed by the attach cookie, which userspace sets to the probe id. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct kp_config);
	__uint(max_entries, 256);
} kp_config SEC(".maps");

/* Cgroups a scoped probe applies to. A probe attached to a kernel function
 * fires for the whole node, including the kubelet and the container runtime, so
 * anything that signals must be able to say "only these workloads" or the first
 * misconfigured policy takes the node down. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 8192);
} kp_governed SEC(".maps");

/* key 0: enabled */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4);
} kp_runtime SEC(".maps");

#define KP_MATCHED   0x00000001u
#define KP_SIGNALLED 0x00000002u
#define KP_WOULD     0x00000004u /* ACT_AUDIT: reported, nothing done */

struct kp_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u64 probe_id;
	__u64 args[KP_ARGS];
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u32 flags;
	__u32 pad;
	__u8  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} kp_events SEC(".maps");

/* The event is larger than the 512-byte stack allows, so it is built in a
 * per-CPU scratch buffer and copied out. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__type(value, struct kp_event);
	__uint(max_entries, 1);
} kp_scratch SEC(".maps");

static __always_inline int kp_enabled(void)
{
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&kp_runtime, &k);
	return v && *v;
}

/* Compare one selector. An unknown operator does not match: a selector the
 * kernel cannot evaluate must never widen what fires, because the action on the
 * other side may be a signal. */
static __always_inline int kp_match_one(const struct kp_selector *s,
					const __u64 *args, __u64 uid_gid, __u32 tgid)
{
	__u64 have;

	switch (s->src) {
	case KP_SRC_UID:
		have = (__u32)uid_gid;
		break;
	case KP_SRC_GID:
		have = uid_gid >> 32;
		break;
	case KP_SRC_PID:
		have = tgid;
		break;
	default: {
		__u8 i = s->arg;
		if (i >= KP_ARGS)
			return 0;
		/* Indexing with a variable needs the bound spelled out for the
		 * verifier on every read, not just once. */
		have = args[i & (KP_ARGS - 1)];
		break;
	}
	}

	switch (s->op) {
	case KP_OP_EQ:
		return have == s->value;
	case KP_OP_NE:
		return have != s->value;
	case KP_OP_LT:
		return have < s->value;
	case KP_OP_GT:
		return have > s->value;
	case KP_OP_MASK:
		return (have & s->value) != 0;
	case KP_OP_NMASK:
		return (have & s->value) == 0;
	}
	return 0;
}

SEC("kprobe/generic")
int generic_kprobe(struct pt_regs *ctx)
{
	if (!kp_enabled())
		return 0;

	/* Which of this program's many attachments is running. */
	__u64 probe_id = bpf_get_attach_cookie(ctx);
	struct kp_config *cfg = bpf_map_lookup_elem(&kp_config, &probe_id);
	if (!cfg)
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();
	if (cfg->scoped) {
		if (!bpf_map_lookup_elem(&kp_governed, &cgroup_id))
			return 0;
	}

	__u64 args[KP_ARGS];
	args[0] = (__u64)PT_REGS_PARM1(ctx);
	args[1] = (__u64)PT_REGS_PARM2(ctx);
	args[2] = (__u64)PT_REGS_PARM3(ctx);
	args[3] = (__u64)PT_REGS_PARM4(ctx);
	args[4] = (__u64)PT_REGS_PARM5(ctx);

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u32 tgid = pid_tgid >> 32;

	/* Selectors are ANDed. A probe with none matches every call, which is
	 * what "watch this function" means and is why the action defaults to
	 * reporting rather than signalling. */
	__u8 n = cfg->nselectors;
	if (n > KP_SELECTORS)
		n = KP_SELECTORS;
#pragma unroll
	for (int i = 0; i < KP_SELECTORS; i++) {
		if (i >= n)
			break;
		if (!kp_match_one(&cfg->sel[i], args, uid_gid, tgid))
			return 0;
	}

	__u32 zero = 0;
	struct kp_event *e = bpf_map_lookup_elem(&kp_scratch, &zero);
	if (!e)
		return 0;

	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->probe_id = probe_id;
#pragma unroll
	for (int i = 0; i < KP_ARGS; i++)
		e->args[i] = args[i];
	e->pid = tgid;
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)uid_gid;
	e->gid = uid_gid >> 32;
	e->pad = 0;
	e->flags = KP_MATCHED;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* What a match does. enforce_apply is not reused here: it returns an
	 * errno for an LSM hook to refuse with, and a kprobe has nothing to
	 * refuse. Only the signalling half applies. */
	__u8 action = ENFORCE_ACTION(cfg->action);
	if (action == ACT_AUDIT) {
		e->flags |= KP_WOULD;
	} else if (action == ACT_KILL) {
		if (bpf_send_signal(9) == 0)
			e->flags |= KP_SIGNALLED;
	} else if (action == ACT_SIGNAL) {
		__u8 sig = ENFORCE_SIGNAL(cfg->action);
		if (sig > 0 && sig <= 64) {
			if (bpf_send_signal(sig) == 0)
				e->flags |= KP_SIGNALLED;
		}
	}

	bpf_ringbuf_output(&kp_events, e, sizeof(*e), 0);
	return 0;
}
