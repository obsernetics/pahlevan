#ifndef __PAHLEVAN_ENFORCE_H__
#define __PAHLEVAN_ENFORCE_H__

/*
 * The enforcement action set, shared by every LSM program.
 *
 * For a long time there were two responses to an operation outside the learned
 * set: refuse it with EPERM, or, for exec only, refuse it and kill the task.
 * Two responses is not enough for the range of situations an operator is
 * actually in.
 *
 * Somebody rolling enforcement out to a workload they do not fully understand
 * needs to know what *would* be denied before anything is. Learning mode is a
 * poor substitute, because it widens the allow-set as it goes - the very thing
 * that would have been denied is added to the set instead of being reported.
 * Somebody responding to an incident wants the process frozen rather than
 * destroyed, because a SIGKILL takes the process memory with it and that memory
 * is the evidence. And a workload that handles ENOENT gracefully and treats
 * EPERM as fatal is better served by the errno it can cope with.
 *
 * So the per-cgroup mode map now carries a packed action rather than a bare
 * mode byte:
 *
 *   bits  0-7   action     one of ACT_*
 *   bits  8-15  signal     signal number, for ACT_SIGNAL
 *   bits 16-31  errno      errno to return, 0 meaning EPERM
 *
 * One __u32, one map lookup, no second map on the hot path. An absent entry is
 * zero, which is ACT_LEARN - so a cgroup nobody has configured behaves exactly
 * as it did before any of this existed.
 */

#define ACT_LEARN  0 /* observe and widen the allow-set; deny nothing */
#define ACT_DENY   1 /* refuse with the configured errno (default EPERM) */
#define ACT_KILL   2 /* refuse, and SIGKILL the task that tried */
#define ACT_AUDIT  3 /* report what would have been denied, and allow it */
#define ACT_SIGNAL 4 /* refuse, and send the configured signal */

/* Event flag bits. The userspace half of this contract is in
 * pkg/ebpf/manager.go and the two must move together. */
#define EV_WOULD_DENY 0x04000000u /* ACT_AUDIT: this would have been refused */

#define ENFORCE_ACTION(spec) ((__u8)((spec) & 0xff))
#define ENFORCE_SIGNAL(spec) ((__u8)(((spec) >> 8) & 0xff))
#define ENFORCE_ERRNO(spec)  ((__u16)(((spec) >> 16) & 0xffff))

/* Whether an action denies at all.
 *
 * ACT_AUDIT deliberately does not. It is the only action that reports a
 * violation and lets it through, which is what makes it useful for a rollout
 * and dangerous to confuse with the others - so it is asked about by name here
 * rather than by comparing against a range. */
static __always_inline int action_denies(__u8 action)
{
	return action == ACT_DENY || action == ACT_KILL || action == ACT_SIGNAL;
}

/* Whether an action learns. Only ACT_LEARN widens the allow-set.
 *
 * ACT_AUDIT specifically must not: an audit pass that quietly added everything
 * it reported would report a violation once and never again, which is the
 * opposite of what somebody enabling it wants. */
static __always_inline int action_learns(__u8 action)
{
	return action == ACT_LEARN;
}

/* The value an LSM hook returns for a denied operation.
 *
 * Zero means "use EPERM", so an unconfigured errno gives the behaviour every
 * previous version had.
 *
 * The clamp after the negation is the part that matters, and it is not
 * defensive programming. An LSM program must return a value in [-4095, 0] and
 * the verifier has to be able to prove it - but the verifier does not propagate
 * bounds through BPF_NEG at all. Even with e provably in [1, 4095], the moment
 * the compiler emits `r8 = -r8` the register becomes an unknown scalar and the
 * program is rejected at load time with "the register R0 has unknown scalar
 * value should have been in [-4095, 0]".
 *
 * Two signed comparisons after the negation re-establish the range, because
 * conditional jumps are something the verifier does track. They can never fire:
 * the value is already in range. They exist to say so in a form the verifier
 * accepts.
 *
 * The 12-bit mask has one behavioural consequence: an errno above 4095 keeps
 * its low bits rather than falling back to EPERM. Userspace rejects those
 * before they are ever written (see EnforcementSpec.Validate), and 4096 masks
 * to 0, which is EPERM anyway. */
static __always_inline long enforce_errno(__u32 spec)
{
	__u32 e = (spec >> 16) & 0xfff;
	if (e == 0)
		e = 1; /* EPERM */

	/* long, not int. With a 32-bit type the compiler zero-extends the clamped
	 * value back to 64 bits - `r8 <<= 32; r8 >>= 32` - and the verifier then
	 * sees 0x00000000fffff001, a large positive number, rather than -4095. The
	 * register the kernel reads is 64 bits wide, so the value has to be
	 * negative in 64 bits. */
	long ret = -(long)e;

	/* barrier_var, or the compiler deletes both comparisons: it can prove they
	 * never fire, and it is right. The verifier cannot, because it lost the
	 * bound at the negation - so the checks have to survive into the object
	 * even though they are provably dead in C. */
	barrier_var(ret);
	if (ret > -1)
		ret = -1;
	if (ret < -4095)
		ret = -4095;
	return ret;
}

/* Act on a violation, and report what was done through *flags.
 *
 * Returns the value the LSM hook should return: 0 to allow, negative to refuse.
 * The caller still submits the event - every action reports, including the two
 * that allow.
 *
 * EV_DENIED and EV_KILLED are passed in rather than defined here because each
 * program already defines them for its own event struct, and duplicating the
 * constants in a shared header is how the two halves drift apart. */
static __always_inline long enforce_apply(__u32 spec, __u32 *flags,
					  __u32 denied_bit, __u32 killed_bit)
{
	__u8 action = ENFORCE_ACTION(spec);

	if (action == ACT_AUDIT) {
		*flags |= EV_WOULD_DENY;
		return 0;
	}
	if (!action_denies(action))
		return 0;

	*flags |= denied_bit;

	if (action == ACT_KILL) {
		if (bpf_send_signal(9) == 0)
			*flags |= killed_bit;
	} else if (action == ACT_SIGNAL) {
		__u8 sig = ENFORCE_SIGNAL(spec);
		/* Signal 0 sends nothing, and a number above the highest real
		 * signal is a configuration error rather than a request. Refuse
		 * quietly in both cases: the operation is still denied, which is
		 * the part that matters. */
		if (sig > 0 && sig <= 64) {
			if (bpf_send_signal(sig) == 0)
				*flags |= killed_bit;
		}
	}

	return enforce_errno(spec);
}

#endif /* __PAHLEVAN_ENFORCE_H__ */
