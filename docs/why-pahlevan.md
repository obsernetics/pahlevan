# What Pahlevan does that Falco and Tetragon do not

This is the advocacy document. [`comparison.md`](comparison.md) is the honest
one, and it lists fifteen things those tools do better — read it second, and
read it before you deploy anything.

Both documents exist because a claim that cannot survive its own counter-example
is not worth making. Everything below is a capability you can verify in this
repository, with the file that implements it named so you can check.

---

## 1. There are no rules to write, and it still blocks

This is the whole argument, and it is the one neither comparator can answer.

- **Falco** detects. It does not block, by design. You write rules, and when one
  matches you get an alert after the syscall has already succeeded.
- **Tetragon** blocks. But only the behaviors you wrote a `TracingPolicy` for,
  which means you had to know in advance what to forbid.
- **Pahlevan** observes a workload for a window, and then denies everything it
  did not do. You did not enumerate the bad things, because the tool enumerated
  the good ones.

The consequence is coverage of attacks nobody has named yet. A rule-based tool
catches the techniques in its ruleset; an allow-set catches everything outside a
few hundred observed operations, including the technique published next week.

*Verify:* [`docs/live-scenario.md`](live-scenario.md) — a real workload learned
for fifty minutes, then attacked. Eight refusals, two controls still served,
nothing hand-written.

## 2. It constrains *who* acts, not only *what* runs

An allow-set has a blind spot, and it is a large one: the interpreter already in
the image. A Python service runs `python3` thousands of times, so `python3` is
learned — and once an attacker has a command-injection bug, so do they.

`syscallPolicy.processFilter` constrains the parent process, the effective uid
and the effective gid at `bprm_check_security`. `psql` may run; `psql` launched
by a shell may not.

Falco can *detect* this shape in a rule. Tetragon can *enforce* it if you write
the selector. Pahlevan enforces it from three lines of policy, in the same
kernel hook that already refuses unlearned binaries.

*Verify:* `pkg/ebpf/procfilter.go`, `bpf/exec_monitor.c`, and
`TestVMProcFilterEnforcedInKernel` — which shows the same binary refused with
the wrong parent and permitted with the right one.

## 3. It detects the runC breakout class by its invariant, not its spelling

CVE-2024-21626 and the vulnerabilities that followed leave the container's
working directory on a file descriptor leaked from the host mount namespace.
Nothing else about the exec is unusual: no capability is used, no mount is made,
and no syscall a seccomp profile would question is issued. A capability
allow-set misses it. A seccomp profile misses it. A learned baseline misses it,
because the binary is one the container runs legitimately.

Pahlevan compares the process's mount namespace with the namespace owning its
working directory and refuses the exec when they differ. That is the property
the exploit violates rather than a pattern matching how it is usually written —
a distinction the implementation learned the hard way, because the first version
pattern-matched `/proc/self/fd/` and a VM test proved it never fires.

It is checked while a container is still *learning*, and never added to the
allow-set. An escape does not wait for you to switch enforcement on.

*Verify:* `TestVMBreakoutAcrossMountNamespacesIsRefused`. It logs `cwd="/"` for a
real breakout, which is exactly why the string-matching version could not work.

## 4. Denials name the thing, not the address

`Denied connect to 10.104.22.9:5432` is a line somebody has to go and look up.
`Denied connect to prod/postgres:5432` is a line they can act on.

More importantly, `destinationKind` separates an in-cluster Service from an
address the cluster has never heard of — the difference between a
misconfiguration and exfiltration, which is invisible when both are just an IP.

The resolution costs no DNS query, which matters when a burst of denials would
otherwise become a burst of DNS traffic at the exact moment the cluster is under
attack.

Falco and Tetragon name external destinations via DNS parsing, which Pahlevan
does not do. Neither names *in-cluster* destinations from cluster state. The
capabilities are complementary and this one is missing from both.

*Verify:* `internal/netmap/resolver.go`.

## 5. One resource across metrics, traces and events

Grafana joins Loki, Tempo and Mimir on shared labels. If the metrics say
`node=X` and the logs say `host=X`, the join silently returns nothing — which
looks exactly like no data.

Pahlevan emits all three signals with one OpenTelemetry resource carrying
`service.instance.id` and the `k8s.*` attributes from the downward API, and
ships a collector plus datasources that wire the correlation up.

Falco's integration story is broader (falcosidekick reaches dozens of
destinations Pahlevan does not). This particular property — three signals that
correlate by construction — is not something either comparator gives you.

*Verify:* `examples/observability/lgtm-stack.yaml`, `pkg/export/otlp.go`.

## 6. You can see what a policy does before you apply it

```
pahlevan policy explain -f policy.yaml --strict
```

Translates the policy offline and names every part the data plane will not
enforce: an ingress rule, a CIDR too wide to enumerate, a glob, an inert field.
`--strict` exits non-zero so it can fail a CI gate.

It also rejects a field the CRD does not have — which the Kubernetes API server
would otherwise *prune without an error*, leaving a policy that applies cleanly
and does a fraction of what it says.

Neither comparator has an equivalent, because neither has the problem in the
same form: their policies are executed more literally. But the general failure —
a policy that looks applied and is not — is one every policy engine has, and
this one tells you.

*Verify:* `cmd/pahlevan/commands/policyexplain.go`.

## 7. It gets out of the way when it is wrong

A learned baseline will sometimes be wrong, because a window is a sample. What
matters is what happens next.

- **Self-healing** returns a container to learning when denials spike right
  after the transition — and only within that window, so an attacker cannot
  un-enforce a container by making noise.
- **`exceptions`** grant what the window missed, applied to the kernel allow-set
  before enforcement begins, and can expire on their own.
- **`deniedPaths`** revoke what the window should not have learned.

The full cycle is demonstrated end to end in
[`docs/scenario-report.md`](scenario-report.md): denied, exception applied,
allowed — same command, no restart, enforcement never switched off.

---

## Where they are ahead

Reading only the above would leave you unprepared, so, briefly:

| | Falco | Tetragon |
|---|---|---|
| Maturity | CNCF Graduated, years of production use | Under a Graduated project, broad production use |
| Detection content | A large curated ruleset you can adopt | — |
| Integrations | falcosidekick: dozens of destinations | Hubble, the Cilium ecosystem |
| Process ancestry | Any depth, in rule conditions | Unbounded, on every event, in selectors |
| Syscall arguments | Yes | Yes, and matchable |
| DNS and L7 | Yes | Yes, with a policy library |
| Architectures | amd64 and arm64, both tested | Same |

Pahlevan has one maintainer, a `v1alpha1` API, no public production adopters,
and an arm64 build that no arm64 kernel has ever loaded.
[`comparison.md`](comparison.md) has the full list, worst first.

**The honest summary:** if you want breadth of detection content, integrations,
or a track record, use Falco. If you want to author precise kernel-level policy
and you know what you want to forbid, use Tetragon. If you want an unknown
workload turned into an enforced baseline without writing a rule — and denied in
the kernel rather than reported afterwards — that is the thing Pahlevan does
that they do not.
