# Security Policy

Pahlevan is a runtime security tool that loads eBPF programs into the kernel and
denies syscalls. Bugs in it are security bugs in a way that bugs in most projects
are not. We take reports seriously and we would rather hear about a maybe than
miss a real one.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `2.0.x` | Yes | Current release line. Fixes land here. |
| `1.0.x` | No | Superseded by the 2.0 redesign, which replaced the data plane and the deployment model entirely. Please upgrade. |
| `main` | Best effort | Unreleased. Report anything you find, but expect the fix to ship in the next release rather than as a patch. |

Only the latest patch release of a supported line receives fixes. There are no
long-term support branches; the project is too young to promise them honestly.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request, or discussion for a security
vulnerability.**

Report privately through **GitHub private security advisories** on this
repository:

1. Go to <https://github.com/obsernetics/pahlevan/security/advisories>.
2. Click **Report a vulnerability**.
3. Fill in the form.

This creates a private thread visible only to you and the maintainers, and it
gives us a place to draft the advisory and the CVE request alongside the fix.

If GitHub advisories are unavailable to you, email `team@obsernetics.com` with
`SECURITY` in the subject line. Please do not include exploit details in an
initial email if you can use the advisory route instead.

### What to include

The more of this you can provide, the faster the fix:

- The affected version, image tag, or commit.
- Kernel version, distribution, and the active LSM list (`cat /sys/kernel/security/lsm`).
- Kubernetes version and container runtime.
- Whether the cluster was in `Monitoring` or `Blocking` enforcement mode.
- Reproduction steps, ideally as a manifest plus commands. A failing test case
  is the gold standard.
- The impact as you understand it, and whether you have disclosed it anywhere.

### What is in scope

- Privilege escalation from a workload, or from the agent, to the node or the
  cluster.
- Any way to bypass enforcement while a policy is in `Blocking` mode: reaching a
  file, destination, or binary that is not in the learned allow-set.
- Poisoning the learning phase so that an attacker-controlled behavior ends up
  in an allow-set.
- eBPF programs that can crash, hang, or corrupt kernel state, or that fail the
  verifier in a way that leaves the node in an inconsistent state.
- Denial of service against the node caused by the agent, including
  enforcement that wedges process creation.
- Anything that lets one tenant's policy affect another tenant's workload.
- Secrets or workload data leaking into logs, metrics, events, or CRD status.
- Supply-chain issues in the published images, charts, or `install.yaml`.

### What is out of scope

- The privilege the agent holds by design. See the threat model below.
- Findings that require an attacker who already has node root or cluster-admin.
- An incomplete learned baseline blocking legitimate traffic. That is a
  correctness and operability issue; please file a normal bug.
- Vulnerabilities in Falco, Tetragon, Kubernetes, containerd, or the Linux
  kernel itself. Report those upstream. If Pahlevan makes such a bug materially
  easier to exploit, that part is in scope here.
- Reports from automated scanners with no demonstrated impact.

## Threat model in brief

Pahlevan is deployed as two workloads with deliberately different privilege:

**The agent (DaemonSet) is privileged by necessity.** Loading and attaching eBPF
and LSM programs, reading kernel BTF, and writing BPF maps cannot be done
without capabilities that are close to node root. The agent runs with `CAP_BPF`,
`CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`, and `CAP_NET_ADMIN`, with
`readOnlyRootFilesystem: true` and everything else dropped, but the honest
statement is this:

> **Compromise of the Pahlevan agent is compromise of the node.** An attacker
> with control of the agent can load arbitrary eBPF, disable enforcement, and
> observe every syscall on that node. Treat the agent's image, its supply chain,
> and write access to its DaemonSet spec as node-root-equivalent.

This is a property Pahlevan shares with every eBPF runtime security tool,
including Falco and Tetragon. It is not a reason to skip a report; a bug that
lets a *workload* reach the agent is squarely in scope and is exactly the class
of issue we most want to hear about.

**The operator (Deployment) is deliberately not privileged.** It has no host
access, no eBPF, and no host mounts. It runs in a user namespace
(`hostUsers: false`, Kubernetes 1.30+), which maps in-container root to an
unprivileged host UID. It does hold cluster-wide API permissions for its own
CRDs, so a compromise of the operator is a cluster-scoped policy compromise: an
attacker could disable protection or relax allow-sets, but could not directly
execute code on nodes. Splitting the blast radius this way is intentional.

**Other assumptions.** Enforcement decisions are made in-kernel and survive the
agent's user-space process, so an attacker who kills the agent does not
immediately unblock traffic, but they do stop new learning and status reporting,
and BPF links are released when the agent's file descriptors go away. Learning
is trust-on-first-use: anything a workload does during its learning window
becomes allowed, so a workload that is already compromised when learning starts
will have its malicious behavior baselined. That limitation is documented rather
than treated as a vulnerability, but concrete attacks that make it worse (for
example, forcing a relearn) are in scope.

## Response timeline

We aim for the following. These are targets for a small volunteer project, not
a contractual SLA, and we will tell you if we are going to miss one.

| Stage | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for high and critical issues | 30 days from triage |
| Fix for medium and low issues | Next scheduled release |
| Public disclosure | Within 90 days of the report, or sooner once a fix is released |

Severity is assessed with CVSS v3.1 as a guide, adjusted for how the issue
behaves in a real cluster. An enforcement bypass is treated as high or critical
even when its CVSS score is modest, because bypass defeats the entire purpose of
the tool.

## Disclosure policy

We follow coordinated disclosure:

1. You report privately. We acknowledge and triage.
2. We work on a fix in private, and keep you updated. You are welcome to review
   the fix before it ships.
3. We agree an embargo date with you. The default is disclosure when the fix is
   released, and no later than 90 days after the report.
4. We release the fix, publish a GitHub Security Advisory, request a CVE where
   appropriate, and note the issue in [CHANGELOG.md](CHANGELOG.md).
5. We credit you in the advisory by the name or handle you choose, unless you
   ask to remain anonymous.

If a vulnerability is being actively exploited, we will shorten the embargo and
may publish a mitigation before a full fix is ready.

We ask that you do not publicly disclose before the agreed date. We will not
take legal action against anyone acting in good faith under this policy, and we
will not ask you to sign anything in exchange for accepting a report.

There is no bug bounty. The project has no funding for one, and we would rather
say so than imply otherwise.
