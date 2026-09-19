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
- Vulnerabilities in Kubernetes, containerd, or the Linux
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
for any node-level eBPF tool. It is not a reason to skip a report; a bug that
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

## Dashboard

The optional dashboard is off by default and absent from `install.yaml`. A
cluster that never enables it runs exactly the bytes it ran before, and nothing
in this section applies to it. What follows is for clusters that turn it on.

**Why it gets this much attention.** A security tool's dashboard is a better
prize than the tool it fronts. It is the one component a browser talks to, it
describes in one place which workloads exist, which paths they read, which
destinations they dial and what has been denied to them, and it is the piece
most likely to be exposed through an ingress because that is what a dashboard
is for. A security tool that ships a dashboard with a cluster-admin service
account and a bespoke login page has handed an attacker a better primitive than
the one it defends against: a reconnaissance report for the whole cluster, plus
a credential that can switch enforcement off.

**What it deliberately cannot do.** These are design constraints, not
configuration. The deployment-shaped ones - the RBAC grant, `ClusterIP`, no
host access, absence from `install.yaml` - are asserted by tests in
`hack/install/`, and the server-shaped ones by tests in `pkg/dashboard`, so
they stay true rather than staying written down:

- **No writes.** The service account holds `get`, `list` and `watch` on three
  CRDs and nothing else. There is no write path in the code either: the router
  registers reads and refuses every other method before a handler runs.
  Changing a policy or an enforcement mode stays a `kubectl` operation under
  the operator's own credentials.
- **No cluster-admin, and no grant beyond five entries.** `create` on
  `tokenreviews` and `subjectaccessreviews`, and read on `pahlevanpolicies`,
  `containerprofiles` and `attacksurfaces`. No pods, so a compromise cannot
  read every container's environment; no secrets; no wildcards; no binding to a
  built-in superuser role.
- **No bespoke authentication.** The browser presents a Kubernetes bearer
  token, a `TokenReview` establishes who that is, and a `SubjectAccessReview`
  runs for every read, so a viewer sees exactly what their own RBAC allows.
  There is no user database to breach, no session secret to leak, and no second
  permission model to drift out of step with yours.
- **No external origins.** A strict Content-Security-Policy forbids inline
  script and every third-party origin, and assets are embedded in the binary. A
  dashboard that loads a charting library from a CDN has made every viewer's
  browser trust a third party on the project's say-so.
- **No exposure the project chose for you.** `ClusterIP` only, a
  `NetworkPolicy` alongside, and no Ingress, NodePort or LoadBalancer manifest
  anywhere in the repository.
- **No privilege and no path into the kernel.** No eBPF, no host namespaces, no
  host mounts, no capabilities, a read-only root filesystem, `runAsNonRoot`,
  and `seccompProfile: RuntimeDefault`. The agent stays the only privileged
  component, which is what makes a browser-facing process acceptable at all.

**What is yours.** The project can refuse to make these decisions for you; it
cannot make them:

- **Exposure.** Reaching the dashboard from outside the cluster is your
  deliberate act through your own ingress. Put it on an internal load balancer
  or behind your VPN, and label only the namespace that should reach it. An
  unreachable port cannot be probed for a bug in the token check.
- **TLS certificates.** You supply the pair, you rotate it, and you keep TLS
  end to end rather than terminating at the edge and forwarding bearer tokens
  in plaintext. There is no self-signed fallback, because a user trained to
  click through a certificate warning cannot tell your certificate from a
  proxy's.
- **Who gets RBAC.** The dashboard shows a viewer exactly what their own RBAC
  allows, which means the answer to "who can see this" is the answer to "who
  did you grant read on Pahlevan's CRDs". Granting that broadly to make the
  dashboard more useful widens what an attacker sees after phishing any one of
  those accounts.
- **Narrowing what it ships open.** The egress rule permits 443 and 6443 to
  `0.0.0.0/0` because the API server's address is cluster-specific; narrow it
  to your control plane. Set a token audience once you mint tokens for the
  dashboard, so a projected token belonging to something else is not accepted.

Bugs in any of the above are in scope, and the classes we most want to hear
about are a read that reaches the browser without a passing
`SubjectAccessReview`, anything that authenticates without a valid token, and
any way to make the dashboard write.

Setup and configuration are in [docs/dashboard.md](docs/dashboard.md).

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
