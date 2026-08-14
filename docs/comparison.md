# Pahlevan vs Falco vs Tetragon

This is a feature-by-feature comparison written for people evaluating Pahlevan,
including CNCF Sandbox reviewers. It is not marketing. Every Pahlevan claim below
is grounded in code in this repository, and where Pahlevan is behind, the table
says so in the Pahlevan column rather than hiding it in a footnote.

If you find a claim here that the code does not support, that is a bug. Please
open an issue.

## Scope and honesty rules

- **Pahlevan** rows describe `v2.0.0` plus what is currently on `main`. Anything
  not implemented is marked **planned** or **in progress**, never described as
  though it works. Where a feature exists in the CRD schema but the agent does
  not act on it, the row says that explicitly, because a field you can set that
  does nothing is worse than a field that does not exist.
- **Falco** rows describe Falco 0.44.x, the version measured in
  [`benchmarks/results.md`](benchmarks/results.md).
- **Tetragon** rows describe Tetragon v1.7.x, the version measured in the same
  run.
- Falco and Tetragon move quickly and both have far more contributors than
  Pahlevan does. Treat their rows as a good-faith snapshot and check their
  upstream documentation before making a decision. If we have understated
  either of them, tell us and we will fix it.
- The behavioral claims in the "blocked" and "detected" columns come from
  [`benchmarks/results.md`](benchmarks/results.md), a measured run in a
  kernel-isolated VM, not from anyone's documentation.

## Summary

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Primary model | Learn a per-container allow-set, then deny everything else in-kernel | Detect and alert on rule matches | Observe deeply, and enforce where you write a policy for it |
| Rules you write | None for the allow-set | Many, from a large curated ruleset | One `TracingPolicy` per behavior you care about |
| Prevention | Yes: `EPERM` from LSM hooks on file open, IPv4 egress, exec, and capability checks | No, by design. Response is a separate project | Yes: `Sigkill`, `Override`, and other actions, when you author them |
| Maturity | Young. `v1alpha1` API, one maintainer, no public production adopters | CNCF Graduated, years of production use, very large ecosystem | Cilium sub-project (Cilium is CNCF Graduated), broad production use |
| Best at | Turning an unknown workload into an enforced baseline with no rule authoring | Breadth of detection content, output integrations, and plugins | Process lineage, event richness, and a mature streaming API |
| Worst at | Everything to do with ecosystem, integrations, portability, and track record | Preventing anything | Requiring you to be right when you author an enforcing policy |

## Detection versus prevention

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Alerts on suspicious behavior | Yes, as log lines and as `AttackSurface` and `ContainerProfile` status. Not as a rich alert stream | Yes. This is the product | Yes, as a detailed event stream |
| Prevents the action | **Yes**, in-kernel, synchronously | **No.** Falco is explicitly alert-only | **Yes**, but only for behaviors you wrote a policy for |
| Where the decision happens | In the LSM hook, in-kernel, before the operation completes | Userspace, after the syscall has already succeeded | In-kernel, in the kprobe or LSM hook |
| Default posture out of the box | Learns, then denies, once you set `mode: Blocking` | Alerts using the default ruleset. Never blocks | Observes. Never blocks until you add a `TracingPolicy` |
| Response tooling | None. Pahlevan prevents rather than responds | [Falco Talon](https://github.com/falcosecurity/falco-talon) and falcosidekick can kill or label a pod after an alert | Actions are part of the policy: `Sigkill`, `Override`, `Signal`, `NotifyEnforcer` |

The measured consequence, with vendor defaults and four attack scenarios: Falco
alerted on 2 of 4 and blocked 0; Tetragon produced exec telemetry on 4 of 4 and
blocked 0; Pahlevan blocked 4 of 4. That result flatters Pahlevan, and the
benchmark document explains exactly why it is narrower than it looks: at the time
of that run, all four blocks came from the file-open hook, because every scenario
had to open a file that was not in the learned set.

Falco's inability to block is a deliberate design choice, not an oversight. An
alert-only tool cannot take your cluster down. Pahlevan's ability to block is
also its main way of causing an outage.

## Policy authoring

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| How policy is produced | **Learned automatically** from observed behavior during a window, per cgroup | Hand-written rules in YAML, plus a large curated default ruleset | Hand-written `TracingPolicy` CRs |
| Rule content ecosystem | **None.** There is nothing to share, because there are no rules | Extensive: `falco-rules`, maturity tiers (stable, incubating, sandbox), distributed as OCI artifacts via `falcoctl` | A library of example policies and a growing set of curated ones |
| Expressiveness | Low. An allow-set of paths, IPv4 destinations, binaries, and capabilities. No conditions, no arguments, no correlation | High. A full condition language over syscall fields, with macros, lists, and priorities | High. Hook selection, argument matching, `matchBinaries`, namespace and pod scoping, per-action selectors |
| Effort to protect a new workload | Apply one `PahlevanPolicy` with a selector and a learning window | None to start (defaults), then ongoing tuning to cut false positives | Write and test a policy per behavior |
| Risk model | You get whatever the workload did during the window. Under-cover the window and you block legitimate work | You get whatever the rules cover. Miss a rule and you never see the attack | You get exactly what you wrote. Write it too broadly and you can kill the node |
| Auditability of the policy | The learned set is visible in `ContainerProfile`, but nobody reviewed it before it took effect | Rules are readable, reviewable, version controlled | Policies are readable, reviewable, version controlled |

This is the central trade. Pahlevan removes the authoring burden and replaces it
with a coverage-of-the-learning-window burden. That is a real trade and not a
free win: a hand-written rule is auditable before it is enforced, and a learned
allow-set is not.

The benchmark run recorded the practical failure mode: with a 30 second learning
window in which only `/` was exercised, enforcement blocked all `kubectl exec`
into the pod. The workload kept serving HTTP 200, but the operator lost a tool
they use every day.

## Syscall observation

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Mechanism | `raw_tracepoint/sys_enter` (`bpf/syscall_monitor.c`) | Modern eBPF CO-RE probe, legacy eBPF probe, or kernel module | kprobes, tracepoints, and LSM hooks, selected per policy |
| What is captured | **The syscall number only.** Deduplicated in-kernel per `(cgroup, syscall)`, so userspace sees each pair exactly once | Full events with **arguments**, return values, and derived fields (`fd.name`, `evt.args`, and so on) | Rich arguments for the hooks a policy selects, including strings, file paths, and socket details |
| Syscall arguments | **No.** Not captured anywhere | Yes | Yes, per hook |
| Counts and rates | **No.** Dedup means you learn the syscall *set*, not how often each one happened | Yes | Yes |
| Syscall-level blocking | **No.** A raw tracepoint cannot deny. See seccomp below | No | Yes, for hooks where an `Override` or LSM action applies |
| Cost model | Low steady state, because dedup collapses repeats after the first sighting | Proportional to syscall volume, mitigated by tuned rulesets | Proportional to the events the loaded policies select |

Pahlevan's dedup is why its ring buffer stays quiet, and it is also why Pahlevan
cannot answer questions Falco and Tetragon answer trivially, like "what path did
this `openat` target" at the syscall layer or "how many times". Pahlevan gets
path fidelity from the LSM file hook instead, not from the syscall stream.

## File monitoring

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Hook | `lsm/file_open` (`bpf/file_monitor.c`) | Syscall-level (`open`, `openat`, and friends) with userspace path resolution | kprobes such as `security_file_permission`, or LSM hooks, per policy |
| Path resolution | In-kernel via `bpf_d_path()`, so the path is the resolved one | Userspace, using the process fd table | In-kernel |
| Operations covered | **Open only.** There is no separate write, rename, unlink, chmod, or truncate hook | Broad coverage across file syscalls | Whatever hooks your policy attaches |
| Read versus write distinction in enforcement | **No.** The allow-set is a set of paths, not paths plus modes. `readOnlyPaths` and `writeAllowedPaths` exist in the CRD schema but the agent does not act on them | Rules can distinguish by flags | Policies can match on flags and modes |
| Blocking | **Yes**, `EPERM` for a path not in the learned set | No | Yes, with a policy |
| Allow-set key | `cgroup_id` combined with a hash of the path. Hash collisions are possible and would allow an unintended path | n/a | n/a |

## Network monitoring

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Hook | `lsm/socket_connect` (`bpf/network_monitor.c`) | Socket syscalls through the driver | kprobes on the TCP stack, plus socket LSM hooks, per policy |
| Direction | **Egress only.** There is no ingress hook at all | Both, as observed at the syscall layer | Both, depending on the policy |
| Address family | IPv4 and IPv6. `socket_connect` governs both families and folds the full 16-byte v6 address into the allow-set key, so a v6 destination cannot be smuggled past a v4 entry | IPv4 and IPv6 | IPv4 and IPv6 |
| Protocol | The allow-set key is destination address and destination port. **Protocol is not part of the key**, and events report TCP unconditionally | Distinguishes protocols | Distinguishes protocols |
| DNS visibility | **No** DNS parsing or name-based policy | Available through rules and fields | Available, including a DNS-oriented policy library |
| L7 visibility | **No** | Limited, through plugins | Limited natively. Cilium and Hubble cover L7 alongside it |
| Blocking | Yes, `EPERM` on `connect()` to an unlearned IPv4 destination | No | Yes, with a policy |
| Relationship to CNI policy | Complementary, not a replacement. Pahlevan does not implement NetworkPolicy | Same | Cilium itself provides full L3 to L7 network policy |

## Process and exec monitoring

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Hook | `lsm/bprm_check_security` (`bpf/exec_monitor.c`) | Driver-level `execve` and clone tracking with a full userspace thread table | Dedicated process sensor with exec and exit tracking |
| Binary path | Yes, resolved in-kernel | Yes | Yes |
| Command-line arguments | **No.** Not captured | Yes | Yes |
| Working directory, environment | **No** | Yes for cwd | Yes for cwd |
| Blocking | Yes, `EPERM` on exec of a binary not in the learned set. There is also an in-kernel `SIGKILL` mode in the C program that the control plane does not currently expose | No | Yes: `Sigkill`, `Override`, and other actions |
| Exit tracking | **No** | Yes | Yes |

### Process ancestry

This deserves its own row because it is the clearest capability gap.

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Immediate parent | Yes, on exec events only: parent tgid and parent comm | Yes | Yes |
| Full ancestor chain | **No.** There is no walk up `real_parent`, no process cache, and no reconstruction in userspace | Yes. `proc.aname[n]` and `proc.apid[n]` address ancestors by depth, backed by a maintained process tree | **Yes, and this is Tetragon's signature strength.** Stable execution ids, a process cache, and a full ancestor chain on every event |
| Ancestry usable in policy | **No** | Yes, directly in rule conditions | Yes, in selectors |
| Ancestry on non-exec events | **No.** File, network, and syscall events carry pid, comm, and cgroup, but no parent | Yes | Yes |

Richer ancestry is on the [roadmap](../ROADMAP.md). Today, if you need to answer
"what chain of processes led to this", Tetragon is the tool for that job and
Pahlevan is not close.

## Capability monitoring

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Observes capability checks | Yes, `lsm/capable` (`bpf/capability_monitor.c`), learned per `(cgroup, capability)`. This landed after `v2.0.0` and is not yet covered by a published benchmark run | Capability-related syscalls, and thread capability sets as event fields | Yes, capability sets on process events, and capability-related hooks in policies |
| Enforces on capabilities | **Yes**, `EPERM` for a capability outside the learned set. Newly landed and less exercised than the file path | No | Yes, with a policy |
| Reports the process capability set | **No.** Pahlevan sees the check, not the full permitted, effective, and inheritable sets | Yes | Yes |

## Enforcement mechanisms and available actions

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Enforcement point | BPF LSM hooks, in-kernel | n/a | kprobes with `bpf_override_return`, and BPF LSM hooks |
| Available actions | **One: deny with `EPERM`.** Plus an unexposed in-kernel `SIGKILL` mode for exec | n/a. Falco emits alerts and other tools act on them | `Sigkill`, `Override` with a chosen errno, `Signal`, `Post`, `NotifyEnforcer`, rate limiting, and more |
| Enforcement modes | `Off`, `Monitoring`, `Blocking`. **The agent currently collapses these to a single boolean**, `Blocking` and not `alertOnly`. `Off` and `Monitoring` behave identically at the data plane, which is to say the maps are simply not switched to enforce | n/a | Per-policy, per-selector |
| Audit or dry-run of a would-be denial | **Partially.** Learning mode observes but does not deny, so it functions as a dry run. There is no first-class "this would have been blocked" event yet, beyond a denial bit on the exported envelope | Everything is effectively audit | Yes, observe-only policies are the default |
| Granularity | Per cgroup, which means per container | Per rule | Per policy, with pod and namespace selectors |
| Failure mode when the agent dies | Existing kernel state persists briefly, but BPF links are released when the agent's descriptors go away, so enforcement stops. Learning and status reporting stop immediately | Alerts stop | Depends on the policy and the attach mechanism |

Several `PahlevanPolicy` spec blocks are **schema only** today: `syscallPolicy`,
`networkPolicy`, `filePolicy`, `enforcementConfig.exceptions`,
`enforcementConfig.blockUnknown`, and `enforcementConfig.gracePeriod` are
accepted by the API server and are not consulted by the agent. That is a real
correctness problem, it is on the [roadmap](../ROADMAP.md), and it is listed
here rather than left for a reviewer to discover.

## Seccomp

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Generates a seccomp profile from observed behavior | **Yes**, from the learned syscall set (`pkg/seccomp`), written to a node directory when `--seccomp-dir` is set | No | No |
| Applies the generated profile | **No.** The profile is written and nothing reads it back. Nothing sets `securityContext.seccompProfile.localhostProfile`. The loop is not closed | n/a | n/a |
| Architectures in the generated profile | x86-64 only, hardcoded | n/a | n/a |

Automatic seccomp profile generation is genuinely something neither Falco nor
Tetragon does. It is also incomplete here, and the prior art worth comparing
against is the
[Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator),
which does close this loop and does it for SELinux and AppArmor as well.

## Kubernetes metadata enrichment

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Attribution mechanism | cgroup id to cgroup path to pod UID and container id (`pkg/attribution`), then a node-scoped pod cache for name and namespace | Container runtime clients plus a Kubernetes client, exposing `k8s.*` and `container.*` fields | Kubernetes watcher with a pod and container cache, keyed by cgroup id |
| Namespace, pod name, container id | Yes | Yes | Yes |
| Container image | **No** | Yes | Yes |
| Pod labels and annotations | **No** | Yes | Yes |
| Workload owner, such as Deployment or Job | **No.** `ContainerProfile` declares `workload` and `policyRef` fields and the agent does not populate them | Yes | Yes |
| QoS class, runtime | Yes, both derived from the cgroup path | Partially | Yes |
| Enrichment on the event stream | Only on the `ContainerProfile` resource and on log lines today. The new JSON envelope has a `kubernetes` block that nothing populates yet | Yes, on every event | Yes, on every event |

## Custom resources and Kubernetes integration

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| CRDs | Three, all namespaced, group `policy.pahlevan.io/v1alpha1`: `PahlevanPolicy`, `ContainerProfile`, `AttackSurface` | None for rules. Rules are config files and OCI artifacts, managed by `falcoctl` | `TracingPolicy` (cluster scoped), `TracingPolicyNamespaced` |
| API stability | `v1alpha1`. Expect breaking changes | Rule schema is versioned and stable in practice | `v1alpha1`, but with a long track record |
| Learned state as a Kubernetes object | **Yes.** `ContainerProfile` persists the learned baseline so a restart does not relearn from zero. This is unusual and useful | No | No |
| Posture aggregation object | `AttackSurface` | No | No |
| Helm chart | Yes. Note the chart currently ships only the `PahlevanPolicy` CRD, so the other two must come from `install.yaml` | Yes, mature | Yes, mature |
| Single-file install | Yes, `install.yaml` attached to each release | Yes | Yes |

## Admission control

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Admission control | **Yes.** A CEL `ValidatingAdmissionPolicy` applied by the operator, rejecting privileged containers, `allowPrivilegeEscalation`, `hostPID`, and `hostNetwork` | No | No |
| Webhook required | **No.** No webhook server, no certificate rotation, no availability risk in the API server path | n/a | n/a |
| Scope | Opt in per namespace, via the label `pahlevan.io/admission=enforce` | n/a | n/a |
| Requires | Kubernetes 1.30 or newer for `ValidatingAdmissionPolicy`. The operator degrades gracefully on older clusters | n/a | n/a |
| Derived from learned data | **No.** The CEL rules are hardcoded in Go and are not generated from any `PahlevanPolicy` | n/a | n/a |

Admission control is a genuine Pahlevan feature that neither comparator has. It
is also narrow: four fixed pod-hardening checks that overlap substantially with
Pod Security Admission, which is built into Kubernetes and which you should
probably be using anyway.

## Event export and integrations

This is the largest gap, so it gets the most detail.

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| gRPC streaming API | **No. Planned.** Events leave the process over a JSON-lines file and an HTTP webhook instead | Yes, the Falco gRPC Output API | Yes. It is the primary interface, and what `tetra getevents` consumes |
| JSON event output | Yes. `pkg/export` provides a versioned envelope covering all five event types with Kubernetes attribution, wired into the agent behind `--export-file`. Size-based rotation, and a bounded queue that drops rather than blocking the ring-buffer readers, with the drops counted | Yes, mature | Yes, including JSON export to file with rotation |
| Webhook or HTTP output | Yes, `--export-webhook`. Batched POSTs, retries on 5xx/408/429 with capped backoff, no retry on other 4xx | Yes | Via the export pipeline |
| Syslog, file, program outputs | File and stdout sinks are wired. No syslog or program output yet | Yes, all of them | File yes |
| Fan-out to third-party destinations | **None** | [falcosidekick](https://github.com/falcosecurity/falcosidekick) forwards to dozens of destinations: Slack, Elasticsearch, Loki, Kafka, S3, PagerDuty, and many more | Via the JSON stream into your own pipeline, plus Hubble and Cilium tooling |
| Kubernetes audit log ingestion | **No.** Planned. Pahlevan sees kernel events only | Yes, the `k8saudit` plugin | No |
| Plugin framework | **No, and none planned** | Yes. Source and extractor plugins, including cloudtrail, gcpaudit, github, okta | No formal plugin framework, but hooks are policy-defined |
| Event filtering before export | Yes, by event type and a denials-only mode, applied before conversion | Yes, in rule conditions | Yes, export filters and field filters |
| Output field stability | The envelope declares a schema version, but nothing emits it yet | Stable and documented | Stable protobuf schema |

If your requirement is "get these events into our SIEM today", Falco is the
answer and Pahlevan is not. Pahlevan's story is currently "read the agent logs",
which is not a story.

## CLI

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| CLI binary | `pahlevan` | `falco`, plus `falcoctl` for rule and plugin management | `tetra` |
| What works | `policy` (list, get, describe, create, delete, update, status), `status`, `version`, `completion` | Running the engine, validating rules, listing fields, plus full artifact management in `falcoctl` | `getevents` streaming, `status`, `tracingpolicy` management, `bugtool` |
| What is a stub | **`attack-surface`, `logs`, `metrics`, and `debug` print "to be implemented" and exit successfully.** Four of eight top-level subcommands | n/a | n/a |
| Live event streaming | Yes, `pahlevan events` with `--follow`, `--type`, `--denials-only`, `--pod`, and `--tail`. It tails the JSON-lines log rather than a gRPC stream, so it handles rotation and partial lines | Yes | Yes, `tetra getevents` is the standard workflow |
| Troubleshooting bundle | **No** | Yes, through supportability tooling | Yes, `tetra bugtool` |

## Metrics and observability

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Prometheus endpoint | Yes, `:8080`, served by controller-runtime | Yes, native | Yes, native and extensive |
| Metrics that actually work | **Six**: syscall, network, file, and capability event totals, enforcement actions (in-kernel denials), plus export sent and dropped counters. All served on the endpoint the agent exposes | A broad set, including rule hit counts, drops, and engine internals | A broad set: per-policy, per-sensor, event counts, map pressure, and overhead |
| Metrics that exist but read zero | `pkg/metrics` defines more than thirty metric names. They now register with the served registry, but **39 record methods are still called from nowhere**, so those series read zero. A dashboard of zeros is worse than an absent metric, so wiring the recording calls is tracked as an open gap | n/a | n/a |
| Policy status counters | `status.enforcementStatus.blocked*` fields exist and **are not incremented** | n/a | n/a |
| Health probes | Yes, `:8081` | Yes | Yes |
| OpenTelemetry tracing | Real OTLP/gRPC and console span exporters, plus a `StartSpan` API proven by tests to record spans and nest them. Instrumentation coverage of the codebase is still thin | Not a tracing tool, but the ecosystem covers it | Metrics focused |
| Grafana dashboards | Types exist in code, nothing is exported | Community dashboards | Published dashboards |

## Multi-architecture support

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| amd64 | Yes, built, tested, and benchmarked | Yes | Yes |
| arm64 | **Partial.** The Go side now cross-compiles: `pkg/seccomp` ships per-arch syscall tables behind build tags and CI runs a `GOOS=linux GOARCH=arm64` build on every PR. Still outstanding: the eBPF objects are compiled `-D__TARGET_ARCH_x86` against an x86_64 `vmlinux.h`, and the published image is single-arch, so arm64 is not yet a shippable target | Yes, officially supported and released | Yes, officially supported and released |
| s390x, ppc64le | No | Falco publishes additional architectures | No |
| Endianness bindings | Both little and big endian bpf2go bindings are committed, which is necessary but nowhere near sufficient | n/a | n/a |

Fixing arm64 is a tractable, well-scoped piece of work and it is on the
[roadmap](../ROADMAP.md). Until it is done, Pahlevan is an amd64-only project and
should be described that way.

## Kernel and platform requirements

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Minimum kernel for observation | 5.8 (CO-RE, ring buffer, `CAP_BPF`) | Modern eBPF driver needs 5.8 with BTF. The kernel module and legacy probe reach much older kernels | 4.19 and newer for the base sensor, with feature availability increasing with version |
| Minimum kernel for enforcement | 5.7 with `CONFIG_BPF_LSM=y` **and `bpf` present in the active `lsm=` list**, which most distributions do not enable by default | n/a | 4.19 and newer for kprobe override where the kernel supports it, 5.7 and newer for LSM based enforcement |
| Behavior without BPF LSM | Degrades to observation. **Enforcement silently does not attach**, and the capability probe does not currently check for BPF LSM support at all, so the agent's self-reported capability state can look healthier than it is | n/a | Kprobe based policies still work |
| Kubernetes version | 1.24 and newer. 1.30 and newer for the user-namespace operator and for admission | Broad | Broad |
| Non-Kubernetes use | Not supported. Pahlevan is Kubernetes only | Yes, Falco runs on plain hosts | Yes, Tetragon runs standalone |
| Node privilege required | Agent needs `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`, `CAP_NET_ADMIN`. Not `privileged: true` | Comparable | Comparable |

The `lsm=bpf` requirement is the single biggest practical barrier to Pahlevan's
value proposition. On a stock cluster where the boot command line has not been
changed, Pahlevan cannot enforce, and its advantage over Falco and Tetragon
disappears. See [`lsm-support.md`](lsm-support.md).

## Performance and footprint

Measured in the same VM, one tool at a time. Full method in
[`benchmarks/results.md`](benchmarks/results.md).

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Agent resident memory | BPF map memory is **17 to 19 MiB measured** across all five programs, down from 399 MiB before the maps were right-sized. The end-to-end agent RSS has not been re-measured since; the 327 MiB benchmark figure predates this fix | ~106 MiB | ~67 MiB |
| CPU idle | ~0.4 percent of a core | ~0.34 percent | ~0.07 percent |
| CPU under load | ~10.4 percent | ~10.4 percent | ~7.0 percent |
| Caveats | The measured build logs a line **per observed syscall** at debug level, which inflates the CPU figure. The memory figure is dominated by the Go runtime plus pre-allocated LRU maps and is a genuine tuning target | Defaults, stable ruleset | Defaults, observe only |

Being three to five times heavier than the alternatives on memory is not a
rounding error, and it is called out in the roadmap as a priority.

## Maturity, governance, and ecosystem

| | Pahlevan | Falco | Tetragon |
|---|---|---|---|
| Foundation status | **None.** Preparing a CNCF Sandbox proposal | **CNCF Graduated** | Sub-project of Cilium, which is **CNCF Graduated** |
| Age | First release 2025, current architecture 2026 | Since 2016 | Open sourced 2022 |
| Maintainers | **One** ([MAINTAINERS.md](../MAINTAINERS.md)) | Many, across multiple companies | Many, primarily Isovalent and Cisco, plus community |
| Public production adopters | **None known** ([ADOPTERS.md](../ADOPTERS.md)) | Very many, including large enterprises | Many |
| Security process | Documented ([SECURITY.md](../SECURITY.md)). Never exercised | Mature, with a security team and published advisories | Mature, under the Cilium process |
| Release cadence | Ad hoc | Regular, scheduled | Regular |
| Documentation | Reasonable for the size, and this comparison is part of an effort to keep it honest | Extensive, with a dedicated site | Extensive, with a dedicated site |
| Third-party integrations | **None** | Very many | Many, especially in the Cilium ecosystem |
| CI depth | Build, image push, CodeQL, Trivy, govulncheck, docs lint. **The unit test suite is not currently run in CI**, and neither eBPF load tests nor the benchmark are automated. All of that is manual today | Extensive, including kernel test matrices | Extensive, including a kernel and architecture matrix |
| Support | Community, best effort, one person | Community plus multiple commercial vendors | Community plus commercial support from Isovalent and Cisco |

## Where Pahlevan is behind

Listed plainly, worst first. Every item here is real and current.

1. **Maturity and adoption.** One maintainer, no public production adopters, a
   `v1alpha1` API, and a security process that has never been used. Falco is
   CNCF Graduated. Tetragon sits under a Graduated project. Nothing in this
   document changes that gap.
2. **No gRPC event API, and no integration ecosystem.** JSON-lines file and
   HTTP webhook export are wired into the agent, and `pahlevan events` streams
   them, so events do leave the process. What is still missing is a streaming
   gRPC API and anything resembling falcosidekick's fan-out to Slack, S3, or a
   SIEM. Integrating means consuming the file or the webhook yourself.
3. **No rule or content ecosystem.** By design there are no rules to share, but
   the consequence is real: there is no community content, no detection
   coverage you can adopt, and nothing to compare against MITRE ATT&CK coverage.
4. **Process ancestry is one hop, on exec only.** No ancestor chain, no process
   cache, no lineage on file or network events. Tetragon is far ahead here and
   this is not close.
5. **arm64 is not shippable yet.** The Go binaries cross-compile and CI proves
   it on every PR, but the eBPF objects are still built for x86_64 and the
   published image is single-arch. Falco and Tetragon both ship arm64.
6. **Memory footprint is unproven since the fix.** BPF map preallocation, which
   dominated the old 327 MiB figure, is down to 17 to 19 MiB measured. The
   end-to-end agent RSS has not been re-measured against Falco and Tetragon, so
   no comparative claim is made here until the benchmark is re-run.
7. **Enforcement requires `lsm=bpf` on the kernel command line**, which most
   distributions do not set. Without it Pahlevan degrades to a weaker
   observability tool than either comparator.
8. **Only one enforcement action.** `EPERM`. No kill, no signal, no audit
   action, no per-rule response. Tetragon offers a genuine action set.
9. **Much of the `PahlevanPolicy` spec is not implemented.** `syscallPolicy`,
   `networkPolicy`, `filePolicy`, `exceptions`, `blockUnknown`, and
   `gracePeriod` are accepted and ignored, and `Off` and `Monitoring` are not
   distinguished at the data plane.
10. **Self-healing does not heal.** The rollback path sets a phase and a
    condition and does not restore anything, and its trigger depends on status
    counters that are never incremented. The elaborate implementation in
    `pkg/policies` is not wired into any binary.
11. **Metrics are thin and partly fictional.** Four counters work. More than
    thirty defined metrics live on a registry that is never served and are never
    recorded. Policy status block counters stay at zero.
12. **The seccomp loop is open.** Profiles are generated and written and never
    applied to anything.
13. **IPv6 egress is not governed at all**, even in blocking mode, and the
    network allow-set ignores protocol.
14. **No syscall arguments, no command-line arguments, no image, no pod labels,
    no workload owner** on events. Both comparators have all of this.
15. **CLI gaps.** Four of eight subcommands are stubs, and there is no live
    event streaming and no troubleshooting bundle.
16. **CI does not run the tests.** Unit tests, eBPF load tests, and the
    benchmark are all manual.
17. **OpenTelemetry is wired but dead.** No span is ever started and no exporter
    is ever attached.
18. **Learning is trust on first use.** A workload that is already compromised
    when learning starts has its malicious behavior baselined, and there is no
    review or approval step before a learned profile takes effect.

## Where Pahlevan is different

Not "better". Different, with the trade stated each time.

**The learned allow-list model.** Falco and Tetragon both start from a list of
bad things: a rule matches an attack, or a policy hooks a behavior you decided
matters. Pahlevan starts from a list of good things, and it does not ask you to
write it. During a learning window it records the files a container opens, the
IPv4 destinations it dials, the binaries it executes, and the capabilities it
checks, per cgroup, and everything outside that set is denied. The security
property is qualitatively different: a rule-based tool can only catch attacks
someone anticipated, and an allow-list catches anything the workload did not do
during learning, including attacks nobody has named yet.

The trade is equally real and cuts three ways. Coverage of the learning window
becomes the whole ballgame, and a path exercised only at month end is a future
outage. Nobody reviews the policy before it takes effect, so a learned baseline
is less auditable than a hand-written rule. And a compromised workload gets its
compromise baselined.

**Prevention is the default outcome, not an add-on.** Once a policy is in
`Blocking` mode, deviation is denied in-kernel with no rule written for that
specific behavior. Falco cannot block. Tetragon can, and the measured benchmark
showed the cost of getting a hand-written enforcement policy wrong: an unscoped
node-wide `Sigkill` policy froze all process creation on the node and needed an
out-of-band reset. Pahlevan's denials are scoped to a cgroup by construction, so
the same class of mistake affects one container.

**The baseline is a Kubernetes object.** `ContainerProfile` makes the learned
allow-set a first-class resource: inspectable with `kubectl`, diffable across
versions, persisted across restarts, and reviewable in the same place as
everything else in the cluster. Neither comparator has an equivalent, because
neither has a learned artifact to store.

**Admission control in the same project.** A CEL `ValidatingAdmissionPolicy`
with no webhook, so no certificates and no new failure mode in the API server
path. Narrow, and it overlaps Pod Security Admission, but neither Falco nor
Tetragon does admission at all.

**Seccomp generated from what the workload actually did.** The learned syscall
set becomes a profile. Incomplete today, since nothing applies it, but the
observation-to-profile direction is a capability neither comparator has.

**Split privilege by design.** The privileged agent has almost no cluster API
power, and the cluster-powerful operator runs in a user namespace with no host
access. The blast radii are deliberately disjoint. Both comparators run a
privileged node agent too; the difference is that Pahlevan's cluster-scoped
component is separate and unprivileged.

## Which should you use

An honest recommendation from the Pahlevan project:

- **You need detection coverage and integrations today, in production.** Use
  Falco. It is graduated, the ruleset is enormous, and falcosidekick will get
  events wherever you need them.
- **You need deep process lineage, rich events, and a mature streaming API, and
  you are willing to author enforcement policies.** Use Tetragon.
- **You want to run them together with Pahlevan.** That is reasonable. Falco or
  Tetragon for detection breadth and telemetry, Pahlevan for prevention on the
  workloads whose behavior is narrow and stable enough to baseline. Note that
  running multiple eBPF agents costs node resources; the benchmark VM could not
  hold all three at once.
- **You have a well-understood workload, a kernel with `lsm=bpf`, an amd64
  cluster, and you want deviation prevented rather than reported without writing
  rules.** That is what Pahlevan is for. Start in `Monitoring`, read the learned
  `ContainerProfile`, then move to `Blocking`.
- **You need this in production on arm64, or you need a SIEM integration, or you
  cannot tolerate a single-maintainer dependency.** Do not use Pahlevan yet.

## Corrections

If any claim here about Falco or Tetragon is wrong or out of date, please open
an issue. We would rather be corrected in public than mislead someone
evaluating tools.
