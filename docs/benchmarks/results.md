# Pahlevan vs Falco vs Tetragon - measured runtime-security benchmark (run 2)

> **These numbers are real and measured**, produced by `test/benchmark/run.sh`
> inside the kernel-isolated VM (`hack/vm/`). Where something could not be
> measured, or a tool could not be deployed as shipped, it is stated explicitly.
> Nothing here is tuned to favour any tool, and the sections that make Pahlevan
> look bad are as load-bearing as the ones that do not.

> **Filename note:** this run happened on the same UTC date as the earlier one,
> so it is filed as `results-2026-08-14-run2.md` rather than overwriting
> `results-2026-08-14.md`, which is the record of that first run and is left
> untouched.

## What changed since the first run

The first run (`results-2026-08-14.md`) covered 4 scenarios and found only the
`file_open` LSM hook wired. Since then the tree gained network egress enforcement
(`lsm/socket_connect`, IPv4 and IPv6), process exec enforcement
(`lsm/bprm_check_security`), capability monitoring and enforcement
(`lsm/capable`), a large BPF map right-sizing, and a JSON-lines/webhook event
export. The scenario suite grew from 4 to 26 attack scenarios plus 3 benign
controls, and this run adds 3 builtin-only **mechanism probes** and a **no-tool
control run**.

The harness also changed in one important way. Previously every scenario was a
separate `kubectl exec`; under Pahlevan enforcement the `runc exec` setup is
itself denied, so that harness could only ever record "exec was denied" and could
say nothing about which mechanism stopped what. Scenarios now run from a
**resident bash runner started inside the target pod during the learning window**,
which drives everything with builtins only. All three tools are driven the same
way. See `test/benchmark/README.md`.

## Environment

| Item | Value |
|------|-------|
| Date (UTC) | 2026-08-14 |
| Host | QEMU/KVM VM (`hack/vm/up.sh`), headless, 4 vCPU / 3.8 GiB RAM |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 6.8.0-137-generic (x86_64) |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor,bpf` (**bpf LSM active**) |
| Kubernetes | k3s v1.36.3+k3s1 |
| Container runtime | containerd v2.3.2-k3s2 |
| cgroup | cgroup2fs (unified) |
| Helm | v3.21.4+g813176c |
| Target workload | `nginx:1.27` (Debian), Deployment `bench/target`, labels `app=target,pahlevan=protected` |

### Tool versions and configuration posture

| Tool | Version | How deployed | Posture |
|------|---------|--------------|---------|
| **Pahlevan** | built from the committed tree at `370f14a` (branch `feat/enforce-the-whole-policy`) | `install.yaml`, patched for the bench: image + `imagePullPolicy: Never` + agent `privileged: true` + operator `replicas: 1`, plus the two workarounds below | one `PahlevanPolicy`: `learningConfig.duration: 180s`, `autoTransition: true`, `enforcementConfig.mode: Blocking`, `blockUnknown: true`, `filePolicy.defaultAction: Deny`. Event export enabled (see caveats) |
| **Falco** | 0.44.1 (chart `falcosecurity/falco` 9.1.0) | `helm install`, **chart defaults** | `driver.kind=modern_ebpf`, `tty=true`, `falco.json_output=true`. Default (stable) ruleset, unmodified |
| **Tetragon** | v1.7.0 (chart `cilium/tetragon` 1.7.0) | `helm install`, **chart defaults** | default process sensor, no `TracingPolicy` |

The only non-default Falco settings are `driver.kind=modern_ebpf` (the CO-RE
driver, so it is compared on the same eBPF footing) and two output settings
(`tty`, `json_output`) that change **how** alerts are printed, not **what** is
detected. No rule was added, removed or tuned for any tool.

**A default-config "did not block" is not a claim that a tool cannot block.**
Falco is alert-only by design and does not block in any configuration. Tetragon
does not block on defaults but does block with a hand-written `TracingPolicy`;
none was applied here, because on the previous run an un-scoped `Sigkill`
`TracingPolicy` killed unrelated processes node-wide and froze the VM. Pahlevan
blocks from an auto-learned allow-list with no hand-written rules.

Because the VM has 3.8 GiB of RAM, the three agents were run **one at a time**
against the same target and the same scenarios, and each was fully removed before
the next was installed.

## How each tool was driven

All three tools ran the identical suite through the identical execution path: a
resident bash runner (`test/benchmark/pod-runner.sh`) started **inside the target
pod during the learning/observe window**, which then drives every scenario using
only shell builtins. This matters for two reasons.

First, once Pahlevan enforces, `kubectl exec` into the pod is refused outright
(measured below), so a harness that shells in per scenario measures exactly one
thing and cannot attribute anything. Second, it models the realistic case: an
attacker who already has a shell in a compromised workload. The cost of that
model is stated plainly: `bash` and its libraries are in Pahlevan's learned
allow-list, because the runner started before enforcement. That makes Pahlevan's
job **harder**, not easier.

Signals are correlated to scenarios by timestamp from each tool's own stream
(Pahlevan's JSON-lines export, Falco's alert stdout, Tetragon's `export-stdout`),
and signals outside every scenario window or belonging to another workload are
counted separately rather than folded into a detection.

## Control run: no security tool installed

Before any tool was installed, the whole suite was run against the bare cluster.
This is what makes the matrix attributable: it shows which scenarios succeed on
their own, and which fail for reasons that have nothing to do with a security
tool (an unroutable TEST-NET destination, a path such as `/host` that is simply
absent, a `mount` that fails for lack of privilege). Those baselines appear in
the "Control" column of the matrix. A "No*" in a Blocked column means the
scenario's own exit code is ambiguous **and** the tool's stream shows no denial,
which is the same outcome the control run produced, so there is no evidence of
blocking either way.

## Results matrix

Legend. **Det** = the tool produced a signal for the action in its own stream,
attributed to the target pod. **Blocked** = the in-pod action was *prevented*,
with the kernel hook that refused it in parentheses. **No\*** = the scenario's
exit code is ambiguous from inside the pod and the tool shows no denial, which is
the same result the no-tool control produced, so there is no evidence of blocking
either way. Falco and Tetragon are in non-blocking configurations by design, so
every Blocked cell for them is a statement about posture, not capability.

### Attack scenarios

| Scenario | Control | Pahlevan Det | Pahlevan Blocked | Falco Det | Falco Blocked | Tetragon Det | Tetragon Blocked |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `01-sensitive-file-read` | allowed | Yes | **Yes** (file) | Yes | No | Yes | No |
| `02-reverse-shell` | attempted | Yes | **Yes** (file) | Yes | No* | Yes | No* |
| `03-crypto-miner-exec` | allowed | Yes | **Yes** (file) | Yes | No | Yes | No |
| `04-unexpected-egress` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `05-serviceaccount-token` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `06-proc-environ` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `07-search-private-keys` | attempted | Yes | **Yes** (file) | Yes | No* | Yes | No* |
| `08-proc-enumeration` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `09-k8s-api-query` | attempted | Yes | **Yes** (file) | Yes | No* | Yes | No* |
| `10-network-discovery` | attempted | Yes | **Yes** (file) | Yes | No* | Yes | No* |
| `11-exec-dev-shm` | allowed | Yes | **Yes** (file) | Yes | No | Yes | No |
| `12-interpreter-abuse` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `13-persistence-profile-cron` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `14-setuid-abuse` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `15-write-passwd-sudoers` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `16-capability-probing` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `17-clear-logs` | allowed | Yes | **Yes** (file) | Yes | No | Yes | No |
| `18-disable-history` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `19-delete-after-exec` | allowed | Yes | **Yes** (file) | Yes | No | Yes | No |
| `20-timestomp` | allowed | Yes | **Yes** (file) | No | No | Yes | No |
| `21-dns-egress` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `22-remote-payload` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `23-docker-sock` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `24-write-sys-procsys` | attempted | No | No* | No | No* | Yes | No* |
| `25-mount-attempt` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |
| `26-host-path-read` | attempted | Yes | **Yes** (file) | No | No* | Yes | No* |

### Mechanism probes (builtin-only; not scored as attacks)

| Probe | Control | Pahlevan outcome | Pahlevan signals | Falco outcome | Falco signals | Tetragon outcome | Tetragon signals |
|---|---|:-:|---|:-:|---|:-:|---|
| `p01-connect-refused-builtin` | attempted | attempted | network/deny:1.0.0.127:9 | attempted | - | attempted | exit:/usr/bin/bash /tmp/bench/pod-runner.sh 3 |
| `p02-connect-clusterdns-builtin` | attempted | attempted | network/deny:10.0.43.10:53 | attempted | - | attempted | exit:/usr/bin/bash /tmp/bench/pod-runner.sh 3 |
| `p03-read-shadow-builtin` | allowed | blocked | file/deny:/etc/shadow | allowed | - | allowed | exit:/usr/bin/bash /tmp/bench/pod-runner.sh 3 |

### Benign controls (false positives)

| Control | Correct | Pahlevan outcome | Pahlevan FP? | Falco outcome | Falco FP? | Tetragon outcome | Tetragon FP? |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `b01-serve-request` | allowed | blocked | **yes** | allowed | no | allowed | no |
| `b02-read-own-config` | allowed | blocked | **yes** | allowed | no | allowed | no |
| `b03-resolve-dns` | allowed | blocked | **yes** | allowed | no | allowed | no |

The probe table is the mechanism evidence: `p01`/`p02` are the only actions in
the whole suite that reach `lsm/socket_connect`, and both were denied in-kernel;
`p03` is the only one that reaches `lsm/file_open` with no exec in front of it,
and it was denied too. Note the byte-reversed addresses in Pahlevan's own event
text (`1.0.0.127` for 127.0.0.1); that is a real export bug, described below.

### Benign controls (false positives)

| Control | Correct | Pahlevan outcome | Pahlevan FP? | Falco outcome | Falco FP? | Tetragon outcome | Tetragon FP? |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `b01-serve-request` | allowed | blocked | **yes** | allowed | no | allowed | no |
| `b02-read-own-config` | allowed | blocked | **yes** | allowed | no | allowed | no |
| `b03-resolve-dns` | allowed | blocked | **yes** | allowed | no | allowed | no |

### Signal accounting

| Tool | Signals total | Attributed to target pod | Other workloads | Outside any scenario window |
|---|--:|--:|--:|--:|
| Pahlevan | 28736 | 552 | 28184 | 28588 |
| Falco | 33 | 33 | 0 | 0 |
| Tetragon | 232 | 232 | 0 | 1 |

### Totals

| Tool | Attacks detected | Attacks blocked | Benign false positives |
|---|--:|--:|--:|
| Pahlevan | 25/26 | 25/26 | 3/3 |
| Falco | 9/26 | 0/26 | 0/3 |
| Tetragon | 26/26 | 0/26 | 0/3 |

Reading the signal-accounting row for Pahlevan: it exported 28736 events in the
run window, of which 552 fell inside a scenario window and were attributable to
the target pod. The rest are node-wide learning observations for every other
cgroup on the box (k3s, containerd, the agent itself). That is a volume problem
for anyone shipping this to a SIEM, and it is why the export defaults to
denials only.

The Tetragon detection count needs one correction, given in the caveats: 26/26
counts any in-window event, but for `24-write-sys-procsys` the only event is the
harness shell's own exit. On a strict reading Tetragon detects **25 of 26**, and
**0 of 3** mechanism probes, because its default sensor emits exec/exit events
and those scenarios exec nothing.

## Deployability findings (Pahlevan)

The agent no longer crash-loops on the two bugs the first run hit (the double
`AttachPrograms()` and the duplicate controller name are both fixed, and the
agent starts clean). Three new blockers took their place. All three were hit
before any measurement, and all three were worked around **in the cluster only**,
never in the repo. `git status` shows no change to `install.yaml`.

### 1. The shipped CRD is rejected by the apiserver

`kubectl apply -f install.yaml` fails:

```
The CustomResourceDefinition "pahlevanpolicies.policy.pahlevan.io" is invalid:
* spec...properties[selector].properties[namespaceSelector].type:
    Required value: must not be empty for specified object fields
* (and four more, under networkPolicy.ingressRules/egressRules peers)
```

Five schema nodes carry a `description` but no `type`, which is not a valid
structural schema. As shipped, **Pahlevan cannot be installed from
`install.yaml`**: the namespace, RBAC, DaemonSet and operator are created and
then the CRD apply fails, leaving a half-installed cluster with no
`PahlevanPolicy` kind. The benchmark patches the five nodes to `type: object` in
its `/tmp` copy.

### 2. The agent's ClusterRole is missing five resources it watches

The agent's controller-runtime manager starts informers for `Deployment`,
`DaemonSet`, `StatefulSet`, `Service` and `NetworkPolicy`, but the `ClusterRole`
in `install.yaml` grants only `policy.pahlevan.io` resources plus `pods`, `nodes`
and `events`. Those informers can never sync, so after the two-minute cache-sync
timeout the agent exits 1:

```
ERROR agent-setup problem running agent {"error": "failed to wait for
pahlevanpolicy caches to sync kind source: *v1alpha1.PahlevanPolicy:
timed out waiting for cache to be synced for Kind *v1alpha1.PahlevanPolicy"}
```

Measured directly: **4 restarts in 10 minutes**, on a ~2 minute cycle
(`Last State: Terminated, Reason: Error, Exit Code: 1`, started 17:23:56,
finished 17:25:57). This is worse than a restart loop. The learned baseline lives
in agent memory, so each restart wipes it and relearning starts from zero; the
agent was observed transitioning a container to enforcing with a baseline of
**one file**, which would deny essentially everything the workload does. With a
read-only supplementary ClusterRole added, the agent ran the whole benchmark with
**0 restarts**.

### 3. Self-healing un-enforces as soon as an attacker makes noise

`internal/adaptive.DefaultRollbackConfig` is `ObservationWindow: 5m`,
`DenialThreshold: 10`, `Cooldown: 10m`, `MaxAttempts: 3`. For the first five
minutes after a container starts enforcing, the tenth in-kernel denial rolls
enforcement **off** for that container and returns it to learning. Measured, from
the agent's own log:

```
INFO adaptive rolled back enforcement to learning
  {"cgroup": 21696, "reason": "10 in-kernel denials within 10s of enforcement
   (threshold 10)", "rollbacks": 1, "attempts": 1, "holdUntil": "17:35:16Z"}
```

The attack suite trips this in about fifteen seconds. The security consequence is
direct: an attacker who triggers ten denials inside the first five minutes turns
enforcement off for ten minutes, and can repeat it until `MaxAttempts: 3` leaves
the container in monitor-only mode permanently. There is no way to change this
from the CRD or a flag: `PahlevanPolicy.spec.selfHealing` exists in the API and
is read by the operator's own reconciler, but it is never wired into the node
agent's `RollbackConfig`, and no agent flag reaches it.

For the matrix above the run therefore waits out the five-minute observation
window before attacking, which is the only way to measure a steady enforcing
state at stock configuration. Enforcement held with **0 rollbacks** through the
settle window and through the entire suite, and the workload kept serving
HTTP 200 throughout.

### 4. `kubectl exec` into an enforcing pod is refused

Measured (this is a real operational cost, not a scenario result):

```
EXEC_PROBE_RC=1
OCI runtime exec failed: ... error executing setns process: exit status 1;
runc init error(s): nsexec: failed to update /proc/self/oom_score_adj:
Operation not permitted
```

`runc`'s write to `/proc/self/oom_score_adj` is denied by the `file_open` hook
because that path is not in the workload's learned set. Debugging an enforcing
pod requires removing the policy first.

> **Fixed after this run.** `bpf_d_path` resolves `/proc/self` to
> `/proc/<pid>`, so no fixed path could ever be seeded to match a pid that
> changes every time; the fix is a targeted kernel-side exemption for that one
> basename under `/proc/`. `oom_score_adj` is a per-process OOM-killer hint and
> not a privilege boundary, so the concession is far smaller than leaving
> enforcing pods undebuggable and exec liveness probes broken.
> `TestVMOomScoreAdjStaysWritableUnderEnforcement` verifies both halves against
> a real kernel: the write goes through, and `/proc/self/environ` is still
> denied, so the exemption did not open up `/proc` generally.

## Which mechanism actually blocked what

This is the question the first run got wrong, so it is worth being exact. All
four LSM hooks were confirmed enforcing on the target cgroup before the suite ran
(`file_mode`, `exec_mode`, `network_mode`, `cap_mode` all set to 1). Despite
that, **every block in the 26-scenario matrix came from `file_open`, and not one
came from `bprm_check_security`, `socket_connect` or `capable`.**

The reason is ordering, not breakage. `execve` opens the binary before the
kernel reaches `bprm_check_security`, so with `filePolicy.defaultAction: Deny`
the open of `/usr/bin/cat` is refused first and the exec hook is never consulted.
The shell reports `rc=126`. The same masking hides the network path: every
network scenario has to exec `curl`, `getent` or `timeout` first, so the
connection is never attempted and `socket_connect` never sees it. The first run
recorded egress as "blocked" and attributed it to the network path; it was the
exec path then, and it is the file path now.

To separate the mechanisms, three **builtin-only probes** were added. They use
`bash` builtins exclusively, so nothing is exec'd and no helper binary's open can
mask the decision under test:

| Probe | What it isolates | Result |
|-------|------------------|--------|
| `p01-connect-refused-builtin` | `socket_connect` on an unlearned destination, via `/dev/tcp` | **Denied in-kernel** (`network/deny`, 127.0.0.1:9) |
| `p02-connect-clusterdns-builtin` | `socket_connect` to a real, reachable, unlearned destination | **Denied in-kernel** (`network/deny`, 10.43.0.10:53) |
| `p03-read-shadow-builtin` | `file_open` on `/etc/shadow` with no exec involved | **Denied in-kernel** (`file/deny`, `/etc/shadow`) |

So network egress enforcement **is** real and does deny unlearned destinations,
including a reachable one. It simply never gets the chance in any of the 26
scenarios, because those scenarios reach the network through a binary the file
hook refuses first. `bprm_check_security` and `capable` were **not** observed
denying anything in this run, and no probe isolates them; that is recorded as
unmeasured rather than as working.

## Two weaknesses the matrix exposes

**The file allow-list is path-only, not mode-aware.**
`15-write-passwd-sudoers` **succeeded** under full enforcement (`outcome=allowed`,
`rc=0`): appending a root-equivalent account to `/etc/passwd` went through. The
scenario writes with a shell redirection, so no binary is exec'd, and
`/etc/passwd` is in the learned allow-set because nginx **reads** it at startup.
`lsm/file_open` keys its decision on the path only, so a file the workload merely
read during learning can be **written** by an attacker afterwards. The companion
write to `/etc/sudoers` was denied (nginx never opened it), which is why a
`file/deny` event still appears for that scenario, but the `/etc/passwd` write
landed. This is the one attack in the suite that Pahlevan detected and did not
stop.

> **Fixed after this run.** `lsm/file_open` now folds write intent, taken from
> `f_mode`, into the allow-set key, so a path learned for reading is not
> writable. `filePolicy.readOnlyPaths` became enforceable at the same time.
> `TestVMWriteIsNotGrantedByALearnedRead` in `pkg/ebpf/vmload_test.go` pins the
> behaviour against a real kernel: the learned read still works, the write is
> refused and the file is verified unchanged, an explicitly seeded write is
> allowed, and revoking it closes the door again. **The matrix above is left as
> it was measured**; re-running the suite would be needed to claim 26/26, and
> that has not been done.

**Anything that needs no new binary and no new path is invisible.**
`24-write-sys-procsys` (writing `/proc/sys/kernel/core_pattern` and friends by
shell redirection) produced **no Pahlevan signal at all** and was not blocked. It
was not blocked by Falco or Tetragon either, and on the bare control cluster the
writes failed anyway because the container lacks the privilege, so nothing here
is attributable to any tool. It is reported as detected=No for Pahlevan and
Falco, and as an exec-only telemetry artefact for Tetragon.

## Resource use

Measured from each agent pod's cgroup v2 `memory.current`, `memory.stat` and
`cpu.stat` inside the VM, not from `kubectl top`. "Idle" is a 30 s sample with
the target serving nothing; "under load" is a 30 s sample with a tight `curl`
loop against nginx. Single-node cluster, one agent at a time.

| Tool (agent) | memory.current | anon (Go heap/stack) | kernel | page cache | peak | CPU idle | CPU under load |
|--------------|---------------:|---------------------:|-------:|-----------:|-----:|---------:|---------------:|
| **Pahlevan** agent | 66.7 MiB | 39.7 MiB | 20.2 MiB | 6.8 MiB | 67.0 MiB | 0.33 % | 11.25 % |
| **Falco** | 195.3 MiB | 45.5 MiB | 26.3 MiB | 123.5 MiB | 201.7 MiB | 0.39 % | 10.65 % |
| **Tetragon** | 78.2 MiB | 36.7 MiB | 38.1 MiB | 3.0 MiB | 118.8 MiB | 0.11 % | 7.77 % |

### Pahlevan memory, split into BPF maps versus Go runtime

The 327 MiB figure in the first run is gone. Summed from `bpftool -j map show`
over Pahlevan's 16 maps, with all five programs loaded:

| Map | max_entries | memlock |
|-----|------------:|--------:|
| `file_allowed` | 131072 | 10241.06 KiB |
| `network_allowed` | 32768 | 2561.06 KiB |
| `syscall_seen` | 16384 | 1281.06 KiB |
| `cap_mode`, `exec_mode`, `file_mode`, `network_mode` | 8192 each | 641.34 KiB each |
| `cap_allowed`, `exec_allowed` | 8192 each | 641.06 KiB each |
| `cap_events`, `events`, `exec_events`, `file_events`, `network_events` | 262144 each | 269.40 KiB each |
| `config_map`, `file_config` | 1 each | 0.38 KiB each |
| **Total (16 maps)** | | **18.83 MiB** (19,741,128 bytes) |

So the breakdown is:

| Component | Size |
|-----------|-----:|
| BPF maps (kernel, `bytes_memlock`) | 18.83 MiB |
| Go runtime + binary (cgroup `anon`) | 39.7 MiB |
| Other kernel accounting for the pod (stacks, page tables, socket buffers) | ~1.3 MiB |
| Page cache attributed to the pod | 6.8 MiB |
| **cgroup `memory.current`** | **66.7 MiB** |

BPF map memory is charged to the creating process's memcg on this kernel, which
is why the cgroup's `kernel` figure and the `bpftool` total agree to within a
couple of MiB. `TestVMMapMemoryFootprint` asserts the total stays under 64 MiB;
it is comfortably inside that.

Reading the table honestly:

- On memory Pahlevan is now the **lightest of the three**, and it is no longer
  the outlier it was. Falco's `memory.current` is dominated by page cache, which
  is reclaimable; on anonymous memory alone the three are within 10 MiB of each
  other, and the real difference is Pahlevan's ~19 MiB of preallocated BPF maps.
- On CPU under load Pahlevan is the **heaviest of the three**. That is a real
  result, though it is measured with event export switched on (below).
- Idle CPU is a wash: all three are well under 1 % of one core.

## Event export and observability

Pahlevan's `pahlevan_*` Prometheus metrics **are** served on `:8080` now (74
series), which the first run reported as broken. Scraped live from the agent
during the run: `pahlevan_containers_enforced 2`,
`pahlevan_enforcement_actions_total 2`, `pahlevan_policy_violations_total 148`
(0 before the suite, so the counter does move), and per-type
`pahlevan_export_events_total`.

The whole event stream for the run, by type and action, straight from the
exported JSON lines:

| Type | observe | deny |
|------|--------:|-----:|
| file | 23238 | 146 |
| syscall | 3905 | 0 |
| process | 1064 | 0 |
| capability | 235 | 0 |
| network | 146 | **2** |
| **total** | **28588** | **148** |

That table is the mechanism finding in one place: 148 in-kernel denials, 146 from
`file_open` and 2 from `socket_connect` (the two probes), none from
`bprm_check_security` or `capable`.

Two problems in the exported events, both visible in the raw JSON lines kept with
this run:

**Destination addresses are byte-reversed.** A denied connect to `127.0.0.1:9` is
exported as `"destinationIp":"1.0.0.127"`, and one to `10.43.0.10:53` as
`"destinationIp":"10.0.43.10"`. The address is rendered with the wrong byte
order, so every network event in the export names the wrong host. The port,
protocol and deny action are correct.

**Pod attribution is mostly missing.** Of 28736 exported events, 763 carried any
`kubernetes` object and only 31 carried a pod name. The denials do carry
`podUid`, `containerId`, `runtime` and `qosClass`, but `namespace` and `pod` are
empty, so a consumer has to resolve cgroup or pod UID to a pod name itself. The
benchmark's correlator falls back to matching `cgroupId` for exactly this reason.
An earlier run in the same session was worse: of 70136 events, 13 carried a pod
name and it was a *previous, deleted* target pod.

`PahlevanPolicy.status` stayed **empty** for the whole run: no phase, no learning
progress, no enforcement counters. Enforcement state is observable through the
BPF maps, the logs and the metrics endpoint, but not through the CRD.

## Reproducibility

The Pahlevan half of this run was executed twice, from two different commits
(`30f4cac` and `370f14a`, the second taken after the tree moved again mid-session).
**Both produced an identical matrix**: the same 25 blocks, the same
`15-write-passwd-sudoers` escape, the same 3/3 benign controls, the same three
probe results, and BPF map memlock identical to the byte (19,741,128). The
figures published here are from `370f14a`.

At the end of the run the node-wide learned allow-sets held 37470 file entries,
1470 exec entries, 342 capability entries and 234 network destinations across all
cgroups on the node (not just the target). The agent finished with **0 restarts**
and the target pod with 0 restarts.

Raw artifacts for each tool (per-scenario timings, the tool's own signal stream,
the correlated matrix as JSON, cgroup resource samples, `bpftool` output) are
produced under `/tmp/pahlevan-bench/results/<tool>/` and the tables above are
rendered from them by `test/benchmark/report.py`, not transcribed by hand.

## Caveats

Read these before quoting any number above.

**Every tool ran in its vendor-default configuration**, and a default-config
non-block does **not** mean a tool is incapable of blocking. Falco is alert-only
by design. Tetragon blocks with a hand-written `TracingPolicy`, which was
deliberately not applied here after the previous run's un-scoped policy froze the
node. Only Pahlevan is being asked to block, and only Pahlevan is credited with
blocking; that asymmetry is a property of the postures, not a measurement of
capability.

**Falco's and Tetragon's detection counts are floors, not ceilings.** Falco's
incubating and sandbox rulesets, and additional Tetragon `TracingPolicy`s, would
detect more. A tuned-vs-default comparison would be dishonest and is not offered.

**Pahlevan's enforcement was measured after waiting out the self-healing
observation window.** That is stock configuration, but it is not the first five
minutes of stock operation. In those first five minutes the results would be
different and worse: enforcement disables itself after ten denials. Both facts
are in this document; neither should be quoted without the other.

**Pahlevan ran with event export enabled** (`--export-file` plus
`--export-denials-only=false`), which is not the shipped default. It was needed
to measure per-scenario detection at all, and it inflates Pahlevan's CPU and
memory relative to a default agent, since every observed event is converted to
JSON and written. It is roughly posture-equivalent to Falco and Tetragon, which
both write every alert or event to stdout by default. The size of the effect was
not isolated: **the same run with export off was not measured.**

**Pahlevan's agent logs one line per observed syscall at DEBUG.** That inflates
its CPU figure further and rotates the container log fast enough to lose earlier
lines. A production build would not do this.

**The attacker is assumed to already have a shell.** The resident runner starts
during learning, so `bash` and its libraries are in Pahlevan's allow-list. This
makes Pahlevan's job harder. It also means the suite never measures the case
where the attacker's shell itself is unlearned, which is the case that produced
the first run's blanket `exec-blocked`.

**Detection latency was not measured.** No shared high-resolution clock between
the in-pod action and the tool's signal is instrumented; scenario windows are
correlated at second granularity with a 3 s settle margin. Do not read the
correlation windows as latency figures.

**Tetragon's detection count needs one qualification.** Its default sensor emits
`process_exec` / `process_exit` only. For scenarios that exec nothing it emits
nothing meaningful: 25 of 26 attacks produced a real exec event, and
`24-write-sys-procsys` produced only the harness shell's own exit event. All 3
builtin-only probes produced no meaningful Tetragon signal for the same reason.
The headline count in the totals table counts any in-window event; the corrected
count is 25/26.

**Tetragon also emits telemetry for the benign controls** (3/3). That is not a
false positive: it is an observability tool doing its job, and nothing was
blocked. It is noted only so the benign row is not misread.

**Falco produced no host-level noise in the measured window** (33 alerts, all 33
attributed to the target pod), unlike the first run. That window is only the
~110 s of the suite, so it is not evidence about Falco's steady-state noise.

**The tree moved under this run.** The repository was being actively committed to
throughout: HEAD advanced from `f67e0ae` to `370f14a` during the session, and at
one point the working tree did not compile. Everything here is built from a
pinned `git archive` of a single commit, `370f14a`, not from the working
directory. Numbers from a later commit may differ.

**Three deviations from the shipped Pahlevan install** were required and are
described above: the CRD schema patch, the supplementary read-only ClusterRole,
and `--platform=$BUILDPLATFORM` dropped from the Dockerfile in the throwaway
build copy (the host has no buildx, and the legacy builder does not expand it;
single-arch build, no functional difference). None of them touch the repository.

### Not measured

| Item | Why |
|------|-----|
| `bprm_check_security` enforcement | Enabled and confirmed active, but `file_open` denies the binary's open first, so the exec hook was never reached. No probe isolates it |
| `capable` enforcement | Same masking; no builtin-only action was found that reaches an unlearned capability check |
| IPv6 egress enforcement | The fix exists in `network_monitor.c`, but the cluster is IPv4-only, so no IPv6 connect was ever attempted |
| Detection latency distributions | Not instrumented |
| Pahlevan resource use with export disabled | Not run; only the export-enabled configuration was measured |
| Tetragon with a blocking `TracingPolicy` | Deliberately not run after the previous run's node outage |
| Falco with incubating/sandbox rules | Out of scope for a defaults comparison |
| All three tools running simultaneously | 3.8 GiB RAM in the VM |

## Summary

At vendor defaults, against 26 ATT&CK-mapped scenarios in the same pod:

- **Falco** alerted on 9 of 26 and blocked none, which is its design. It
  produced zero false positives on the benign controls and attributed every one
  of its alerts to the right pod.
- **Tetragon** produced exec telemetry for 25 of 26 (the 26th execs nothing) and
  blocked none, which is its default. Zero false positives, and it also emits
  telemetry for benign activity, as expected of an observability tool.
- **Pahlevan** detected 25 of 26 and blocked 25 of 26 from an
  auto-learned allow-list with no hand-written rules, and it is now the lightest
  of the three on memory. But: every one of those blocks came from the
  **`file_open`** hook and none from the exec, network or capability hooks, which
  the ordering of `execve` makes unreachable behind it; it blocked **3 of 3**
  benign controls, so a workload doing anything outside its learned baseline
  breaks; an attacker can write to any file the workload merely read during
  learning, which is how `15-write-passwd-sudoers` succeeded; enforcement
  disables itself after ten denials in the first five minutes; and the shipped
  `install.yaml` does not install at all without two fixes.

The honest headline is not "Pahlevan blocks 25 of 26". It is that Pahlevan is the
only one of the three configured to block, that its learned allow-list really
does stop most of this suite in-kernel and now does so at a competitive memory
cost, and that its false-positive profile, its install manifest and its
self-healing default are the three things standing between that and something
anyone should run in production.

### The benign-control result deserves its own paragraph

Pahlevan blocked all three benign controls, and that number should not be
softened. It also should not be misread. The controls invoke `curl`, `cat` and
`getent`, binaries nginx itself never runs, so under an exec-and-open allow-list
learned from nginx they are correctly unlearned. Two things are true at once:

- **The workload itself never broke.** nginx served HTTP 200 before, during and
  after enforcement, including through the whole attack suite, and the target pod
  never restarted. Measured separately from the node, outside the pod.
- **Anything else in that pod breaks.** Sidecar commands, `kubectl exec`, debug
  tooling, liveness probes implemented as `exec` rather than `httpGet`, and any
  code path not exercised during the learning window are all denied. The 3/3 is a
  fair measure of that cost.

A 180 s learning window driven by a single traffic pattern is a small baseline.
A longer window covering more of the workload's real behaviour would reduce this,
and that is the tuning knob that matters most for anyone deploying it.

