# Reproducible benchmark

This harness runs Pahlevan in a kernel-isolated k3s cluster against a set of
attack scenarios plus a set of benign controls, and records what it detected,
what it prevented, and what it cost. It runs the identical scenarios first with
no agent installed at all, because a detection count means nothing until you
know the attacks succeed when nothing is watching, and a CPU figure means
nothing without the idle node to subtract.

It is meant to be reproducible: the numbers in `docs/benchmarks/` are produced
by running it, never hand-written.

> All eBPF runs inside a VM (see `hack/vm/`), never on the host.

## What is measured

For each attack scenario (`scenarios/*.sh`), on each pass:

| Metric | Meaning |
|--------|---------|
| **Detected** | Was the malicious action observed, read from the agent's own exported event stream and kernel maps? |
| **Blocked** | Was it *prevented* - did the in-pod action fail? Not just reported. |
| **Detection latency** | Time from action to signal |
| **Agent CPU / memory** | Steady-state resource use of the node agent, against the control pass |
| **False positives** | Benign control actions (`scenarios/benign/*.sh`) wrongly flagged or blocked |

The column that matters is **Blocked**, and the claim being tested is narrower
than it looks: the allow-list doing the blocking was learned from the workload,
with no rule written by hand for any of these scenarios. A benchmark where
somebody wrote a rule per attack the week before proves only that they can
write rules.

## How outcomes are classified

Every scenario script is a small POSIX `sh` program that an attacker-with-exec
could run inside the compromised nginx pod. `run.sh` pipes each script to `sh`
inside the target pod (`kubectl exec -i`), and every script prints exactly one
self-classifying marker line:

```
BENCH_RESULT tag=<name> kind=<attack|benign> outcome=<allowed|blocked|attempted|skipped> rc=<n>
```

- `outcome=blocked` - the in-pod action was **prevented** (e.g. `EPERM`). For an
  attack this is a **Blocked=Yes**.
- `outcome=allowed` - the action **completed**. Blocked=No.
- `outcome=attempted` - success/failure is **ambiguous from inside the pod**
  (network reaching an unroutable destination, probes for paths that are normally
  absent such as `/host` or a runtime socket). For these, judge Blocked from the
  tool's own logs, **not** from the exit code. This is deliberate honesty: a
  `curl` to an unroutable address fails whether or not any tool blocked it.
- `outcome=skipped` - a required tool (e.g. `python3`, `curl`) is not present in
  the image, so the scenario could not run.
- If the pod's `exec` itself is denied (Pahlevan enforcing on the runc-exec
  setup), no marker is printed and `run.sh` records `outcome=exec-blocked`.

Network- and socket-oriented scenarios use documentation/`TEST-NET` addresses
(`198.51.100.0/24`, `example.com`) and loopback, so nothing real is ever
contacted. All scripts use timeouts, finish in a few seconds, never hang, and are
safe to run repeatedly in a throwaway pod (any file they create in `/tmp`,
`/dev/shm`, `/etc`, etc. is cleaned up or restored).

## Attack scenarios, grouped by MITRE ATT&CK for Containers

Roughly one to three per tactic. Technique ids are given only where the mapping
is clear; where a step does not map cleanly to a single technique, the id is
omitted rather than guessed.

### Credential Access (TA0006)
1. `01-sensitive-file-read` - read `/etc/shadow` (T1003.008).
2. `05-serviceaccount-token` - read the mounted Kubernetes SA token (T1552.001).
3. `06-proc-environ` - read `/proc/self/environ` for secrets in env (T1552).
4. `07-search-private-keys` - sweep the filesystem for private keys (T1552.004).

### Discovery (TA0007)
5. `08-proc-enumeration` - enumerate `/proc` for other processes (T1057).
6. `09-k8s-api-query` - query the Kubernetes API with the SA token (T1613).
7. `10-network-discovery` - probe common service ports on the network (T1046).

### Execution / Persistence (TA0002 / TA0003)
8. `03-crypto-miner-exec` - exec a binary dropped in `/tmp` (T1496 / T1204).
9. `11-exec-dev-shm` - exec a binary dropped in `/dev/shm` (T1059).
10. `12-interpreter-abuse` - python/perl interpreter one-liner (T1059.006).
11. `13-persistence-profile-cron` - plant payloads in shell profile files and a
    cron drop dir (T1546.004 / T1053.003).

### Privilege Escalation (TA0004)
12. `14-setuid-abuse` - enumerate setuid binaries and set the setuid bit on a
    dropped binary (T1548.001).
13. `15-write-passwd-sudoers` - append a rogue account to `/etc/passwd` and a
    NOPASSWD rule to `/etc/sudoers` (T1548.003 / T1098).
14. `16-capability-probing` - read process capability sets to gauge escalation
    posture (technique id omitted; recon for later escalation).

### Defense Evasion (TA0005)
15. `17-clear-logs` - truncate log files (T1070.002).
16. `18-disable-history` - neutralise shell command history (T1070.003).
17. `19-delete-after-exec` - drop, run, then delete a payload (T1070.004).
18. `20-timestomp` - backdate file timestamps (T1070.006).

### Exfiltration / Command and Control (TA0010 / TA0011)
19. `02-reverse-shell` - interactive shell wired to a TCP socket (T1059.004).
20. `04-unexpected-egress` - connect out to an unbaselined destination
    (T1041 / T1071.001).
21. `21-dns-egress` - burst of DNS lookups to an attacker domain (T1071.004).
22. `22-remote-payload` - fetch a remote payload with curl/wget (T1105).

### Container Escape signals (TA0004 - Escape to Host)
23. `23-docker-sock` - touch a mounted container runtime socket (T1610 / T1611).
24. `24-write-sys-procsys` - write kernel pseudo-files under `/proc/sys` and
    `/sys` (e.g. `core_pattern`) (T1611).
25. `25-mount-attempt` - exec `mount` to attach a filesystem (T1611).
26. `26-host-path-read` - read host paths exposed via `/host` or `/rootfs`
    (T1611).

Most of these are actions a normal nginx workload would **never** do, which is
what makes an auto-learned allow-list able to block them without hand-written
rules.

## Benign controls (false-positive counterweight)

`scenarios/benign/*.sh` are actions a normal nginx workload legitimately performs.
They are the fairness counterweight to the attack list: a tool that blocks
everything scores perfectly on attacks but is useless if it also breaks the
workload. **False positives matter as much as detections.** These are **never**
counted as attacks; the correct outcome for each is always `allowed`, and any
`blocked`/failed outcome is a false positive and is counted as one.

- `b01-serve-request` - serve an HTTP request on loopback (the liveness/probe
  and real-client path).
- `b02-read-own-config` - read nginx's own config and served content.
- `b03-resolve-dns` - resolve an in-cluster service name via cluster DNS.

## How it runs

`run.sh` will:
1. `hack/vm/up.sh` - boot the kernel-isolated VM.
2. Install k3s in the VM and deploy the target workload.
3. Deploy a benign target workload (`nginx:1.27`); let Pahlevan learn its baseline.
4. Start the resident in-pod runner (see below) while the agent is still
   learning/observing, switch Pahlevan to enforcing, then run every attack
   scenario and every benign control inside the target pod.
5. Scrape the exported event stream and the agent cgroup v2 CPU/memory, plus the
   BPF map memlock total.
6. Correlate signals to scenarios by timestamp and record a matrix under
   `docs/benchmarks/`.

Usage:

```
hack/vm/up.sh
test/benchmark/run.sh setup       # cluster + target workload
test/benchmark/run.sh control     # no tool installed: baseline outcome per scenario
test/benchmark/run.sh pahlevan    # learn, enforce, attacks + benign controls
test/benchmark/run.sh all         # setup + control + pahlevan, in sequence
```

Artifacts land in `/tmp/pahlevan-bench/results/<tool>/` on the host:
`scenarios.txt` (raw, timestamped), `signals.raw` (the exported event stream),
`matrix.txt` / `matrix.json` (correlated), `resources.txt`, `meta.txt`.

### The resident in-pod runner (`pod-runner.sh`)

Scenarios are **not** run with one `kubectl exec` each. Once Pahlevan is
enforcing, the `runc exec` setup itself opens unlearned paths, so every
`kubectl exec` into the pod is refused and a per-scenario `exec` harness can only
ever measure "exec was denied". That is what the 2026-08-14 run hit, and it is
why that run could not say which mechanism stopped which action.

Instead `run.sh` starts `pod-runner.sh` inside the target pod **while the agent
under test is still learning/observing**. At that point the runner reads every
scenario into memory, opens its output file (fd 9) and a fifo it uses as a
builtin sleep (fd 8), and then waits. From the trigger onward it uses **only bash
builtins**: no `exec` of a new binary and no `open` of a new path, so the harness
itself cannot be blocked by the enforcement it is measuring. Each scenario body
runs via `eval` inside a command substitution, which is a fork rather than an
exec; the binaries the scenario itself invokes (`cat`, `curl`, `timeout`, ...) are
the things under test.

The node arms the run and reads the results through `/proc/<pid>/root/tmp/bench`,
so no `kubectl exec` is needed after enforcement begins.

Two consequences, both stated in the results:

- The runner assumes the attacker **already has a shell** in the compromised pod,
  so `bash` and its libraries end up in the learned allow-list. This makes the
  tools' job harder, not easier.
- Because every tool is driven the same way, the comparison stays apples to
  apples.

Whether `kubectl exec` is refused under enforcement is measured separately and
reported as its own line rather than being allowed to swallow the matrix.

### Correlating signals to scenarios (`correlate.py`)

Every scenario records the wall-clock window `[t0, t1]` in which it ran. After
the exported event stream is pulled for the run window and bucketed into
those windows (plus a settle margin, since userspace alerting is asynchronous):

| Tool | Signal source | Attribution |
|------|---------------|-------------|
| Pahlevan | JSON-lines event export (`--export-file`) | `kubernetes.pod`, falling back to `cgroupId` |

Signals that fall outside every window, or that belong to another workload, are
counted and reported separately rather than being folded into a detection.

## Honesty rules

A benchmark you run on your own product is worth exactly as much as the rules
you follow while running it.

- **State the configuration posture with every result.** Which hooks were
  attached, how long learning ran, whether the BPF LSM was active. A result
  recorded with only `file_open` wired is not the same product as one with
  network and exec enforcement attached, and reporting the two as one number is
  a lie of omission.
- **Report what was not measured, and why.** The recorded results files do this
  and the habit is deliberate.
- **A scenario that Pahlevan fails stays in the suite.** Removing it is how a
  benchmark becomes marketing.
- **Never edit a results file to change a number.** Re-run and replace.
- **The control pass is not optional.** Without it, "detected 14 of 16" has no
  denominator you can trust: a scenario that silently failed to execute looks
  identical to one that was prevented. Scenarios and tool configs are
committed so runs are comparable and auditable. Do not fabricate results: the
scenarios in this suite beyond the original four have not yet been run, and no
results for them are recorded.
