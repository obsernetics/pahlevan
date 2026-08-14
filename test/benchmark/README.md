# Pahlevan vs Falco vs Tetragon - reproducible benchmark

This harness runs Pahlevan, Falco, and Tetragon **side by side, in the same
kernel-isolated k3s cluster**, against an identical set of attack scenarios plus
a set of benign controls, and records what each tool actually did. It is meant to
be reproducible: the numbers in `docs/benchmarks/` are produced by running it,
never hand-written.

> All eBPF runs inside a VM (see `hack/vm/`), never on the host.

## What is measured

For each attack scenario (`scenarios/*.sh`) and each tool:

| Metric | Meaning |
|--------|---------|
| **Detected** | Did the tool observe/flag the malicious action? (read from the tool's own signal source: Pahlevan kernel maps/logs, Falco alerts, Tetragon telemetry) |
| **Blocked** | Did the tool *prevent* it (the in-pod action failed)? Not just alert. |
| **Detection latency** | Time from action to signal |
| **Agent CPU / memory** | Steady-state resource use of the node agent(s) |
| **False positives** | Benign control actions (`scenarios/benign/*.sh`) wrongly flagged/blocked |

The decisive column is **Blocked**: Falco is alert-only by design, so it cannot
block; Tetragon blocks only with a hand-written `TracingPolicy`; Pahlevan blocks
from an **auto-learned** allow-list with no rules authored by hand.

## How outcomes are classified

Every scenario script is a small POSIX `sh` program that an attacker-with-exec
could run inside the compromised nginx pod. `run.sh` pipes each script to `sh`
inside the target pod (`kubectl exec -i`), and every script prints exactly one
self-classifying marker line:

```
BENCH_RESULT tag=<name> kind=<attack|benign> outcome=<allowed|blocked|attempted|skipped> rc=<n>
```

- `outcome=blocked` - the in-pod action was **prevented** (e.g. `EPERM`). For an
  attack this is a **Blocked=Yes** for the tool under test.
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
`blocked`/failed outcome is a false positive counted against the tool.

- `b01-serve-request` - serve an HTTP request on loopback (the liveness/probe
  and real-client path).
- `b02-read-own-config` - read nginx's own config and served content.
- `b03-resolve-dns` - resolve an in-cluster service name via cluster DNS.

## How it runs

`run.sh` will:
1. `hack/vm/up.sh` - boot the kernel-isolated VM.
2. Install k3s in the VM; deploy Falco, Tetragon, and Pahlevan (one at a time).
3. Deploy a benign target workload (`nginx:1.27`); let Pahlevan learn its baseline.
4. Switch Pahlevan to enforcing; stage the scenario scripts into the VM, then run
   every attack scenario and every benign control in the target pod.
5. Scrape each tool's signals + `kubectl top` / cgroup resource usage.
6. Record a results matrix under `docs/benchmarks/`.

Usage is unchanged:

```
hack/vm/up.sh
test/benchmark/run.sh setup       # cluster + target workload
test/benchmark/run.sh pahlevan    # learn, enforce, attacks + benign controls
test/benchmark/run.sh falco       # attacks + benign controls
test/benchmark/run.sh tetragon    # attacks + benign controls
test/benchmark/run.sh all         # setup + all three, sequentially
```

## Fairness: results are only comparable at equal configuration posture

Results are **only** comparable when every tool is run with the **same
configuration posture**: either all three on vendor defaults, or all three
equally tuned. Comparing one tool's tuned ruleset against another's defaults is
not a fair comparison and must not be presented as one.

In particular, a **default-config** result of "did not block" must **not** be read
as "tool X cannot block":

- **Falco** is alert-only by design and does not block in any configuration;
  reporting Blocked=No for Falco is a statement about its design, not a failure.
- **Tetragon** does not block on defaults but **can** block with a hand-written
  `TracingPolicy` (an unscoped one caused a node-wide outage on a past run - see
  `docs/benchmarks/results.md`).
- **Pahlevan** blocks from an auto-learned allow-list, but on the recorded run
  only its `file_open` LSM path was wired; network/syscall enforcement was not
  attached, so some scenarios are blocked only incidentally (via the file open of
  an unlearned binary).

State the posture used with every result. Scenarios and tool configs are
committed so runs are comparable and auditable. Do not fabricate results: the
scenarios in this suite beyond the original four have not yet been run, and no
results for them are recorded.
