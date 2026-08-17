# Benchmarks

Measured numbers for what Pahlevan detects, what it prevents, and what it costs
to run. Nothing here is hand-written: every published figure comes from a run of
[`test/benchmark/run.sh`](../../test/benchmark/run.sh) inside the
kernel-isolated VM, and the raw artifacts that produced it - per-scenario
timings, the exported event stream, cgroup resource samples - are kept alongside
the run.

Anything that could not be measured is written down as such rather than
estimated or quietly omitted.

## Published runs

| File | Date (UTC) | Coverage |
|------|-----------|----------|
| _none yet_ | | The previous runs measured Pahlevan alongside two other tools. Those files were removed rather than edited, because a recorded measurement is not something to revise after the fact. A standalone run is pending. |

## What is measured

Each run is two passes over the identical scenarios: a **control pass with no
agent installed**, then a Pahlevan pass.

The control pass is not a formality. It establishes that each attack actually
succeeds when nothing is watching, so a later "blocked" can be attributed to the
agent rather than to a missing binary, an unroutable destination, or a scenario
that silently failed to run. It also gives the CPU and memory figures a
denominator: agent cost is the difference from an unwatched node, not an
absolute number.

| Metric | Meaning |
|--------|---------|
| **Detected** | An event was produced for the action, read from the agent's exported stream |
| **Blocked** | The action was *prevented*, not merely reported |
| **Mechanism** | For a block, which kernel hook refused it (`file_open`, `socket_connect`, `bprm_check_security`, `capable`, `commit_creds`) |
| **False positives** | Benign control actions wrongly blocked |
| **Agent CPU / memory** | cgroup v2 `cpu.stat` and `memory.current`, plus the BPF map memlock total |

Scenarios live in [`test/benchmark/scenarios/`](../../test/benchmark/scenarios)
and are grouped by MITRE ATT&CK for Containers tactic; the full list, the
self-classifying marker contract, and the harness design are documented in
[`test/benchmark/README.md`](../../test/benchmark/README.md).

## Reproducing a run

```bash
hack/vm/up.sh                     # boot the VM: kernel 6.8, bpf LSM active
test/benchmark/run.sh setup       # k3s, helm, the nginx:1.27 target
test/benchmark/run.sh all         # control pass, then Pahlevan
```

eBPF is loaded only inside that VM. Nothing in this directory is produced by
running an agent on a developer machine.
