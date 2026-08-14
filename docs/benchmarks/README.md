# Benchmarks

This directory holds Pahlevan's competitive benchmark results (vs. Falco and
Tetragon) and the methodology used to produce them.

> **Status:** results are generated, not hand-written. Every published figure
> comes from a run of `test/benchmark/run.sh` inside the kernel-isolated VM, and
> the raw artifacts that produced it (per-scenario timings, each tool's own
> signal stream, cgroup resource samples) are kept alongside the run. No figures
> are invented, and anything that could not be measured is written down as such
> instead of being estimated or omitted.

## Published runs

| File | Date (UTC) | Coverage |
|------|-----------|----------|
| [`results.md`](results.md) | latest | Always a copy of the most recent run below |
| [`results-2026-08-14-run2.md`](results-2026-08-14-run2.md) | 2026-08-14 | 26 attack scenarios, 3 benign controls, 3 mechanism probes, a no-tool control run, per-mechanism block attribution, BPF-vs-Go memory split |
| [`results-2026-08-14.md`](results-2026-08-14.md) | 2026-08-14 | First run: 4 scenarios, file-open enforcement only. Superseded, kept as a record |

## What is measured

For each scenario and each tool:

| Metric | Meaning |
|--------|---------|
| **Detected** | The tool produced a signal for the action, read from its own stream |
| **Blocked** | The action was *prevented*, not merely alerted |
| **Mechanism** | For a block, which kernel hook refused it (`file_open`, `socket_connect`, `bprm_check_security`, `capable`) |
| **False positives** | Benign control actions wrongly blocked |
| **Agent CPU / memory** | cgroup v2 `cpu.stat` and `memory.current`, plus the BPF map memlock total for Pahlevan |

Scenarios live in [`test/benchmark/scenarios/`](../../test/benchmark/scenarios)
and are grouped by MITRE ATT&CK for Containers tactic; the full list, the
self-classifying marker contract, and the harness design are documented in
[`test/benchmark/README.md`](../../test/benchmark/README.md).

A **control run with no security tool installed** establishes the baseline
outcome of every scenario, so a later "blocked" can be attributed to the tool
rather than to a missing binary or an unroutable destination.

## Fairness

Every tool is run in its **vendor-default** configuration, one at a time, against
the same `nginx:1.27` target and the same scenarios. A default-config "did not
block" is **not** a claim that a tool cannot block: Falco is alert-only by
design, and Tetragon blocks only with a hand-written `TracingPolicy`. Results are
comparable only at equal configuration posture; each run states the posture it
used and every deviation from stock.

## Reproducing

Enforcement requires a kernel with `CONFIG_BPF_LSM` and `lsm=bpf`, so the harness
runs inside a VM (see [`hack/vm/`](../../hack/vm)). eBPF is never loaded on the
host.

```bash
hack/vm/up.sh
test/benchmark/run.sh setup       # k3s + the nginx:1.27 target
test/benchmark/run.sh control     # baseline with no tool installed
test/benchmark/run.sh pahlevan
test/benchmark/run.sh falco
test/benchmark/run.sh tetragon
python3 test/benchmark/report.py  # render the matrix from the artifacts
```
