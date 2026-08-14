# Benchmarks

This directory holds Pahlevan's competitive benchmark results (vs. Falco and
Tetragon) and the methodology used to produce them.

> **Status:** results are generated, not hand-written. This page describes how to
> reproduce them; published numbers are added here only after a run on real
> hardware. No figures are invented.

## What is measured

The benchmark exercises a set of realistic attack scenarios against an
instrumented workload and records, for each tool, whether the action was
**detected**, **alerted**, or **blocked in-kernel**, along with runtime overhead.

Attack scenarios live in [`test/benchmark/scenarios/`](../../test/benchmark/scenarios):

| Scenario | Script |
| --- | --- |
| Sensitive credential file read (`cat /etc/shadow`) | `01-sensitive-file-read.sh` |
| Reverse shell | `02-reverse-shell.sh` |
| Crypto-miner execution | `03-crypto-miner-exec.sh` |
| Unexpected egress connection | `04-unexpected-egress.sh` |

Each scenario documents the expected outcome per tool. For example, on a sensitive
file read Pahlevan (in enforce mode) **denies the open in-kernel with `EPERM`**,
whereas an alert-only tool merely raises an event.

## Reproducing

Enforcement requires a kernel with `CONFIG_BPF_LSM` and `lsm=bpf`, so the harness
runs inside a VM (see [`hack/vm/`](../../hack/vm)):

```bash
# bring up the eBPF-capable VM, then:
make test-benchmark
```

Results (raw output + a comparison summary) are written back to this directory.
Until a full run is committed here, treat any performance claim as unpublished.
