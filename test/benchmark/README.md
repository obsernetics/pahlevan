# Pahlevan vs Falco vs Tetragon — reproducible benchmark

This harness runs Pahlevan, Falco, and Tetragon **side by side, in the same
kernel-isolated k3s cluster**, against an identical set of attack scenarios, and
records what each tool actually did. It is meant to be reproducible: the numbers
in the repo's README/`docs/benchmarks/` are produced by running it — never
hand-written.

> All eBPF runs inside a VM (see `hack/vm/`), never on the host.

## What is measured

For each scenario (`scenarios/*.sh`) and each tool:

| Metric | Meaning |
|--------|---------|
| **Detected** | Did the tool observe/flag the malicious action? |
| **Blocked** | Did the tool *prevent* it (action failed) — not just alert? |
| **Detection latency** | Time from action to signal |
| **Agent CPU / memory** | Steady-state resource use of the node agent(s) |
| **False positives** | Benign baseline workload actions wrongly flagged/blocked |

The decisive column is **Blocked**: Falco is alert-only by design, so it cannot
block; Tetragon blocks only with a hand-written `TracingPolicy`; Pahlevan blocks
from an **auto-learned** allow-list with no rules authored by hand.

## Scenarios

1. `01-sensitive-file-read` — read `/etc/shadow` (never in baseline).
2. `02-reverse-shell` — shell wired to a TCP socket.
3. `03-crypto-miner-exec` — exec a binary from an unbaselined path.
4. `04-unexpected-egress` — connect to an unbaselined destination.

## How it runs

`run.sh` (added with the harness) will:
1. `hack/vm/up.sh` — boot the kernel-isolated VM.
2. Install k3s in the VM; deploy Falco, Tetragon, and Pahlevan.
3. Deploy a benign target workload; let Pahlevan learn its baseline.
4. Switch Pahlevan to enforcing; execute each scenario in the target pod.
5. Scrape each tool's signals + `kubectl top` resource usage.
6. Emit a results matrix to `docs/benchmarks/results-<date>.md`.

Fairness notes: each tool uses its vendor-recommended defaults; scenarios and
tool configs are committed so runs are comparable and auditable.
