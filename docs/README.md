# Pahlevan Documentation

Pahlevan is an eBPF Kubernetes security operator. It learns what a container
actually does, then refuses everything else in the kernel, at the LSM hook,
before the operation completes.

This directory is the reference for deploying, configuring and operating it.

## Start here

| Document | What it is |
|---|---|
| [Quick start](quick-start.md) | Install Pahlevan, put one workload under a policy, watch it learn, and switch enforcement on. |
| [System requirements](system-requirements.md) | Kernel versions, Kubernetes versions and node resources, and what each capability needs. |
| [LSM support](lsm-support.md) | Which kernels and distributions serve the BPF LSM, and what Pahlevan can still do without it. |

## Understanding it

| Document | What it is |
|---|---|
| [Architecture](architecture.md) | The split between the privileged node agent and the unprivileged operator, the eight eBPF programs, the five enforcement actions, and the learn-to-enforce lifecycle. |
| [Packages and releases](packages.md) | The container image, Helm chart and single-file manifest published per release, and how to pin each one. |
| [Benchmarks](benchmarks/) | Measured detection, prevention and overhead figures, each traceable to a run rather than an estimate. |
| [What Pahlevan does to a real workload](live-scenario.md) | The harness that runs a real application under the data plane for an hour, learns it, enforces, and then attacks it. |
| [Live scenario report](scenario-report.md) | The recorded output of that harness: what the kernel actually did, line by line. |

## Configuring and running it

| Document | What it is |
|---|---|
| [Deployment guide](deployment.md) | Production install, sizing, rolling enforcement out safely, metrics and alerting, getting events off the node, upgrades and uninstall. |
| [Policy reference](policy-reference.md) | Every `PahlevanPolicy` field, with examples. |
| [API reference](api-reference.md) | The generated CRD field reference, produced from the Go types so it cannot drift from what the API server serves. |
| [The optional dashboard](dashboard.md) | The browser view of what each workload does and what was denied, and how to deploy it. |
| [Troubleshooting](troubleshooting.md) | Diagnosing an install that is not behaving. |

`assets/` holds the diagrams and the demo recording these pages embed, together
with the sources they are generated from. [`../CHANGELOG.md`](../CHANGELOG.md)
is the release history and [`../ROADMAP.md`](../ROADMAP.md) separates what is
implemented from what is not.

## The CLI

Every command below is in the `pahlevan` binary shipped in the release image.
The ones marked "no cluster" read nothing but a local file or the binary's own
compiled-in tables, which makes them usable in CI and in a bug report.

| Command | What it does |
|---|---|
| `pahlevan status` | Whether the components, CRDs and admission policy are installed and healthy. |
| `pahlevan policy` | List, describe, create, update and delete policies. |
| `pahlevan policy explain -f` | **No cluster.** Translates a policy file offline and names every part of it the data plane cannot enforce. `--strict` exits non-zero, for CI. |
| `pahlevan profile` | The seccomp profiles generated from learned behavior. `profile patch` prints the workload patch that applies one, and applies nothing itself. |
| `pahlevan events` | The agent's JSON-lines event log, filtered by type, pod or denial, as a stream that composes with `jq`. |
| `pahlevan ui` | An interactive view of the live event stream, per-workload counts and the coverage table. Falls back to a plain summary off a terminal. |
| `pahlevan coverage` | **No cluster.** The eBPF detectors, their kernel hooks, and the MITRE ATT&CK techniques their observations are evidence for. |
| `pahlevan attack-surface` | What remains reachable for a workload - syscalls, ports, writable paths, capabilities - and its risk score. |
| `pahlevan logs` / `pahlevan metrics` | Read logs and scrape `/metrics` from either component without hunting for pod names. |
| `pahlevan debug` | A support bundle: pod state, node kernels, CRD availability, recent events and metric highlights. Reads no Secrets or tokens. |

`pahlevan ui` is the one worth trying first after an install, because it is the
only view that shows what is being observed and what is being refused at the
same time. It is a reader: it never changes a policy, a mode or a profile, so it
cannot be the thing that turns enforcement off during an incident. `--replay`
points it at a captured JSON-lines file and needs no cluster at all. See
[the quick start](quick-start.md#watch-it-work).

## Key concepts

### Learning

A `PahlevanPolicy` selects workloads by label. During the learning window the
agent records what each matched container does - the files it opens, the
destinations it dials, the binaries it runs, the capabilities it exercises, the
syscalls it makes - into per-cgroup BPF maps, and persists the result as a
`ContainerProfile` so a restart does not relearn from zero.

### Enforcement

Switching a policy to `Blocking` is a map update, not a program reload. After
it, an open of an unlearned path, an egress to an unlearned destination or an
exec of an unlearned binary is refused in the kernel with `EPERM`, before it
completes. A detection tool can only tell you it already happened.

`enforcementConfig.mode` accepts `Off`, `Monitoring` and `Blocking`. Quote
`Off`: unquoted it is a YAML 1.1 boolean.

### Self-healing

A baseline learned in five minutes can miss a code path that runs at month end,
and enforcement built on it will deny something the workload needs. The operator
watches violation rate and workload health after a transition, relaxes the
policy when enforcement correlates with disruption, and rolls back to monitoring
if relaxing did not help. Turn it off when you would rather have a hard failure
than an automatic rollback.

## Getting help

- **Issues**: [GitHub Issues](https://github.com/obsernetics/pahlevan/issues).
  Attach `pahlevan debug -o json --file pahlevan-debug.json` - it carries the
  node kernel versions and LSM state that most reports are missing, and reads no
  Secrets, tokens or container environment variables.
- **Contributing to these docs**: test every command you add. A documented flag
  that does not exist costs a reader more time than the missing paragraph would
  have.
