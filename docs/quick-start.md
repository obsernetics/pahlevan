# Quick Start Guide

This guide will get Pahlevan running in your Kubernetes cluster in under 5 minutes.

## Prerequisites

Before starting, ensure your cluster meets the [system requirements](system-requirements.md):

- Kubernetes 1.24+
- Linux kernel 5.8 or newer, with cgroup v2 and kernel BTF at
  `/sys/kernel/btf/vmlinux`
- 128Mi memory and 100m CPU per node for the agent, 64Mi and 50m for the
  operator (the requests in the shipped manifests)

Your kernel version decides how much of Pahlevan works, not whether the install
succeeds. 5.8 is the floor to run at all; the file monitor needs 5.10 and the
exec and credential monitors need 5.11, so 5.11 is the first kernel on which
every detector `pahlevan coverage` lists is present. A program that cannot load
costs its own observations and leaves the rest of the agent running, with a log
line saying so.

**In-kernel enforcement is a separate question from the version.** The four
LSM-hooked programs need the kernel booted with `bpf` in its active LSM list,
which most distributions do not set by default. Without it Pahlevan still loads,
still learns and still reports, but it cannot refuse anything. Check this before
you plan a rollout, not after:
[`lsm-support.md`](lsm-support.md).

### Verify System Compatibility

Pahlevan's own compatibility check (`pahlevan debug`) inspects the
already-running agent and node state, so it only has something to report
after install. Before installing, check what gates whether the agent can
load: the kernel version, and whether the nodes are Linux.

```bash
kubectl get nodes -o custom-columns=NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion,OS:.status.nodeInfo.operatingSystem
```

[System requirements](system-requirements.md) has the per-program kernel
floors, the exact helper that sets each one, and a script that checks one node
properly.

## Installation

### Method 1: One-Line Install (Recommended)

```bash
# Install everything with one command
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Verify installation
kubectl get pods -n pahlevan-system
```

This installs:
- The `pahlevan-agent` DaemonSet (the eBPF data plane) and the
  `pahlevan-operator` Deployment (the control plane), with RBAC
- The three CRDs: `PahlevanPolicy`, `ContainerProfile`, `AttackSurface`
- A Prometheus-format `/metrics` endpoint on both components (no
  ServiceMonitor is installed; wire one up yourself if you run the
  Prometheus Operator)

### Method 2: Helm Chart

```bash
# Add the Helm repository
helm repo add pahlevan https://obsernetics.github.io/pahlevan/charts
helm repo update

# Install with default values
helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace

# Or with custom values
helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace \
  --values values.yaml
```

### Method 3: From Source

```bash
# Clone the repository
git clone https://github.com/obsernetics/pahlevan.git
cd pahlevan

# Build and deploy locally
make quick-start

# This will:
# - Build the operator image
# - Load it into your cluster
# - Deploy all components
```

## First Policy

### Create a Simple Monitoring Policy

```bash
cat <<EOF | kubectl apply -f -
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: nginx-monitor
  namespace: default
spec:
  selector:
    matchLabels:
      app: nginx
  learningConfig:
    duration: 5m
    autoTransition: false  # Manual transition for learning
  enforcementConfig:
    mode: Monitoring        # Start with monitoring only; Blocking denies in-kernel
    blockUnknown: false
EOF
```

### Check what the policy will actually do

A policy is not enforced literally. It becomes a set of decisions the agent
acts on, and anything the data plane cannot represent - a CIDR wider than a
host, a glob, a DNS name, an ingress rule - is dropped with a warning. Those
warnings normally land on the policy's status, which means you see them only
after applying to a cluster and knowing to look.

`pahlevan policy explain` shows them against a file, before anything is
applied, and needs no cluster:

```bash
pahlevan policy explain -f examples/policies/web-application.yaml
```

It prints the mode, the learning window, every allow and deny rule that will be
written into the kernel allow-sets, and then, if there are any, the parts that
will not be enforced and why. Add `--strict` to make it exit non-zero when
anything is unrepresentable, which is what you want in CI: a policy with
warnings is doing less than it says.

### Deploy a Test Application

```bash
# Create nginx deployment
kubectl create deployment nginx --image=nginx:latest

# Add the required label for policy targeting
kubectl label deployment nginx app=nginx

# Expose the service
kubectl expose deployment nginx --port=80 --target-port=80

# Generate some traffic
kubectl run curl --rm -i --tty --image=curlimages/curl -- sh
# Inside the curl pod:
# curl nginx
# exit
```

### Monitor Learning Progress

```bash
# Watch policy status
kubectl get pahlevanpolicy nginx-monitor -w

# Check detailed status
kubectl describe pahlevanpolicy nginx-monitor

# List the per-container profiles the policy is learning
pahlevan profile list -n default
```

After 5 minutes the policy's status phase moves from `Learning` to
`Transition` and then `Enforcing` if `autoTransition` is set - here it is not,
so it stays in `Learning` until you flip the mode yourself (see below).

## Understanding the Output

### What's actually learned

The learned baseline is not on the `PahlevanPolicy` itself - it is on one
`ContainerProfile` per matched container, which is what `pahlevan profile`
reads:

```bash
pahlevan profile get <pod-uid> -o yaml
```

The fields worth reading on that resource's `status` are `learnedSyscalls`,
`learnedFiles`, `learnedNetworkDestinations`, `learnedExecutables` and
`learnedCapabilities`, plus the summary counts `syscallCount`, `fileCount`
and `networkCount`. See [`docs/api-reference.md`](api-reference.md) for the
full generated field reference.

### Agent Logs

Enforcement decisions are made and logged by the **agent** (the DaemonSet
that runs the eBPF data plane), not the operator:

```bash
kubectl logs -n pahlevan-system daemonset/pahlevan-agent -f

# Or, from anywhere kubectl works:
pahlevan logs --component agent --follow
```

Every in-kernel denial logs a line starting `DENIED in-kernel`, naming what
was refused, by whom, and its parent process.

## Watch it work

`pahlevan ui` is an interactive view of what the agents are reporting: a live
event stream, per-workload counts of what was observed and what was refused,
and the ATT&CK coverage table. It is a reader - it never changes a policy, a
mode or a profile, so it cannot be the thing that turns enforcement off during
an incident.

It reads the agent's gRPC event stream:

```bash
pahlevan ui --grpc localhost:9090
```

That address has to be reachable, which usually means a port-forward to one
agent pod. **The stream is off unless the agent was started with
`--grpc-bind-address`**, and because the CLI dials in plaintext, an agent
serving the stream over TLS cannot be read by `pahlevan ui` directly. The
chart does not enable the stream by default; see
[`deployment.md`](deployment.md#the-grpc-event-stream).

### Without a cluster

`--replay` reads a JSON-lines event file instead of connecting, which is the
same format the agent's file sink writes and `pahlevan events` prints. That
makes a UI problem reproducible from a bug report, and lets you look at a
capture from a cluster you cannot reach:

```bash
# From a captured file
pahlevan ui --replay events.jsonl

# Or from a pipe. `pahlevan events` reads the agent's JSON-lines log, which
# lives on the node at /var/log/pahlevan/events.json unless --file says
# otherwise, so this runs where the log is or against a copy of it.
pahlevan events --file events.jsonl --denials-only | pahlevan ui --replay -
```

`--capacity` bounds how many events the event view retains (4096 by default).
The view keeps the most recent ones and drops the oldest, so a long-running
session has a fixed memory cost rather than a growing one.

### Keys

| Key | Does |
|---|---|
| `1` `2` `3` | Events, workloads, coverage |
| `tab` / `shift-tab`, or `h` / `l` | Previous / next view |
| `j` `k`, arrows, `pgup` `pgdn`, `g` `G` | Move, page, jump to top or bottom |
| `enter` | On the workloads view, open the selected workload's detail |
| `/` | Filter; `esc` clears it |
| `space` | Pause and resume the stream |
| `c` | Clear the retained events |
| `?` | Help |
| `q`, `ctrl+c` | Quit |

### In a pipeline

The interactive view never draws into something that is not a terminal. When
stdout is a pipe or a file, when `CI`, `NO_COLOR` or `TERM=dumb` is set, or
when you pass `--no-tui`, the command prints a plain summary instead and exits:

```bash
pahlevan ui --replay events.jsonl | tee report.txt
```

```text
source	events.jsonl
events	3
denied	2
workloads	2

WORKLOAD                                        FILE     NET   EXEC    CAP  SYSCALL   DENIED
default/Deployment/web                             1       1      0      0        0        1
payments/Deployment/api                            0       0      1      0        0        1
```

That block is a different, useful thing rather than a degraded drawing of the
screen: it is stable and greppable, which is what a pipeline wants. Escape
codes written into a log file are worse than no interface at all, so a job that
runs `pahlevan ui` is safe whether or not anyone remembered it was interactive.

## Transition to Enforcement

Once you are satisfied with the learned baseline, switch the policy to
`Blocking`:

```bash
# Update the policy to enforcing mode
kubectl patch pahlevanpolicy nginx-monitor --type='merge' -p='{
  "spec": {
    "enforcementConfig": {
      "mode": "Blocking",
      "blockUnknown": true
    }
  }
}'

# Watch for denials
pahlevan logs --component agent --follow | grep "DENIED"
```

## Testing Enforcement

```bash
# Try something outside the learned baseline
kubectl exec deployment/nginx -- ls /etc/passwd

# Watch for the denial
pahlevan logs --component agent --follow | grep DENIED

# Confirm it counted in the metrics
pahlevan metrics --component agent --filter pahlevan_enforcement_actions_total
```

## Cleanup

```bash
# Remove the test policy and deployment
kubectl delete pahlevanpolicy nginx-monitor
kubectl delete deployment nginx
kubectl delete service nginx

# Uninstall Pahlevan (if needed)
kubectl delete -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Or with Helm
helm uninstall pahlevan -n pahlevan-system
```

## Apply the generated seccomp profile

Learning produces a seccomp profile per container as well as the kernel
allow-sets. That profile is a second, independent layer, and applying it is a
change to the workload rather than something Pahlevan can do for you: a pod's
`seccompProfile` cannot be changed after admission, so it takes effect on the
next rollout.

```bash
pahlevan profile list -n default
pahlevan profile patch <container-profile> -n default
```

`profile patch` prints the `securityContext` patch and applies nothing, which
is deliberate - it is yours to review. Two things to check before you do apply
it. The profile file lives on the node that wrote it, so every node that can
schedule the workload needs a copy. And the profile permits only what the
container was observed doing during its learning window, so a code path that
did not run in that window will be denied.

## What Pahlevan can and cannot see

`pahlevan coverage` prints the eBPF detectors, the kernel hook each attaches
to, whether that hook needs the BPF LSM, and the MITRE ATT&CK techniques the
detector's observations are useful evidence for. It reads nothing but the
binary's own compiled-in table, so it works before you have a cluster:

```bash
pahlevan coverage
pahlevan coverage -o json    # the full per-detector detail
```

A listed technique means the detector gives an analyst evidence for it, not
that the technique is blocked. The same table is the third view in
`pahlevan ui`.

## Next Steps

Now that you have Pahlevan running:

1. **[Configure Production Policies](policy-reference.md)** - Learn advanced policy configuration
2. **[Architecture Overview](architecture.md)** - Understand system components and design
3. **[Deployment Patterns](deployment.md)** - Production deployment best practices
4. **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

## Common First-Time Issues

### eBPF Programs Not Loading

The programs load in the **agent**, not the operator - it is the agent that
runs privileged with the eBPF capabilities.

```bash
pahlevan logs --component agent | grep -i "lsm\|unable to load"

# Common causes:
# 1. The kernel is not booted with lsm=bpf, so the four LSM-hooked programs
#    cannot attach. The syscall, cred and shell programs work without it;
#    see lsm-support.md.
# 2. The kernel is below a program's floor: 5.10 for the file monitor, 5.11
#    for exec and cred, 5.15 for ad-hoc kernel probes. Each logs which
#    helper it could not use; see system-requirements.md.
# 3. The agent pod is missing CAP_BPF/CAP_PERFMON (both 5.8) or the
#    CAP_SYS_ADMIN that covers runtimes where the pair is not enough -
#    check its securityContext against
#    charts/pahlevan-operator/values.yaml.
```

### No Learning Data

```bash
# Ensure pods have the correct labels
kubectl get pods --show-labels | grep nginx

# Verify policy selector matches
kubectl get pahlevanpolicy nginx-monitor -o yaml | grep -A5 selector

# Confirm a ContainerProfile was created for the container
pahlevan profile list -n default
```

### High Resource Usage

```bash
# Check current resource usage
kubectl top pods -n pahlevan-system
```

The agent's DaemonSet requests/limits are a Helm value
(`agent.resources` in
[`charts/pahlevan-operator/values.yaml`](../charts/pahlevan-operator/values.yaml)),
set at install or upgrade time - not something patched into a ConfigMap
afterward.

Need help? Check our [troubleshooting guide](troubleshooting.md) or [open an issue](https://github.com/obsernetics/pahlevan/issues).
