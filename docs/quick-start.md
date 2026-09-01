# Quick Start Guide

This guide will get Pahlevan running in your Kubernetes cluster in under 5 minutes.

## Prerequisites

Before starting, ensure your cluster meets the [system requirements](system-requirements.md):

- Kubernetes 1.24+
- Linux kernel 4.18+ with eBPF support
- At least 256MB memory and 100m CPU available

### Verify System Compatibility

Pahlevan's own compatibility check (`pahlevan debug`) inspects the
already-running agent and node state, so it only has something to report
after install. Before installing, check the two things that actually gate
whether the agent can load: the kernel version, and whether the nodes are
Linux.

```bash
kubectl get nodes -o custom-columns=NAME:.metadata.name,KERNEL:.status.nodeInfo.kernelVersion,OS:.status.nodeInfo.operatingSystem
```

See [system requirements](system-requirements.md) for what each Pahlevan
capability needs from the kernel.

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
# 1. Kernel older than what the four LSM-hooked programs need (lsm=bpf on
#    the kernel command line). The syscall, cred and shell programs work
#    without it; see lsm-support.md.
# 2. The agent pod is missing CAP_BPF/CAP_PERFMON (or CAP_SYS_ADMIN on an
#    older kernel) - check its securityContext against
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
