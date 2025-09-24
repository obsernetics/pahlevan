# Quick Start Guide

This guide will get Pahlevan running in your Kubernetes cluster in under 5 minutes.

## Prerequisites

Before starting, ensure your cluster meets the [system requirements](system-requirements.md):

- Kubernetes 1.24+
- Linux kernel 4.18+ with eBPF support
- At least 256MB memory and 100m CPU available

### Verify System Compatibility

```bash
# Check if your cluster supports eBPF
kubectl run pahlevan-check --rm -i --tty \
  --image=obsernetics/pahlevan:latest \
  --command -- /pahlevan debug system-capabilities

# Expected output should show:
# eBPF Support: true
# Tracepoint Support: true
# TC Support: true
```

## Installation

### Method 1: One-Line Install (Recommended)

```bash
# Install everything with one command
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Verify installation
kubectl get pods -n pahlevan-system
```

This installs:
- Pahlevan operator with RBAC
- Custom Resource Definitions (CRDs)
- Default configuration
- Service monitors for Prometheus

### Method 2: Helm Chart

```bash
# Add the Helm repository
helm repo add pahlevan https://obsernetics.github.io/pahlevan-charts
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
  learning:
    enabled: true
    duration: 5m
    autoTransition: false  # Manual transition for learning
  enforcement:
    mode: "monitor"        # Start with monitoring only
    blockUnknown: false
  observability:
    metrics:
      enabled: true
    alerts:
      enabled: true
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

# View learned behaviors
kubectl get pahlevanpolicy nginx-monitor -o yaml
```

After 5 minutes, you should see the policy status change to `LearningComplete`.

## Understanding the Output

### Policy Status

```yaml
status:
  phase: "Learning"  # or "Enforcing", "Failed"
  conditions:
  - type: "LearningComplete"
    status: "True"
    reason: "MinimumSamplesReached"
  - type: "Ready"
    status: "True"
  learnedProfile:
    syscalls:
      allowed: [1, 2, 3, 4, 5, 6, 39, 41, 42, 45, 48, 49, 257, 262]
    network:
      allowedEgressPorts: [80, 443]
      allowedIngressPorts: [80]
    files:
      allowedPaths:
      - "/usr/share/nginx/html/*"
      - "/var/cache/nginx/*"
      deniedPaths:
      - "/etc/passwd"
      - "/proc/*/mem"
```

### Operator Logs

```bash
# View operator logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator -f

# Look for these events:
# - "Learning started for container"
# - "Syscall profile updated"
# - "Policy generated successfully"
# - "Enforcement enabled"
```

## Transition to Enforcement

Once learning is complete, you can enable enforcement:

```bash
# Update the policy to enforce mode
kubectl patch pahlevanpolicy nginx-monitor --type='merge' -p='{
  "spec": {
    "enforcement": {
      "mode": "enforce",
      "blockUnknown": true
    }
  }
}'

# Monitor enforcement actions
kubectl logs -n pahlevan-system deployment/pahlevan-operator -f | grep "BLOCKED"
```

## Testing Enforcement

```bash
# Try to execute a potentially blocked action
kubectl exec deployment/nginx -- ls /etc/passwd

# Monitor for enforcement actions
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "policy violation"

# Check metrics for blocked events
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- curl localhost:8080/metrics | grep pahlevan_blocked_events
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

```bash
# Check system capabilities
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "capability"

# Common solutions:
# 1. Ensure kernel version >= 4.18
# 2. Check if eBPF is enabled in kernel config
# 3. Verify the operator has sufficient privileges
```

### No Learning Data

```bash
# Ensure pods have the correct labels
kubectl get pods --show-labels | grep nginx

# Verify policy selector matches
kubectl get pahlevanpolicy nginx-monitor -o yaml | grep -A5 selector

# Check if containers are being monitored
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "container attached"
```

### High Resource Usage

```bash
# Check current resource usage
kubectl top pods -n pahlevan-system

# Tune ring buffer size if needed
kubectl patch configmap pahlevan-config -n pahlevan-system -p='{
  "data": {
    "ring-buffer-size": "16384"
  }
}'
```

Need help? Check our [troubleshooting guide](troubleshooting.md) or [open an issue](https://github.com/obsernetics/pahlevan/issues).
