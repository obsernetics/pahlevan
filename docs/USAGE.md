# Pahlevan Usage Guide

This guide provides comprehensive instructions for using the Pahlevan eBPF-based Kubernetes Security Operator.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Basic Configuration](#basic-configuration)
- [Policy Examples](#policy-examples)
- [CLI Usage](#cli-usage)
- [Monitoring & Observability](#monitoring--observability)
- [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Install Pahlevan

```bash
# Quick install with kubectl
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Verify installation
kubectl get pods -n pahlevan-system
```

### 2. Create Your First Policy

```bash
# Create a basic monitoring policy
cat << EOF | kubectl apply -f -
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: nginx-security
  namespace: default
spec:
  selector:
    matchLabels:
      app: nginx
  learning:
    enabled: true
    duration: 5m
  enforcement:
    mode: "monitor"
EOF
```

### 3. Deploy a Test Application

```bash
# Deploy nginx with the targeted label
kubectl create deployment nginx --image=nginx:latest
kubectl label deployment nginx app=nginx
```

### 4. Monitor Learning Progress

```bash
# Check policy status
kubectl get pahlevanpolicy nginx-security -o yaml

# View logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator
```

## Installation Methods

### Method 1: Quick Install (Recommended)

Best for: Development, testing, quick evaluation

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml
```

### Method 2: Helm Chart

Best for: Production deployments with customization

```bash
# Add repository
helm repo add pahlevan https://obsernetics.github.io/pahlevan-charts
helm repo update

# Install with custom values
helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace \
  --values - << EOF
image:
  tag: "v1.0.0"
resources:
  limits:
    memory: 512Mi
    cpu: 500m
  requests:
    memory: 256Mi
    cpu: 100m
observability:
  prometheus:
    enabled: true
  datadog:
    enabled: false
EOF
```

### Method 3: Manual Installation

Best for: Air-gapped environments, custom builds

```bash
# Clone and build
git clone https://github.com/obsernetics/pahlevan.git
cd pahlevan

# Build eBPF programs
make ebpf-build

# Build and deploy
make build deploy IMG=my-registry/pahlevan:latest
```

### Method 4: Development Setup

Best for: Contributing, development

```bash
# Clone repository
git clone https://github.com/obsernetics/pahlevan.git
cd pahlevan

# Create development cluster
make dev-cluster

# Build and deploy
make dev-deploy

# View logs
make dev-logs
```

## Basic Configuration

### System Requirements Verification

```bash
# Check system capabilities
kubectl run pahlevan-check --rm -i --tty \
  --image=pahlevan/operator:latest \
  --command -- /pahlevan debug system-capabilities

# Expected output:
# ✅ eBPF Support: true
# ✅ TC Support: true
# ✅ Tracepoint Support: true
# ⚠️  KProbe Support: false (some features will be limited)
```

### Global Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
  namespace: pahlevan-system
data:
  config.yaml: |
    global:
      defaultMode: "monitor"
      learningWindow: "5m"
      enforcementDelay: "30s"

    observability:
      metrics:
        enabled: true
        interval: "30s"
      alerts:
        enabled: true
        slack:
          webhookURL: "https://hooks.slack.com/your/webhook"

    selfHealing:
      enabled: true
      rollbackThreshold: 5
      recoveryStrategy: "Rollback"
```

## Policy Examples

### 1. Basic Monitoring Policy

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: basic-monitoring
  namespace: default
spec:
  selector:
    matchLabels:
      app: web-app

  learning:
    enabled: true
    duration: 5m
    autoTransition: true

  enforcement:
    mode: "monitor"
    blockUnknown: false

  observability:
    metrics:
      enabled: true
    alerts:
      enabled: true
```

### 2. Production Enforcement Policy

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: production-enforcement
  namespace: production
spec:
  selector:
    matchLabels:
      tier: production

  learning:
    enabled: true
    duration: 2m
    minSamples: 100

  enforcement:
    mode: "enforce"
    blockUnknown: true
    gracePeriod: 10s

    syscalls:
      defaultAction: "deny"
      allowedSyscalls:
        - "read"
        - "write"
        - "open"
        - "close"
        - "socket"
        - "connect"
      deniedSyscalls:
        - "ptrace"
        - "process_vm_readv"

    network:
      defaultAction: "deny"
      allowedEgressPorts: [80, 443, 5432]
      allowedIngressPorts: [8080]

    files:
      defaultAction: "deny"
      allowedPaths:
        - "/app/*"
        - "/usr/lib/*"
        - "/tmp/*"
      protectedPaths:
        - "/etc/passwd"
        - "/etc/shadow"

  selfHealing:
    enabled: true
    rollbackThreshold: 3
    recoveryStrategy: "Rollback"
```

### 3. Development-Friendly Policy

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: development-policy
  namespace: dev
spec:
  selector:
    matchLabels:
      environment: development

  learning:
    enabled: true
    duration: 10m
    autoTransition: false  # Manual transition

  enforcement:
    mode: "monitor"
    alertOnly: true

    exceptions:
    - type: "Syscall"
      patterns: ["ptrace", "process_vm_readv"]
      reason: "Debugging tools"
      temporary: true
      expiresAt: "2025-12-31T23:59:59Z"

  observability:
    metrics:
      enabled: true
    alerts:
      enabled: false  # Quiet for development
```

## CLI Usage

### Installation

```bash
# Download latest CLI
curl -L https://github.com/obsernetics/pahlevan/releases/latest/download/pahlevan-cli -o pahlevan
chmod +x pahlevan
sudo mv pahlevan /usr/local/bin/
```

### Basic Commands

```bash
# Check version
pahlevan version

# List policies
pahlevan policy list

# Get policy details
pahlevan policy get my-policy

# Create policy from file
pahlevan policy create -f my-policy.yaml

# Update policy
pahlevan policy update my-policy --mode=enforce

# Delete policy
pahlevan policy delete my-policy
```

### Monitoring Commands

```bash
# Check attack surface
pahlevan attack-surface analyze

# View real-time events
pahlevan logs --follow

# Get policy violations
pahlevan policy violations my-policy

# System status
pahlevan status

# Debug system capabilities
pahlevan debug system-capabilities
```

### Advanced Usage

```bash
# Export policy from learned profile
pahlevan policy export my-app > learned-policy.yaml

# Simulate policy changes
pahlevan policy simulate --policy=my-policy.yaml --events=test-events.json

# Bulk operations
pahlevan policy apply -f policies/

# Performance analysis
pahlevan metrics --component=ebpf --duration=1h
```

## Monitoring & Observability

### Prometheus Metrics

Key metrics to monitor:

```promql
# Policy violations rate
rate(pahlevan_policy_violations_total[5m])

# Enforcement actions
rate(pahlevan_enforcement_actions_total[5m])

# Learning progress
pahlevan_learning_progress_ratio

# System performance
rate(pahlevan_syscall_events_total[5m])
```

### Grafana Dashboard

Import the provided dashboard:

```bash
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/grafana-dashboard.json
```

### Alerting Rules

```yaml
groups:
- name: pahlevan-alerts
  rules:
  - alert: PahlevanHighViolationRate
    expr: rate(pahlevan_policy_violations_total[5m]) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High policy violation rate detected"
      description: "Policy {{ $labels.policy }} has {{ $value }} violations/min"

  - alert: PahlevanEnforcementFailure
    expr: increase(pahlevan_enforcement_failures_total[5m]) > 0
    labels:
      severity: critical
    annotations:
      summary: "Enforcement engine failure"
```

### Log Analysis

```bash
# Follow operator logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator -f

# Filter for specific policy
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "policy=my-policy"

# View violation events
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "violation"
```

## Troubleshooting

### Common Issues

#### 1. eBPF Programs Not Loading

```bash
# Check system capabilities
pahlevan debug system-capabilities

# Check kernel messages
dmesg | grep bpf

# Verify permissions
id  # Should show root or have CAP_BPF capability
```

**Solution:**
- Ensure kernel 4.18+ with eBPF support
- Run with sufficient privileges
- Install required packages: `clang`, `llvm`, `libbpf-dev`

#### 2. High CPU Usage

```bash
# Check event rates
pahlevan metrics --component=ebpf

# Monitor specific container
pahlevan logs --container=high-cpu-container
```

**Solution:**
- Tune ring buffer sizes
- Reduce monitoring scope
- Optimize policy rules

#### 3. Policy Not Enforcing

```bash
# Check policy status
kubectl describe pahlevanpolicy my-policy

# Verify target pods
kubectl get pods -l app=my-app --show-labels

# Check operator logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator --tail=100
```

**Solution:**
- Verify label selectors match target pods
- Check policy validation errors
- Ensure learning phase completed

#### 4. Network Policy Issues

```bash
# Test network connectivity
kubectl run test-pod --rm -i --tty --image=curlimages/curl -- curl -v my-service

# Check TC support
pahlevan debug system-capabilities | grep TC
```

**Solution:**
- Install `iproute2` package
- Ensure root privileges for TC operations
- Verify network policy syntax

### Debug Commands

```bash
# System information
pahlevan debug system-info

# eBPF program status
pahlevan debug ebpf-status

# Policy validation
pahlevan policy validate my-policy.yaml

# Performance profiling
pahlevan debug profile --duration=30s

# Export debug information
pahlevan debug export --output=debug-info.tar.gz
```

### Getting Help

1. **Documentation**: [https://obsernetics.github.io/pahlevan/docs.html](https://obsernetics.github.io/pahlevan/docs.html)
2. **GitHub Issues**: [https://github.com/obsernetics/pahlevan/issues](https://github.com/obsernetics/pahlevan/issues)
3. **Discussions**: [https://github.com/obsernetics/pahlevan/discussions](https://github.com/obsernetics/pahlevan/discussions)
4. **Slack**: [#pahlevan](https://kubernetes.slack.com/channels/pahlevan)

### Support Information

When reporting issues, include:

```bash
# System information
pahlevan debug system-info > system-info.txt

# Recent logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator --tail=500 > operator-logs.txt

# Policy configuration
kubectl get pahlevanpolicy -o yaml > policies.yaml

# Kubernetes version
kubectl version > k8s-version.txt
```
