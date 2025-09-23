# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with Pahlevan.

## Quick Diagnostics

### System Check

```bash
# Check if Pahlevan is running
kubectl get pods -n pahlevan-system

# Verify system capabilities
kubectl run pahlevan-check --rm -i --tty \
  --image=obsernetics/pahlevan:latest \
  --command -- /pahlevan debug system-capabilities

# Check recent logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator --tail=50
```

### Health Check

```bash
# Check operator health
kubectl get deployment pahlevan-operator -n pahlevan-system

# Verify CRDs are installed
kubectl get crd | grep pahlevan

# Check policies status
kubectl get pahlevanpolicy --all-namespaces
```

## Common Issues

### 1. eBPF Programs Not Loading

#### Symptoms
```
Error: failed to load eBPF program: operation not permitted
Error: eBPF program verification failed
Error: unknown syscall number
```

#### Diagnosis
```bash
# Check kernel version
uname -r

# Verify eBPF support
ls /sys/fs/bpf/

# Check for required kernel features
grep CONFIG_BPF /boot/config-$(uname -r)
grep CONFIG_BPF_SYSCALL /boot/config-$(uname -r)
```

#### Solutions

**Insufficient Privileges:**
```yaml
# Ensure operator has required capabilities
securityContext:
  capabilities:
    add:
    - CAP_BPF
    - CAP_SYS_ADMIN
    - CAP_NET_ADMIN
```

**Kernel Too Old:**
```bash
# Check minimum kernel version (4.18+)
uname -r

# Upgrade kernel if needed (Ubuntu example)
sudo apt update
sudo apt install linux-generic-hwe-20.04
```

**Missing Kernel Features:**
```bash
# Enable eBPF in kernel config (requires recompilation)
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_EVENTS=y
```

### 2. High CPU Usage

#### Symptoms
```
Pod CPU usage > 80%
High system load
Slow policy evaluation
```

#### Diagnosis
```bash
# Check resource usage
kubectl top pod -n pahlevan-system

# Profile CPU usage
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug cpu-profile --duration=30s

# Check event rates
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "events/sec" | tail -10
```

#### Solutions

**Reduce Event Volume:**
```yaml
# Adjust ring buffer size
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
data:
  config.yaml: |
    ebpf:
      ringBufferSize: 16384  # Reduce from default 32768
      eventBatchSize: 50     # Process in smaller batches
```

**Optimize Sampling:**
```yaml
# Reduce sampling rate during learning
spec:
  learning:
    syscalls:
      sampleRate: 0.5  # Sample 50% instead of 100%
    network:
      sampleRate: 0.3  # Sample 30%
```

**Increase Resources:**
```yaml
resources:
  limits:
    cpu: "1000m"      # Increase from 500m
    memory: "1Gi"     # Increase memory too
```

### 3. High Memory Usage

#### Symptoms
```
OOMKilled pods
Memory usage growing over time
Slow garbage collection
```

#### Diagnosis
```bash
# Check memory usage
kubectl top pod -n pahlevan-system

# Memory profile
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug memory-profile

# Check for memory leaks
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug gc-stats
```

#### Solutions

**Tune Go Memory:**
```yaml
env:
- name: GOMEMLIMIT
  value: "450MiB"     # Set Go memory limit
- name: GOGC
  value: "50"         # More frequent GC
```

**Optimize Maps:**
```yaml
# Reduce eBPF map sizes
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
data:
  config.yaml: |
    ebpf:
      maxEntriesPerMap: 5000  # Reduce from 10000
      mapCleanupInterval: 60s  # Clean up more frequently
```

**Increase Memory Limits:**
```yaml
resources:
  limits:
    memory: "1Gi"     # Increase from 512Mi
```

### 4. Policies Not Learning

#### Symptoms
```
Policy stuck in "Learning" phase
No learned profile generated
Learning timeout exceeded
```

#### Diagnosis
```bash
# Check policy status
kubectl describe pahlevanpolicy <policy-name>

# Verify target pods exist
kubectl get pods -l <selector-from-policy> --show-labels

# Check learning progress
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "learning" | grep <container-id>
```

#### Solutions

**No Target Pods:**
```bash
# Verify labels match
kubectl get pahlevanpolicy <policy> -o yaml | grep -A5 selector
kubectl get pods --show-labels | grep <expected-label>

# Fix label mismatch
kubectl label pods <pod-name> <missing-label>=<value>
```

**Insufficient Events:**
```yaml
# Reduce minimum samples
spec:
  learning:
    minSamples: 10      # Reduce from default 50
    duration: "10m"     # Increase learning time
```

**Container Startup Issues:**
```bash
# Check if containers are actually running
kubectl get pods -l <selector> -o wide

# Check for crashlooping pods
kubectl describe pod <pod-name>
```

### 5. Enforcement Not Working

#### Symptoms
```
Violations not blocked
Policy in "Enforcing" but allowing everything
No enforcement actions logged
```

#### Diagnosis
```bash
# Check policy mode
kubectl get pahlevanpolicy <policy> -o yaml | grep mode

# Verify enforcement actions
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "BLOCKED\|DENIED"

# Test with known violation
kubectl exec <pod> -- strace -c ls /etc/passwd
```

#### Solutions

**Wrong Enforcement Mode:**
```yaml
# Ensure enforcement is enabled
spec:
  enforcement:
    mode: "enforce"      # Not "monitor"
    blockUnknown: true   # Block unknown behavior
```

**Policy Not Applied:**
```bash
# Check if policy is active
kubectl get pahlevanpolicy <policy> -o yaml | grep phase

# Force policy reload
kubectl annotate pahlevanpolicy <policy> reload="$(date)"
```

**eBPF Programs Not Attached:**
```bash
# Check program attachment
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "attached\|program"
```

### 6. Self-Healing Not Working

#### Symptoms
```
High violation rates not triggering rollback
Policy failures not auto-recovering
Emergency mode not activating
```

#### Diagnosis
```bash
# Check self-healing configuration
kubectl get pahlevanpolicy <policy> -o yaml | grep -A10 selfHealing

# Check violation metrics
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "violation.*rate"

# Check rollback history
kubectl get pahlevanpolicy <policy> -o yaml | grep -A5 rollback
```

#### Solutions

**Self-Healing Disabled:**
```yaml
# Enable self-healing
spec:
  selfHealing:
    enabled: true
    rollbackThreshold: 5   # Rollback after 5 violations
    rollbackWindow: "5m"   # Within 5 minutes
```

**Thresholds Too High:**
```yaml
# Lower thresholds for faster response
spec:
  selfHealing:
    rollbackThreshold: 2   # More sensitive
    emergencyThreshold: 5  # Emergency mode sooner
```

### 7. Network Policies Not Working

#### Symptoms
```
Network connections not blocked
TC programs not loading
Port restrictions ignored
```

#### Diagnosis
```bash
# Check TC support
which tc
tc qdisc show

# Verify network programs
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "network\|tc"

# Test network connectivity
kubectl exec <pod> -- nc -zv <blocked-host> <blocked-port>
```

#### Solutions

**Missing TC Support:**
```bash
# Install iproute2
apt-get update && apt-get install -y iproute2

# Or on the node
sudo apt install iproute2
```

**Insufficient Privileges:**
```yaml
# Ensure NET_ADMIN capability
securityContext:
  capabilities:
    add:
    - CAP_NET_ADMIN
```

**CNI Conflicts:**
```bash
# Check for CNI conflicts
kubectl get pods -n kube-system | grep -E "calico|cilium|flannel"

# Some CNIs may interfere with TC programs
# Consult CNI documentation for compatibility
```

### 8. File Policies Not Working

#### Symptoms
```
File access not restricted
Tracepoint hooks not working
Path restrictions ignored
```

#### Diagnosis
```bash
# Check tracepoint support
cat /sys/kernel/debug/tracing/available_events | grep syscalls

# Verify file programs
kubectl logs -n pahlevan-system deployment/pahlevan-operator | \
  grep "file\|tracepoint"

# Test file access
kubectl exec <pod> -- cat /etc/passwd
```

#### Solutions

**Current Implementation Note:**
> The current implementation uses tracepoint-based file monitoring, not LSM hooks.

**Tracepoint Issues:**
```bash
# Check if tracepoints are available
cat /sys/kernel/debug/tracing/available_events | grep -E "syscalls|fs"

# Verify file monitoring is working
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "file.*event"
```

**Missing Kernel Features:**
```bash
# Ensure tracepoint support is enabled
grep CONFIG_TRACEPOINTS /boot/config-$(uname -r)
grep CONFIG_FTRACE /boot/config-$(uname -r)
```

## Performance Troubleshooting

### Slow Policy Evaluation

#### Symptoms
```
High latency in container operations
Timeout errors during enforcement
Slow learning phase
```

#### Solutions
```yaml
# Optimize evaluation timeout
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
data:
  config.yaml: |
    enforcement:
      evaluationTimeout: 50ms  # Reduce from 100ms
      cacheSize: 10000        # Increase cache size

    learning:
      analysisInterval: 60s    # Analyze less frequently
```

### High Event Volume

#### Symptoms
```
Ring buffer overruns
Dropped events
High CPU usage
```

#### Solutions
```yaml
# Increase buffer sizes
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
data:
  config.yaml: |
    ebpf:
      ringBufferSize: 65536   # Double the size
      eventBatchSize: 200     # Process larger batches

    # Or reduce sampling
    learning:
      syscalls:
        sampleRate: 0.5       # Sample 50% of events
```

## Monitoring and Alerting Issues

### Missing Metrics

#### Symptoms
```
Prometheus not scraping metrics
Grafana dashboards empty
No violation alerts
```

#### Solutions
```bash
# Check metrics endpoint
kubectl port-forward -n pahlevan-system deployment/pahlevan-operator 8080:8080
curl localhost:8080/metrics

# Verify Prometheus config
kubectl get configmap prometheus-config -o yaml

# Check service discovery
kubectl get servicemonitor pahlevan-operator
```

### Alert Fatigue

#### Symptoms
```
Too many alerts
False positive violations
Alert storms during deployment
```

#### Solutions
```yaml
# Tune alert thresholds
spec:
  observability:
    alerts:
      rules:
      - name: "High Violation Rate"
        condition: "violation_rate > 20"  # Increase threshold
        window: "10m"                     # Longer window
```

## Recovery Procedures

### Complete Recovery

```bash
#!/bin/bash
# emergency-recovery.sh

echo "Starting emergency recovery procedure"

# 1. Stop all enforcement
kubectl patch pahlevanpolicy --all --type='merge' -p='{
  "spec": {
    "enforcement": {
      "mode": "disabled"
    }
  }
}'

# 2. Restart operator
kubectl rollout restart deployment/pahlevan-operator -n pahlevan-system

# 3. Wait for operator to be ready
kubectl rollout status deployment/pahlevan-operator -n pahlevan-system

# 4. Clear eBPF programs
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug clear-programs

# 5. Gradually re-enable policies
for policy in $(kubectl get pahlevanpolicy -o name); do
  echo "Re-enabling $policy"
  kubectl patch $policy --type='merge' -p='{
    "spec": {
      "enforcement": {
        "mode": "monitor"
      }
    }
  }'
  sleep 30
done

echo "Recovery completed"
```

### Rollback Policy

```bash
#!/bin/bash
# rollback-policy.sh

POLICY_NAME="$1"
NAMESPACE="${2:-default}"

if [ -z "$POLICY_NAME" ]; then
  echo "Usage: $0 <policy-name> [namespace]"
  exit 1
fi

# Get current policy
kubectl get pahlevanpolicy "$POLICY_NAME" -n "$NAMESPACE" -o yaml > "/tmp/$POLICY_NAME-backup.yaml"

# Reset to learning mode
kubectl patch pahlevanpolicy "$POLICY_NAME" -n "$NAMESPACE" --type='merge' -p='{
  "spec": {
    "learning": {
      "enabled": true,
      "duration": "10m",
      "autoTransition": false
    },
    "enforcement": {
      "mode": "monitor",
      "blockUnknown": false
    }
  }
}'

echo "Policy $POLICY_NAME rolled back to learning mode"
echo "Backup saved to /tmp/$POLICY_NAME-backup.yaml"
```

## Getting Help

### Collect Debug Information

```bash
#!/bin/bash
# collect-debug-info.sh

DEBUG_DIR="/tmp/pahlevan-debug-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DEBUG_DIR"

# Operator logs
kubectl logs -n pahlevan-system deployment/pahlevan-operator --tail=1000 > "$DEBUG_DIR/operator.log"

# System information
kubectl get nodes -o wide > "$DEBUG_DIR/nodes.txt"
kubectl version > "$DEBUG_DIR/version.txt"

# Pahlevan resources
kubectl get pahlevanpolicy --all-namespaces -o yaml > "$DEBUG_DIR/policies.yaml"
kubectl get pods -n pahlevan-system -o yaml > "$DEBUG_DIR/pods.yaml"
kubectl get configmap -n pahlevan-system -o yaml > "$DEBUG_DIR/configmaps.yaml"

# System capabilities
kubectl run pahlevan-check --rm -i --tty \
  --image=obsernetics/pahlevan:latest \
  --command -- /pahlevan debug system-capabilities > "$DEBUG_DIR/capabilities.txt" 2>&1

echo "Debug information collected in $DEBUG_DIR"
echo "Please attach this directory when creating a support ticket"
```

### Support Resources

- **GitHub Issues**: [https://github.com/obsernetics/pahlevan/issues](https://github.com/obsernetics/pahlevan/issues)
- **Discussions**: [https://github.com/obsernetics/pahlevan/discussions](https://github.com/obsernetics/pahlevan/discussions)
- **Documentation**: [https://docs.pahlevan.io](https://docs.pahlevan.io)
- **Slack Community**: [#pahlevan](https://kubernetes.slack.com/channels/pahlevan)

### Before Opening an Issue

1. Check this troubleshooting guide
2. Search existing issues
3. Collect debug information using the script above
4. Include your environment details:
   - Kubernetes version
   - Linux kernel version
   - Pahlevan version
   - CNI plugin used
   - Node specifications

### Issue Template

```markdown
**Environment:**
- Kubernetes version:
- Kernel version:
- Pahlevan version:
- CNI:
- Node OS:

**Problem Description:**
[Describe the issue]

**Steps to Reproduce:**
1.
2.
3.

**Expected Behavior:**
[What you expected to happen]

**Actual Behavior:**
[What actually happened]

**Logs:**
[Attach relevant logs]

**Additional Context:**
[Any other relevant information]
```

This troubleshooting guide should help you resolve most common issues with Pahlevan. If you encounter problems not covered here, please refer to the support resources above.
