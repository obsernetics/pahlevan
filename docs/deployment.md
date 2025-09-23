# Deployment Guide

This guide covers production deployment patterns, best practices, and operational considerations for Pahlevan.

## Production Deployment

### Prerequisites

Before deploying Pahlevan in production, ensure your environment meets these requirements:

```bash
# Check Kubernetes version
kubectl version --short

# Verify eBPF support
kubectl run ebpf-check --rm -i --tty \
  --image=obsernetics/pahlevan:latest \
  --command -- /pahlevan debug system-capabilities

# Check node resources
kubectl describe nodes | grep -A5 "Allocated resources"
```

**Required:**
- Kubernetes 1.24+
- Linux kernel 5.8+ (4.18+ minimum)
- eBPF support enabled
- 512MB RAM per operator instance
- 500m CPU per operator instance

### High Availability Setup

> **Note**: Leader election is implemented in the operator, allowing multiple replicas for high availability.

Deploy Pahlevan with multiple replicas for high availability:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pahlevan-operator
  namespace: pahlevan-system
spec:
  replicas: 3  # HA setup
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: pahlevan-operator
  template:
    metadata:
      labels:
        app: pahlevan-operator
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values: ["pahlevan-operator"]
              topologyKey: kubernetes.io/hostname
      containers:
      - name: operator
        image: obsernetics/pahlevan:v1.0.0  # Pin specific version
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        env:
        - name: LEADER_ELECTION
          value: "true"
        - name: LEASE_DURATION
          value: "15s"
        - name: RENEW_DEADLINE
          value: "10s"
        - name: RETRY_PERIOD
          value: "2s"
```

### Security Configuration

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pahlevan-operator
  namespace: pahlevan-system
---
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: pahlevan-operator
  namespace: pahlevan-system
spec:
  selector:
    matchLabels:
      app: pahlevan-operator
  mtls:
    mode: STRICT
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pahlevan-operator
  namespace: pahlevan-system
spec:
  podSelector:
    matchLabels:
      app: pahlevan-operator
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080  # Metrics port
  egress:
  - to: []  # Allow all egress (for Kubernetes API)
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 6443
```

### Resource Management

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: pahlevan-system-quota
  namespace: pahlevan-system
spec:
  hard:
    requests.cpu: "2"
    requests.memory: "2Gi"
    limits.cpu: "4"
    limits.memory: "4Gi"
    pods: "10"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: pahlevan-system-limits
  namespace: pahlevan-system
spec:
  limits:
  - default:
      cpu: "1000m"
      memory: "1Gi"
    defaultRequest:
      cpu: "500m"
      memory: "512Mi"
    type: Container
```

## Deployment Patterns

### Pattern 1: Single Cluster

For single cluster deployments:

```yaml
# values.yaml for Helm deployment
global:
  image:
    tag: "v1.0.0"
    pullPolicy: IfNotPresent

operator:
  replicas: 1
  resources:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "1Gi"
      cpu: "1000m"

monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true

rbac:
  create: true

networkPolicy:
  enabled: true
```

```bash
helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace \
  --values values.yaml
```

### Pattern 2: Multi-Cluster with Centralized Monitoring

Deploy Pahlevan in each cluster with centralized monitoring:

```yaml
# Cluster 1, 2, N configuration
operator:
  replicas: 1

monitoring:
  enabled: true
  prometheus:
    enabled: true
    remoteWrite:
      url: "https://central-prometheus.company.com/api/v1/write"
      basicAuth:
        username: "pahlevan-cluster-1"
        password: "${PROMETHEUS_PASSWORD}"

  grafana:
    enabled: false  # Central Grafana only
```

### Pattern 3: GitOps with ArgoCD

```yaml
# argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: pahlevan
  namespace: argocd
spec:
  project: security
  source:
    repoURL: https://obsernetics.github.io/pahlevan-charts
    chart: pahlevan-operator
    targetRevision: 1.0.0
    helm:
      valueFiles:
      - values-production.yaml
  destination:
    server: https://kubernetes.default.svc
    namespace: pahlevan-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

### Pattern 4: Multi-Tenancy

For multi-tenant environments:

```yaml
# Tenant-specific namespace and policies
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-a
  labels:
    tenant: tenant-a
    security.policy/pahlevan: "enabled"
---
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: tenant-a-policy
  namespace: tenant-a
spec:
  selector:
    matchLabels:
      tenant: tenant-a
  learning:
    duration: "10m"
  enforcement:
    mode: "enforce"
    blockUnknown: true
  observability:
    metrics:
      enabled: true
      labels:
        tenant: tenant-a
```

## Configuration Management

### Environment-Specific Configuration

#### Development

```yaml
# dev-values.yaml
operator:
  replicas: 1
  image:
    tag: "latest"

defaultPolicy:
  learning:
    duration: "30m"
    autoTransition: false
  enforcement:
    mode: "monitor"

monitoring:
  alerts:
    enabled: false
```

#### Staging

```yaml
# staging-values.yaml
operator:
  replicas: 2
  image:
    tag: "v1.0.0-rc.1"

defaultPolicy:
  learning:
    duration: "10m"
    autoTransition: true
  enforcement:
    mode: "monitor"

monitoring:
  alerts:
    enabled: true
    severity: "warning"
```

#### Production

```yaml
# prod-values.yaml
operator:
  replicas: 3
  image:
    tag: "v1.0.0"
    pullPolicy: IfNotPresent

defaultPolicy:
  learning:
    duration: "5m"
    autoTransition: true
  enforcement:
    mode: "enforce"
    blockUnknown: true

monitoring:
  alerts:
    enabled: true
    severity: "critical"

security:
    networkPolicy:
      enabled: true
    podSecurityPolicy:
      enabled: true
```

### Secret Management

> **Note**: Webhook integrations are planned for future releases.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pahlevan-secrets
  namespace: pahlevan-system
type: Opaque
stringData:
  prometheus-password: "${PROMETHEUS_PASSWORD}"
  # Additional integrations planned:
  # datadog-api-key: "${DD_API_KEY}"
  # slack-webhook: "${SLACK_WEBHOOK_URL}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pahlevan-operator
spec:
  template:
    spec:
      containers:
      - name: operator
        env:
        - name: PROMETHEUS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: pahlevan-secrets
              key: prometheus-password
        - name: DD_API_KEY
          valueFrom:
            secretKeyRef:
              name: pahlevan-secrets
              key: datadog-api-key
```

## Monitoring and Observability

### Prometheus Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    rule_files:
    - "/etc/prometheus/rules/*.yml"

    scrape_configs:
    - job_name: 'pahlevan-operator'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['pahlevan-system']
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: pahlevan-operator
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
```

### Alert Rules

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-alerts
  namespace: monitoring
data:
  pahlevan.yml: |
    groups:
    - name: pahlevan
      rules:
      - alert: PahlevanOperatorDown
        expr: up{job="pahlevan-operator"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Pahlevan operator is down"
          description: "Pahlevan operator has been down for more than 5 minutes"

      - alert: HighViolationRate
        expr: rate(pahlevan_policy_violations_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High policy violation rate"
          description: "Policy violations are occurring at {{ $value }} per second"

      - alert: EBPFProgramLoadFailure
        expr: increase(pahlevan_ebpf_program_load_errors_total[10m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "eBPF program load failure"
          description: "Failed to load eBPF programs"
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Pahlevan Security Dashboard",
    "panels": [
      {
        "title": "Policy Violations",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(pahlevan_policy_violations_total[5m])",
            "legendFormat": "{{policy}} - {{container}}"
          }
        ]
      },
      {
        "title": "Enforcement Actions",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(pahlevan_enforcement_actions_total[5m])",
            "legendFormat": "{{action}} - {{policy}}"
          }
        ]
      },
      {
        "title": "Learning Progress",
        "type": "singlestat",
        "targets": [
          {
            "expr": "pahlevan_learning_progress_ratio",
            "legendFormat": "Learning Complete"
          }
        ]
      }
    ]
  }
}
```

## Backup and Recovery

### Policy Backup

```bash
#!/bin/bash
# backup-policies.sh

BACKUP_DIR="/backup/pahlevan/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup all PahlevanPolicy resources
kubectl get pahlevanpolicy --all-namespaces -o yaml > "$BACKUP_DIR/policies.yaml"

# Backup operator configuration
kubectl get configmap -n pahlevan-system -o yaml > "$BACKUP_DIR/configmaps.yaml"
kubectl get secret -n pahlevan-system -o yaml > "$BACKUP_DIR/secrets.yaml"

# Backup custom resource definitions
kubectl get crd pahlevanpolicies.policy.pahlevan.io -o yaml > "$BACKUP_DIR/crds.yaml"

echo "Backup completed in $BACKUP_DIR"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore-pahlevan.sh

BACKUP_DIR="$1"

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    exit 1
fi

# Restore CRDs first
kubectl apply -f "$BACKUP_DIR/crds.yaml"

# Wait for CRDs to be ready
kubectl wait --for condition=established --timeout=60s crd/pahlevanpolicies.policy.pahlevan.io

# Restore operator
helm install pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace

# Wait for operator to be ready
kubectl wait --for=condition=available --timeout=300s deployment/pahlevan-operator -n pahlevan-system

# Restore configuration
kubectl apply -f "$BACKUP_DIR/configmaps.yaml"
kubectl apply -f "$BACKUP_DIR/secrets.yaml"

# Restore policies
kubectl apply -f "$BACKUP_DIR/policies.yaml"

echo "Recovery completed"
```

## Upgrade Procedures

### Rolling Upgrade

```bash
#!/bin/bash
# upgrade-pahlevan.sh

NEW_VERSION="$1"

if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new-version>"
    exit 1
fi

echo "Starting upgrade to version $NEW_VERSION"

# Backup current state
./backup-policies.sh

# Update Helm repository
helm repo update

# Perform rolling upgrade
helm upgrade pahlevan pahlevan/pahlevan-operator \
  --namespace pahlevan-system \
  --set image.tag="$NEW_VERSION" \
  --wait \
  --timeout=600s

# Verify upgrade
kubectl rollout status deployment/pahlevan-operator -n pahlevan-system

# Run post-upgrade checks
kubectl run pahlevan-check --rm -i --tty \
  --image="obsernetics/pahlevan:$NEW_VERSION" \
  --command -- /pahlevan debug system-capabilities

echo "Upgrade to $NEW_VERSION completed successfully"
```

### Rollback Procedure

```bash
#!/bin/bash
# rollback-pahlevan.sh

echo "Rolling back Pahlevan deployment"

# Get rollout history
kubectl rollout history deployment/pahlevan-operator -n pahlevan-system

# Rollback to previous version
kubectl rollout undo deployment/pahlevan-operator -n pahlevan-system

# Wait for rollback to complete
kubectl rollout status deployment/pahlevan-operator -n pahlevan-system

# Verify rollback
kubectl get deployment pahlevan-operator -n pahlevan-system -o jsonpath='{.spec.template.spec.containers[0].image}'

echo "Rollback completed"
```

## Performance Tuning

### eBPF Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
  namespace: pahlevan-system
data:
  config.yaml: |
    ebpf:
      ringBufferSize: 32768      # Adjust based on event volume
      maxEntriesPerMap: 10000    # Adjust based on container count
      eventBatchSize: 100        # Batch events for efficiency

    learning:
      batchSize: 1000           # Events to batch for learning
      analysisInterval: 30s      # How often to analyze data

    enforcement:
      cacheSize: 5000           # Policy cache size
      evaluationTimeout: 100ms   # Max time for policy evaluation

    observability:
      metricsInterval: 30s      # Metrics collection interval
      maxTraceSpans: 10000      # OpenTelemetry span limit
```

### Node-Level Tuning

```bash
# Increase eBPF memory limits
echo 'net.core.bpf_jit_kallsyms = 1' >> /etc/sysctl.conf
echo 'net.core.bpf_jit_harden = 0' >> /etc/sysctl.conf
echo 'kernel.unprivileged_bpf_disabled = 0' >> /etc/sysctl.conf

# Apply changes
sysctl -p

# Increase file descriptor limits
echo 'fs.file-max = 1000000' >> /etc/sysctl.conf
```

### Resource Optimization

```yaml
# Resource-optimized deployment
spec:
  containers:
  - name: operator
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"
    env:
    - name: GOMEMLIMIT
      value: "450MiB"      # Go memory limit
    - name: GOMAXPROCS
      value: "2"           # Limit CPU usage
```

## Troubleshooting Production Issues

### Common Issues

#### High Memory Usage

```bash
# Check memory usage
kubectl top pod -n pahlevan-system

# Check for memory leaks
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug memory-profile

# Adjust memory limits
kubectl patch deployment pahlevan-operator -n pahlevan-system -p='
{
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "operator",
            "resources": {
              "limits": {
                "memory": "1Gi"
              }
            }
          }
        ]
      }
    }
  }
}'
```

#### eBPF Program Failures

```bash
# Check eBPF program status
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "ebpf"

# Verify kernel support
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug system-capabilities

# Check for conflicting programs
kubectl exec -n pahlevan-system deployment/pahlevan-operator -- \
  /pahlevan debug ebpf-programs
```

#### Policy Not Working

```bash
# Check policy status
kubectl describe pahlevanpolicy <policy-name> -n <namespace>

# Verify target pods
kubectl get pods -l <selector> --show-labels

# Check learning progress
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep "learning"
```

This comprehensive deployment guide should help you successfully deploy and operate Pahlevan in production environments.