# API Reference

This document provides a complete reference for the Pahlevan API, including custom resources, status fields, and configuration options.

## Custom Resource Definitions

### PahlevanPolicy

The `PahlevanPolicy` is the primary custom resource for defining security policies.

#### API Version and Kind

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
```

#### Metadata

Standard Kubernetes metadata fields:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Policy name (must be unique within namespace) |
| `namespace` | string | Namespace where policy applies |
| `labels` | map[string]string | Kubernetes labels |
| `annotations` | map[string]string | Kubernetes annotations |

#### Spec Fields

##### Selector

Defines which containers the policy applies to.

```yaml
selector:
  matchLabels:
    app: nginx
  matchExpressions:
  - key: tier
    operator: In
    values: ["frontend", "backend"]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `matchLabels` | map[string]string | No | Label selector |
| `matchExpressions` | []LabelSelectorRequirement | No | Expression-based selector |

**LabelSelectorRequirement:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | string | Yes | Label key |
| `operator` | string | Yes | Operator: `In`, `NotIn`, `Exists`, `DoesNotExist` |
| `values` | []string | No | List of values (required for `In`/`NotIn`) |

##### Learning Configuration

```yaml
learning:
  enabled: true
  duration: "5m"
  minSamples: 50
  maxSamples: 1000
  autoTransition: true
  confidence: 0.95
  aggressive: false
  strictMode: false
  syscalls:
    enabled: true
    sampleRate: 1.0
  network:
    enabled: true
    sampleRate: 0.5
  files:
    enabled: true
    sampleRate: 1.0
  initialWindow: "2m"
  stabilizationWindow: "3m"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable learning phase |
| `duration` | string | `"5m"` | Learning duration (Go duration format) |
| `minSamples` | int | `50` | Minimum samples before transition |
| `maxSamples` | int | `1000` | Maximum samples to collect |
| `autoTransition` | bool | `true` | Auto-transition to enforcement |
| `confidence` | float | `0.95` | Required confidence level (0.0-1.0) |
| `aggressive` | bool | `false` | More permissive learning |
| `strictMode` | bool | `false` | More restrictive learning (planned) |

**Learning Target Configuration:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable learning for this target |
| `sampleRate` | float | `1.0` | Sampling rate (0.0-1.0) |

##### Enforcement Configuration

```yaml
enforcement:
  mode: "enforce"
  blockUnknown: true
  syscalls:
    defaultAction: "deny"
    allowedSyscalls: ["read", "write"]
    deniedSyscalls: ["ptrace"]
    allowedSyscallNumbers: [0, 1, 2]
    deniedSyscallNumbers: [101]
    filters:
    - syscall: "openat"
      arguments:
        path:
          operator: "startsWith"
          value: "/etc/"
      action: "deny"
  network:
    defaultAction: "allow"
    allowedEgressPorts: [80, 443]
    allowedIngressPorts: [8080]
    deniedEgressPorts: [22]
    deniedIngressPorts: [445]
    allowedProtocols: ["tcp", "udp"]
    deniedProtocols: ["icmp"]
    allowedDestinations: ["10.0.0.0/8"]
    deniedDestinations: ["169.254.0.0/16"]
    rules:
    - direction: "egress"
      protocol: "tcp"
      port: 443
      destination: "api.company.com"
      action: "allow"
  files:
    defaultAction: "allow"
    allowedPaths: ["/usr/share/nginx/html/*"]
    deniedPaths: ["/etc/passwd"]
    readOnlyPaths: ["/etc/*"]
    writeOnlyPaths: ["/var/log/*"]
    rules:
    - path: "/var/log/app.log"
      operations: ["write", "append"]
      action: "allow"
```

**Enforcement Mode:**

| Value | Description |
|-------|-------------|
| `disabled` | No enforcement, only learning |
| `monitor` | Log violations without blocking |
| `enforce` | Block violations and log events |

**Syscall Enforcement:**

| Field | Type | Description |
|-------|------|-------------|
| `defaultAction` | string | Default action: `allow`, `deny`, `audit` |
| `allowedSyscalls` | []string | Syscalls to explicitly allow |
| `deniedSyscalls` | []string | Syscalls to explicitly deny |
| `allowedSyscallNumbers` | []int | Syscall numbers to allow |
| `deniedSyscallNumbers` | []int | Syscall numbers to deny |
| `filters` | []SyscallFilter | Advanced syscall filtering rules |

**SyscallFilter:**

| Field | Type | Description |
|-------|------|-------------|
| `syscall` | string | Syscall name to filter |
| `arguments` | map[string]ArgumentFilter | Argument-based filtering |
| `action` | string | Action to take: `allow`, `deny`, `audit` |

**Network Enforcement:**

| Field | Type | Description |
|-------|------|-------------|
| `defaultAction` | string | Default action: `allow`, `deny` |
| `allowedEgressPorts` | []int | Egress ports to allow |
| `allowedIngressPorts` | []int | Ingress ports to allow |
| `deniedEgressPorts` | []int | Egress ports to deny |
| `deniedIngressPorts` | []int | Ingress ports to deny |
| `allowedProtocols` | []string | Protocols to allow: `tcp`, `udp`, `icmp` |
| `deniedProtocols` | []string | Protocols to deny |
| `allowedDestinations` | []string | Destination CIDRs to allow |
| `deniedDestinations` | []string | Destination CIDRs to deny |
| `rules` | []NetworkRule | Advanced network rules |

**NetworkRule:**

| Field | Type | Description |
|-------|------|-------------|
| `direction` | string | Direction: `ingress`, `egress` |
| `protocol` | string | Protocol: `tcp`, `udp`, `icmp` |
| `port` | int | Specific port number |
| `portRange` | string | Port range (e.g., "8000-8999") |
| `destination` | string | Destination CIDR or hostname |
| `source` | string | Source CIDR |
| `action` | string | Action: `allow`, `deny` |

**File Enforcement:**

| Field | Type | Description |
|-------|------|-------------|
| `defaultAction` | string | Default action: `allow`, `deny` |
| `allowedPaths` | []string | Paths to allow (supports wildcards) |
| `deniedPaths` | []string | Paths to deny (supports wildcards) |
| `readOnlyPaths` | []string | Paths that are read-only |
| `writeOnlyPaths` | []string | Paths that are write-only |
| `rules` | []FileRule | Advanced file rules |

**FileRule:**

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | File path (supports wildcards) |
| `operations` | []string | Operations: `read`, `write`, `append`, `delete` |
| `user` | string | User that performs the operation |
| `action` | string | Action: `allow`, `deny` |

##### Self-Healing Configuration

```yaml
selfHealing:
  enabled: true
  rollbackThreshold: 5
  rollbackWindow: "10m"
  maxRollbackAttempts: 3
  emergencyMode: true
  emergencyThreshold: 10
  emergencyWindow: "5m"
  strategies:
  - type: "gradual"
    steps: 5
    interval: "2m"
  - type: "emergency"
    action: "disable"
  conditions:
  - metric: "violation_rate"
    operator: ">"
    value: 10
    window: "5m"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable self-healing |
| `rollbackThreshold` | int | `5` | Violations before rollback |
| `rollbackWindow` | string | `"10m"` | Time window for violation counting |
| `maxRollbackAttempts` | int | `3` | Maximum rollback attempts |
| `emergencyMode` | bool | `true` | Enable emergency mode |
| `emergencyThreshold` | int | `10` | Violations for emergency mode |
| `emergencyWindow` | string | `"5m"` | Emergency mode time window |

**Self-Healing Strategy:**

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Strategy type: `gradual`, `emergency` |
| `steps` | int | Number of rollback steps (for gradual) |
| `interval` | string | Interval between steps |
| `action` | string | Emergency action: `disable`, `monitor` |

**Self-Healing Condition:**

| Field | Type | Description |
|-------|------|-------------|
| `metric` | string | Metric to monitor |
| `operator` | string | Comparison operator: `>`, `<`, `>=`, `<=`, `==` |
| `value` | float | Threshold value |
| `window` | string | Time window for evaluation |

##### Observability Configuration

```yaml
observability:
  metrics:
    enabled: true
    interval: "30s"
    custom:
    - name: "app_specific_violations"
      labels:
        app: "nginx"
    exporters:
    - type: "prometheus"
      endpoint: "http://prometheus:9090"
    # Additional exporters planned:
    # - type: "datadog"
    #   apiKey: "${DD_API_KEY}"
  alerts:
    enabled: true
    rules:
    - name: "High Violation Rate"
      condition: "violation_rate > 10"
      severity: "critical"
      window: "5m"
    # Notification channels (planned for future releases):
    notifications:
    - type: "slack"
      webhook: "https://hooks.slack.com/..."
      channel: "#security-alerts"
  tracing:
    enabled: false
    sampler: "probabilistic"
    sampleRate: 0.1
    exporters:
    - type: "jaeger"
      endpoint: "http://jaeger-collector:14268/api/traces"
```

**Metrics Configuration:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable metrics collection |
| `interval` | string | Collection interval |
| `custom` | []CustomMetric | Custom metrics to collect |
| `exporters` | []MetricsExporter | Metrics exporters |

**Alerts Configuration:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable alerting |
| `rules` | []AlertRule | Alert rules |
| `notifications` | []NotificationChannel | Notification channels |

**Tracing Configuration:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable distributed tracing |
| `sampler` | string | Sampling strategy: `always`, `never`, `probabilistic` |
| `sampleRate` | float | Sampling rate (0.0-1.0) |
| `exporters` | []TracingExporter | Tracing exporters |

#### Status Fields

The policy status provides information about the current state and learned behaviors.

```yaml
status:
  phase: "Enforcing"
  conditions:
  - type: "LearningComplete"
    status: "True"
    reason: "MinimumSamplesReached"
    message: "Learning completed successfully"
    lastTransitionTime: "2023-12-01T10:00:00Z"
  - type: "Ready"
    status: "True"
    reason: "PolicyActive"
    message: "Policy is active and enforcing"
    lastTransitionTime: "2023-12-01T10:05:00Z"
  learnedProfile:
    syscalls:
      allowed: [0, 1, 2, 3, 5, 9]
      confidence: 0.95
      samples: 1500
    network:
      allowedEgressPorts: [80, 443, 5432]
      allowedIngressPorts: [8080]
      confidence: 0.92
      samples: 800
    files:
      allowedPaths:
      - "/usr/share/nginx/html/*"
      - "/var/cache/nginx/*"
      confidence: 0.98
      samples: 2000
  statistics:
    containersMonitored: 5
    eventsProcessed: 15420
    violationsDetected: 3
    enforcementActions: 2
    learningStarted: "2023-12-01T09:55:00Z"
    learningCompleted: "2023-12-01T10:00:00Z"
    lastUpdate: "2023-12-01T10:30:00Z"
  selfHealing:
    rollbacksPerformed: 1
    emergencyModeActive: false
    lastRollback: "2023-12-01T09:45:00Z"
    rollbackHistory:
    - timestamp: "2023-12-01T09:45:00Z"
      reason: "HighViolationRate"
      success: true
  observedGeneration: 1
```

**Phase Values:**

| Phase | Description |
|-------|-------------|
| `Pending` | Policy created but not yet active |
| `Learning` | Currently in learning phase |
| `Enforcing` | Actively enforcing policy |
| `Failed` | Policy failed to apply |
| `Disabled` | Policy is disabled |

**Condition Types:**

| Type | Description |
|------|-------------|
| `LearningComplete` | Learning phase has completed |
| `Ready` | Policy is ready and active |
| `ProgamsLoaded` | eBPF programs loaded successfully |
| `Error` | Error condition occurred |

**Learned Profile:**

Contains the behavioral profile learned during the learning phase.

| Field | Type | Description |
|-------|------|-------------|
| `syscalls` | SyscallProfile | Learned syscall behavior |
| `network` | NetworkProfile | Learned network behavior |
| `files` | FileProfile | Learned file access behavior |

**Statistics:**

Runtime statistics about policy operation.

| Field | Type | Description |
|-------|------|-------------|
| `containersMonitored` | int | Number of containers being monitored |
| `eventsProcessed` | int64 | Total events processed |
| `violationsDetected` | int64 | Total violations detected |
| `enforcementActions` | int64 | Total enforcement actions taken |
| `learningStarted` | time | When learning phase started |
| `learningCompleted` | time | When learning phase completed |
| `lastUpdate` | time | Last status update time |

## Webhook API

> **Note**: Webhook support is planned for future releases.

Pahlevan will provide webhook endpoints for external integrations.

### Validation Webhook

Will validate PahlevanPolicy resources before they are stored in etcd.

#### Endpoint

```
POST /validate/policy.pahlevan.io/v1alpha1/pahlevanpolicy
```

#### Request Body

```json
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "uuid",
    "kind": {"group": "policy.pahlevan.io", "version": "v1alpha1", "kind": "PahlevanPolicy"},
    "resource": {"group": "policy.pahlevan.io", "version": "v1alpha1", "resource": "pahlevanpolicies"},
    "object": {
      // PahlevanPolicy object
    }
  }
}
```

#### Response

```json
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "response": {
    "uid": "uuid",
    "allowed": true,
    "result": {
      "status": "Success"
    }
  }
}
```

### Mutation Webhook

Mutates PahlevanPolicy resources to add defaults and annotations.

#### Endpoint

```
POST /mutate/policy.pahlevan.io/v1alpha1/pahlevanpolicy
```

## Metrics API

Pahlevan exposes Prometheus metrics on port 8080.

### Metrics Endpoint

```
GET /metrics
```

### Available Metrics

#### Policy Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `pahlevan_policies_total` | Counter | Total number of policies |
| `pahlevan_policies_by_phase` | Gauge | Policies by phase |
| `pahlevan_policy_violations_total` | Counter | Total policy violations |
| `pahlevan_enforcement_actions_total` | Counter | Total enforcement actions |

#### Learning Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `pahlevan_learning_progress_ratio` | Gauge | Learning progress (0.0-1.0) |
| `pahlevan_learning_samples_total` | Counter | Total learning samples |
| `pahlevan_learning_duration_seconds` | Histogram | Learning duration |

#### eBPF Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `pahlevan_ebpf_programs_loaded` | Gauge | Number of eBPF programs loaded |
| `pahlevan_ebpf_events_total` | Counter | Total eBPF events processed |
| `pahlevan_ebpf_program_load_errors_total` | Counter | eBPF program load errors |

#### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `pahlevan_containers_monitored` | Gauge | Containers being monitored |
| `pahlevan_operator_info` | Info | Operator version and build info |

### Metric Labels

Common labels across metrics:

| Label | Description |
|-------|-------------|
| `policy` | Policy name |
| `namespace` | Policy namespace |
| `container` | Container ID |
| `violation_type` | Type of violation |
| `action` | Enforcement action taken |

## Events API

Pahlevan generates Kubernetes events for important lifecycle events.

### Event Types

| Type | Reason | Description |
|------|--------|-------------|
| `Normal` | `LearningStarted` | Learning phase started |
| `Normal` | `LearningCompleted` | Learning phase completed |
| `Normal` | `EnforcementEnabled` | Enforcement mode enabled |
| `Warning` | `PolicyViolation` | Policy violation detected |
| `Warning` | `EBPFProgramLoadFailed` | eBPF program failed to load |
| `Normal` | `SelfHealingTriggered` | Self-healing rollback triggered |

### Event Example

```yaml
apiVersion: v1
kind: Event
metadata:
  name: nginx-policy.learning-completed
  namespace: default
type: Normal
reason: LearningCompleted
involvedObject:
  kind: PahlevanPolicy
  name: nginx-policy
  namespace: default
source:
  component: pahlevan-operator
message: "Learning completed successfully with 1500 samples and 0.95 confidence"
firstTimestamp: "2023-12-01T10:00:00Z"
lastTimestamp: "2023-12-01T10:00:00Z"
count: 1
```

## Configuration API

Global operator configuration is managed through ConfigMaps.

### Configuration ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pahlevan-config
  namespace: pahlevan-system
data:
  config.yaml: |
    # eBPF configuration
    ebpf:
      ringBufferSize: 32768
      maxEntriesPerMap: 10000
      eventBatchSize: 100
      mapCleanupInterval: 300s

    # Learning configuration
    learning:
      batchSize: 1000
      analysisInterval: 30s
      defaultDuration: 5m
      defaultMinSamples: 50

    # Enforcement configuration
    enforcement:
      cacheSize: 5000
      evaluationTimeout: 100ms
      defaultMode: monitor

    # Observability configuration
    observability:
      metricsInterval: 30s
      maxTraceSpans: 10000
      logLevel: info

    # Self-healing configuration
    selfHealing:
      defaultEnabled: true
      defaultThreshold: 5
      defaultWindow: 10m
```

This API reference provides complete documentation for all Pahlevan APIs and configuration options. Use this as a reference when building integrations or troubleshooting issues.
