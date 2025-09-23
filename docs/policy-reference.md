# Policy Reference

This document provides a comprehensive reference for Pahlevan policy configuration. PahlevanPolicy resources define how containers should be monitored, learned from, and secured.

## Policy Structure

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: example-policy
  namespace: default
spec:
  # Target selection
  selector:
    matchLabels: {}
    matchExpressions: []

  # Learning configuration
  learning:
    enabled: true
    duration: "5m"
    minSamples: 50
    autoTransition: true
    confidence: 0.95

  # Enforcement configuration
  enforcement:
    mode: "monitor"
    blockUnknown: false
    syscalls: {}
    network: {}
    files: {}

  # Self-healing configuration
  selfHealing:
    enabled: true
    rollbackThreshold: 5
    rollbackWindow: "10m"
    emergencyMode: true

  # Observability configuration
  observability:
    metrics:
      enabled: true
    alerts:
      enabled: true
    tracing:
      enabled: false

status:
  phase: "Learning"
  conditions: []
  learnedProfile: {}
  statistics: {}
```

## Selector Configuration

The selector determines which containers the policy applies to.

### Match Labels

```yaml
spec:
  selector:
    matchLabels:
      app: nginx
      version: v1.0
      environment: production
```

### Match Expressions

```yaml
spec:
  selector:
    matchExpressions:
    - key: app
      operator: In
      values: ["nginx", "apache"]
    - key: version
      operator: NotIn
      values: ["beta", "alpha"]
    - key: environment
      operator: Exists
```

**Supported Operators:**
- `In`: Label value must be in the list
- `NotIn`: Label value must not be in the list
- `Exists`: Label key must exist
- `DoesNotExist`: Label key must not exist

### Complex Selectors

```yaml
spec:
  selector:
    matchLabels:
      tier: frontend
    matchExpressions:
    - key: app
      operator: In
      values: ["web", "api"]
    - key: security-level
      operator: NotIn
      values: ["low"]
```

## Learning Configuration

### Basic Learning

```yaml
spec:
  learning:
    enabled: true
    duration: "5m"
    autoTransition: true
```

### Advanced Learning

```yaml
spec:
  learning:
    enabled: true
    duration: "10m"
    minSamples: 100
    maxSamples: 1000
    autoTransition: false
    confidence: 0.95

    # Learning modes
    aggressive: false        # More permissive learning
    # strictMode: false       # More restrictive learning (planned)

    # Specific learning targets
    syscalls:
      enabled: true
      sampleRate: 1.0       # 100% sampling
    network:
      enabled: true
      sampleRate: 0.5       # 50% sampling
    files:
      enabled: true
      sampleRate: 1.0

    # Learning windows
    initialWindow: "2m"     # Initial rapid learning
    stabilizationWindow: "3m" # Stabilization period
```

**Parameters:**
- `duration`: How long to learn (e.g., "5m", "1h")
- `minSamples`: Minimum samples before transition
- `maxSamples`: Maximum samples to collect
- `autoTransition`: Automatically move to enforcement
- `confidence`: Required confidence level (0.0-1.0)

## Enforcement Configuration

### Enforcement Modes

```yaml
spec:
  enforcement:
    mode: "monitor"  # Options: disabled, monitor, enforce
    blockUnknown: false
```

**Modes:**
- `disabled`: No enforcement, only learning
- `monitor`: Log violations without blocking
- `enforce`: Block violations and log events

### Syscall Enforcement

```yaml
spec:
  enforcement:
    syscalls:
      defaultAction: "allow"  # allow, deny, audit

      # Explicit allow list
      allowedSyscalls:
      - "read"
      - "write"
      - "open"
      - "close"
      - "mmap"

      # Explicit deny list
      deniedSyscalls:
      - "ptrace"
      - "process_vm_readv"
      - "process_vm_writev"
      - "kexec_load"

      # Syscall by number
      allowedSyscallNumbers: [0, 1, 2, 3, 5, 9]
      deniedSyscallNumbers: [101, 311]

      # Advanced filtering
      filters:
      - syscall: "openat"
        arguments:
          path:
            operator: "startsWith"
            value: "/etc/"
        action: "deny"
```

### Network Enforcement

```yaml
spec:
  enforcement:
    network:
      defaultAction: "allow"

      # Port-based rules
      allowedEgressPorts: [80, 443, 5432, 6379]
      allowedIngressPorts: [8080, 8443]
      deniedEgressPorts: [22, 23, 3389]
      deniedIngressPorts: [445, 135]

      # Protocol-based rules
      allowedProtocols: ["tcp", "udp"]
      deniedProtocols: ["icmp"]

      # IP-based rules
      allowedDestinations:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      deniedDestinations:
      - "169.254.0.0/16"  # Block metadata service

      # Advanced rules
      rules:
      - direction: "egress"
        protocol: "tcp"
        port: 443
        destination: "api.company.com"
        action: "allow"
      - direction: "ingress"
        protocol: "tcp"
        portRange: "8000-8999"
        source: "10.0.0.0/8"
        action: "allow"
```

### File System Enforcement

```yaml
spec:
  enforcement:
    files:
      defaultAction: "allow"

      # Path-based rules
      allowedPaths:
      - "/usr/share/nginx/html/*"
      - "/var/cache/nginx/*"
      - "/tmp/*"
      deniedPaths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/proc/*/mem"
      - "/sys/kernel/*"

      # Operation-based rules
      readOnlyPaths:
      - "/etc/*"
      - "/usr/*"
      writeOnlyPaths:
      - "/var/log/*"

      # Advanced rules
      rules:
      - path: "/var/log/app.log"
        operations: ["write", "append"]
        action: "allow"
      - path: "/etc/secrets/*"
        operations: ["read"]
        user: "root"
        action: "deny"
```

## Self-Healing Configuration

### Basic Self-Healing

```yaml
spec:
  selfHealing:
    enabled: true
    rollbackThreshold: 5
    rollbackWindow: "10m"
```

### Advanced Self-Healing

```yaml
spec:
  selfHealing:
    enabled: true

    # Rollback configuration
    rollbackThreshold: 5
    rollbackWindow: "10m"
    maxRollbackAttempts: 3

    # Emergency mode
    emergencyMode: true
    emergencyThreshold: 10
    emergencyWindow: "5m"

    # Recovery strategies
    strategies:
    - type: "gradual"
      steps: 5
      interval: "2m"
    - type: "emergency"
      action: "disable"

    # Conditions for rollback
    conditions:
    - metric: "violation_rate"
      operator: ">"
      value: 10
      window: "5m"
    - metric: "error_rate"
      operator: ">"
      value: 0.05
      window: "10m"
```

## Observability Configuration

### Metrics

```yaml
spec:
  observability:
    metrics:
      enabled: true
      interval: "30s"

      # Custom metrics
      custom:
      - name: "app_specific_violations"
        labels:
          app: "nginx"
          team: "platform"

      # Exporters (prometheus enabled by default)
      exporters:
      - type: "prometheus"
        endpoint: "http://prometheus:9090"
      # Additional exporters planned:
      # - type: "datadog"
      #   apiKey: "${DD_API_KEY}"
```

### Alerts

```yaml
spec:
  observability:
    alerts:
      enabled: true

      # Built-in alerts
      rules:
      - name: "High Violation Rate"
        condition: "violation_rate > 10"
        severity: "critical"
        window: "5m"

      - name: "Policy Learning Complete"
        condition: "learning_complete == 1"
        severity: "info"

      # Notification channels (planned for future releases)
      notifications:
      - type: "slack"
        webhook: "https://hooks.slack.com/..."
        channel: "#security-alerts"
      - type: "pagerduty"
        integrationKey: "${PD_INTEGRATION_KEY}"
```

### Tracing

```yaml
spec:
  observability:
    tracing:
      enabled: true
      sampler: "probabilistic"
      sampleRate: 0.1

      # Exporters
      exporters:
      - type: "jaeger"
        endpoint: "http://jaeger-collector:14268/api/traces"
      - type: "zipkin"
        endpoint: "http://zipkin:9411/api/v2/spans"
```

## Policy Examples

### Development Environment

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: dev-policy
  namespace: development
spec:
  selector:
    matchLabels:
      environment: development
  learning:
    enabled: true
    duration: "10m"
    autoTransition: false
    aggressive: true  # More permissive learning
  enforcement:
    mode: "monitor"
    blockUnknown: false
  observability:
    metrics:
      enabled: true
    alerts:
      enabled: false  # No alerts in dev
```

### Production Environment

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: prod-policy
  namespace: production
spec:
  selector:
    matchLabels:
      environment: production
      tier: frontend
  learning:
    enabled: true
    duration: "5m"
    minSamples: 100
    autoTransition: true
    # strictMode: true  # More restrictive learning (planned)
  enforcement:
    mode: "enforce"
    blockUnknown: true
    syscalls:
      defaultAction: "deny"
      allowedSyscalls:
      - "read"
      - "write"
      - "open"
      - "close"
      - "mmap"
      deniedSyscalls:
      - "ptrace"
      - "process_vm_readv"
    network:
      allowedEgressPorts: [80, 443]
      allowedIngressPorts: [8080]
      deniedDestinations:
      - "169.254.0.0/16"  # Block metadata
    files:
      deniedPaths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/proc/*/mem"
  selfHealing:
    enabled: true
    rollbackThreshold: 3
    emergencyMode: true
  observability:
    metrics:
      enabled: true
    alerts:
      enabled: true
      notifications:
      - type: "slack"
        webhook: "https://hooks.slack.com/..."
```

### Compliance Environment (PCI DSS)

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: pci-compliance
  namespace: payment-processing
spec:
  selector:
    matchLabels:
      compliance: pci-dss
      data-classification: sensitive
  learning:
    enabled: true
    duration: "2m"
    minSamples: 200
    # strictMode: true  # More restrictive learning (planned)
  enforcement:
    mode: "enforce"
    blockUnknown: true
    syscalls:
      defaultAction: "deny"
      allowedSyscalls:
      - "read"
      - "write"
      - "open"
      - "close"
      # Very minimal syscall set
    network:
      defaultAction: "deny"
      allowedEgressPorts: [443]  # Only HTTPS
      deniedDestinations:
      - "0.0.0.0/0"  # Block all by default
      allowedDestinations:
      - "secure-api.payment.com"
    files:
      defaultAction: "deny"
      allowedPaths:
      - "/app/data/*"
      deniedPaths:
      - "/etc/*"
      - "/proc/*"
      - "/sys/*"
  selfHealing:
    enabled: false  # No auto-healing in compliance mode
  observability:
    metrics:
      enabled: true
    alerts:
      enabled: true
    tracing:
      enabled: true
      sampleRate: 1.0  # 100% tracing for compliance
```

### Web Application

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: webapp-policy
spec:
  selector:
    matchLabels:
      app: webapp
      tier: frontend
  learning:
    duration: "5m"
    syscalls:
      sampleRate: 1.0
    network:
      sampleRate: 0.8
    files:
      sampleRate: 1.0
  enforcement:
    mode: "enforce"
    syscalls:
      allowedSyscalls:
      - "read"
      - "write"
      - "open"
      - "close"
      - "socket"
      - "connect"
      - "sendto"
      - "recvfrom"
    network:
      allowedEgressPorts: [80, 443, 5432, 6379]  # HTTP, HTTPS, PostgreSQL, Redis
      allowedIngressPorts: [8080]
    files:
      allowedPaths:
      - "/app/*"
      - "/tmp/*"
      - "/var/cache/app/*"
      deniedPaths:
      - "/etc/passwd"
      - "/etc/shadow"
```

## Policy Status

The policy status provides information about the current state and learned behaviors.

### Status Fields

```yaml
status:
  phase: "Enforcing"  # Learning, Enforcing, Failed, Disabled

  conditions:
  - type: "LearningComplete"
    status: "True"
    reason: "MinimumSamplesReached"
    lastTransitionTime: "2023-12-01T10:00:00Z"
  - type: "Ready"
    status: "True"
    reason: "PolicyActive"

  # Learned behavioral profile
  learnedProfile:
    syscalls:
      allowed: [0, 1, 2, 3, 5, 9, 39, 41, 42, 45, 48, 49, 257, 262]
      confidence: 0.95
    network:
      allowedEgressPorts: [80, 443, 5432]
      allowedIngressPorts: [8080]
      confidence: 0.92
    files:
      allowedPaths:
      - "/usr/share/nginx/html/*"
      - "/var/cache/nginx/*"
      confidence: 0.98

  # Runtime statistics
  statistics:
    containersMonitored: 5
    eventsProcessed: 15420
    violationsDetected: 3
    enforcementActions: 2
    lastUpdate: "2023-12-01T10:30:00Z"

  # Self-healing status
  selfHealing:
    rollbacksPerformed: 1
    emergencyModeActive: false
    lastRollback: "2023-12-01T09:45:00Z"
```

## Best Practices

### Policy Naming

- Use descriptive names: `webapp-production-policy`
- Include environment: `dev-`, `staging-`, `prod-`
- Include application: `nginx-`, `postgres-`, `redis-`

### Learning Configuration

- **Development**: Longer learning (10-30m), more permissive
- **Staging**: Medium learning (5-10m), balanced
- **Production**: Shorter learning (2-5m), more restrictive

### Enforcement Strategy

1. Start with `monitor` mode
2. Analyze violations and tune policies
3. Gradually move to `enforce` mode
4. Enable self-healing once stable

### Resource Management

```yaml
# Always set resource limits
resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

This comprehensive policy reference should help you configure Pahlevan policies for any use case, from development to high-security production environments.