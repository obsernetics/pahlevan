# Pahlevan Policy Examples

This directory contains comprehensive examples of Pahlevan security policies for different types of workloads. These examples demonstrate best practices for configuring adaptive eBPF-based security policies in Kubernetes environments.

## Policy Examples

### 1. Web Application Policy (`policies/web-application.yaml`)

**Use Case**: Frontend web applications, API servers, HTTP/HTTPS services

**Key Features**:
- Optimized for predictable web traffic patterns
- Short learning duration (3 minutes)
- Network enforcement for HTTP/HTTPS traffic
- File system restrictions for web app security
- PCI DSS and SOC2 compliance annotations

**Target Workloads**:
- React/Angular/Vue.js frontends
- Express.js/Spring Boot APIs
- NGINX/Apache web servers
- REST API services

**Learning Configuration**:
- Duration: 3 minutes (web apps have predictable patterns)
- Confidence Threshold: 92%
- Auto-transition enabled
- Focuses on network and file I/O patterns

### 2. Database Policy (`policies/database.yaml`)

**Use Case**: Production database workloads requiring high security

**Key Features**:
- Extended learning duration (10 minutes) for complex database patterns
- Strict enforcement with minimal exceptions
- High confidence threshold (95%)
- Comprehensive audit logging
- HIPAA, PCI DSS, SOC2, FedRAMP compliance

**Target Workloads**:
- PostgreSQL databases
- MySQL databases
- MongoDB instances
- Redis caches

**Learning Configuration**:
- Duration: 10 minutes (databases have complex startup patterns)
- Manual transition control for critical systems
- Enhanced anomaly detection
- Strict syscall and network enforcement

### 3. Microservices Policy (`policies/microservices.yaml`)

**Use Case**: Cloud-native microservices with service mesh integration

**Key Features**:
- Service mesh (Istio) compatibility
- Adaptive learning for dynamic service patterns
- Circuit breaker integration
- Distributed tracing support
- Flexible network policies for service-to-service communication

**Target Workloads**:
- REST/gRPC microservices
- API gateways
- Service mesh enabled applications
- Cloud-native applications

**Learning Configuration**:
- Duration: 5 minutes (moderate complexity)
- Confidence Threshold: 90%
- Service mesh aware network learning
- Container lifecycle phase awareness

### 4. Batch Jobs Policy (`policies/batch-jobs.yaml`)

**Use Case**: Data processing, ETL jobs, scheduled tasks, ML training

**Key Features**:
- Extended learning window (15 minutes) for variable patterns
- Flexible enforcement for data processing requirements
- Support for process spawning and file manipulation
- Job completion monitoring
- Lower sensitivity for pattern variations

**Target Workloads**:
- ETL data pipelines
- Machine learning training jobs
- Report generation tasks
- Data analytics workloads

**Learning Configuration**:
- Duration: 15 minutes (variable patterns require longer learning)
- Manual transition control
- Permissive file and network access
- Process execution support

## Quick Start

### Deploy a Web Application Policy

```bash
# Apply the web application policy and example deployment
kubectl apply -f examples/policies/web-application.yaml

# Check policy status
kubectl get pahlevanpolicy web-application-policy

# View learning progress
kubectl describe pahlevanpolicy web-application-policy
```

### Deploy a Database Policy

```bash
# Apply the database policy and PostgreSQL StatefulSet
kubectl apply -f examples/policies/database.yaml

# Monitor policy transition (manual transition required)
kubectl get pahlevanpolicy database-policy -w

# Manually transition to enforcement when ready
kubectl patch pahlevanpolicy database-policy --type='merge' -p='{"spec":{"enforcementConfig":{"mode":"Blocking"}}}'
```

### Deploy Microservices Policies

```bash
# Ensure Istio is installed in your cluster
istioctl install --set values.defaultRevision=default

# Apply the microservices policy
kubectl apply -f examples/policies/microservices.yaml

# Label namespace for Istio injection
kubectl label namespace default istio-injection=enabled
```

### Deploy Batch Job Policies

```bash
# Apply the batch jobs policy
kubectl apply -f examples/policies/batch-jobs.yaml

# Run the example ETL job
kubectl create job etl-example --from=cronjob/daily-report-generation
```

## Policy Customization

### Learning Configuration

Adjust learning parameters based on your workload characteristics:

```yaml
learningConfig:
  duration: "5m"              # Longer for complex workloads
  confidenceThreshold: 0.90   # Higher for critical workloads
  autoTransition: true        # false for manual control
  lifecycleAware: true        # Enable for container lifecycle awareness
```

### Enforcement Modes

Choose the appropriate enforcement mode:

- **Off**: No enforcement, learning only
- **Monitoring**: Log violations but don't block
- **Blocking**: Block unknown behavior (production mode)

```yaml
enforcementConfig:
  mode: "Monitoring"  # Start with monitoring
  gracePeriod: "30s"  # Allow time for legitimate operations
  blockUnknown: true  # Block unlearned patterns
```

### Self-Healing Configuration

Configure self-healing based on workload stability:

```yaml
selfHealing:
  enabled: true
  rollbackThreshold: 5        # Number of failures before rollback
  rollbackWindow: "10m"       # Time window for failure counting
  recoveryStrategy: "Rollback" # Rollback, Relax, or Maintenance
```

## Best Practices

### 1. Start with Monitoring Mode

Always begin with `enforcementConfig.mode: "Monitoring"` to observe behavior before blocking.

### 2. Gradual Transition

For critical workloads:
1. Deploy in monitoring mode
2. Observe for 24-48 hours
3. Review logs and metrics
4. Gradually transition to blocking mode

### 3. Environment-Specific Policies

Create separate policies for different environments:

```yaml
metadata:
  name: web-app-policy-dev
  labels:
    environment: development
---
metadata:
  name: web-app-policy-prod
  labels:
    environment: production
```

### 4. Compliance Integration

Use annotations to track compliance requirements:

```yaml
metadata:
  annotations:
    policy.pahlevan.io/compliance: "pci-dss,hipaa,soc2"
    policy.pahlevan.io/risk-level: "high"
    policy.pahlevan.io/data-classification: "sensitive"
```

### 5. Monitoring and Alerting

Set up monitoring for policy violations:

```bash
# View policy metrics
kubectl port-forward svc/pahlevan-operator-metrics 8080:8080
curl http://localhost:8080/metrics | grep pahlevan_policy

# Check violation events
kubectl get events --field-selector reason=PolicyViolation
```

## Troubleshooting

### Policy Not Learning

1. Check pod labels match policy selector
2. Verify eBPF programs are loaded
3. Check operator logs for errors

```bash
kubectl logs -n pahlevan-system deployment/pahlevan-operator
```

### High Violation Rates

1. Review learning configuration
2. Increase confidence threshold
3. Add necessary exceptions
4. Consider relaxing enforcement temporarily

### Performance Impact

1. Monitor resource usage
2. Adjust eBPF buffer sizes
3. Reduce tracing sample rates
4. Optimize policy selectors

## Advanced Configuration

### Custom Syscall Lists

```yaml
enforcementConfig:
  syscallEnforcement:
    allowList:
    - "read"
    - "write"
    - "openat"
    blockList:
    - "ptrace"
    - "mount"
```

### Network Policy Integration

```yaml
enforcementConfig:
  networkEnforcement:
    allowedConnections:
    - direction: "egress"
      ports: [443]
      protocols: ["tcp"]
      destinations: ["api.example.com"]
```

### File System Restrictions

```yaml
enforcementConfig:
  fileEnforcement:
    readOnlyPaths:
    - "/app/config"
    writablePaths:
    - "/tmp"
    - "/var/log"
    forbiddenPaths:
    - "/proc/*/mem"
```

## Support

For additional help:

- 📖 [Documentation](https://obsernetics.github.io/pahlevan/docs.html)
- 💬 [GitHub Discussions](https://github.com/obsernetics/pahlevan/discussions)
- 🐛 [Issue Tracker](https://github.com/obsernetics/pahlevan/issues)
- 📧 [Mailing List](mailto:pahlevan-dev@googlegroups.com)