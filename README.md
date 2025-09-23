# Pahlevan - eBPF Kubernetes Security Operator

[![Go Report Card](https://goreportcard.com/badge/github.com/obsernetics/pahlevan)](https://goreportcard.com/report/github.com/obsernetics/pahlevan)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/obsernetics/pahlevan/workflows/CI/badge.svg)](https://github.com/obsernetics/pahlevan/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/obsernetics/pahlevan/branch/main/graph/badge.svg)](https://codecov.io/gh/obsernetics/pahlevan)

**Pahlevan** is a Kubernetes security operator that provides **runtime security monitoring and enforcement** through eBPF-powered workload profiling and policy-based protection.

## Key Features

- **eBPF-Powered Monitoring**: Real-time syscall, network, and file access monitoring at kernel level
- **Adaptive Learning**: Automatically profiles workload behavior and generates security policies
- **Policy-Based Enforcement**: Configurable security policies with monitoring and blocking modes
- **Self-Healing**: Automatic policy rollback when enforcement causes issues
- **Kubernetes-Native**: Full integration with Kubernetes APIs, RBAC, and operator patterns
- **Rich Observability**: Prometheus metrics, OpenTelemetry tracing, and attack surface analysis

## Quick Start

```bash
# Install with one command
kubectl apply -f https://github.com/obsernetics/pahlevan/releases/latest/download/install.yaml

# Create a policy
cat <<EOF | kubectl apply -f -
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
    autoTransition: true
  enforcement:
    mode: "monitor"
    blockUnknown: false
  selfHealing:
    enabled: true
EOF

# Deploy and label a workload
kubectl create deployment nginx --image=nginx:latest
kubectl label deployment nginx app=nginx

# Monitor progress
kubectl get pahlevanpolicy nginx-security -w
```

## How It Works

1. **Learning Phase**: eBPF programs monitor and profile container behavior (syscalls, network connections, file access)
2. **Policy Generation**: Security policies are automatically generated based on observed behavior patterns
3. **Enforcement**: Policies can monitor or block unwanted behavior at kernel level using eBPF
4. **Self-Healing**: When policies cause issues, they can be automatically rolled back to maintain availability

## System Requirements

- **Kubernetes**: 1.24+
- **Linux Kernel**: 4.18+ with eBPF support (5.8+ recommended)
- **Memory**: 256MB minimum (512MB recommended)
- **CPU**: 100m minimum (500m recommended)

## Installation Methods

### Helm Chart
```bash
helm repo add pahlevan https://obsernetics.github.io/pahlevan-charts
helm install pahlevan pahlevan/pahlevan-operator --namespace pahlevan-system --create-namespace
```

### From Source
```bash
git clone https://github.com/obsernetics/pahlevan.git
cd pahlevan
make quick-start
```

## Documentation

- **[Quick Start Guide](docs/quick-start.md)** - Get running in 5 minutes
- **[Architecture Overview](docs/architecture.md)** - System design and components
- **[Policy Reference](docs/policy-reference.md)** - Complete policy syntax
- **[Deployment Guide](docs/deployment.md)** - Production deployment patterns
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions
- **[API Reference](docs/api-reference.md)** - Complete API documentation

## Use Cases

| Environment | Mode | Description |
|-------------|------|-------------|
| Development | `monitor` | Full observability without blocking |
| Staging | `monitor` + alerts | Catch issues before production |
| Production | `enforce` | Zero-compromise security with self-healing |
| Compliance | `enforce` + reporting | PCI, HIPAA, SOC2 ready |

## Performance Impact

- **CPU Overhead**: Low overhead eBPF programs with minimal performance impact
- **Memory Usage**: Approximately 20-50MB per monitored container
- **Network Latency**: Minimal additional latency from eBPF monitoring
- **Zero** application code changes required

> **Note**: Performance characteristics depend on workload patterns and policy complexity. Monitoring mode has lower overhead than enforcement mode.

## Community & Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/obsernetics/pahlevan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/obsernetics/pahlevan/discussions)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Licensed under the [Apache License 2.0](LICENSE).

---

**Ready to minimize your attack surface?** Star ⭐ this repository and get started in under 5 minutes!