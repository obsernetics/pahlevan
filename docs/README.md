# Pahlevan Documentation

Welcome to the Pahlevan documentation! This directory contains comprehensive guides and references for deploying, configuring, and operating the Pahlevan eBPF Kubernetes Security Operator.

## Documentation Structure

### Quick Start
- **[Quick Start Guide](quick-start.md)** - Get Pahlevan running in 5 minutes
- **[System Requirements](system-requirements.md)** - Hardware and software requirements

### Architecture & Design
- **[Architecture Overview](architecture.md)** - System design and components
- **[API Reference](api-reference.md)** - Complete API documentation

### Configuration & Deployment
- **[Policy Reference](policy-reference.md)** - Complete policy syntax and examples
- **[Deployment Guide](deployment.md)** - Production deployment patterns
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

## Getting Started

If you're new to Pahlevan, start with the [Quick Start Guide](quick-start.md) to get a basic deployment running in your cluster.

For production deployments, review the [System Requirements](system-requirements.md) and [Deployment Guide](deployment.md).

## Key Concepts

### Learning Phase
Pahlevan automatically profiles container behavior during a configurable learning window, collecting data on:
- Syscall patterns and frequencies
- Network connection patterns
- File access patterns

### Enforcement Phase
After learning, Pahlevan generates minimal security policies and enforces them at the kernel level using eBPF programs.

### Self-Healing
When policies cause issues, Pahlevan can automatically roll back changes and adjust policies to maintain availability.

## Common Use Cases

### Development Environment
```yaml
# Monitor-only mode for development
enforcement:
  mode: "monitor"
  blockUnknown: false
learning:
  duration: "30m"
  autoTransition: false
```

### Production Environment
```yaml
# Strict enforcement for production
enforcement:
  mode: "enforce"
  blockUnknown: true
learning:
  duration: "5m"
  autoTransition: true
  strictMode: true
selfHealing:
  enabled: true
```

### Compliance Environment
```yaml
# Zero-tolerance for compliance workloads
enforcement:
  mode: "enforce"
  blockUnknown: true
  syscalls:
    defaultAction: "deny"
    allowedSyscalls: ["read", "write", "open", "close"]
selfHealing:
  enabled: false  # No auto-healing in compliance mode
```

## Documentation Conventions

- **Code blocks** show exact commands or configuration
- **Examples** demonstrate real-world usage patterns
- **Notes** highlight important considerations
- **Warnings** indicate potential issues or breaking changes

## Contributing to Documentation

We welcome improvements to the documentation! Please:

1. Check existing issues before creating new ones
2. Use clear, concise language
3. Include working examples
4. Test all commands and configurations
5. Follow the existing structure and style

## Getting Help

If you need help with Pahlevan:

- **Issues**: [GitHub Issues](https://github.com/obsernetics/pahlevan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/obsernetics/pahlevan/discussions)
- **Documentation**: This docs directory
- **Community**: [Kubernetes Slack #pahlevan](https://kubernetes.slack.com/channels/pahlevan)

## Document Status

| Document | Status | Last Updated |
|----------|--------|--------------|
| [Quick Start Guide](quick-start.md) | ✅ Complete | 2023-12-01 |
| [Architecture Overview](architecture.md) | ✅ Complete | 2023-12-01 |
| [Policy Reference](policy-reference.md) | ✅ Complete | 2023-12-01 |
| [Deployment Guide](deployment.md) | ✅ Complete | 2023-12-01 |
| [Troubleshooting](troubleshooting.md) | ✅ Complete | 2023-12-01 |
| [API Reference](api-reference.md) | ✅ Complete | 2023-12-01 |
| [System Requirements](system-requirements.md) | ✅ Complete | 2023-12-01 |

---

**Need something specific?** Use the search function in your editor or browser to quickly find what you're looking for across all documentation files.
