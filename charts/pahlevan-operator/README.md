# Pahlevan Operator Helm Chart

## Overview
This Helm chart deploys the Pahlevan security operator for Kubernetes, providing eBPF-based security monitoring and enforcement.

## Prerequisites
- Kubernetes 1.19+
- Helm 3.0+
- Linux kernel 5.8+ (for eBPF support)

## Installation

### Quick Install
```bash
helm install pahlevan ./charts/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace
```

### Install with Custom Values
```bash
helm install pahlevan ./charts/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace \
  --set operator.env.LOG_LEVEL=debug \
  --set ebpf.enabled=true
```

### Install for Development (Minikube/Local)
```bash
helm install pahlevan ./charts/pahlevan-operator \
  --namespace pahlevan-system \
  --create-namespace \
  --set image.repository=pahlevan \
  --set image.tag=latest \
  --set image.pullPolicy=Never \
  --set webhooks.enabled=false
```

## Configuration

### Core Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/obsernetics/pahlevan` |
| `image.tag` | Container image tag | `v1.0.0` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `operator.replicaCount` | Number of operator replicas | `1` |
| `operator.resources.limits.cpu` | CPU limit | `500m` |
| `operator.resources.limits.memory` | Memory limit | `512Mi` |
| `operator.resources.requests.cpu` | CPU request | `100m` |
| `operator.resources.requests.memory` | Memory request | `128Mi` |

### Security Context

The operator requires elevated privileges for eBPF operations:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `true` |
| `operator.securityContext.runAsUser` | User ID | `0` (root) |
| `operator.securityContext.capabilities.add` | Linux capabilities | `[NET_ADMIN, BPF, SYS_ADMIN, SYS_RESOURCE, IPC_LOCK]` |
| `operator.securityContext.seccompProfile.type` | Seccomp profile | `Unconfined` |

### eBPF Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ebpf.enabled` | Enable eBPF monitoring | `true` |
| `ebpf.config.enableSyscallMonitoring` | Monitor system calls | `true` |
| `ebpf.config.enableNetworkMonitoring` | Monitor network activity | `true` |
| `ebpf.config.enableFileMonitoring` | Monitor file operations | `true` |
| `ebpf.config.bufferSize` | Perf event buffer size | `65536` |
| `ebpf.config.maxEvents` | Maximum events in buffer | `10000` |

### Webhook Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhooks.enabled` | Enable admission webhooks | `true` |
| `webhooks.port` | Webhook service port | `9443` |
| `webhooks.certificate.autoGenerate` | Auto-generate certificates | `true` |
| `webhooks.failurePolicy` | Webhook failure policy | `Ignore` |

### Leader Election

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.env.ENABLE_LEADER_ELECTION` | Enable leader election | `true` |

## Supported Command-Line Flags

The operator binary supports the following flags:
- `--health-probe-bind-address`: Health probe endpoint (default: `:8081`)
- `--metrics-bind-address`: Metrics endpoint (default: `:8080`)
- `--leader-elect`: Enable leader election
- `--enable-webhooks`: Enable admission webhooks
- `--zap-devel`: Enable development logging
- `--learning-window`: Duration for learning phase (default: `5m0s`)
- `--enforcement-delay`: Delay before enforcement (default: `30s`)

## Recent Changes

### Version 0.2.0
- **Security Context Updates**: Added required privileges for eBPF operations
  - Changed to run as root (UID 0) for eBPF functionality
  - Added SYS_ADMIN, SYS_RESOURCE, and IPC_LOCK capabilities
  - Set seccomp profile to Unconfined for eBPF access

- **Fixed Leader Election**: Simplified leader election configuration
  - Removed unsupported detailed lease configuration flags
  - Now uses simple `--leader-elect` flag when enabled

- **Container Image**: Updated to use scratch base image with static binaries
  - Reduced image size from 102MB to 87.9MB
  - Built with static linking for better compatibility

- **Webhook Fixes**: Corrected admission webhook resource types
  - Fixed ValidatingAdmissionWebhookConfiguration
  - Fixed MutatingAdmissionWebhookConfiguration

## Troubleshooting

### eBPF Permission Errors
If you see errors like `failed to remove memory limit: operation not permitted`:
1. Ensure the security context has the required capabilities
2. Check that your cluster allows privileged containers
3. Verify kernel version supports eBPF (5.8+)

### Image Pull Errors
For local development with Minikube:
1. Build the image locally: `docker build -t pahlevan:latest .`
2. Load into Minikube: `minikube image load pahlevan:latest`
3. Install with `pullPolicy: Never`

### Leader Election Issues
If pods are competing for leadership:
1. Ensure only one replica when testing
2. Set `ENABLE_LEADER_ELECTION: "false"` for single instances

## Uninstallation

```bash
helm uninstall pahlevan -n pahlevan-system
kubectl delete namespace pahlevan-system
```

## Development

### Building from Source
```bash
# Generate eBPF bindings
go generate ./...

# Build binary
CGO_ENABLED=1 go build \
  -ldflags="-w -s -linkmode external -extldflags '-static'" \
  -o manager cmd/operator/main.go

# Build Docker image
docker build -t pahlevan:latest .
```

### Running Tests
```bash
go test -v ./...
```

## License
See LICENSE file in the repository root.