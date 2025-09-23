# System Requirements

This document outlines the system requirements for running Pahlevan in different environments.

## Minimum Requirements

### Kubernetes Cluster

| Component | Minimum Version | Recommended |
|-----------|----------------|-------------|
| **Kubernetes** | 1.24 | 1.28+ |
| **kubectl** | 1.24 | 1.28+ |
| **Helm** (optional) | 3.8 | 3.12+ |

### Operating System

| OS | Minimum Version | Kernel | Notes |
|----|----------------|--------|-------|
| **Ubuntu** | 20.04 LTS | 5.4+ | Preferred platform |
| **CentOS/RHEL** | 8.0 | 4.18+ | Production tested |
| **Debian** | 11 | 5.10+ | Community tested |
| **Amazon Linux** | 2 | 4.14+ | EKS compatible |
| **Bottlerocket** | 1.0+ | 5.4+ | EKS optimized |

### Linux Kernel Requirements

#### Essential Features

```bash
# Check required kernel features
grep -E "(CONFIG_BPF=|CONFIG_BPF_SYSCALL=|CONFIG_BPF_JIT=)" /boot/config-$(uname -r)

# Expected output:
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
```

#### Minimum Kernel Version Matrix

| Kernel Version | eBPF Support | TC Support | LSM Support | Tracepoints | Notes |
|---------------|--------------|------------|-------------|-------------|-------|
| **4.18** | ✅ Basic | ✅ | ❌ | ✅ | Minimum supported |
| **5.4** | ✅ Good | ✅ | ❌ | ✅ | Ubuntu 20.04 default |
| **5.7** | ✅ Full | ✅ | ✅ | ✅ | BPF LSM introduced |
| **5.8+** | ✅ Optimal | ✅ | ✅ | ✅ | **Recommended** |

> **Note**: Current implementation uses tracepoint-based file monitoring, not LSM hooks.

### Hardware Requirements

#### Development Environment

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 2 cores | 4 cores |
| **Memory** | 4 GB | 8 GB |
| **Storage** | 20 GB | 50 GB |
| **Network** | 1 Gbps | 10 Gbps |

#### Production Environment

| Resource | Minimum | Recommended | High-Scale |
|----------|---------|-------------|-----------|
| **CPU** | 4 cores | 8 cores | 16+ cores |
| **Memory** | 8 GB | 16 GB | 32+ GB |
| **Storage** | 100 GB SSD | 500 GB SSD | 1+ TB NVMe |
| **Network** | 10 Gbps | 25 Gbps | 100 Gbps |

#### Per-Node Resources

| Component | CPU (per node) | Memory (per node) | Storage |
|-----------|---------------|------------------|---------|
| **Operator** | 500m-1000m | 512Mi-1Gi | - |
| **eBPF Programs** | 100m per 100 containers | 10MB per container | - |
| **Ring Buffers** | - | 32KB-64KB per container | - |
| **Policy Cache** | 50m per 1000 policies | 100MB per 1000 policies | - |

## Environment-Specific Requirements

### Development

```yaml
# Minimal dev cluster requirements
nodes:
  count: 1
  cpu: 2 cores
  memory: 4 GB
  storage: 20 GB

pahlevan:
  replicas: 1
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi
```

### Staging

```yaml
# Staging environment
nodes:
  count: 3
  cpu: 4 cores
  memory: 8 GB
  storage: 100 GB

pahlevan:
  replicas: 2
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
```

### Production

```yaml
# Production environment
nodes:
  count: 5+
  cpu: 8+ cores
  memory: 16+ GB
  storage: 500+ GB NVMe

pahlevan:
  replicas: 3
  resources:
    requests:
      cpu: 1000m
      memory: 1Gi
    limits:
      cpu: 2000m
      memory: 2Gi
```

## Container Runtime Compatibility

### Supported Runtimes

| Runtime | Version | Support Level | Notes |
|---------|---------|--------------|-------|
| **containerd** | 1.6+ | ✅ Full | Preferred runtime |
| **Docker** | 20.10+ | ✅ Full | Legacy support |
| **CRI-O** | 1.24+ | ✅ Full | OpenShift default |
| **runc** | 1.1+ | ✅ Full | Low-level runtime |
| **crun** | 1.5+ | ⚠️ Limited | Experimental |

### Runtime Configuration

#### containerd

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri"]
  [plugins."io.containerd.grpc.v1.cri".cni]
    bin_dir = "/opt/cni/bin"
    conf_dir = "/etc/cni/net.d"
```

#### Docker

```json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
```

## CNI Plugin Compatibility

### Tested CNI Plugins

| CNI Plugin | Version | Compatibility | Network Policies | Notes |
|------------|---------|--------------|-----------------|-------|
| **Calico** | 3.24+ | ✅ Full | ✅ | Excellent integration |
| **Cilium** | 1.12+ | ✅ Full | ✅ | eBPF-native CNI |
| **Flannel** | 0.20+ | ✅ Good | ❌ | Basic networking |
| **Weave** | 2.8+ | ✅ Good | ✅ | Legacy support |
| **Antrea** | 1.8+ | ✅ Good | ✅ | VMware CNI |

### CNI-Specific Considerations

#### Cilium

```yaml
# Cilium configuration for optimal Pahlevan integration
cilium:
  kubeProxyReplacement: strict
  bpf:
    masquerade: true
    hostLegacyRouting: false
  hubble:
    enabled: true
    relay:
      enabled: true
```

#### Calico

```yaml
# Calico configuration
calicoNetwork:
  bgp: Disabled
  ipPools:
  - blockSize: 26
    cidr: 10.244.0.0/16
    encapsulation: VXLANCrossSubnet
```

## Cloud Provider Compatibility

### AWS EKS

| EKS Version | Pahlevan Support | Notes |
|-------------|-----------------|-------|
| **1.24** | ✅ Full | Minimum supported |
| **1.25** | ✅ Full | Recommended |
| **1.26** | ✅ Full | Latest stable |
| **1.27** | ✅ Full | Latest |

**EKS-Specific Requirements:**
- Amazon Linux 2 or Bottlerocket AMI
- Instance types with enhanced networking
- VPC CNI or Calico

#### Recommended Instance Types

| Workload | Instance Type | vCPU | Memory | Network |
|----------|--------------|------|--------|---------|
| **Dev/Test** | t3.medium | 2 | 4 GB | Up to 5 Gbps |
| **Staging** | m5.large | 2 | 8 GB | Up to 10 Gbps |
| **Production** | m5.xlarge | 4 | 16 GB | Up to 10 Gbps |
| **High-Scale** | c5n.2xlarge | 8 | 21 GB | Up to 25 Gbps |

### Google GKE

| GKE Version | Pahlevan Support | Notes |
|-------------|-----------------|-------|
| **1.24** | ✅ Full | Minimum supported |
| **1.25** | ✅ Full | Recommended |
| **1.26** | ✅ Full | Latest stable |

**GKE-Specific Requirements:**
- Ubuntu or Container-Optimized OS
- VPC-native networking
- GKE Autopilot: ⚠️ Limited (eBPF restrictions)

#### Recommended Machine Types

| Workload | Machine Type | vCPU | Memory |
|----------|-------------|------|--------|
| **Dev/Test** | e2-standard-2 | 2 | 8 GB |
| **Staging** | n1-standard-4 | 4 | 15 GB |
| **Production** | n1-standard-8 | 8 | 30 GB |

### Azure AKS

| AKS Version | Pahlevan Support | Notes |
|-------------|-----------------|-------|
| **1.24** | ✅ Full | Minimum supported |
| **1.25** | ✅ Full | Recommended |
| **1.26** | ✅ Full | Latest stable |

**AKS-Specific Requirements:**
- Ubuntu 20.04 node image
- Azure CNI or Calico
- System-assigned managed identity

#### Recommended VM Sizes

| Workload | VM Size | vCPU | Memory |
|----------|---------|------|--------|
| **Dev/Test** | Standard_D2s_v3 | 2 | 8 GB |
| **Staging** | Standard_D4s_v3 | 4 | 16 GB |
| **Production** | Standard_D8s_v3 | 8 | 32 GB |

## Verification Scripts

### System Compatibility Check

```bash
#!/bin/bash
# check-system-compatibility.sh

echo "=== Pahlevan System Compatibility Check ==="

# Check kernel version
KERNEL_VERSION=$(uname -r)
echo "Kernel Version: $KERNEL_VERSION"

# Check for required kernel features
echo -e "\n=== Kernel Features ==="
for feature in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_BPF_EVENTS; do
    if grep -q "${feature}=y" /boot/config-$(uname -r) 2>/dev/null; then
        echo "✅ $feature: Enabled"
    else
        echo "❌ $feature: Disabled or not found"
    fi
done

# Check eBPF filesystem
if [ -d "/sys/fs/bpf" ]; then
    echo "✅ BPF filesystem: Available"
else
    echo "❌ BPF filesystem: Not available"
fi

# Check for required commands
echo -e "\n=== Required Commands ==="
for cmd in kubectl tc ip; do
    if command -v $cmd >/dev/null 2>&1; then
        echo "✅ $cmd: Available"
    else
        echo "❌ $cmd: Not found"
    fi
done

# Check Kubernetes version
if command -v kubectl >/dev/null 2>&1; then
    K8S_VERSION=$(kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion')
    echo "Kubernetes Client: $K8S_VERSION"
fi

# Check available resources
echo -e "\n=== System Resources ==="
echo "CPU Cores: $(nproc)"
echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo "Disk Space: $(df -h / | awk 'NR==2 {print $4}')"

echo -e "\n=== Compatibility Summary ==="
echo "Kernel version should be 4.18+"
echo "All kernel features should be enabled"
echo "All required commands should be available"
echo "Minimum 2 CPU cores and 4GB RAM recommended"
```

### Kubernetes Cluster Check

```bash
#!/bin/bash
# check-k8s-cluster.sh

echo "=== Kubernetes Cluster Check ==="

# Check cluster version
kubectl version --short

# Check node readiness
echo -e "\n=== Node Status ==="
kubectl get nodes -o wide

# Check available resources
echo -e "\n=== Node Resources ==="
kubectl describe nodes | grep -E "(Name:|cpu:|memory:)" | grep -A2 "Name:"

# Check CNI plugin
echo -e "\n=== CNI Plugin ==="
kubectl get pods -n kube-system | grep -E "(calico|cilium|flannel|weave)"

# Check for required namespaces
echo -e "\n=== Namespace Check ==="
kubectl get ns kube-system
kubectl get ns kube-public

# Check RBAC
echo -e "\n=== RBAC Check ==="
kubectl auth can-i create customresourcedefinitions --as=system:serviceaccount:pahlevan-system:pahlevan-operator

echo -e "\n=== Cluster Summary ==="
echo "Cluster should be running Kubernetes 1.24+"
echo "All nodes should be Ready"
echo "CNI plugin should be running"
echo "RBAC should allow CRD creation"
```

### Runtime Pahlevan Check

```bash
#!/bin/bash
# check-pahlevan-readiness.sh

echo "=== Pahlevan Readiness Check ==="

# Check if Pahlevan is installed
if ! kubectl get crd pahlevanpolicies.policy.pahlevan.io >/dev/null 2>&1; then
    echo "❌ Pahlevan CRDs not installed"
    exit 1
fi
echo "✅ Pahlevan CRDs installed"

# Check operator status
if kubectl get deployment pahlevan-operator -n pahlevan-system >/dev/null 2>&1; then
    echo "✅ Pahlevan operator deployed"

    # Check operator readiness
    READY=$(kubectl get deployment pahlevan-operator -n pahlevan-system -o jsonpath='{.status.readyReplicas}')
    DESIRED=$(kubectl get deployment pahlevan-operator -n pahlevan-system -o jsonpath='{.spec.replicas}')

    if [ "$READY" = "$DESIRED" ]; then
        echo "✅ Operator is ready ($READY/$DESIRED)"
    else
        echo "⚠️  Operator not fully ready ($READY/$DESIRED)"
    fi
else
    echo "❌ Pahlevan operator not deployed"
fi

# Check operator logs for errors
echo -e "\n=== Recent Operator Logs ==="
kubectl logs -n pahlevan-system deployment/pahlevan-operator --tail=10

# Test system capabilities
echo -e "\n=== System Capabilities Test ==="
kubectl run pahlevan-test --rm -i --tty --restart=Never \
    --image=obsernetics/pahlevan:latest \
    --command -- /pahlevan debug system-capabilities
```

## Performance Benchmarks

> **Note**: Performance characteristics may vary based on workload patterns and system configuration.

### eBPF Program Performance

| Metric | Baseline | Target | Maximum |
|--------|----------|--------|---------|
| **Syscall Latency** | Minimal | <5μs | <10μs |
| **Network Latency** | Minimal | <1ms | <5ms |
| **Memory Usage** | - | 20-35MB/container | <50MB/container |
| **CPU Overhead** | - | 3-7% | <10% |

### Scale Limits

> **Note**: Actual limits depend on hardware configuration and workload characteristics.

| Resource | Development | Production | Enterprise |
|----------|-------------|------------|-----------|
| **Containers/Node** | 50-100 | 200-500 | 1000+ |
| **Policies/Cluster** | 10-50 | 100-1000 | 5000+ |
| **Events/Second** | 1K | 10K-100K | 500K+ |
| **Nodes/Cluster** | 1-3 | 10-100 | 500+ |

Use these requirements to plan your Pahlevan deployment and ensure optimal performance in your environment.
