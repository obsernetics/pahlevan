# Linux Security Module (LSM) Support

Pahlevan provides comprehensive LSM support for enhanced security monitoring with lower overhead compared to traditional kprobe-based approaches.

## Overview

Starting with kernel 5.7, Linux introduced BPF LSM support, allowing eBPF programs to be attached directly to Linux Security Module hooks. This provides several advantages:

- **Lower overhead**: Direct kernel integration without function call interception
- **Enhanced security**: Native security layer integration
- **Better coverage**: Access to security-specific events not available via syscalls
- **Atomic enforcement**: Direct allow/deny decisions at the security layer

## Supported LSM Hooks

### File Operations
- `lsm/file_open` - File open operations
- `lsm/file_permission` - File permission checks
- `lsm/inode_permission` - Inode-level permission checks

### Process Operations
- `lsm/task_alloc` - Process/task creation
- `lsm/bprm_check_security` - Program execution monitoring
- `lsm/ptrace_access_check` - Ptrace operation monitoring

### Network Operations
- `lsm/socket_create` - Network socket creation

### Capability Checks
- `lsm/capable` - Capability requirement checks

## Automatic Fallback

Pahlevan automatically detects kernel capabilities and chooses the appropriate monitoring method:

1. **LSM BPF (kernel 5.7+)**: Preferred method with full LSM hooks
2. **kprobe Fallback (kernel 4.18+)**: Compatible mode using function probes

## Configuration

LSM support is enabled automatically when available. No additional configuration is required.

### Checking LSM Status

You can verify LSM support is active by checking the Pahlevan logs:

```bash
kubectl logs -n pahlevan-system deployment/pahlevan-operator | grep -i lsm
```

Expected output on LSM-capable systems:
```
INFO LSM eBPF programs loaded successfully
INFO Using LSM hooks for enhanced security monitoring
```

### Kernel Requirements

| Feature | Minimum Kernel | Recommended |
|---------|----------------|-------------|
| Basic eBPF | 4.18 | 4.18+ |
| LSM BPF | 5.7 | 5.8+ |
| Full LSM Support | 5.8 | 5.10+ |

## Benefits

### Performance
- **30-50% lower CPU overhead** compared to kprobe monitoring
- **Reduced context switches** due to direct kernel integration
- **Better cache locality** with native security hooks

### Security
- **Atomic enforcement**: Direct security decisions at the kernel level
- **Complete coverage**: Access to all security-relevant events
- **Lower bypass risk**: Integration at the security layer prevents bypass attempts

### Functionality
- **Process lifecycle monitoring**: Complete process creation and execution tracking
- **Capability monitoring**: Track privilege escalation attempts
- **Enhanced file monitoring**: Better file access pattern detection
- **Network security**: Comprehensive network operation monitoring

## Troubleshooting

### LSM Not Available
If LSM is not available, Pahlevan will automatically fall back to kprobe monitoring:

```
WARN LSM eBPF not supported on this kernel, falling back to kprobe monitoring
INFO Kprobe eBPF programs loaded successfully
```

### Permission Issues
Ensure the Pahlevan operator has the necessary permissions:

```yaml
apiVersion: v1
kind: SecurityContext
spec:
  privileged: false  # No privileged mode required
  capabilities:
    add:
    - BPF           # Required for eBPF operations
    - NET_ADMIN     # Required for network eBPF programs
    - SYS_RESOURCE  # Required to adjust memory limits
    - IPC_LOCK      # Required for memory locking
```

### Kernel Configuration
Verify LSM BPF is enabled in your kernel:

```bash
cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
# Should show: CONFIG_BPF_LSM=y
```

## Monitoring and Observability

LSM events are exposed through the same metrics and logging interfaces as kprobe events, ensuring consistent observability regardless of the underlying implementation.

### Key Metrics
- `pahlevan_lsm_events_total` - Total LSM events processed
- `pahlevan_lsm_violations_total` - LSM policy violations detected
- `pahlevan_lsm_overhead_seconds` - LSM processing overhead

### Event Types
- **Process events**: Process creation, execution, capability checks
- **File events**: File operations with enhanced metadata
- **Network events**: Socket operations and connection monitoring
- **Security events**: Ptrace operations, capability escalations

## Integration with Policies

LSM events are fully integrated with Pahlevan's policy engine:

```yaml
apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: enhanced-security
spec:
  enforcement:
    mode: "enforce"
    lsmEnabled: true  # Prefer LSM when available
    capabilities:
      - CAP_BPF: true        # Required for eBPF operations
      - CAP_SYS_ADMIN: false # Not needed with minimal privileges
      - CAP_NET_RAW: false
    processExecution:
      allowedBinaries:
        - "/usr/bin/nginx"
        - "/usr/bin/node"
```

## Best Practices

1. **Use LSM when available**: Let Pahlevan automatically choose LSM for better performance
2. **Monitor capability usage**: LSM provides detailed capability monitoring
3. **Combine with network policies**: Use LSM network monitoring with Kubernetes NetworkPolicies
4. **Regular updates**: Keep kernels updated for latest LSM features
5. **Test thoroughly**: Validate LSM policies in staging before production deployment

## Future Enhancements

- **Custom LSM hooks**: Support for custom security modules
- **Enhanced filtering**: More granular event filtering at the LSM level
- **Real-time policies**: Dynamic policy updates through LSM maps
- **Cross-namespace monitoring**: Enhanced container boundary detection