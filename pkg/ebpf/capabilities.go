/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SystemCapabilities represents the eBPF capabilities of the system
type SystemCapabilities struct {
	HasEBPFSupport       bool
	HasTCSupport         bool
	HasTracepointSupport bool
	HasKProbeSupport     bool
	HasUProbeSupport     bool
	HasCGroupSupport     bool
	HasNetlinkSupport    bool
	KernelVersion        string
	MissingFeatures      []string
	Warnings             []string
}

// CapabilityChecker provides methods to check system capabilities
type CapabilityChecker struct {
	logger logr.Logger
}

// NewCapabilityChecker creates a new capability checker
func NewCapabilityChecker() *CapabilityChecker {
	return &CapabilityChecker{
		logger: log.Log.WithName("capability-checker"),
	}
}

// CheckSystemCapabilities performs a comprehensive check of eBPF capabilities
func (c *CapabilityChecker) CheckSystemCapabilities() (*SystemCapabilities, error) {
	caps := &SystemCapabilities{
		MissingFeatures: make([]string, 0),
		Warnings:        make([]string, 0),
	}

	// Get kernel version
	kernelVersion, err := c.getKernelVersion()
	if err != nil {
		c.logger.Error(err, "Failed to get kernel version")
		caps.Warnings = append(caps.Warnings, "Could not determine kernel version")
	} else {
		caps.KernelVersion = kernelVersion
		c.logger.Info("Detected kernel version", "version", kernelVersion)
	}

	// Check basic eBPF support
	caps.HasEBPFSupport = c.checkEBPFSupport()
	if !caps.HasEBPFSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "eBPF support")
		return caps, fmt.Errorf("eBPF is not supported on this system")
	}

	// Check TC (traffic control) support
	caps.HasTCSupport = c.checkTCSupport()
	if !caps.HasTCSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "TC (traffic control) support")
		caps.Warnings = append(caps.Warnings, "TC not available - network monitoring will be limited")
	}

	// Check tracepoint support
	caps.HasTracepointSupport = c.checkTracepointSupport()
	if !caps.HasTracepointSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "Tracepoint support")
		caps.Warnings = append(caps.Warnings, "Tracepoints not available - syscall monitoring will be limited")
	}

	// Check kprobe support
	caps.HasKProbeSupport = c.checkKProbeSupport()
	if !caps.HasKProbeSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "KProbe support")
		caps.Warnings = append(caps.Warnings, "KProbes not available - some monitoring features will be disabled")
	}

	// Check uprobe support
	caps.HasUProbeSupport = c.checkUProbeSupport()
	if !caps.HasUProbeSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "UProbe support")
		caps.Warnings = append(caps.Warnings, "UProbes not available - userspace monitoring will be limited")
	}

	// Check cgroup support
	caps.HasCGroupSupport = c.checkCGroupSupport()
	if !caps.HasCGroupSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "CGroup eBPF support")
		caps.Warnings = append(caps.Warnings, "CGroup eBPF not available - container isolation features will be limited")
	}

	// Check netlink support
	caps.HasNetlinkSupport = c.checkNetlinkSupport()
	if !caps.HasNetlinkSupport {
		caps.MissingFeatures = append(caps.MissingFeatures, "Netlink support")
		caps.Warnings = append(caps.Warnings, "Netlink not available - network event reporting will be limited")
	}

	c.logCapabilitiesSummary(caps)
	return caps, nil
}

// checkEBPFSupport checks if basic eBPF is supported
func (c *CapabilityChecker) checkEBPFSupport() bool {
	// Try to create a simple eBPF program
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		c.logger.V(1).Info("eBPF not supported", "error", err)
		return false
	}
	defer prog.Close()

	return true
}

// checkTCSupport checks if TC (traffic control) is available
func (c *CapabilityChecker) checkTCSupport() bool {
	// Check if tc binary exists
	if !c.commandExists("tc") {
		c.logger.V(1).Info("tc binary not found")
		return false
	}

	// Check if we can list TC rules (requires root privileges)
	cmd := exec.Command("tc", "qdisc", "show")
	err := cmd.Run()
	if err != nil {
		c.logger.V(1).Info("tc not functional", "error", err)
		return false
	}

	// Try to create a simple eBPF program that can be attached to TC
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		c.logger.V(1).Info("TC eBPF programs not supported", "error", err)
		return false
	}
	defer prog.Close()

	return true
}

// checkTracepointSupport checks if tracepoints are available
func (c *CapabilityChecker) checkTracepointSupport() bool {
	// Check if tracepoint directory exists
	if _, err := os.Stat("/sys/kernel/debug/tracing/events"); os.IsNotExist(err) {
		c.logger.V(1).Info("Tracepoint events directory not found")
		return false
	}

	// Try to create a tracepoint program
	spec := &ebpf.ProgramSpec{
		Type: ebpf.TracePoint,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		c.logger.V(1).Info("Tracepoint programs not supported", "error", err)
		return false
	}
	defer prog.Close()

	return true
}

// checkKProbeSupport checks if kprobes are available
func (c *CapabilityChecker) checkKProbeSupport() bool {
	// Check if kprobe events file exists
	if _, err := os.Stat("/sys/kernel/debug/tracing/kprobe_events"); os.IsNotExist(err) {
		c.logger.V(1).Info("KProbe events file not found")
		return false
	}

	// Try to create a kprobe program
	spec := &ebpf.ProgramSpec{
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		c.logger.V(1).Info("KProbe programs not supported", "error", err)
		return false
	}
	defer prog.Close()

	return true
}

// checkUProbeSupport checks if uprobes are available
func (c *CapabilityChecker) checkUProbeSupport() bool {
	// Check if uprobe events file exists
	if _, err := os.Stat("/sys/kernel/debug/tracing/uprobe_events"); os.IsNotExist(err) {
		c.logger.V(1).Info("UProbe events file not found")
		return false
	}

	// Try to create a uprobe program
	spec := &ebpf.ProgramSpec{
		Type: ebpf.Kprobe, // UProbes use the same program type as KProbes
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		c.logger.V(1).Info("UProbe programs not supported", "error", err)
		return false
	}
	defer prog.Close()

	return true
}

// checkCGroupSupport checks if cgroup eBPF programs are supported
func (c *CapabilityChecker) checkCGroupSupport() bool {
	// Check if cgroup v2 is mounted
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); os.IsNotExist(err) {
		c.logger.V(1).Info("CGroup v2 not found")
		return false
	}

	// Try to create a cgroup program
	spec := &ebpf.ProgramSpec{
		Type: ebpf.CGroupSKB,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 1, asm.DWord), // Allow
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		c.logger.V(1).Info("CGroup eBPF programs not supported", "error", err)
		return false
	}
	defer prog.Close()

	return true
}

// checkNetlinkSupport checks if netlink sockets work
func (c *CapabilityChecker) checkNetlinkSupport() bool {
	// Try to create a netlink socket
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		c.logger.V(1).Info("Netlink socket creation failed", "error", err)
		return false
	}
	defer syscall.Close(fd)

	return true
}

// commandExists checks if a command exists in PATH
func (c *CapabilityChecker) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// getKernelVersion gets the kernel version string
func (c *CapabilityChecker) getKernelVersion() (string, error) {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get kernel version: %v", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// logCapabilitiesSummary logs a summary of detected capabilities
func (c *CapabilityChecker) logCapabilitiesSummary(caps *SystemCapabilities) {
	c.logger.Info("System capability check completed",
		"ebpf", caps.HasEBPFSupport,
		"tc", caps.HasTCSupport,
		"tracepoints", caps.HasTracepointSupport,
		"kprobes", caps.HasKProbeSupport,
		"uprobes", caps.HasUProbeSupport,
		"cgroups", caps.HasCGroupSupport,
		"netlink", caps.HasNetlinkSupport,
		"kernel", caps.KernelVersion)

	if len(caps.MissingFeatures) > 0 {
		c.logger.Info("Missing features detected", "features", caps.MissingFeatures)
	}

	if len(caps.Warnings) > 0 {
		for _, warning := range caps.Warnings {
			c.logger.Info("Capability warning", "message", warning)
		}
	}
}

// RequireFeature returns an error if a required feature is not available
func (caps *SystemCapabilities) RequireFeature(feature string) error {
	switch feature {
	case "ebpf":
		if !caps.HasEBPFSupport {
			return fmt.Errorf("eBPF support is required but not available on this system")
		}
	case "tc":
		if !caps.HasTCSupport {
			return fmt.Errorf("TC (traffic control) support is required but not available. Please install iproute2 and ensure you have root privileges")
		}
	case "tracepoints":
		if !caps.HasTracepointSupport {
			return fmt.Errorf("tracepoint support is required but not available. Please ensure debugfs is mounted and kernel has tracepoint support")
		}
	case "kprobes":
		if !caps.HasKProbeSupport {
			return fmt.Errorf("kprobe support is required but not available. Please ensure kernel has kprobe support enabled")
		}
	case "uprobes":
		if !caps.HasUProbeSupport {
			return fmt.Errorf("uprobe support is required but not available. Please ensure kernel has uprobe support enabled")
		}
	case "cgroups":
		if !caps.HasCGroupSupport {
			return fmt.Errorf("cgroup eBPF support is required but not available. Please ensure cgroup v2 is enabled")
		}
	case "netlink":
		if !caps.HasNetlinkSupport {
			return fmt.Errorf("netlink support is required but not available")
		}
	default:
		return fmt.Errorf("unknown feature: %s", feature)
	}
	return nil
}

// GetFallbackMode returns a fallback mode based on available capabilities
func (caps *SystemCapabilities) GetFallbackMode() string {
	if !caps.HasEBPFSupport {
		return "disabled"
	}

	if caps.HasTCSupport && caps.HasTracepointSupport && caps.HasKProbeSupport {
		return "full"
	}

	if caps.HasTracepointSupport || caps.HasKProbeSupport {
		return "limited"
	}

	return "minimal"
}
