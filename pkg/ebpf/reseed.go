package ebpf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Rebuilding allow-sets from the published profiles.
//
// This is the FALLBACK, and it is deliberately kept apart from pinning.go so
// the two are never confused. Pinning is the real mechanism: it keeps the maps
// themselves alive across a restart, with full fidelity and no gap at all,
// because nothing is ever detached or recreated. This file covers the nodes
// where that is impossible - no bpffs mounted, a kernel too old for
// BPF_OBJ_PIN, a read-only /sys/fs/bpf, or a deliberate rebuild after a version
// change - by reconstructing the learned sets from the ContainerProfile
// resources the agent already publishes.
//
// It is strictly worse than pinning, in three ways an operator has to know
// about:
//
//   - It is not gapless. The programs were detached when the old agent exited
//     and the new maps are empty until this runs, so there IS a window.
//   - It is lossy. A ContainerProfile records a file path but not whether the
//     workload opened it for writing, and a destination but not the transport
//     it was reached over. The kernel keys on both. Restoring can therefore only
//     reproduce the read entries and the TCP entries; a write or a UDP flow that
//     was learned before the restart has to be learned again, and until it is,
//     enforcement would deny it.
//   - It depends on the cgroup id in the profile still being live. That holds
//     for an agent restart, where the containers keep running, and does not hold
//     for a node reboot, where every cgroup is new. Entries for a dead cgroup are
//     harmless, just useless.
//
// Because it is lossy, restoring must never be treated as "the container is
// fully protected again". It restores what it can and reports exactly what it
// restored, so the caller can decide - the safe decision being to leave the
// container learning for a further window rather than to enforce a baseline that
// is known to be missing entries.

// RestoreEntry is one container's published baseline, flattened to what the
// kernel maps need. It is deliberately free of Kubernetes types: this package
// owns the key derivations, not the API.
type RestoreEntry struct {
	// Name identifies the container in log lines and in the report. Free-form.
	Name string
	// CgroupID is the cgroup v2 id the allow-set keys are derived from. An
	// entry with no cgroup id cannot be keyed at all and is skipped.
	CgroupID uint64
	// Files are paths the container opened during learning. Restored as reads.
	Files []string
	// Executables are binaries the container ran.
	Executables []string
	// Capabilities are capability names without the CAP_ prefix, as the
	// profile spells them.
	Capabilities []string
	// NetworkDestinations are egress destinations. Two spellings are accepted,
	// because both exist in the wild: "host:port", and the raw form the
	// learner publishes, "<ipv4 as decimal u32>:port".
	NetworkDestinations []string
}

// RestoreReport says exactly what was put back, so the caller can log one line
// that an operator can act on rather than a claim that everything is fine.
type RestoreReport struct {
	Containers   int
	Skipped      int
	Files        int
	Executables  int
	Capabilities int
	Destinations int
	// Errors is capped: a profile with ten thousand unparseable entries must
	// produce a log line, not a log flood.
	Errors []string
}

// maxRestoreErrors bounds the report.
const maxRestoreErrors = 16

func (r *RestoreReport) note(format string, args ...any) {
	if len(r.Errors) >= maxRestoreErrors {
		return
	}
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

// Total is the number of allow-set entries written.
func (r RestoreReport) Total() int {
	return r.Files + r.Executables + r.Capabilities + r.Destinations
}

// RestoreAllowSets writes published baselines back into the kernel allow-sets.
//
// It never returns an error for a single bad entry: a restore that gives up
// halfway leaves a container with a partial allow-set, which is the worst
// possible state to then enforce against. Everything that can be restored is
// restored, and everything that could not is named in the report.
//
// Safe to call when a monitor is not loaded - the per-kind writers already
// report that as an error, and it is recorded rather than fatal, because a node
// with no BPF LSM has no file allow-set to restore into and that is expected.
func (m *Manager) RestoreAllowSets(entries []RestoreEntry) RestoreReport {
	var rep RestoreReport
	for _, e := range entries {
		if e.CgroupID == 0 {
			// No cgroup id means the profile was written before the container
			// was attributed, or the container is gone. Either way there is no
			// key to write under.
			rep.Skipped++
			continue
		}
		rep.Containers++

		for _, p := range e.Files {
			if p == "" {
				continue
			}
			// Read-only on purpose: the profile does not record write intent
			// and the kernel keys on it, so restoring a write entry here would
			// be granting a permission that was never observed.
			if err := m.AllowFilePathMode(e.CgroupID, p, false, true); err != nil {
				rep.note("%s: file %q: %v", e.Name, p, err)
				continue
			}
			rep.Files++
		}

		for _, p := range e.Executables {
			if p == "" {
				continue
			}
			if err := m.AllowExecPath(e.CgroupID, p, true); err != nil {
				rep.note("%s: exec %q: %v", e.Name, p, err)
				continue
			}
			rep.Executables++
		}

		for _, c := range e.Capabilities {
			num, ok := CapabilityNumber(c)
			if !ok {
				rep.note("%s: unknown capability %q", e.Name, c)
				continue
			}
			if err := m.AllowCapability(e.CgroupID, num, true); err != nil {
				rep.note("%s: capability %q: %v", e.Name, c, err)
				continue
			}
			rep.Capabilities++
		}

		for _, d := range e.NetworkDestinations {
			ip, port, err := ParseLearnedDestination(d)
			if err != nil {
				rep.note("%s: destination %q: %v", e.Name, d, err)
				continue
			}
			// TCP only, for the same reason files are restored read-only: the
			// profile does not record the transport, and the kernel key folds
			// it in. Seeding UDP as well would permit flows that were never
			// observed.
			if err := m.AllowNetworkDestinationProto(e.CgroupID, ip, port, ProtocolTCP, true); err != nil {
				rep.note("%s: destination %q: %v", e.Name, d, err)
				continue
			}
			rep.Destinations++
		}
	}
	return rep
}

// ParseLearnedDestination decodes a destination as a ContainerProfile spells it.
//
// Two spellings, because the learner and the event formatter disagree and both
// reach this function: the learner publishes the IPv4 address as the decimal
// value of the raw 32-bit word the kernel reported, while anything rendered for
// a human is a dotted quad or a bracketed IPv6 literal. Guessing wrong turns a
// restored allow-set entry into a key for a destination nobody will ever dial,
// which fails silently and denies the workload's real traffic.
func ParseLearnedDestination(s string) (net.IP, uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, 0, fmt.Errorf("empty destination")
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, 0, fmt.Errorf("no port")
	}
	host, portStr := s[:i], s[i+1:]
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("port %q: %w", portStr, err)
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		return nil, 0, fmt.Errorf("no host")
	}

	// A bare decimal is the learner's raw IPv4 word. IPv4String reverses the
	// same byte order the allow-set key derivation reads, so the address that
	// comes out here hashes to the key the kernel would have computed.
	if raw, perr := strconv.ParseUint(host, 10, 32); perr == nil && !strings.Contains(host, ".") {
		ip := net.ParseIP(IPv4String(uint32(raw)))
		if ip == nil {
			return nil, 0, fmt.Errorf("raw address %q is not an IPv4 address", host)
		}
		return ip, uint16(port64), nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("host %q is not an IP address", host)
	}
	return ip, uint16(port64), nil
}
