// Package attribution resolves kernel identifiers (cgroup id, PID) observed by
// eBPF programs back to Kubernetes objects (pod, namespace, container).
//
// The eBPF data plane keys everything on the cgroup v2 id returned by
// bpf_get_current_cgroup_id(), which is the kernfs id (inode) of the cgroup
// directory. This package maps that id to the container by walking the cgroup
// filesystem and parsing the pod/container identifiers out of the cgroup path,
// which works correctly regardless of user namespaces (unlike host-PID mapping).
package attribution

import (
	"fmt"
	"regexp"
	"strings"
)

// ContainerRef identifies a container and the pod it belongs to.
type ContainerRef struct {
	PodUID      string // Kubernetes pod UID (from the cgroup path)
	ContainerID string // container runtime ID (may be empty for the pod cgroup)
	Runtime     string // "containerd", "crio", "docker", or "" if unknown
	QoSClass    string // "guaranteed", "burstable", "besteffort", or ""
	CgroupPath  string // the source cgroup path (for diagnostics)
}

var (
	// systemd driver: .../kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice/<runtime>-<id>.scope
	// The pod UID uses underscores in the systemd form (pod<uid> with '_' for '-').
	rePodSystemd = regexp.MustCompile(`pod([0-9a-fA-F_]{32,})\.slice`)
	// cgroupfs driver: .../kubepods/<qos>/pod<uid>/<id>
	rePodCgroupfs = regexp.MustCompile(`pod([0-9a-f-]{36})`)
	// container scope/dir: <runtime>-<64hex>.scope  OR  a bare 64-hex dir.
	reScope = regexp.MustCompile(`(?:^|/)(?:(crio|cri-containerd|containerd|docker)-)?([0-9a-f]{64})(?:\.scope)?$`)
	reQoS   = regexp.MustCompile(`kubepods[-/](guaranteed|burstable|besteffort)`)
)

// ParseCgroupPath extracts the pod/container identity from a cgroup v2 path.
// It handles both the systemd and cgroupfs cgroup drivers. It returns ok=false
// when the path is not a Kubernetes pod cgroup (e.g. system.slice).
func ParseCgroupPath(path string) (ContainerRef, bool) {
	if !strings.Contains(path, "kubepods") {
		return ContainerRef{}, false
	}
	ref := ContainerRef{CgroupPath: path}

	if m := reQoS.FindStringSubmatch(path); m != nil {
		ref.QoSClass = m[1]
	}

	if m := rePodSystemd.FindStringSubmatch(path); m != nil {
		ref.PodUID = normalizeUID(m[1])
	} else if m := rePodCgroupfs.FindStringSubmatch(path); m != nil {
		ref.PodUID = m[1]
	}

	if m := reScope.FindStringSubmatch(path); m != nil {
		switch m[1] {
		case "cri-containerd", "containerd":
			ref.Runtime = "containerd"
		case "crio":
			ref.Runtime = "crio"
		case "docker":
			ref.Runtime = "docker"
		}
		ref.ContainerID = m[2]
	}

	// A valid pod cgroup must at least identify the pod.
	if ref.PodUID == "" {
		return ContainerRef{}, false
	}
	return ref, true
}

// normalizeUID converts a systemd-form pod UID (32 hex chars, '_' separators or
// none) into the canonical dashed UUID form Kubernetes uses in pod.metadata.uid.
func normalizeUID(s string) string {
	s = strings.ReplaceAll(s, "_", "-")
	// systemd sometimes emits the UID with no separators at all.
	if len(s) == 32 && !strings.Contains(s, "-") {
		return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
	}
	return s
}
