package main

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// Rebuilding the learned allow-sets from the published profiles.
//
// This is the FALLBACK for a restart, kept in its own file so it is never
// mistaken for the primary mechanism. The primary mechanism is bpffs pinning
// (pkg/ebpf/pinning.go): the maps themselves survive the agent, with every
// entry intact, and the programs never detach, so there is no gap and nothing
// to rebuild. This path exists only for the nodes where pinning is impossible -
// no bpffs, a kernel without BPF_OBJ_PIN, a read-only /sys/fs/bpf - and for the
// deliberate rebuild that follows a change to the BPF programs themselves.
//
// It runs ONLY when pinned state was not adopted. Running it after a successful
// adoption would write entries into maps that already hold the real, complete
// sets, re-adding anything an operator had since revoked.
//
// What it restores is lossy, and pkg/ebpf/reseed.go spells out why: a
// ContainerProfile records a path but not write intent, and a destination but
// not its transport, while the kernel keys on both. So this is a head start on
// re-learning, not a restoration of the previous state, and the log line says
// how much came back so nobody mistakes it for one.

// restoreAllowSetsFromProfiles seeds the kernel allow-sets from the
// ContainerProfile resources this node's agent published before it restarted.
//
// The reader is deliberately the direct API reader rather than the manager's
// cache: this runs before the manager starts, and a cache that has not synced
// would report that no container on this node has ever been profiled - which
// looks exactly like a first install and would silently restore nothing.
func restoreAllowSetsFromProfiles(ctx context.Context, r client.Reader, m *ebpf.Manager, node string) (ebpf.RestoreReport, error) {
	var list policyv1beta1.ContainerProfileList
	if err := r.List(ctx, &list); err != nil {
		return ebpf.RestoreReport{}, fmt.Errorf("listing container profiles: %w", err)
	}

	entries := make([]ebpf.RestoreEntry, 0, len(list.Items))
	for i := range list.Items {
		p := &list.Items[i]
		// Another node's profile describes another node's cgroups. Its cgroup
		// ids are meaningless here and would key allow-set entries onto
		// whatever local cgroup happened to collide with them.
		if node != "" && p.Spec.Node != node {
			continue
		}
		if p.Spec.CgroupID == 0 {
			continue
		}
		entries = append(entries, ebpf.RestoreEntry{
			Name:                p.Namespace + "/" + p.Name,
			CgroupID:            uint64(p.Spec.CgroupID),
			Files:               p.Status.LearnedFiles,
			Executables:         p.Status.LearnedExecutables,
			Capabilities:        p.Status.LearnedCapabilities,
			NetworkDestinations: p.Status.LearnedNetworkDestinations,
		})
	}
	if len(entries) == 0 {
		return ebpf.RestoreReport{}, nil
	}
	return m.RestoreAllowSets(entries), nil
}
