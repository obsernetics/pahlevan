package install

import (
	"os"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// A kubebuilder RBAC marker is the easiest permission in this project to grant
// by accident. It sits in a comment above a controller, controller-gen turns it
// into config/rbac/role.yaml, and nothing connects it to what the code actually
// reads or to the RBAC the project ships.
//
// That is how `secrets` came to be granted. A marker listed
// pods;services;configmaps;secrets, no code ever read a Secret or a ConfigMap,
// and the manifests under deploy/ granted neither, so a cluster installed from
// install.yaml or the chart was fine. But anyone deploying from config/ with
// kustomize got a controller that could read every Secret in the cluster, and
// Trivy reported it as a critical finding: "ClusterRole 'manager-role'
// shouldn't have access to manage resource 'secrets'".

// coreResourcesIn returns the core-group ("") resources a manifest grants.
func coreResourcesIn(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a fixed in-tree path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, doc := range strings.Split(string(raw), "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var obj struct {
			Kind  string `json:"kind"`
			Rules []struct {
				APIGroups []string `json:"apiGroups"`
				Resources []string `json:"resources"`
			} `json:"rules"`
		}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			continue // not every document in these files is a role
		}
		if obj.Kind != "ClusterRole" && obj.Kind != "Role" {
			continue
		}
		for _, r := range obj.Rules {
			for _, g := range r.APIGroups {
				if g != "" {
					continue
				}
				for _, res := range r.Resources {
					out[res] = true
				}
			}
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTheGeneratedRoleGrantsNoSecrets is the narrow guard for the critical
// finding. Secrets are the one core resource whose exposure turns a read-only
// observability controller into a credential harvester.
func TestTheGeneratedRoleGrantsNoSecrets(t *testing.T) {
	for _, path := range []string{
		repoPath("config/rbac/role.yaml"),
		repoPath("deploy/base/rbac.yaml"),
	} {
		granted := coreResourcesIn(t, path)
		for _, forbidden := range []string{"secrets"} {
			if granted[forbidden] {
				t.Errorf("%s grants %q in the core API group. Nothing in this project reads a Secret, and a controller "+
					"that can list Secrets cluster-wide is a credential harvester if it is ever compromised. If a feature "+
					"genuinely needs this, it needs a narrower Role in one namespace, not a ClusterRole", path, forbidden)
			}
		}
	}
}

// TestTheGeneratedRoleDoesNotExceedTheShippedRBAC is the general guard: the
// markers may not quietly grant more than the manifests the project actually
// ships, because the shipped manifests are the set proven to be enough to run.
func TestTheGeneratedRoleDoesNotExceedTheShippedRBAC(t *testing.T) {
	generated := coreResourcesIn(t, repoPath("config/rbac/role.yaml"))
	shipped := coreResourcesIn(t, repoPath("deploy/base/rbac.yaml"))

	if len(generated) == 0 || len(shipped) == 0 {
		t.Fatalf("read no core-group rules (generated=%v shipped=%v); this guard is checking nothing",
			sortedKeys(generated), sortedKeys(shipped))
	}

	for _, res := range sortedKeys(generated) {
		if !shipped[res] {
			t.Errorf("config/rbac/role.yaml grants core resource %q but deploy/base/rbac.yaml does not. "+
				"The shipped manifests are the permission set the operator is known to run with, so a marker granting "+
				"more is either dead permission or a privilege the project never tested. Shipped: %v",
				res, sortedKeys(shipped))
		}
	}
}

func BenchmarkCoreResourceScan(b *testing.B) {
	path := repoPath("config/rbac/role.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- a fixed in-tree path
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, doc := range strings.Split(string(raw), "\n---") {
			var obj struct {
				Kind  string `json:"kind"`
				Rules []struct {
					APIGroups []string `json:"apiGroups"`
					Resources []string `json:"resources"`
				} `json:"rules"`
			}
			_ = yaml.Unmarshal([]byte(doc), &obj)
		}
	}
}
