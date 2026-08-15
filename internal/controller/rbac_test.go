package controller

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

const rbacManifest = "../../deploy/base/rbac.yaml"

// watchedType matches the builder calls that install an informer. Each one
// makes controller-runtime list and watch that kind at startup, and a missing
// grant means the cache never syncs and the manager exits.
var watchedType = regexp.MustCompile(`(?:For|Owns|Watches)\(&([a-zA-Z0-9_]+)\.([A-Za-z0-9]+)\{\}`)

// goTypeToResource maps the Go types the controllers watch onto the
// (apiGroup, resource) pair RBAC names them by.
var goTypeToResource = map[string]struct{ group, resource string }{
	"corev1.Pod":                      {"", "pods"},
	"corev1.Node":                     {"", "nodes"},
	"corev1.Service":                  {"", "services"},
	"corev1.Namespace":                {"", "namespaces"},
	"corev1.Event":                    {"", "events"},
	"appsv1.Deployment":               {"apps", "deployments"},
	"appsv1.ReplicaSet":               {"apps", "replicasets"},
	"appsv1.DaemonSet":                {"apps", "daemonsets"},
	"appsv1.StatefulSet":              {"apps", "statefulsets"},
	"networkingv1.NetworkPolicy":      {"networking.k8s.io", "networkpolicies"},
	"policyv1alpha1.PahlevanPolicy":   {"policy.pahlevan.io", "pahlevanpolicies"},
	"policyv1alpha1.ContainerProfile": {"policy.pahlevan.io", "containerprofiles"},
	"policyv1alpha1.AttackSurface":    {"policy.pahlevan.io", "attacksurfaces"},
}

type clusterRole struct {
	name  string
	rules []rbacRule
}

type rbacRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

func (r clusterRole) grants(group, resource string, verbs ...string) bool {
	for _, rule := range r.rules {
		if !contains(rule.APIGroups, group) || !contains(rule.Resources, resource) {
			continue
		}
		all := true
		for _, v := range verbs {
			if !contains(rule.Verbs, v) && !contains(rule.Verbs, "*") {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func loadClusterRoles(t *testing.T) map[string]clusterRole {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(rbacManifest))
	require.NoError(t, err)

	roles := map[string]clusterRole{}
	for _, chunk := range strings.Split(string(raw), "\n---") {
		if strings.TrimSpace(chunk) == "" {
			continue
		}
		var doc struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Rules []rbacRule `json:"rules"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(chunk), &doc))
		if doc.Kind != "ClusterRole" {
			continue
		}
		roles[doc.Metadata.Name] = clusterRole{name: doc.Metadata.Name, rules: doc.Rules}
	}
	require.NotEmpty(t, roles, "expected ClusterRoles in %s", rbacManifest)
	return roles
}

// watchedResources scans the controllers for every kind they install an
// informer on, so the check is derived from the code rather than from a list
// somebody has to remember to update.
func watchedResources(t *testing.T) map[struct{ group, resource string }][]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	out := map[struct{ group, resource string }][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		require.NoError(t, err)
		for _, m := range watchedType.FindAllStringSubmatch(string(src), -1) {
			goType := m[1] + "." + m[2]
			res, known := goTypeToResource[goType]
			require.True(t, known,
				"%s watches %s, which this test does not know how to map to an RBAC "+
					"resource. Add it to goTypeToResource so the grant is checked.", e.Name(), goType)
			out[res] = append(out[res], e.Name())
		}
	}
	require.NotEmpty(t, out, "expected to find watched types in the controllers")
	return out
}

// Every kind a controller installs an informer on must be listable and
// watchable by both service accounts that run these controllers.
//
// This shipped broken. The agent runs AttackSurfaceAnalyzerReconciler, which
// Owns() Services, Deployments, StatefulSets, DaemonSets and NetworkPolicies,
// and its ClusterRole granted none of them. The informers never synced, the
// manager exited after the two-minute cache timeout, and the agent restarted
// four times in ten minutes. Each restart wipes the in-memory learned
// baseline, and it was observed enforcing with a baseline of a single file,
// which is far worse than not enforcing at all.
func TestRBACCoversEveryWatchedResource(t *testing.T) {
	roles := loadClusterRoles(t)
	watched := watchedResources(t)

	// Both binaries construct the same reconcilers, so both need the grants.
	for _, roleName := range []string{"pahlevan-agent", "pahlevan-operator"} {
		role, ok := roles[roleName]
		require.True(t, ok, "no ClusterRole named %s in %s", roleName, rbacManifest)

		var missing []string
		for res, sources := range watched {
			if !role.grants(res.group, res.resource, "list", "watch") {
				group := res.group
				if group == "" {
					group = "core"
				}
				missing = append(missing, group+"/"+res.resource+
					" (watched by "+strings.Join(uniq(sources), ", ")+")")
			}
		}
		sort.Strings(missing)
		require.Empty(t, missing,
			"ClusterRole %s cannot list+watch resources its controllers watch, so the "+
				"informer cache will never sync and the manager will exit: %v", roleName, missing)
	}
}

// The agent must not be able to write cluster workloads. It reads them only to
// describe the attack surface, and a DaemonSet running privileged on every
// node is the last thing that should be able to edit a Deployment.
func TestAgentCannotWriteWorkloads(t *testing.T) {
	role, ok := loadClusterRoles(t)["pahlevan-agent"]
	require.True(t, ok)

	for _, res := range []struct{ group, resource string }{
		{"apps", "deployments"},
		{"apps", "daemonsets"},
		{"apps", "statefulsets"},
		{"apps", "replicasets"},
		{"networking.k8s.io", "networkpolicies"},
		{"", "services"},
		{"", "namespaces"},
		{"", "nodes"},
	} {
		for _, verb := range []string{"create", "update", "patch", "delete"} {
			require.False(t, role.grants(res.group, res.resource, verb),
				"the agent should not be able to %s %s/%s", verb, res.group, res.resource)
		}
	}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
