// The optional dashboard is the one Pahlevan component a browser talks to, and
// the one whose mistakes would be worth the most to an attacker: a service
// that describes what every workload in the cluster does, reachable from a
// laptop. The promises that keep it from becoming the soft target are all
// made in YAML - a short RBAC grant, ClusterIP, no host access, and absence
// from the manifest every cluster installs - and YAML has no compiler.
//
// This file is that compiler. Each test asserts one promise and fails if a
// manifest, or the chart, quietly stops keeping it.
package install

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// manifest is one YAML document, kept next to where it came from so a failure
// names the file an operator has to open.
type manifest struct {
	source string
	kind   string
	name   string
	raw    []byte
}

func (m manifest) String() string { return m.source + ": " + m.kind + "/" + m.name }

// splitManifests decodes a multi-document YAML stream. Kustomization
// documents are skipped: they are build instructions, not cluster objects,
// and they carry none of the fields these tests check.
func splitManifests(t *testing.T, source string, data []byte) []manifest {
	t.Helper()
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	var out []manifest
	for {
		doc, err := r.Read()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("splitting %s: %v", source, err)
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := yaml.Unmarshal(doc, &head); err != nil {
			t.Fatalf("parsing a document in %s: %v", source, err)
		}
		if head.Kind == "" || head.Kind == "Kustomization" {
			continue
		}
		out = append(out, manifest{source: source, kind: head.Kind, name: head.Metadata.Name, raw: doc})
	}
}

// dashboardManifests is everything under deploy/dashboard, including
// rbac-namespaced.yaml, which the default kustomization does not apply but an
// operator may. A grant that is shipped is a grant that will be used.
func dashboardManifests(t *testing.T) []manifest {
	t.Helper()
	files, err := filepath.Glob(repoPath("deploy/dashboard/*.yaml"))
	if err != nil {
		t.Fatalf("globbing deploy/dashboard: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("deploy/dashboard has no manifests; the optional dashboard is supposed to ship one")
	}
	var out []manifest
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		rel, _ := filepath.Rel(repoRoot, f)
		out = append(out, splitManifests(t, rel, b)...)
	}
	return out
}

func kinds(ms []manifest, kind ...string) []manifest {
	want := map[string]bool{}
	for _, k := range kind {
		want[k] = true
	}
	var out []manifest
	for _, m := range ms {
		if want[m.kind] {
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 1. The dashboard is optional, and optional means absent from the manifest
//    every cluster installs.
// ---------------------------------------------------------------------------

func TestDashboardIsAbsentFromTheInstallManifest(t *testing.T) {
	b, err := os.ReadFile(repoPath("install.yaml"))
	if err != nil {
		t.Fatalf("reading install.yaml: %v", err)
	}
	// The generator is an explicit list of files, so the check is on both the
	// committed manifest and a fresh run: a new emit line would show up here
	// before it shows up in a cluster that applied a release asset.
	for name, content := range map[string]string{
		"install.yaml":                  string(b),
		"scripts/gen-install.sh output": generate(t),
	} {
		for _, m := range splitManifests(t, name, []byte(content)) {
			if strings.Contains(strings.ToLower(m.name), "dashboard") {
				t.Errorf("%s ships %s/%s; the dashboard is opt-in, and a release manifest that installs it makes every cluster run a browser-facing service it never asked for", name, m.kind, m.name)
			}
		}
		if strings.Contains(strings.ToLower(content), "pahlevan-dashboard") {
			t.Errorf("%s references the dashboard image or objects; see deploy/dashboard, which is deliberately not one of the files gen-install.sh emits", name)
		}
	}
}

func TestGenInstallDoesNotReadTheDashboardDirectory(t *testing.T) {
	b, err := os.ReadFile(repoPath("scripts/gen-install.sh"))
	if err != nil {
		t.Fatalf("reading scripts/gen-install.sh: %v", err)
	}
	if strings.Contains(string(b), "deploy/dashboard") {
		t.Error("gen-install.sh reads deploy/dashboard, so the opt-in dashboard would ship inside the all-in-one install manifest")
	}
}

// ---------------------------------------------------------------------------
// 2. The RBAC grant is the short list the docs promise.
// ---------------------------------------------------------------------------

// dashboardGrant is the entire set of permissions the dashboard's identity may
// hold, keyed "apiGroup/resource". Anything outside it fails: the dashboard
// authenticates and authorises through the API server and reads three CRDs,
// and every additional grant is something a request-handling bug could reach.
var dashboardGrant = map[string][]string{
	"authentication.k8s.io/tokenreviews":        {"create"},
	"authorization.k8s.io/subjectaccessreviews": {"create"},
	"policy.pahlevan.io/pahlevanpolicies":       {"get", "list", "watch"},
	"policy.pahlevan.io/containerprofiles":      {"get", "list", "watch"},
	"policy.pahlevan.io/attacksurfaces":         {"get", "list", "watch"},
}

// superuserRoles are the built-in roles a binding must never name. Binding to
// one would replace the whole audited grant above with "everything", and it
// would do so in a single line nobody reads twice.
var superuserRoles = map[string]bool{
	"cluster-admin": true,
	"admin":         true,
	"edit":          true,
}

func checkDashboardRBAC(t *testing.T, ms []manifest) {
	t.Helper()
	defined := map[string]bool{}

	for _, m := range kinds(ms, "Role", "ClusterRole") {
		var role rbacv1.ClusterRole // same Rules field as rbacv1.Role
		if err := yaml.Unmarshal(m.raw, &role); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		defined[m.kind+"/"+m.name] = true
		for _, rule := range role.Rules {
			if len(rule.NonResourceURLs) > 0 {
				t.Errorf("%s grants non-resource URLs %v, which is outside the dashboard's documented grant", m, rule.NonResourceURLs)
			}
			for _, g := range rule.APIGroups {
				if g == "*" {
					t.Errorf("%s grants apiGroups: [\"*\"]; the dashboard's grant is five entries long and auditable by reading it, which a wildcard destroys", m)
				}
			}
			for _, r := range rule.Resources {
				if r == "*" {
					t.Errorf("%s grants resources: [\"*\"]; a browser-facing process would then be able to read every object type in the cluster, secrets included", m)
				}
			}
			for _, v := range rule.Verbs {
				if v == "*" {
					t.Errorf("%s grants verbs: [\"*\"]; the dashboard is read-only, and a wildcard verb makes it a write primitive", m)
				}
			}
			for _, g := range rule.APIGroups {
				for _, res := range rule.Resources {
					key := g + "/" + res
					allowed, ok := dashboardGrant[key]
					if !ok {
						t.Errorf("%s grants %s, which is not in the dashboard's documented grant (%s). Widening it means widening what a compromised dashboard reaches", m, key, strings.Join(grantKeys(), ", "))
						continue
					}
					for _, v := range rule.Verbs {
						if !contains(allowed, v) {
							t.Errorf("%s grants %q on %s; only %v is documented, and anything beyond a read makes the dashboard able to change the policies it displays", m, v, key, allowed)
						}
					}
				}
			}
		}
	}

	for _, m := range kinds(ms, "RoleBinding", "ClusterRoleBinding") {
		var b rbacv1.ClusterRoleBinding // same RoleRef/Subjects fields as rbacv1.RoleBinding
		if err := yaml.Unmarshal(m.raw, &b); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		if superuserRoles[b.RoleRef.Name] {
			t.Errorf("%s binds the dashboard to the built-in %q role; that is cluster-admin by another name and it discards every limit this file checks", m, b.RoleRef.Name)
		}
		if !defined[b.RoleRef.Kind+"/"+b.RoleRef.Name] {
			t.Errorf("%s binds to %s/%s, which is not defined in deploy/dashboard; a binding to a role defined elsewhere is a grant nobody reviewing this directory can see", m, b.RoleRef.Kind, b.RoleRef.Name)
		}
		for _, s := range b.Subjects {
			if s.Kind != "ServiceAccount" {
				t.Errorf("%s grants the dashboard's role to a %s subject; the grant is meant for the dashboard's own identity and nothing else", m, s.Kind)
			}
			if !strings.Contains(s.Name, "dashboard") {
				t.Errorf("%s grants the dashboard's role to %q; another component picking it up spreads the grant beyond the component it was reviewed for", m, s.Name)
			}
		}
	}
}

func TestDashboardRBACIsTheShortListItClaims(t *testing.T) {
	checkDashboardRBAC(t, dashboardManifests(t))
}

// ---------------------------------------------------------------------------
// 3. ClusterIP only: nothing the project ships can publish the dashboard.
// ---------------------------------------------------------------------------

func checkDashboardServices(t *testing.T, ms []manifest) {
	t.Helper()
	seen := 0
	for _, m := range kinds(ms, "Service") {
		var svc corev1.Service
		if err := yaml.Unmarshal(m.raw, &svc); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		seen++
		if svc.Spec.Type != "" && svc.Spec.Type != corev1.ServiceTypeClusterIP {
			t.Errorf("%s is type %q; a NodePort publishes the dashboard on every node's address and a LoadBalancer asks a cloud provider for a public IP, so applying the optional dashboard would put a view of every workload's behaviour on the network without anyone deciding to", m, svc.Spec.Type)
		}
		for _, p := range svc.Spec.Ports {
			if p.NodePort != 0 {
				t.Errorf("%s pins nodePort %d on port %q, which reaches outside the cluster regardless of the service type", m, p.NodePort, p.Name)
			}
		}
		if len(svc.Spec.ExternalIPs) > 0 {
			t.Errorf("%s sets externalIPs %v, which exposes it as surely as a LoadBalancer would", m, svc.Spec.ExternalIPs)
		}
	}
	if seen == 0 {
		t.Error("no Service found for the dashboard; either it stopped shipping one or these checks stopped looking at the right place")
	}
}

func TestDashboardServiceIsClusterIPOnly(t *testing.T) {
	checkDashboardServices(t, dashboardManifests(t))
}

// ---------------------------------------------------------------------------
// 4. No host access, no privilege. The agent is the only privileged component,
//    and that is what lets the dashboard face a browser at all.
// ---------------------------------------------------------------------------

func checkDashboardPods(t *testing.T, ms []manifest) {
	t.Helper()
	seen := 0
	for _, m := range kinds(ms, "Deployment", "DaemonSet", "StatefulSet", "Pod") {
		var d appsv1.Deployment
		if err := yaml.Unmarshal(m.raw, &d); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		spec := d.Spec.Template.Spec
		seen++

		if spec.HostNetwork {
			t.Errorf("%s sets hostNetwork; the dashboard would then listen on the node's address, bypassing the ClusterIP Service and the NetworkPolicy in one line", m)
		}
		if spec.HostPID {
			t.Errorf("%s sets hostPID; a browser-facing process has no business seeing the node's processes, and it hands a request-handling bug a view of every workload on the node", m)
		}
		if spec.HostIPC {
			t.Errorf("%s sets hostIPC, which shares the node's IPC namespace with a process that talks to the internet-facing side of an ingress", m)
		}
		for _, v := range spec.Volumes {
			if v.HostPath != nil {
				t.Errorf("%s mounts hostPath %q; the dashboard reads the API server and nothing else, and a path into the node's filesystem is how a read-only viewer becomes a node compromise", m, v.HostPath.Path)
			}
		}
		if spec.SecurityContext == nil || spec.SecurityContext.RunAsNonRoot == nil || !*spec.SecurityContext.RunAsNonRoot {
			t.Errorf("%s does not set runAsNonRoot on the pod; a container escape then starts as root on the node", m)
		}
		if spec.SecurityContext == nil || spec.SecurityContext.SeccompProfile == nil ||
			spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("%s does not set seccompProfile RuntimeDefault, leaving the whole syscall table open to a process that parses untrusted HTTP", m)
		}

		for _, c := range spec.Containers {
			sc := c.SecurityContext
			if sc == nil {
				t.Errorf("%s container %q has no securityContext at all", m, c.Name)
				continue
			}
			if sc.Privileged != nil && *sc.Privileged {
				t.Errorf("%s container %q is privileged; that is node root for a process serving a browser", m, c.Name)
			}
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				t.Errorf("%s container %q allows privilege escalation, so a setuid binary in the image undoes runAsNonRoot", m, c.Name)
			}
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Errorf("%s container %q has a writable root filesystem, which lets a code-execution bug persist across the process restart that would otherwise clear it", m, c.Name)
			}
			if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				t.Errorf("%s container %q does not set runAsNonRoot", m, c.Name)
			}
			dropsAll := false
			if sc.Capabilities != nil {
				for _, d := range sc.Capabilities.Drop {
					if d == "ALL" {
						dropsAll = true
					}
				}
				if len(sc.Capabilities.Add) > 0 {
					t.Errorf("%s container %q adds capabilities %v; the dashboard needs none, and every one of them is a capability an attacker inherits", m, c.Name, sc.Capabilities.Add)
				}
			}
			if !dropsAll {
				t.Errorf("%s container %q does not drop ALL capabilities", m, c.Name)
			}
		}
	}
	if seen == 0 {
		t.Error("no dashboard workload found; either it stopped shipping one or these checks stopped looking at the right place")
	}
}

func TestDashboardPodsHoldNoHostAccessOrPrivilege(t *testing.T) {
	checkDashboardPods(t, dashboardManifests(t))
}

// ---------------------------------------------------------------------------
// 5. The chart keeps the same promises, and keeps quiet by default.
// ---------------------------------------------------------------------------

func helmTemplate(t *testing.T, args ...string) []manifest {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed; the chart assertions need it")
	}
	cmd := exec.Command("helm", append([]string{"template", "pahlevan", "charts/pahlevan-operator"}, args...)...)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("helm template %v failed: %v\n%s", args, err, ee.Stderr)
		}
		t.Fatalf("running helm template %v: %v", args, err)
	}
	return splitManifests(t, "helm template "+strings.Join(args, " "), out)
}

func dashboardOnly(ms []manifest) []manifest {
	var out []manifest
	for _, m := range ms {
		if strings.Contains(strings.ToLower(m.name), "dashboard") {
			out = append(out, m)
		}
	}
	return out
}

// Default values must render not one dashboard object. Not a scaled-to-zero
// Deployment and not an unused ServiceAccount either: an idle ServiceAccount
// with a cluster-wide read binding is still a credential in the cluster.
func TestChartRendersNoDashboardByDefault(t *testing.T) {
	rendered := helmTemplate(t)
	if got := dashboardOnly(rendered); len(got) != 0 {
		var names []string
		for _, m := range got {
			names = append(names, m.kind+"/"+m.name)
		}
		sort.Strings(names)
		t.Errorf("a default chart install renders %d dashboard object(s): %s. The dashboard is off by default, which has to mean the objects do not exist", len(got), strings.Join(names, ", "))
	}
	if len(rendered) == 0 {
		t.Error("the chart rendered nothing at all, so this test would pass no matter what the dashboard template did")
	}
}

func TestChartRendersTheDashboardWhenEnabled(t *testing.T) {
	got := dashboardOnly(helmTemplate(t, "--set", "dashboard.enabled=true"))
	if len(got) == 0 {
		t.Fatal("dashboard.enabled=true rendered no dashboard objects")
	}
	want := map[string]bool{
		"ServiceAccount": false, "ClusterRole": false, "ClusterRoleBinding": false,
		"Deployment": false, "Service": false, "NetworkPolicy": false,
	}
	for _, m := range got {
		if _, ok := want[m.kind]; !ok {
			t.Errorf("the chart renders an unexpected dashboard object %s", m)
			continue
		}
		want[m.kind] = true
	}
	for kind, seen := range want {
		if !seen {
			t.Errorf("dashboard.enabled=true renders no %s; the chart and deploy/dashboard are supposed to deploy the same shapes", kind)
		}
	}
	// The same promises, checked against what Helm actually produces rather
	// than against the template's intent.
	checkDashboardRBAC(t, got)
	checkDashboardServices(t, got)
	checkDashboardPods(t, got)
}

// ---------------------------------------------------------------------------

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func grantKeys() []string {
	out := make([]string, 0, len(dashboardGrant))
	for k := range dashboardGrant {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func BenchmarkDashboardManifestChecks(b *testing.B) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "deploy/dashboard/*.yaml"))
	if err != nil || len(files) == 0 {
		b.Fatalf("globbing deploy/dashboard: %v", err)
	}
	var docs [][]byte
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			b.Fatal(err)
		}
		docs = append(docs, raw)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, d := range docs {
			r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(d)))
			for {
				doc, err := r.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					b.Fatal(err)
				}
				var obj map[string]interface{}
				if err := yaml.Unmarshal(doc, &obj); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
}
