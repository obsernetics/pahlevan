package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// Guards for the Kubernetes misconfiguration scan and its waiver file.
//
// This repo shipped manifests, a Helm chart, a released all-in-one YAML and a
// directory of examples people copy, and nothing scanned any of them for
// misconfiguration: .github/workflows/security.yml ran Trivy with scan-type
// fs, which looks at dependencies. The gap was invisible because a workflow
// named "Security" was green the whole time.
//
// So the job is guarded here rather than trusted. A deleted job is a failing
// test, which is the difference between a gap somebody notices and a gap that
// lasts a year.
//
// The waiver file gets the heavier guard, because that is where a scanner's
// findings go to be forgotten. Two properties are enforced: every entry says
// why, and the entries that waive the agent's privilege cannot reach the
// operator or the dashboard. The agent must be privileged to load eBPF; the
// other two must not be, and a waiver broad enough to cover them would turn a
// real regression into a silent pass.

const (
	securityWorkflow = ".github/workflows/security.yml"
	configScanJob    = "trivy-config"
	ignoreFile       = ".trivyignore.yaml"
	trivyConfigFile  = "hack/trivy/config.yaml"
)

// noisyDirs are the directories the scan must skip, and the reason the scan is
// worth running at all.
//
// pages/charts holds a published chart archive per historical release, so
// every finding in the chart is reported once per past version - hundreds of
// findings about artifacts nobody can change. Those are the
// worktrees, which are whole copies of this repo. test holds fixtures that are
// wrong on purpose.
var noisyDirs = []string{"pages", "test"}

// agentManifests are the only files a privilege waiver may name: the agent
// DaemonSet as it reaches users through the kustomize base, the Helm chart and
// the released manifest. Everything else in the tree runs unprivileged.
var agentManifests = map[string]bool{
	"deploy/base/daemonset-agent.yaml":                  true,
	"charts/pahlevan-operator/templates/daemonset.yaml": true,
	"install.yaml": true,
}

// privilegeRules are the checks that fire only on a container asking for host
// access, root, raised capabilities or a relaxed seccomp profile. The agent
// needs all of them to load and attach eBPF programs. The operator and the
// dashboard need none of them, so a waiver for one of these rules that names
// an operator or dashboard manifest is hiding a regression rather than
// documenting a requirement.
var privilegeRules = map[string]bool{
	"KSV-0001": true, // allowPrivilegeEscalation
	"KSV-0005": true, // SYS_ADMIN
	"KSV-0010": true, // hostPID
	"KSV-0012": true, // runs as root
	"KSV-0020": true, // uid <= 10000
	"KSV-0021": true, // gid <= 10000
	"KSV-0022": true, // specific capabilities added
	"KSV-0023": true, // hostPath volumes
	"KSV-0030": true, // seccomp profile not RuntimeDefault
	"KSV-0104": true, // seccomp policies disabled
	"KSV-0105": true, // runAsUser 0
	"KSV-0106": true, // capabilities beyond NET_BIND_SERVICE
	"KSV-0118": true, // default security context
	"KSV-0121": true, // disallowed volumes
}

type trivyIgnoreFile struct {
	Misconfigurations []trivyIgnoreEntry `json:"misconfigurations"`
}

type trivyIgnoreEntry struct {
	ID        string   `json:"id"`
	Paths     []string `json:"paths"`
	Statement string   `json:"statement"`
}

func loadSecurityWorkflow(t *testing.T) workflowFile {
	t.Helper()
	b, err := os.ReadFile(repoPath(securityWorkflow))
	if err != nil {
		t.Fatalf("reading %s: %v", securityWorkflow, err)
	}
	var wf workflowFile
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatalf("parsing %s: %v", securityWorkflow, err)
	}
	return wf
}

func loadIgnoreFile(t *testing.T) trivyIgnoreFile {
	t.Helper()
	b, err := os.ReadFile(repoPath(ignoreFile))
	if err != nil {
		t.Fatalf("reading %s: %v", ignoreFile, err)
	}
	var f trivyIgnoreFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		t.Fatalf("parsing %s: %v", ignoreFile, err)
	}
	if len(f.Misconfigurations) == 0 {
		t.Fatalf("%s lists no misconfiguration waivers; the guards below would pass by vacuity", ignoreFile)
	}
	return f
}

// withString reads a step's `with:` value as a string. Workflow inputs are
// always strings to Actions, but YAML may have decoded one as a bool or a
// number, so this does not assume.
func withString(with map[string]interface{}, key string) (string, bool) {
	v, ok := with[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// configScanSteps returns the Trivy step and the SARIF upload step of the
// config-scan job, failing if the job is gone.
func configScanSteps(t *testing.T) (scan, upload map[string]interface{}) {
	t.Helper()
	wf := loadSecurityWorkflow(t)
	job, ok := wf.Jobs[configScanJob]
	if !ok {
		t.Fatalf("%s has no %q job. Kubernetes misconfiguration scanning is the one thing the fs scan does not do, "+
			"and this repo went without it entirely: nothing checked the DaemonSet, the chart, install.yaml or the "+
			"examples users copy. If the job is being renamed, rename the constant in this test with it",
			securityWorkflow, configScanJob)
	}
	for i := range job.Steps {
		s := job.Steps[i]
		if !strings.Contains(s.Uses, "trivy-action") {
			continue
		}
		st, ok := withString(s.With, "scan-type")
		if !ok || st != "config" {
			continue
		}
		scan = s.With
	}
	for i := range job.Steps {
		s := job.Steps[i]
		if strings.Contains(s.Uses, "upload-sarif") {
			upload = s.With
		}
	}
	if scan == nil {
		t.Fatalf("the %q job runs no trivy-action step with scan-type: config, so it scans for vulnerabilities "+
			"and reports no misconfigurations", configScanJob)
	}
	if upload == nil {
		t.Fatalf("the %q job uploads no SARIF, so its findings reach nobody", configScanJob)
	}
	return scan, upload
}

func TestConfigScanJobExists(t *testing.T) {
	scan, _ := configScanSteps(t)
	ref, ok := withString(scan, "scan-ref")
	if !ok || ref != "." {
		t.Errorf("the config scan's scan-ref is %q, want \".\": a narrower ref silently stops covering whatever was "+
			"added outside it", scan["scan-ref"])
	}
	if f, ok := withString(scan, "format"); !ok || f != "sarif" {
		t.Errorf("the config scan's format is %q, want \"sarif\": any other format cannot be uploaded to code scanning", scan["format"])
	}
	if out, ok := withString(scan, "output"); !ok || out == "" {
		t.Error("the config scan writes no output file, so the upload step has nothing to send")
	}
}

// The skip list is the difference between a report somebody reads and a few
// hundred findings about immutable archives. Measured on this tree: 297
// findings unscoped against 89 scoped, and the 208 in between were all
// pages/charts/*.tgz - the same chart findings repeated once per released
// version.
func TestConfigScanSkipsTheNoisyDirectories(t *testing.T) {
	scan, _ := configScanSteps(t)
	raw, ok := withString(scan, "skip-dirs")
	if !ok {
		t.Fatal("the config scan sets no skip-dirs. Unscoped it reports every manifest once per released chart " +
			"archive under pages/charts, and a scanner whose output is " +
			"mostly unactionable noise gets ignored - which is worse than not running it, because it looks like coverage")
	}
	got := map[string]bool{}
	for _, d := range strings.Split(raw, ",") {
		got[strings.TrimSpace(d)] = true
	}
	for _, want := range noisyDirs {
		if !got[want] {
			t.Errorf("skip-dirs is %q and does not skip %q", raw, want)
		}
	}
}

// Two SARIF uploads from one workflow and one commit are treated as two runs
// of the same analysis unless they declare different categories, and the
// second replaces the first. Without a category here the config findings and
// the filesystem findings would delete each other depending on which job
// finished last, which looks exactly like a scan that found nothing.
func TestConfigScanUploadsUnderItsOwnCategory(t *testing.T) {
	_, upload := configScanSteps(t)
	cat, ok := withString(upload, "category")
	if !ok || strings.TrimSpace(cat) == "" {
		t.Fatal("the config scan's SARIF upload declares no category, so it shares one with the filesystem scan " +
			"in the same workflow and the two overwrite each other")
	}

	// And it must differ from every other upload in the file.
	wf := loadSecurityWorkflow(t)
	for name, job := range wf.Jobs {
		if name == configScanJob {
			continue
		}
		for _, s := range job.Steps {
			if !strings.Contains(s.Uses, "upload-sarif") {
				continue
			}
			if other, ok := withString(s.With, "category"); ok && other == cat {
				t.Errorf("job %q uploads SARIF under the same category %q as the config scan", name, cat)
			}
		}
	}
}

// The waiver file and the Rego data file are referenced by path from the
// workflow, so a rename that misses one turns into a scan that quietly waives
// nothing (hundreds of findings) or trusts no registry (eight more). The
// action fails hard on a missing ignorefile; it does not fail on a missing
// config file.
func TestConfigScanReferencesItsIgnoreFileAndItsData(t *testing.T) {
	scan, _ := configScanSteps(t)

	ign, ok := withString(scan, "trivyignores")
	if !ok || ign == "" {
		t.Fatalf("the config scan passes no trivyignores, so %s is not applied and the agent's inherent "+
			"privilege is reported as a few dozen findings on every run", ignoreFile)
	}
	if ign != ignoreFile {
		t.Errorf("the config scan reads waivers from %q, want %q", ign, ignoreFile)
	}
	if _, err := os.Stat(repoPath(ign)); err != nil {
		t.Errorf("the config scan reads waivers from %q, which does not exist: %v", ign, err)
	}

	cfg, ok := withString(scan, "trivy-config")
	if !ok || cfg == "" {
		t.Fatalf("the config scan passes no trivy-config, so the Rego data under hack/trivy/data is never loaded "+
			"and KSV-0125 falls back to its built-in registry list, which does not include ghcr.io. See %s", trivyConfigFile)
	}
	if cfg != trivyConfigFile {
		t.Errorf("the config scan reads its Trivy config from %q, want %q", cfg, trivyConfigFile)
	}
	if _, err := os.Stat(repoPath(cfg)); err != nil {
		t.Errorf("the config scan reads its Trivy config from %q, which does not exist: %v", cfg, err)
	}
}

// Every waiver has to say why, and has to say where.
//
// A statement is what separates "the kernel will not load a BPF program
// without this capability" from "this was noisy". A path list is what keeps a
// waiver from spreading: an entry with no paths waives its rule across the
// whole repository, including files that do not exist yet.
func TestEveryIgnoreWaiverIsJustified(t *testing.T) {
	// Long enough that a word cannot pass for a reason. The shortest real
	// justification in the file is several lines.
	const minStatement = 60

	for _, e := range loadIgnoreFile(t).Misconfigurations {
		if strings.TrimSpace(e.ID) == "" {
			t.Error("a waiver has no id, so it is not clear what it waives")
			continue
		}
		if n := len(strings.TrimSpace(e.Statement)); n < minStatement {
			t.Errorf("the waiver for %s has a %d-character statement, want at least %d. "+
				"An undocumented waiver is security debt with the evidence deleted: write why the finding is not a "+
				"defect, or fix the finding", e.ID, n, minStatement)
		}
		if len(e.Paths) == 0 {
			t.Errorf("the waiver for %s lists no paths, so it suppresses that rule across the entire repository, "+
				"including files nobody has written yet. Name the files it applies to", e.ID)
			continue
		}
		for _, p := range e.Paths {
			if _, err := os.Stat(repoPath(p)); err != nil {
				t.Errorf("the waiver for %s names %q, which does not exist: %v. A waiver for a file that is gone is "+
					"dead text that still widens the next person's idea of what is waived", e.ID, p, err)
			}
		}
	}
}

// The waivers for the agent's privilege must reach the agent and nothing else.
//
// SYS_ADMIN, host PID, the hostPath mounts and the Unconfined seccomp profile
// are what loading eBPF costs, and the agent is the only component that pays
// it. The operator runs unprivileged in a user namespace and the dashboard is
// a read-only web process; if either one grows a hostPath mount or starts
// running as root, this scan is the thing that should say so, and it cannot if
// the waiver covers them.
func TestPrivilegeWaiversCoverTheAgentOnly(t *testing.T) {
	for _, e := range loadIgnoreFile(t).Misconfigurations {
		if !privilegeRules[e.ID] {
			continue
		}
		for _, p := range e.Paths {
			if !agentManifests[p] {
				t.Errorf("%s waives privilege check %s for %q, which is not an agent manifest. "+
					"Only the agent DaemonSet may be waived for this rule (%v). Waiving it for the operator or the "+
					"dashboard means a regression in the components that run unprivileged would pass this scan",
					ignoreFile, e.ID, p, sortedKeys(agentManifests))
			}
		}
	}
}

// Every agent manifest should be covered by the privilege waivers, or the scan
// is red on one of the three paths the same DaemonSet ships through and
// everybody learns to ignore it.
func TestPrivilegeWaiversCoverEveryAgentManifest(t *testing.T) {
	covered := map[string]int{}
	for _, e := range loadIgnoreFile(t).Misconfigurations {
		if !privilegeRules[e.ID] {
			continue
		}
		for _, p := range e.Paths {
			covered[p]++
		}
	}
	for m := range agentManifests {
		if covered[m] == 0 {
			t.Errorf("no privilege waiver names %q, so the agent's inherent capabilities are reported as findings "+
				"on that path. The agent ships through the kustomize base, the Helm chart and install.yaml, and all "+
				"three carry the same securityContext", m)
		}
	}
}

// The deploy targets and the manifests they render.
//
// `make deploy` and `make install-all` used to run `kustomize build
// config/default`, a tree that duplicated deploy/base and had drifted: no
// startupProbe, a 64Mi memory request against BPF maps bounded at 64 MiB and
// charged to the container's memcg since kernel 5.11, a kube-rbac-proxy
// sidecar from a 2022 image upstream kubebuilder no longer scaffolds, no
// PodDisruptionBudget, no priorityClassName - and no agent DaemonSet at all,
// so the target installed a control plane with nothing on the nodes.
func TestDeployTargetsRenderTheShippedBase(t *testing.T) {
	b, err := os.ReadFile(repoPath("Makefile"))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	// Comments are stripped first. The comment above these targets explains
	// what config/default was and why `kustomize edit set image` is not used,
	// and a guard that matched prose would fail on its own documentation.
	mk := stripMakeComments(string(b))

	for _, dead := range []string{"config/default", "config/manager"} {
		if strings.Contains(mk, "build "+dead) || strings.Contains(mk, "cd "+dead) {
			t.Errorf("the Makefile still points a target at %s. deploy/base is the tree that ships - "+
				"scripts/gen-install.sh builds install.yaml from it and hack/install guards it - so a second tree "+
				"means `make deploy` installs something nobody tests", dead)
		}
	}

	for _, target := range []string{"deploy", "install-all", "undeploy"} {
		recipe := makeRecipe(t, mk, target)
		if recipe == "" {
			t.Errorf("the Makefile has no %s target", target)
			continue
		}
		if !strings.Contains(recipe, "RENDER_DEPLOY") && !strings.Contains(recipe, "deploy/base") {
			t.Errorf("the %s target does not render deploy/base:\n%s", target, recipe)
		}
	}

	// The flag is not cosmetic: deploy/base/kustomization.yaml lists the CRDs
	// from ../../config/crd, and kustomize refuses to load a resource outside
	// the base without it. Dropping it makes every deploy target fail at the
	// render step.
	if !strings.Contains(mk, "LoadRestrictionsNone") {
		t.Error("the deploy targets render deploy/base without --load-restrictor=LoadRestrictionsNone, " +
			"and deploy/base/kustomization.yaml reads the CRDs from ../../config/crd, so kustomize will refuse to build it")
	}

	// `kustomize edit set image` rewrites the base in place, which both dirties
	// the tree and pins a version in the one file ci_test.go requires to stay
	// at :latest.
	if strings.Contains(mk, "kustomize edit set image") || strings.Contains(mk, "KUSTOMIZE) edit set image") {
		t.Error("a target runs `kustomize edit set image`, which rewrites deploy/base/kustomization.yaml in place; " +
			"substitute the image in the rendered output instead")
	}
}

// The duplicate tree has to be gone, not merely unreferenced. Left on disk it
// is the next contributor's starting point, and it is also 25 of the 89
// findings this scan reports.
func TestTheDuplicateManifestTreeIsGone(t *testing.T) {
	for _, dead := range []string{"config/default", "config/manager"} {
		if _, err := os.Stat(repoPath(dead)); err == nil {
			t.Errorf("%s still exists. It duplicates deploy/base with weaker settings and nothing renders it, "+
				"so it can only drift further out of step with what ships", dead)
		}
	}

	// What stays, and why: config/crd is read by deploy/base/kustomization.yaml
	// and by scripts/gen-install.sh, and config/rbac/role.yaml is written by
	// controller-gen.
	for _, keep := range []string{"config/crd", "config/rbac/role.yaml"} {
		if _, err := os.Stat(repoPath(keep)); err != nil {
			t.Errorf("%s is missing: %v. It is generated and consumed elsewhere, so removing it breaks "+
				"install.yaml generation rather than removing a duplicate", keep, err)
		}
	}
}

// The image must not hand root to a workload that forgot to ask for it.
//
// One image carries all three binaries and the agent genuinely needs root, so
// the privilege is granted by the agent's pod spec - which says why - rather
// than by the image default. Every workload already pins a uid, so this
// changes none of them.
func TestTheImageDefaultsToANonRootUser(t *testing.T) {
	b, err := os.ReadFile(repoPath("Dockerfile"))
	if err != nil {
		t.Fatalf("reading the Dockerfile: %v", err)
	}
	df := string(b)
	if !strings.Contains(df, "\nUSER ") {
		t.Error("the Dockerfile sets no USER, so the image's default user is root and any workload that omits " +
			"runAsUser gets it")
	}
	if strings.Contains(df, "\nUSER root") || strings.Contains(df, "\nUSER 0") {
		t.Error("the Dockerfile's USER is root")
	}

	// The agent is the one workload that must override it, and it has to say so
	// explicitly rather than rely on the image.
	for _, m := range sortedKeys(agentManifests) {
		raw, err := os.ReadFile(repoPath(m))
		if err != nil {
			t.Fatalf("reading %s: %v", m, err)
		}
		if !strings.Contains(string(raw), "runAsUser: 0") {
			t.Errorf("%s does not pin runAsUser: 0 for the agent. With a non-root USER in the image the agent "+
				"would start unprivileged and bpf(2) would fail, so the override is load-bearing", m)
		}
	}
}

// stripMakeComments drops whole-line comments, so the checks below read the
// Makefile's instructions rather than its explanations.
func stripMakeComments(mk string) string {
	var out []string
	for _, l := range strings.Split(mk, "\n") {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// makeRecipe returns the recipe lines of a Makefile target.
func makeRecipe(t *testing.T, mk, target string) string {
	t.Helper()
	lines := strings.Split(mk, "\n")
	var out []string
	in := false
	for _, l := range lines {
		if strings.HasPrefix(l, target+":") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if strings.HasPrefix(l, "\t") {
			out = append(out, l)
			continue
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		break
	}
	return strings.Join(out, "\n")
}

// The Rego data has to name the registries the manifests pull from, or
// KSV-0125 falls back to its built-in Azure/ECR/GCR list and reports every
// workload in the repo.
func TestTheTrustedRegistryDataNamesTheRegistriesInUse(t *testing.T) {
	matches, err := filepath.Glob(repoPath("hack/trivy/data/*.yaml"))
	if err != nil {
		t.Fatalf("globbing hack/trivy/data: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("hack/trivy/data holds no YAML, so hack/trivy/config.yaml points at an empty data directory")
	}
	var data struct {
		KSV0125 struct {
			TrustedRegistries []string `json:"trusted_registries"`
		} `json:"ksv0125"`
	}
	var found bool
	for _, m := range matches {
		b, err := os.ReadFile(m) // #nosec G304 -- a fixed in-tree directory
		if err != nil {
			t.Fatalf("reading %s: %v", m, err)
		}
		if err := yaml.Unmarshal(b, &data); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		if len(data.KSV0125.TrustedRegistries) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no file under hack/trivy/data sets ksv0125.trusted_registries, which is the key the check reads")
	}
	// ghcr.io is where this project's own images live. Without it every
	// manifest in the repo fails KSV-0125, which is how that check became
	// eight of the 89 findings.
	var hasGHCR bool
	for _, r := range data.KSV0125.TrustedRegistries {
		if r == "ghcr.io" {
			hasGHCR = true
		}
	}
	if !hasGHCR {
		t.Errorf("ksv0125.trusted_registries is %v and does not include ghcr.io, the registry this project "+
			"publishes to", data.KSV0125.TrustedRegistries)
	}
}

func BenchmarkConfigScanGuards(b *testing.B) {
	t := &testing.T{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loadSecurityWorkflow(t)
		loadIgnoreFile(t)
	}
}

func BenchmarkParseIgnoreFile(b *testing.B) {
	raw, err := os.ReadFile(repoPath(ignoreFile))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var f trivyIgnoreFile
		if err := yaml.Unmarshal(raw, &f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrivilegeWaiverScope(b *testing.B) {
	raw, err := os.ReadFile(repoPath(ignoreFile))
	if err != nil {
		b.Fatal(err)
	}
	var f trivyIgnoreFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range f.Misconfigurations {
			if !privilegeRules[e.ID] {
				continue
			}
			for _, p := range e.Paths {
				if !agentManifests[p] {
					b.Fatalf("unexpected waiver scope for %s: %s", e.ID, p)
				}
			}
		}
	}
}
