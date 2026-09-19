// Package install holds the guard for the generated install manifest.
//
// install.yaml is assembled by scripts/gen-install.sh from deploy/base and
// config/crd, and it is the file attached to every GitHub release.
// docs/packages.md points readers at
// releases/download/<version>/install.yaml and calls it the immutable tag
// recommended for production.
//
// Nothing checked either half of that. The manifest could drift from the
// sources it claims to be generated from, because no workflow regenerated it;
// and it shipped `image: ghcr.io/obsernetics/pahlevan:latest`, so the path
// sold as immutable pinned nothing at all and every node pulled a tag that
// moves on each merge to main.
package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const repoRoot = "../.."

func repoPath(rel string) string { return filepath.Join(repoRoot, rel) }

func generate(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("bash", "scripts/gen-install.sh")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("gen-install.sh failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("running gen-install.sh: %v", err)
	}
	return string(out)
}

// makefileVersion is the release the manifest should pin to, read the same way
// gen-install.sh and hack/pagesync read it: from the Makefile, which is the
// one place the version is declared.
func makefileVersion(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(repoPath("Makefile"))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	m := regexp.MustCompile(`(?m)^VERSION\?=\s*(v[0-9][^\s]*)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("the Makefile has no VERSION?= line")
	}
	return string(m[1])
}

func TestInstallYAMLIsRegeneratedFromItsSources(t *testing.T) {
	committed, err := os.ReadFile(repoPath("install.yaml"))
	if err != nil {
		t.Fatalf("reading install.yaml: %v", err)
	}
	if got := generate(t); got != string(committed) {
		t.Error("install.yaml differs from what scripts/gen-install.sh produces.\n" +
			"A change to deploy/base or config/crd does not reach the released manifest on its own.\n" +
			"Run: scripts/gen-install.sh > install.yaml")
	}
}

func TestInstallYAMLPinsTheRelease(t *testing.T) {
	b, err := os.ReadFile(repoPath("install.yaml"))
	if err != nil {
		t.Fatalf("reading install.yaml: %v", err)
	}
	manifest := string(b)
	want := "ghcr.io/obsernetics/pahlevan:" + makefileVersion(t)

	// Every workload image must carry the release tag. A manifest attached to
	// an immutable release that pulls a moving tag is worse than one that says
	// nothing, because the reader was told it was pinned.
	image := regexp.MustCompile(`image:\s*(ghcr\.io/obsernetics/pahlevan:\S+)`)
	found := image.FindAllStringSubmatch(manifest, -1)
	if len(found) == 0 {
		t.Fatal("install.yaml references no pahlevan image; the generator or the base changed shape")
	}
	for _, m := range found {
		if m[1] != want {
			t.Errorf("install.yaml deploys %q, want %q", m[1], want)
		}
	}
	if strings.Contains(manifest, "pahlevan:latest") {
		t.Error("install.yaml still references pahlevan:latest, so the release manifest pins nothing")
	}
}

// deploy/base keeps :latest on purpose: it is a kustomize base and an overlay
// sets its own tag. Pinning it there would push a version bump into a file
// that has no business carrying one, so the pin belongs in the generator.
func TestTheKustomizeBaseIsNotPinned(t *testing.T) {
	for _, f := range []string{
		"deploy/base/daemonset-agent.yaml",
		"deploy/base/deployment-operator.yaml",
	} {
		b, err := os.ReadFile(repoPath(f))
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		if !strings.Contains(string(b), "ghcr.io/obsernetics/pahlevan:latest") {
			t.Errorf("%s no longer uses :latest; the base is where a version should NOT be hardcoded", f)
		}
	}
}

// The version the docs tell people to download has to be the version the
// manifest at that URL deploys, or the instructions send them somewhere that
// installs something else.
func TestPackagesDocAndManifestAgree(t *testing.T) {
	b, err := os.ReadFile(repoPath("docs/packages.md"))
	if err != nil {
		t.Fatalf("reading docs/packages.md: %v", err)
	}
	want := makefileVersion(t)
	doc := string(b)
	if !strings.Contains(doc, "releases/download/") {
		t.Skip("docs/packages.md no longer points at a release asset")
	}
	// pagesync keeps these spans in step with the Makefile; this asserts the
	// result rather than trusting that it ran.
	span := regexp.MustCompile(`releases/download/<!--\s*pahlevan:sync version\s*-->(v[0-9][^<]*)<!--`)
	m := span.FindAllStringSubmatch(doc, -1)
	if len(m) == 0 {
		t.Fatal("the release-download URL in docs/packages.md is not covered by a sync marker, so it can go stale silently")
	}
	for _, g := range m {
		if g[1] != want {
			t.Errorf("docs/packages.md sends readers to release %s, but the manifest pins %s", g[1], want)
		}
	}
}

func BenchmarkGenerateInstallManifest(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("bash", "scripts/gen-install.sh")
		cmd.Dir = repoRoot
		if _, err := cmd.Output(); err != nil {
			b.Fatal(err)
		}
	}
}

// The release-tag check is itself a workflow, and a workflow that stops
// running is indistinguishable from one that keeps passing. These assert it
// still exists, still runs on a schedule, and still calls the script - the
// three ways it could quietly stop protecting anything.
func TestTheReleaseTagCheckStillRuns(t *testing.T) {
	const wf = repoRoot + "/.github/workflows/release-tagged.yml"
	b, err := os.ReadFile(wf)
	if err != nil {
		t.Fatalf("reading %s: %v", wf, err)
	}
	var w struct {
		On struct {
			Schedule []struct {
				Cron string `json:"cron"`
			} `json:"schedule"`
		} `json:"true"` // unquoted `on:` is YAML 1.1's boolean true
		Jobs map[string]struct {
			Steps []struct {
				Run string `json:"run"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatalf("parsing %s: %v", wf, err)
	}
	if len(w.On.Schedule) == 0 {
		t.Error("no schedule; an untagged release would go unnoticed, which is the entire point")
	}
	var runsCheck bool
	for _, j := range w.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, "check-release-tagged.sh") {
				runsCheck = true
			}
		}
	}
	if !runsCheck {
		t.Error("no step runs scripts/check-release-tagged.sh, so the job passes without checking anything")
	}
}

// The script is the check. If it stops failing on an untagged version it is a
// green tick that means nothing, so this drives it both ways against a
// throwaway repo rather than trusting it against whatever this clone happens
// to have fetched.
func TestCheckReleaseTaggedScript(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) error {
		c := exec.Command(args[0], args[1:]...)
		c.Dir = dir
		return c.Run()
	}
	for _, c := range [][]string{
		{"git", "init", "-q"},
		{"git", "config", "user.email", "t@example.com"},
		{"git", "config", "user.name", "t"},
	} {
		if err := run(c...); err != nil {
			t.Skipf("git unavailable: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(repoPath("scripts/check-release-tagged.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts/check-release-tagged.sh"), src, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(v string) {
		if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("VERSION?="+v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("v1.0.0")
	if err := run("git", "add", "-A"); err != nil {
		t.Fatal(err)
	}
	if err := run("git", "commit", "-qm", "x"); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(dir, "scripts/check-release-tagged.sh")

	// Untagged: must fail. This is the case that shipped three phantom
	// releases.
	if err := exec.Command("bash", script).Run(); err == nil {
		t.Error("the script passed with v1.0.0 untagged; it would not have caught v3.1.0, v3.3.1 or v3.3.3")
	}

	// Tagged: must pass.
	if err := run("git", "tag", "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("bash", script).Run(); err != nil {
		t.Errorf("the script failed with v1.0.0 tagged: %v", err)
	}

	// A Makefile with no VERSION is a different failure and must not be
	// reported as an untagged release.
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("all:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = exec.Command("bash", script).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Errorf("a Makefile with no VERSION exited %v, want exit code 2", err)
	}
}
