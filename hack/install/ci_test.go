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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
