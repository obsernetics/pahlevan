package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// repoRoot is the repository, from this package's directory.
const repoRoot = "../.."

// builtSite caches the one genuinely expensive fixture in this package:
// rendering the whole repository's site. Build only reads root and the tests
// below only read site.Files, so the five tests that each rebuilt it were
// paying five times for identical bytes - most of this package's -race
// runtime. Tests that need a site they can modify build their own from a
// temp-dir copy of the repo and are unaffected.
var builtSite = sync.OnceValues(func() (*Site, error) { return Build(repoRoot) })

// repoSite returns the shared render of the real repository. The result is
// shared across tests, so callers must treat it as read-only.
func repoSite(t *testing.T) *Site {
	t.Helper()
	site, err := builtSite()
	if err != nil {
		t.Fatalf("building the site: %v", err)
	}
	return site
}

// docsOnDisk lists the real documents, so these tests describe the repository
// rather than a copy of it. Hardcoding the list is how a new document gets
// written, merged, and published nowhere: the list would still pass.
func docsOnDisk(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot, docsDir))
	if err != nil {
		t.Fatalf("reading docs/: %v", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".md" {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("no markdown found in docs/; this test is proving nothing")
	}
	return names
}

func TestEveryDocumentIsPublishedAndIndexed(t *testing.T) {
	t.Parallel()
	index, err := os.ReadFile(filepath.Join(repoRoot, docsOut, "index.html"))
	if err != nil {
		t.Fatalf("reading the documentation index: %v", err)
	}

	for _, name := range docsOnDisk(t) {
		slug := slugOf(name)
		page := filepath.Join(repoRoot, docsOut, slug+".html")
		if _, err := os.Stat(page); err != nil {
			t.Errorf("docs/%s has no published page at %s/%s.html, so the site does not have it at all.\n"+
				"run: go run ./hack/sitegen -write", name, docsOut, slug)
			continue
		}
		if !strings.Contains(string(index), `href="`+slug+`.html"`) {
			t.Errorf("docs/%s is published but the documentation index does not link to it, "+
				"so nobody browsing the site will find it.\nrun: go run ./hack/sitegen -write", name)
		}
	}
}

func TestThePublishedPagesHaveASource(t *testing.T) {
	t.Parallel()
	// The other direction: a page for a document that no longer exists is a
	// page describing something that was removed, still served and still
	// linked to.
	have := map[string]bool{}
	for _, name := range docsOnDisk(t) {
		have[slugOf(name)+".html"] = true
	}
	have["index.html"] = true

	entries, err := os.ReadDir(filepath.Join(repoRoot, docsOut))
	if err != nil {
		t.Fatalf("reading the published docs directory: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".html" {
			continue
		}
		if !have[e.Name()] {
			t.Errorf("%s/%s is published but no document in docs/ produces it.\nrun: go run ./hack/sitegen -write",
				docsOut, e.Name())
		}
	}
}

// Adding a document has to be enough. If it is not, the next person to write
// one will find out months later that nobody could read it.
func TestANewDocumentIsPublishedWithNoOtherChange(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	if err := os.WriteFile(filepath.Join(root, docsDir, "brand-new-topic.md"),
		[]byte("# A brand new topic\n\nThe opening paragraph.\n\n## A section\n\nBody.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	site, err := Build(root)
	if err != nil {
		t.Fatalf("building the site: %v", err)
	}
	if _, ok := site.Files[docsOut+"/brand-new-topic.html"]; !ok {
		t.Error("a new document in docs/ produced no page")
	}
	index, ok := site.Files[docsOut+"/index.html"]
	if !ok {
		t.Fatal("no documentation index was produced")
	}
	if !strings.Contains(string(index), `href="brand-new-topic.html"`) {
		t.Error("a new document produced a page but no index entry, so it is published where nobody will look")
	}
	if !strings.Contains(string(index), "A brand new topic") {
		t.Error("the index does not show the new document's title")
	}
}

// Deleting a document has to unpublish it.
func TestADeletedDocumentTakesItsPageWithIt(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	if err := os.Remove(filepath.Join(root, docsDir, "architecture.md")); err != nil {
		t.Fatal(err)
	}
	site, err := Build(root)
	if err != nil {
		t.Fatalf("building the site: %v", err)
	}
	stale, err := Apply(root, site, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range stale {
		if strings.Contains(s, "architecture.html") && strings.Contains(s, "left over") {
			found = true
		}
	}
	if !found {
		t.Errorf("deleting a document left its page published and -check said nothing: %v", stale)
	}

	if _, err := Apply(root, site, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, docsOut, "architecture.html")); !os.IsNotExist(err) {
		t.Error("-write did not remove the orphaned page")
	}
}

// A diagram a document embeds has to be published with it.
func TestEmbeddedDiagramsArePublished(t *testing.T) {
	t.Parallel()
	site := repoSite(t)
	want := docsOut + "/assets/architecture.svg"
	data, ok := site.Files[want]
	if !ok {
		t.Fatalf("docs/architecture.md embeds a diagram but %s is not published; "+
			"the page would show a broken image and still return 200", want)
	}
	src, err := os.ReadFile(filepath.Join(repoRoot, "docs", "assets", "architecture.svg"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(src) {
		t.Error("the published diagram is not byte-identical to the one in docs/")
	}
}

// The repository's own site has to be current. This is the test that fails in
// review when somebody edits a document and does not regenerate.
func TestTheGeneratedSiteIsUpToDate(t *testing.T) {
	t.Parallel()
	// Apply in check mode (write=false) only reads, so the shared site is safe.
	stale, err := Apply(repoRoot, repoSite(t), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) > 0 {
		t.Errorf("the published site does not match its sources:\n  %s\n\nrun: go run ./hack/sitegen -write",
			strings.Join(stale, "\n  "))
	}
}

func TestOrderedPutsTheStartingPointsFirst(t *testing.T) {
	t.Parallel()
	docs := []Doc{
		{Slug: "zebra"}, {Slug: "architecture"}, {Slug: "aardvark"}, {Slug: "quick-start"},
	}
	got := ordered(docs)
	want := []string{"quick-start", "architecture", "aardvark", "zebra"}
	for i, w := range want {
		if got[i].Slug != w {
			t.Fatalf("order is %v, want %v", slugs(got), want)
		}
	}
}

func slugs(docs []Doc) []string {
	var out []string
	for _, d := range docs {
		out = append(out, d.Slug)
	}
	return out
}

// scratchRepo copies the parts of the repository the generator reads into a
// temporary directory, so a test can add or remove a document without touching
// the working tree.
func scratchRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{docsDir, filepath.Join(docsDir, "assets"), "pages", docsOut} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{changelogSrc, changelogOut} {
		copyFile(t, filepath.Join(repoRoot, rel), filepath.Join(root, rel))
	}
	entries, err := os.ReadDir(filepath.Join(repoRoot, docsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".md" {
			copyFile(t, filepath.Join(repoRoot, docsDir, e.Name()), filepath.Join(root, docsDir, e.Name()))
		}
	}
	copyFile(t, filepath.Join(repoRoot, docsDir, "assets", "architecture.svg"),
		filepath.Join(root, docsDir, "assets", "architecture.svg"))

	// Publish once, so the scratch repository starts in the state a checkout
	// is in: generated and up to date.
	site, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(root, site, true); err != nil {
		t.Fatal(err)
	}
	return root
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
