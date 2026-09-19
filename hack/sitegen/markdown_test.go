package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// update rewrites the golden files. The conversion is a hundred small
// decisions - which links leave the site, what a table becomes, whether a code
// fence keeps its language - and a golden file is the only way to see all of
// them change at once when the renderer or its options move.
//
//	go test ./hack/sitegen -update
var update = flag.Bool("update", false, "rewrite the golden files")

// siblingSlugs is the fixture's idea of which documents the site publishes.
// architecture.md, quick-start.md and troubleshooting.md are published;
// Makefile and CHANGELOG.md are not.
func siblingSlugs() map[string]bool {
	return map[string]bool{"architecture": true, "quick-start": true, "troubleshooting": true}
}

func TestMarkdownGolden(t *testing.T) {
	for _, name := range []string{"kitchen-sink", "sync-markers"} {
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata", name+".md"))
			if err != nil {
				t.Fatal(err)
			}
			page, err := Convert(src, siblingSlugs())
			if err != nil {
				t.Fatalf("converting %s: %v", name, err)
			}

			got := "TITLE: " + page.Title + "\nSUMMARY: " + page.SummaryHTML + "\nHEADINGS:\n"
			for _, h := range page.Headings {
				got += "  #" + h.ID + " " + h.Text + "\n"
			}
			got += "ASSETS: " + strings.Join(page.Assets, ", ") + "\nBODY:\n" + page.BodyHTML + "\n"

			golden := filepath.Join("testdata", name+".golden")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run: go test ./hack/sitegen -update)", err)
			}
			if got != string(want) {
				t.Errorf("%s renders differently than its golden file.\n--- got ---\n%s\n--- want ---\n%s\n"+
					"If the change is intended: go test ./hack/sitegen -update", name, got, string(want))
			}
		})
	}
}

// The individual conversions the golden file covers, called out so a failure
// says which one broke rather than printing a whole document.
func TestMarkdownConversions(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "kitchen-sink.md"))
	if err != nil {
		t.Fatal(err)
	}
	page, err := Convert(src, siblingSlugs())
	if err != nil {
		t.Fatal(err)
	}
	body := page.BodyHTML

	cases := []struct {
		what string
		want string
	}{
		{"the H1 becomes the page title, not body content", ""},
		{"a heading keeps a stable id for the table of contents", `<h2 id="a-table">A table</h2>`},
		{"a third-level heading renders", `<h3 id="a-third-level-heading">A third-level heading</h3>`},
		{"inline code renders", "<code>inline code</code>"},
		{"bold renders", "<strong>bold</strong>"},
		{"a fenced block keeps its language so the page can highlight it", `<pre><code class="language-yaml">`},
		{"a fence without a language still renders as code", "<pre><code>no language on this fence"},
		{"the fence content is not re-indented", "apiVersion: policy.pahlevan.io/v1alpha1\n"},
		{"a GFM table renders as a table", "<table>"},
		{"a table header cell renders", "<th>Field</th>"},
		{"a link to a published document stays on the site", `href="architecture.html"`},
		{"a fragment survives the rewrite", `href="quick-start.html#installation"`},
		{"a link to a repository file goes to GitHub", `href="` + blobURL + `Makefile"`},
		{"the changelog links to the page, not the markdown", `href="../changelog.html"`},
		{"an external link opens in a new tab", `target="_blank"`},
		{"an external link cannot reach back through window.opener", `rel="noopener"`},
		{"a block quote renders", "<blockquote>"},
		{"a nested list renders", "<ol>"},
	}
	for _, c := range cases {
		if c.want == "" {
			continue
		}
		if !strings.Contains(body, c.want) {
			t.Errorf("%s: %q is not in the rendered body", c.what, c.want)
		}
	}

	if page.Title != "Policy reference" {
		t.Errorf("title is %q, want %q", page.Title, "Policy reference")
	}
	if strings.Contains(body, "<h1") {
		t.Error("the H1 is still in the body; it would be printed twice, once in each of two type scales")
	}
	if !strings.HasPrefix(page.SummaryHTML, "A policy says which workloads") {
		t.Errorf("the lede was not lifted out of the body: %q", page.SummaryHTML)
	}
	if strings.Contains(body, "A policy says which workloads") {
		t.Error("the lede is in the page header and still in the body")
	}
}

// The markers are plumbing between two generators. Published as written they
// would put an HTML comment in the middle of a command a reader copies.
func TestSyncMarkersArePublishedAsTheirValue(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sync-markers.md"))
	if err != nil {
		t.Fatal(err)
	}
	page, err := Convert(src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.BodyHTML, "pahlevan:sync") {
		t.Errorf("a pagesync marker reached the published page:\n%s", page.BodyHTML)
	}
	if !strings.Contains(page.BodyHTML, "ghcr.io/obsernetics/pahlevan:v9.9.9") {
		t.Errorf("the value inside the marker was lost:\n%s", page.BodyHTML)
	}
}

// Anyone with commit access can put a <script> in a docs file, and several
// people are rewriting these documents. The renderer, not a reviewer, is what
// has to stop it reaching the site.
func TestMarkupInMarkdownNeverReachesThePage(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "unsafe.md"))
	if err != nil {
		t.Fatal(err)
	}
	page, err := Convert(src, nil)
	if err != nil {
		// Refusing to build is an acceptable outcome, and the safer one.
		if !strings.Contains(err.Error(), "must never reach the published site") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	for _, bad := range []string{"<script", "onerror=", "<iframe", "javascript:", "onclick="} {
		if strings.Contains(strings.ToLower(page.BodyHTML), bad) {
			t.Errorf("%q survived into the rendered page:\n%s", bad, page.BodyHTML)
		}
	}
}

func TestRejectScript(t *testing.T) {
	if err := rejectScript("<p>ordinary text</p>"); err != nil {
		t.Errorf("ordinary markup was rejected: %v", err)
	}
	for _, bad := range []string{`<script src="x">`, `<SCRIPT>`, `<a href="javascript:x">`, `<img onerror=x>`, `<iframe>`} {
		if err := rejectScript(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestLinkRewriting(t *testing.T) {
	rw := &linkRewriter{base: docsDir, siblings: siblingSlugs(), assets: map[string]bool{}}
	cases := []struct {
		in, want string
		external bool
	}{
		{"architecture.md", "architecture.html", false},
		{"architecture.md#components", "architecture.html#components", false},
		{"lsm-support.md", blobURL + "docs/lsm-support.md", true},
		{"../CHANGELOG.md", "../changelog.html", false},
		{"../Makefile", blobURL + "Makefile", true},
		{"benchmarks/", treeURL + "docs/benchmarks", true},
		{"assets/architecture.svg", "assets/architecture.svg", false},
		{"https://example.org", "https://example.org", true},
		{"mailto:someone@example.org", "mailto:someone@example.org", true},
		{"#anchor", "#anchor", false},
	}
	for _, c := range cases {
		got, external := rw.rewrite(c.in)
		if got != c.want || external != c.external {
			t.Errorf("rewrite(%q) = (%q, %v), want (%q, %v)", c.in, got, external, c.want, c.external)
		}
	}
	if !rw.assets["docs/assets/architecture.svg"] {
		t.Error("the diagram was not collected for publication; the page would show a broken image and still return 200")
	}
}

// A document with no H1 would publish a page whose header is empty and whose
// browser tab says only "Pahlevan - ".
func TestADocumentWithNoTitleIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, docsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, docsDir, "untitled.md"), []byte("just a paragraph\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocs(dir); err == nil || !strings.Contains(err.Error(), "no H1") {
		t.Fatalf("expected a missing-title error, got %v", err)
	}
}

func TestSummarise(t *testing.T) {
	if got := summarise("short text", 100); got != "short text" {
		t.Errorf("short text was changed: %q", got)
	}
	long := strings.Repeat("word ", 100)
	got := summarise(long, 50)
	if len(got) > 53 {
		t.Errorf("summary is %d characters, want at most ~50: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a truncated summary should say so: %q", got)
	}
	if got := summarise("line one\n  line two", 100); got != "line one line two" {
		t.Errorf("wrapping was not collapsed: %q", got)
	}
}
