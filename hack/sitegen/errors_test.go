package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The failure modes worth having tests for are the quiet ones: the cases where
// a generator that kept going would publish something wrong rather than stop.

func TestAnEmptyDocsDirectoryIsAnError(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, docsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDocs(root)
	if err == nil || !strings.Contains(err.Error(), "no markdown files") {
		t.Fatalf("an empty docs/ should stop the build rather than publish an empty documentation section, got %v", err)
	}
}

func TestAMissingDocsDirectoryIsAnError(t *testing.T) {
	t.Parallel()
	if _, err := LoadDocs(t.TempDir()); err == nil {
		t.Fatal("a missing docs/ was accepted")
	}
}

func TestAMissingChangelogIsAnError(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	if err := os.Remove(filepath.Join(root, changelogSrc)); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root); err == nil || !strings.Contains(err.Error(), changelogSrc) {
		t.Fatalf("a missing CHANGELOG.md should stop the build, got %v", err)
	}
}

func TestAChangelogWithNoReleasesIsAnError(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	if err := os.WriteFile(filepath.Join(root, changelogSrc), []byte("# Changelog\n\nNothing here.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseChangelog(root); err == nil || !strings.Contains(err.Error(), "no release headings") {
		t.Fatalf("a changelog with no releases should stop the build rather than publish an empty list, got %v", err)
	}
}

// If the markers are deleted from the page, the articles have nowhere to go.
// Carrying on would leave whatever was last committed published for ever.
func TestAChangelogPageWithNoRegionIsAnError(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	page, err := os.ReadFile(filepath.Join(root, changelogOut))
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Replace(string(page), releaseOpen, "", 1)
	if err := os.WriteFile(filepath.Join(root, changelogOut), []byte(stripped), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "region") {
		t.Fatalf("a page with no generated region should be an error, got %v", err)
	}
}

// A document embedding a diagram that is not in the repository would publish a
// page with a broken image, and the page would still return 200.
func TestAMissingDiagramIsAnError(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	if err := os.Remove(filepath.Join(root, docsDir, "assets", "architecture.svg")); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "architecture.svg") {
		t.Fatalf("a missing diagram should stop the build, got %v", err)
	}
}

// Every page needs a meta description: it is what a search result shows, and
// an empty one shows a scrape of the navigation instead.
func TestADocumentWithNoLedeStillDescribesItself(t *testing.T) {
	t.Parallel()
	page := &Page{Title: "A topic"}
	got := metaDescription(page)
	if !strings.Contains(got, "A topic") {
		t.Errorf("description is %q, want it to name the page", got)
	}
}

func TestCollapseProse(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"a\nb   c", "a b c"},
		{"<p>one</p>\n<p>two</p>", "<p>one</p> <p>two</p>"},
		{"text\n<pre><code>a\nb\n</code></pre>\nmore", "text\n<pre><code>a\nb\n</code></pre>\nmore"},
		{"<pre>only</pre>", "<pre>only</pre>"},
		// Unbalanced markup: collapse rather than guess where the block ends.
		{"<pre>never closed", "<pre>never closed"},
	}
	for _, c := range cases {
		if got := collapseProse(c.in); got != c.want {
			t.Errorf("collapseProse(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnwrapParagraph(t *testing.T) {
	t.Parallel()
	if got := unwrapParagraph("<p>text</p>\n"); got != "text" {
		t.Errorf("got %q", got)
	}
	// Two paragraphs are not a single one: unwrapping them would concatenate
	// two sentences into one with no space and no break.
	two := "<p>one</p>\n<p>two</p>"
	if got := unwrapParagraph(two); got != two {
		t.Errorf("got %q, want the input unchanged", got)
	}
	if got := unwrapParagraph("plain"); got != "plain" {
		t.Errorf("got %q", got)
	}
}

// A title or description out of a markdown file lands inside an HTML
// attribute. A quote in one would close the attribute and spill the rest of
// the sentence into the markup.
func TestLayoutEscapesItsValues(t *testing.T) {
	t.Parallel()
	l := newLayout(`A "quoted" <title>`, `An & ampersand`, "docs/x.html", "docs/x.md", "<p>body</p>")
	out, err := l.render()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, `<title>Pahlevan - A "quoted" <title></title>`) {
		t.Error("the title was not escaped")
	}
	if !strings.Contains(s, "&#34;quoted&#34;") || !strings.Contains(s, "&lt;title&gt;") {
		t.Errorf("expected escaped title in:\n%s", s[:600])
	}
	if !strings.Contains(s, "An &amp; ampersand") {
		t.Error("the description was not escaped")
	}
	if !strings.Contains(s, "<p>body</p>") {
		t.Error("the generated body was escaped; it is markup, not text")
	}
}

// -write has to create the directory the first time.
func TestWriteCreatesTheOutputDirectory(t *testing.T) {
	t.Parallel()
	root := scratchRepo(t)
	if err := os.RemoveAll(filepath.Join(root, docsOut)); err != nil {
		t.Fatal(err)
	}
	site, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(root, site, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, docsOut, "index.html")); err != nil {
		t.Fatalf("-write did not create the output directory: %v", err)
	}
}
