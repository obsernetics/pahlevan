package main

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Every file in docs/ is a page somebody was expected to read, and until now
// none of them were published: the site linked out to the markdown on GitHub,
// where it renders in GitHub's chrome, with GitHub's navigation, and where a
// reader who arrived from the landing page has left the site. Twelve documents
// - the quick start, the policy reference, the API reference, troubleshooting
// - were reachable only that way.
//
// This file publishes them, and the rule that keeps it honest is that the
// directory listing is the source of truth: a new docs/*.md is a new page and
// a new index entry with no second place to register it, and a deleted one
// takes its page with it.

// docsDir is the input directory and docsOut the directory this generator owns
// completely. Owning it completely is what lets -write delete a page whose
// markdown is gone; a page left behind would go on being served, and being
// linked to, after the document was retired.
const (
	docsDir = "docs"
	docsOut = "pages/docs"
)

// featured is the reading order for the documents a newcomer needs first.
//
// It is a prominence hint, not a registry: anything not named here is still
// published and still indexed, appended in alphabetical order. A curated list
// that a new document had to be added to is the same hand-maintenance this
// generator exists to remove, and it would fail silently - the document would
// simply not be listed.
var featured = []string{
	"quick-start",
	"architecture",
	"system-requirements",
	"deployment",
	"policy-reference",
	"api-reference",
	"packages",
	"troubleshooting",
}

// Doc is one published documentation page.
type Doc struct {
	Source string // "docs/architecture.md"
	Slug   string // "architecture"
	Out    string // "pages/docs/architecture.html"
	Page   *Page
}

// LoadDocs converts every markdown file in docs/.
func LoadDocs(root string) ([]Doc, error) {
	dir := filepath.Join(root, docsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", docsDir, err)
	}

	var names []string
	for _, e := range entries {
		// Sub-directories (assets/, benchmarks/) are not pages. benchmarks/
		// holds generated results that the landing page already links to.
		if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no markdown files in %s; the site would publish an empty documentation section", dir)
	}
	sort.Strings(names)

	// Two passes: the first learns which slugs exist, so the second can tell a
	// cross-reference that stays on the site from one that has to go to
	// GitHub. Without it, a link to a document we do publish would be sent to
	// GitHub anyway and the reader would leave the site for no reason.
	siblings := map[string]bool{}
	for _, n := range names {
		siblings[slugOf(n)] = true
	}

	var docs []Doc
	for _, n := range names {
		src, err := os.ReadFile(filepath.Join(dir, n)) // #nosec G304 -- a fixed in-tree directory
		if err != nil {
			return nil, err
		}
		page, err := Convert(src, siblings)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", docsDir, n, err)
		}
		if page.Title == "" {
			return nil, fmt.Errorf("%s/%s has no H1; the published page would have no title", docsDir, n)
		}
		slug := slugOf(n)
		docs = append(docs, Doc{
			Source: docsDir + "/" + n,
			Slug:   slug,
			Out:    docsOut + "/" + slug + ".html",
			Page:   page,
		})
	}
	return docs, nil
}

func slugOf(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))
}

// ordered returns the docs in reading order: featured first, then the rest
// alphabetically.
func ordered(docs []Doc) []Doc {
	rank := map[string]int{}
	for i, s := range featured {
		rank[s] = i
	}
	out := append([]Doc(nil), docs...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := rank[out[i].Slug]
		rj, jok := rank[out[j].Slug]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok
		default:
			return out[i].Slug < out[j].Slug
		}
	})
	return out
}

// renderDocPage builds one documentation page.
func renderDocPage(d Doc) ([]byte, error) {
	var b strings.Builder

	b.WriteString(`    <header class="page-head" id="top">` + "\n")
	b.WriteString(`        <div class="container">` + "\n")
	b.WriteString(`            <span class="eyebrow">Documentation</span>` + "\n")
	b.WriteString(`            <h1>` + html.EscapeString(d.Page.Title) + `</h1>` + "\n")
	if d.Page.SummaryHTML != "" {
		b.WriteString(`            <p>` + d.Page.SummaryHTML + `</p>` + "\n")
	}
	b.WriteString(`            <div class="hero-actions">` + "\n")
	b.WriteString(`                <a href="index.html" class="btn btn-outline btn-sm">All documentation</a>` + "\n")
	b.WriteString(`                <a href="` + blobURL + d.Source + `" class="btn btn-outline btn-sm" target="_blank" rel="noopener">Edit this page &#8599;</a>` + "\n")
	b.WriteString(`            </div>` + "\n")
	b.WriteString(`        </div>` + "\n")
	b.WriteString(`    </header>` + "\n\n")

	// A rail of one entry is noise, and on a short document it is wider than
	// the thing it indexes.
	withTOC := len(d.Page.Headings) >= 2
	layoutClass := "container doc-layout"
	if !withTOC {
		layoutClass += " doc-layout-plain"
	}

	b.WriteString(`    <section class="section doc-section">` + "\n")
	b.WriteString(`        <div class="` + layoutClass + `">` + "\n")
	if withTOC {
		b.WriteString(`            <aside class="doc-toc" aria-label="On this page">` + "\n")
		b.WriteString(`                <h2>On this page</h2>` + "\n")
		b.WriteString(`                <ul>` + "\n")
		for _, h := range d.Page.Headings {
			b.WriteString(`                    <li><a href="#` + html.EscapeString(h.ID) + `">` + html.EscapeString(h.Text) + `</a></li>` + "\n")
		}
		b.WriteString(`                </ul>` + "\n")
		b.WriteString(`            </aside>` + "\n")
	}
	b.WriteString(`            <article class="doc-body">` + "\n")
	// The body is written at column zero rather than indented to match the
	// markup around it: indenting it would add leading spaces to every line
	// inside a <pre>, and the commands readers copy out of these pages would
	// arrive with the indentation baked in.
	b.WriteString(d.Page.BodyHTML + "\n")
	b.WriteString(`            </article>` + "\n")
	b.WriteString(`        </div>` + "\n")
	b.WriteString(`    </section>` + "\n")

	return newLayout(d.Page.Title, metaDescription(d.Page), "docs/"+d.Slug+".html", d.Source, b.String()).render()
}

// indexLede introduces the documentation section. It has no second copy
// anywhere, so unlike the release version or the benchmark counts it cannot go
// out of sync with a source.
const indexLede = "Everything Pahlevan ships with, published here rather than only in the repository: " +
	"how it learns a workload, what the policy fields mean, what the kernel needs, and what to do when enforcement " +
	"is not doing what you expected."

// renderDocIndex builds the documentation landing page.
func renderDocIndex(docs []Doc) ([]byte, error) {
	var b strings.Builder

	b.WriteString(`    <header class="page-head" id="top">` + "\n")
	b.WriteString(`        <div class="container">` + "\n")
	b.WriteString(`            <span class="eyebrow">Documentation</span>` + "\n")
	b.WriteString(`            <h1>Pahlevan documentation</h1>` + "\n")
	b.WriteString(`            <p>` + indexLede + `</p>` + "\n")
	b.WriteString(`            <div class="hero-actions">` + "\n")
	b.WriteString(`                <a href="quick-start.html" class="btn btn-primary">Quick start</a>` + "\n")
	b.WriteString(`                <a href="` + treeURL + `docs" class="btn btn-outline" target="_blank" rel="noopener">Source on GitHub &#8599;</a>` + "\n")
	b.WriteString(`            </div>` + "\n")
	b.WriteString(`        </div>` + "\n")
	b.WriteString(`    </header>` + "\n\n")

	b.WriteString(`    <section class="section">` + "\n")
	b.WriteString(`        <div class="container">` + "\n")
	b.WriteString(`            <div class="doc-index">` + "\n")
	for _, d := range ordered(docs) {
		b.WriteString(`                <a class="doc-card" href="` + d.Slug + `.html">` + "\n")
		b.WriteString(`                    <h2>` + html.EscapeString(d.Page.Title) + `</h2>` + "\n")
		b.WriteString(`                    <p>` + html.EscapeString(summarise(d.Page.SummaryText, 190)) + `</p>` + "\n")
		b.WriteString(`                    <span class="doc-card-more">Read &#8594;</span>` + "\n")
		b.WriteString(`                </a>` + "\n")
	}
	b.WriteString(`            </div>` + "\n")
	b.WriteString(`        </div>` + "\n")
	b.WriteString(`    </section>` + "\n")

	return newLayout("Documentation", indexLede, "docs/index.html", docsDir+"/", b.String()).render()
}

// metaDescription is the page summary a search result shows.
func metaDescription(p *Page) string {
	if s := summarise(p.SummaryText, 200); s != "" {
		return s
	}
	return p.Title + " - Pahlevan documentation."
}

// summarise trims text to a length a search result will actually display,
// cutting at a word boundary so the snippet does not end mid-word.
func summarise(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	if i := strings.LastIndexByte(cut, ' '); i > max/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,.;:") + "..."
}
