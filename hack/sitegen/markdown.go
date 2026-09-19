package main

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

// This file turns one markdown document into the HTML fragment the site
// publishes.
//
// goldmark is the renderer because it is already in the module graph (it
// arrives with golang.org/x/tools), it is pure Go with no cgo and no external
// binary to install in CI, it is CommonMark-compliant with a GFM extension for
// the pipe tables docs/scenario-report.md is built out of, and - the reason
// that decided it - it refuses to emit raw HTML unless you explicitly ask for
// it with html.WithUnsafe(). We never ask. Anyone with commit access can put a
// <script> in a docs page, and the docs are being rewritten by several people;
// the renderer, not a review, is what stops that reaching the published site.

// newMarkdown builds the converter. It is deliberately constructed per call
// rather than shared in a package variable: goldmark itself is safe to reuse,
// but the per-document state we hang off it (the asset list) is not, and a
// shared converter is how one document's assets end up attributed to another.
func newMarkdown() goldmark.Markdown {
	return goldmark.New(
		// GFM for tables, strikethrough, autolinks and task lists - the docs
		// use all four.
		goldmark.WithExtensions(extension.GFM),
		// Stable heading ids so the on-page table of contents can link to
		// them, and so a link somebody wrote as docs/x.md#some-heading still
		// lands in the right place after conversion.
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		// No html.WithUnsafe(): raw HTML in a docs file is dropped, not
		// forwarded.
	)
}

// syncSpan matches a pagesync marker and captures the value inside it.
//
// docs/packages.md carries these markers so pagesync can keep the version it
// tells people to pull up to date. Inside a fenced code block they are not
// HTML - they are literal text - so a reader of the published page would be
// told to run
//
//	docker pull ghcr.io/obsernetics/pahlevan:<!--pahlevan:sync version-->v3.3.3<!--/pahlevan:sync-->
//
// and would copy a command that pulls nothing. The marker is plumbing between
// two generators; only the value it wraps is content.
var syncSpan = regexp.MustCompile(
	`(?s)<!--\s*pahlevan:sync\s+[a-z0-9-]+\s*-->(.*?)<!--\s*/pahlevan:sync\s*-->`)

// stripSyncMarkers replaces every marked span with the value it publishes.
func stripSyncMarkers(src []byte) []byte {
	return syncSpan.ReplaceAll(src, []byte("$1"))
}

// Heading is one entry in a page's table of contents.
type Heading struct {
	ID   string
	Text string
}

// Page is one converted markdown document.
type Page struct {
	// Title is the document's H1, lifted out of the body so the page header
	// can show it the way every other page on the site shows its title.
	Title string
	// SummaryHTML and SummaryText are the document's opening paragraph, also
	// lifted out of the body: it becomes the lede under the title and the
	// <meta name="description"> a search result shows.
	SummaryHTML string
	SummaryText string
	// BodyHTML is everything else.
	BodyHTML string
	// Headings are the H2s, for the "On this page" rail.
	Headings []Heading
	// Assets are the repository-relative paths of local files the document
	// references (its diagrams). They have to be published alongside it or the
	// page renders with a broken image and still returns 200.
	Assets []string
}

// linkRewriter decides what each markdown link destination becomes on the site.
type linkRewriter struct {
	// base is the directory the markdown file lives in, relative to the
	// repository root. Relative destinations resolve against it: the same
	// "../CHANGELOG.md" means something different in docs/ than at the root.
	base string
	// siblings are the doc slugs that get their own generated page. A link to
	// one of them stays inside the site; a link to anything else leaves for
	// GitHub, because there is nothing on the site to point at.
	siblings map[string]bool
	// assets collects local files the document needs published with it. It is
	// nil for sources that are not published into pages/docs/, where a copied
	// image would land next to a page that never references it.
	assets map[string]bool
}

const (
	repoURL = "https://github.com/obsernetics/pahlevan"
	blobURL = repoURL + "/blob/main/"
	treeURL = repoURL + "/tree/main/"
)

// publishableAsset is the set of extensions worth copying next to the page.
// Anything else (a .go file, a values.yaml) is better read on GitHub, where it
// is syntax-highlighted and version-linked.
var publishableAsset = map[string]bool{
	".svg": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
}

// rewrite maps one markdown destination to a destination that works from
// pages/docs/. It returns the new destination and whether it leaves the site.
//
// The whole point: docs/*.md link to each other as "architecture.md", which
// resolves to nothing once the file is published as architecture.html, and
// resolves to a 404 rather than an error - a broken documentation site that
// loads perfectly.
func (l *linkRewriter) rewrite(dest string) (string, bool) {
	if dest == "" || strings.HasPrefix(dest, "#") {
		return dest, false
	}
	if i := strings.Index(dest, ":"); i > 0 && !strings.Contains(dest[:i], "/") {
		// An absolute URL, or mailto:. Leaves the site untouched.
		return dest, true
	}

	target, fragment := dest, ""
	if i := strings.Index(dest, "#"); i >= 0 {
		target, fragment = dest[:i], dest[i:]
	}

	// Resolve against the file's own directory, so a docs page's
	// "../CHANGELOG.md" becomes "CHANGELOG.md".
	full := path.Clean(path.Join(l.base, target))

	switch {
	case full == "CHANGELOG.md":
		// The changelog has a page on this site; sending a reader to the raw
		// markdown on GitHub instead would be a worse version of a page we
		// publish.
		return "../changelog.html" + fragment, false
	case strings.HasPrefix(full, "docs/") && strings.HasSuffix(full, ".md"):
		slug := strings.TrimSuffix(strings.TrimPrefix(full, "docs/"), ".md")
		if l.siblings[slug] {
			return slug + ".html" + fragment, false
		}
		return blobURL + full + fragment, true
	case l.assets != nil && strings.HasPrefix(full, "docs/") && publishableAsset[strings.ToLower(path.Ext(full))]:
		l.assets[full] = true
		// Published next to the page, keeping the relative path the author
		// wrote, so the same markdown renders on GitHub and here.
		return strings.TrimPrefix(full, "docs/") + fragment, false
	case strings.HasSuffix(target, "/"):
		return treeURL + full + fragment, true
	default:
		return blobURL + full + fragment, true
	}
}

// Convert renders one markdown document.
func Convert(src []byte, siblings map[string]bool) (*Page, error) {
	src = stripSyncMarkers(src)

	md := newMarkdown()
	reader := text.NewReader(src)
	doc := md.Parser().Parse(reader)

	rw := &linkRewriter{base: docsDir, siblings: siblings, assets: map[string]bool{}}
	if err := rewriteLinks(doc, src, rw); err != nil {
		return nil, err
	}

	page := &Page{}

	// Lift the H1 and the opening paragraph out of the body. They are shown in
	// the page header instead; leaving them in the body as well would print
	// the document's title twice, once in each of two different type scales.
	if h := firstHeading(doc, 1); h != nil {
		page.Title = plainText(h, src)
		h.Parent().RemoveChild(h.Parent(), h)
	}
	if p := firstParagraph(doc); p != nil {
		html, err := renderNode(md, src, p)
		if err != nil {
			return nil, err
		}
		page.SummaryHTML = unwrapParagraph(html)
		page.SummaryText = plainText(p, src)
		p.Parent().RemoveChild(p.Parent(), p)
	}

	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		h, ok := c.(*ast.Heading)
		if !ok || h.Level != 2 {
			continue
		}
		id, _ := h.AttributeString("id")
		idStr, _ := id.([]byte)
		page.Headings = append(page.Headings, Heading{ID: string(idStr), Text: plainText(h, src)})
	}

	body, err := renderNode(md, src, doc)
	if err != nil {
		return nil, err
	}
	page.BodyHTML = strings.TrimRight(body, "\n")

	for a := range rw.assets {
		page.Assets = append(page.Assets, a)
	}

	// A belt-and-braces check on top of goldmark's own refusal to emit raw
	// HTML. If a future edit ever turns html.WithUnsafe() on, or an extension
	// starts emitting markup of its own, the build stops here rather than
	// publishing a docs page that can run script from a markdown file.
	if err := rejectScript(page.BodyHTML, page.SummaryHTML); err != nil {
		return nil, err
	}
	return page, nil
}

func rejectScript(fragments ...string) error {
	for _, f := range fragments {
		lower := strings.ToLower(f)
		for _, bad := range []string{"<script", "javascript:", " onerror=", " onload=", "<iframe", "<object", "<embed"} {
			if strings.Contains(lower, bad) {
				return fmt.Errorf("the rendered markdown contains %q, which must never reach the published site", strings.TrimSpace(bad))
			}
		}
	}
	return nil
}

func rewriteLinks(doc ast.Node, src []byte, rw *linkRewriter) error {
	return ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := n.(type) {
		case *ast.Link:
			dest, external := rw.rewrite(string(v.Destination))
			v.Destination = []byte(dest)
			if external {
				// Matching the rest of the site, where every off-site link
				// opens in a new tab. rel="noopener" because the opened page
				// can otherwise reach back through window.opener.
				v.SetAttributeString("target", []byte("_blank"))
				v.SetAttributeString("rel", []byte("noopener"))
			}
		case *ast.Image:
			dest, _ := rw.rewrite(string(v.Destination))
			v.Destination = []byte(dest)
		}
		return ast.WalkContinue, nil
	})
}

func renderNode(md goldmark.Markdown, src []byte, n ast.Node) (string, error) {
	var buf bytes.Buffer
	if err := md.Renderer().Render(&buf, src, n); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func firstHeading(doc ast.Node, level int) ast.Node {
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if h, ok := c.(*ast.Heading); ok && h.Level == level {
			return h
		}
	}
	return nil
}

func firstParagraph(doc ast.Node) ast.Node {
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if _, ok := c.(*ast.Paragraph); ok {
			return c
		}
	}
	return nil
}

// unwrapParagraph removes the <p> wrapper from a single rendered paragraph, so
// the lede can be dropped into markup that supplies its own <p class="...">.
//
// Only from a single one. Two paragraphs also start with <p> and end with
// </p>, and stripping the outer pair there would splice the last sentence of
// the first onto the first sentence of the second, with the paragraph break
// turned into a stray closing tag in the middle.
func unwrapParagraph(html string) string {
	s := strings.TrimSpace(html)
	if strings.Count(s, "<p>") == 1 && strings.HasPrefix(s, "<p>") && strings.HasSuffix(s, "</p>") {
		return strings.TrimSpace(s[len("<p>") : len(s)-len("</p>")])
	}
	return s
}

// plainText collects the visible text of a node.
//
// ast.Node.Text is deprecated in goldmark and drops the contents of code
// spans, which in these documents are often the whole point of the sentence -
// a heading like "The `lsm=bpf` boot flag" would become "The  boot flag".
func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := node.(type) {
		case *ast.Text:
			b.Write(v.Segment.Value(src))
			if v.SoftLineBreak() || v.HardLineBreak() {
				b.WriteByte(' ')
			}
		case *ast.String:
			b.Write(v.Value)
		case *ast.AutoLink:
			b.Write(v.URL(src))
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(b.String())
}
