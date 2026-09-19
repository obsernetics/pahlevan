package main

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// The release articles on the changelog page were typed by hand, and that is
// how 3.3.3 shipped to nobody's screen.
//
// pagesync keeps the version strings correct, because those live in marked
// spans, so the page badged itself v3.3.3 in three places while the article
// list below still ended at 3.3.2 - and `go run ./hack/pagesync -check`
// reported the site up to date, because a paragraph of prose is not a marked
// span and there was nothing for it to compare. A reader scrolling the
// changelog would conclude 3.3.3 did not exist.
//
// The articles are now derived from CHANGELOG.md, which is the file the
// release process already updates. There is no second place to write a release
// note, so there is no second place to forget one.

// releaseRegion delimits the generated part of pages/changelog.html. Everything
// outside it - the page header, the packages section, the install commands -
// stays hand-written, because it is design work, not a transcription of
// another file.
const (
	releaseOpen  = "<!--pahlevan:sitegen releases-->"
	releaseClose = "<!--/pahlevan:sitegen-->"
	changelogSrc = "CHANGELOG.md"
	changelogOut = "pages/changelog.html"
)

// changeGroup is one "### Added" style block of a release.
type changeGroup struct {
	Kind  string   // "Added", "Fixed", "Breaking changes"
	Items []string // rendered HTML, one per bullet
}

// release is one "## [version] - date" section.
type release struct {
	Version   string // "3.3.3", or "Unreleased"
	Date      string // "2026-09-14", empty for Unreleased
	Summaries []string
	Groups    []changeGroup
}

// Released reports whether this section describes a shipped version.
func (r release) Released() bool { return r.Version != unreleased }

const unreleased = "Unreleased"

var (
	// The Keep a Changelog heading form, with the date optional so an entry
	// written before its release date still parses instead of vanishing.
	releaseHeading = regexp.MustCompile(`(?m)^## \[([^\]]+)\](?:\s*[-\x{2013}]\s*(\S+))?\s*$`)
	groupHeading   = regexp.MustCompile(`(?m)^### +(.+?)\s*$`)
	// Link reference definitions at the foot of the file. They belong to the
	// markdown, not to the last release, and without stripping them the 1.0.0
	// article would end with four bare URLs.
	linkRefDef = regexp.MustCompile(`(?m)^\[[^\]]+\]:\s+\S+\s*$`)
)

// groupClass maps a change kind to the class the stylesheet colours it with.
// A kind outside the Keep a Changelog set (3.0.0 has "Breaking changes") gets
// no class rather than a wrong one.
var groupClass = map[string]string{
	"added": "added", "changed": "changed", "fixed": "fixed",
	"removed": "removed", "deprecated": "deprecated", "security": "security",
}

// ParseChangelog reads CHANGELOG.md into release sections, newest first.
func ParseChangelog(root string) ([]release, error) {
	data, err := os.ReadFile(filepath.Join(root, changelogSrc)) // #nosec G304 -- a fixed in-tree path
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", changelogSrc, err)
	}
	src := linkRefDef.ReplaceAll(stripSyncMarkers(data), nil)

	idx := releaseHeading.FindAllSubmatchIndex(src, -1)
	if len(idx) == 0 {
		return nil, fmt.Errorf("%s has no release headings; the page would publish an empty changelog", changelogSrc)
	}

	var out []release
	for i, m := range idx {
		end := len(src)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		r := release{Version: string(src[m[2]:m[3]])}
		if m[4] >= 0 {
			r.Date = string(src[m[4]:m[5]])
		}
		if err := parseSection(src[m[1]:end], &r); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", changelogSrc, r.Version, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// parseSection fills in one release's lede and change groups.
func parseSection(body []byte, r *release) error {
	groups := groupHeading.FindAllSubmatchIndex(body, -1)

	leadEnd := len(body)
	if len(groups) > 0 {
		leadEnd = groups[0][0]
	}
	lead, err := renderParagraphs(body[:leadEnd])
	if err != nil {
		return err
	}
	r.Summaries = lead

	for i, g := range groups {
		end := len(body)
		if i+1 < len(groups) {
			end = groups[i+1][0]
		}
		items, err := renderBullets(body[g[1]:end])
		if err != nil {
			return err
		}
		if len(items) == 0 {
			continue
		}
		r.Groups = append(r.Groups, changeGroup{Kind: string(body[g[2]:g[3]]), Items: items})
	}
	return nil
}

// changelogRewriter resolves links in CHANGELOG.md, which sits at the
// repository root rather than in docs/.
func changelogRewriter() *linkRewriter {
	return &linkRewriter{base: ".", siblings: map[string]bool{}}
}

// renderParagraphs renders a release's opening prose, one string per paragraph.
func renderParagraphs(src []byte) ([]string, error) {
	md := newMarkdown()
	doc := md.Parser().Parse(text.NewReader(src))
	if err := rewriteLinks(doc, src, changelogRewriter()); err != nil {
		return nil, err
	}

	var out []string
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		if _, ok := c.(*ast.Paragraph); !ok {
			continue
		}
		s, err := renderNode(md, src, c)
		if err != nil {
			return nil, err
		}
		if s = unwrapParagraph(s); s != "" {
			out = append(out, collapseProse(s))
		}
	}
	return out, rejectScript(out...)
}

// renderBullets renders the bullet list under a "###" heading, one HTML string
// per list item.
//
// The items are rendered individually rather than by handing goldmark the
// whole list, because the page's markup puts its own <ul> around them and a
// nested list element would inherit the wrong bullet styling - the change
// groups are styled with a generated dot, not a list marker.
func renderBullets(src []byte) ([]string, error) {
	md := newMarkdown()
	doc := md.Parser().Parse(text.NewReader(src))
	if err := rewriteLinks(doc, src, changelogRewriter()); err != nil {
		return nil, err
	}

	var items []string
	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		list, ok := c.(*ast.List)
		if !ok {
			continue
		}
		for li := list.FirstChild(); li != nil; li = li.NextSibling() {
			var parts []string
			for child := li.FirstChild(); child != nil; child = child.NextSibling() {
				s, err := renderNode(md, src, child)
				if err != nil {
					return nil, err
				}
				// A bullet with one paragraph is a sentence, and the site's
				// markup expects the sentence directly inside the <li>. A
				// bullet with several keeps its paragraphs.
				if li.ChildCount() == 1 {
					s = unwrapParagraph(s)
				}
				parts = append(parts, strings.TrimSpace(s))
			}
			if item := collapseProse(strings.Join(parts, "\n")); item != "" {
				items = append(items, item)
			}
		}
	}
	return items, rejectScript(items...)
}

// oneLine collapses rendered HTML onto a single line.
//
// Markdown wraps its source at 80 columns, and those line breaks survive into
// the rendered fragment. Left alone they make the generated page's diff churn
// whenever somebody re-wraps a paragraph in CHANGELOG.md, which turns every
// changelog edit into a large and unreviewable page diff.
func oneLine(s string) string {
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

// collapseProse collapses whitespace everywhere except inside a <pre>, where a
// newline is content rather than formatting.
//
// Collapsing them flattened the three-line YAML snippet in the 3.0.0 entry
// into one line. <pre> does not wrap, so that line set the minimum width of
// the grid column every release article sits in, and the whole changelog page
// rendered 1986px wide inside a 900px column: every article overflowed the
// viewport and the page scrolled sideways. The snippet was also no longer
// valid YAML, which is the worse half of the bug - it is meant to be pasted
// into a DaemonSet.
func collapseProse(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "<pre")
		if i < 0 {
			b.WriteString(oneLine(s))
			break
		}
		j := strings.Index(s[i:], "</pre>")
		if j < 0 {
			// Unbalanced markup: collapse nothing rather than guess.
			b.WriteString(oneLine(s))
			break
		}
		end := i + j + len("</pre>")
		if head := oneLine(s[:i]); head != "" {
			b.WriteString(head)
			b.WriteString("\n")
		}
		b.WriteString(s[i:end])
		b.WriteString("\n")
		s = s[end:]
	}
	return strings.Trim(b.String(), "\n")
}

// RenderReleases builds the article list that goes between the region markers.
func RenderReleases(releases []release) string {
	var b strings.Builder
	current := true

	for _, r := range releases {
		if !r.Released() && len(r.Summaries) == 0 && len(r.Groups) == 0 {
			// An empty [Unreleased] section is a heading with nothing under
			// it. Publishing it as an article tells a reader that work is in
			// progress and then shows them nothing.
			continue
		}

		b.WriteString(`                <article class="release">` + "\n")
		b.WriteString(`                    <div class="release-head">` + "\n")
		b.WriteString(`                        <h3 class="release-version">` + html.EscapeString(r.Version) + `</h3>` + "\n")
		if r.Date != "" {
			b.WriteString(`                        <span class="release-date">` + html.EscapeString(r.Date) + `</span>` + "\n")
		}
		switch {
		case !r.Released():
			b.WriteString(`                        <span class="release-pill">In progress</span>` + "\n")
		case current:
			// The newest released version is the one the site tells people to
			// install, so it is the one that wears the badge. Deriving it from
			// the order in CHANGELOG.md means a new release moves the badge
			// without anyone remembering to.
			b.WriteString(`                        <span class="release-pill">Current</span>` + "\n")
			current = false
		}
		b.WriteString(`                    </div>` + "\n")

		for _, s := range r.Summaries {
			b.WriteString(`                    <p class="release-summary">` + s + `</p>` + "\n")
		}

		for _, g := range r.Groups {
			b.WriteString(`                    <div class="change-group">` + "\n")
			if class, ok := groupClass[strings.ToLower(g.Kind)]; ok {
				b.WriteString(`                        <h4 class="` + class + `">` + html.EscapeString(g.Kind) + `</h4>` + "\n")
			} else {
				b.WriteString(`                        <h4>` + html.EscapeString(g.Kind) + `</h4>` + "\n")
			}
			b.WriteString(`                        <ul>` + "\n")
			for _, item := range g.Items {
				b.WriteString(`                            <li>` + item + `</li>` + "\n")
			}
			b.WriteString(`                        </ul>` + "\n")
			b.WriteString(`                    </div>` + "\n")
		}

		b.WriteString(`                </article>` + "\n\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// SpliceReleases replaces the generated region of the changelog page.
func SpliceReleases(page []byte, articles string) ([]byte, error) {
	s := string(page)
	open := strings.Index(s, releaseOpen)
	closeIdx := strings.Index(s, releaseClose)
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return nil, fmt.Errorf(
			"%s has no %s ... %s region, so there is nowhere to put the release articles and the page would keep whatever it was last edited to say",
			changelogOut, releaseOpen, releaseClose)
	}
	var b strings.Builder
	b.WriteString(s[:open+len(releaseOpen)])
	b.WriteString("\n")
	b.WriteString(articles)
	b.WriteString("\n                ")
	b.WriteString(s[closeIdx:])
	return []byte(b.String()), nil
}
