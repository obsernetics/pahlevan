package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This is the 3.3.3 bug, written down as a test.
//
// CHANGELOG.md documented 3.3.3. The changelog page badged itself v3.3.3,
// because pagesync owns the version strings. But the newest article on the
// page was 3.3.2, and nothing compared the two, so `pagesync -check` passed
// and the site told every reader that 3.3.3 did not exist.
//
// auditReleases is the comparison that was missing. TestRemovingAnArticle...
// below deletes an article from the generated page and asserts this audit
// catches it, so the test cannot quietly stop proving anything.

var (
	siteVersion = regexp.MustCompile(`class="release-version">([^<]+)<`)
	currentPill = regexp.MustCompile(`class="release-pill">Current<`)
)

// auditReleases returns one complaint per disagreement between CHANGELOG.md
// and the published page.
func auditReleases(releases []release, page string) []string {
	var complaints []string

	onPage := map[string]bool{}
	var pageOrder []string
	for _, m := range siteVersion.FindAllStringSubmatch(page, -1) {
		onPage[m[1]] = true
		pageOrder = append(pageOrder, m[1])
	}

	documented := map[string]bool{}
	newest := ""
	for _, r := range releases {
		if !r.Released() {
			continue
		}
		documented[r.Version] = true
		if newest == "" {
			newest = r.Version
		}
		if !onPage[r.Version] {
			complaints = append(complaints, fmt.Sprintf(
				"CHANGELOG.md documents %s but the page has no article for it, so the site says that release does not exist", r.Version))
		}
	}
	for _, v := range pageOrder {
		if v == unreleased {
			continue
		}
		if !documented[v] {
			complaints = append(complaints, fmt.Sprintf(
				"the page shows an article for %s, which CHANGELOG.md does not document", v))
		}
	}

	switch n := len(currentPill.FindAllString(page, -1)); {
	case n == 0:
		complaints = append(complaints, "no article is badged Current, so the page will not say which release to install")
	case n > 1:
		complaints = append(complaints, fmt.Sprintf("%d articles are badged Current; the page contradicts itself", n))
	default:
		idx := currentPill.FindStringIndex(page)[0]
		before := siteVersion.FindAllStringSubmatch(page[:idx], -1)
		badged := ""
		if len(before) > 0 {
			badged = before[len(before)-1][1]
		}
		if badged != newest {
			complaints = append(complaints, fmt.Sprintf(
				"the page badges %s as current, but the newest release in CHANGELOG.md is %s; readers are pointed at an older version than the one that shipped",
				badged, newest))
		}
	}
	return complaints
}

func realReleases(t *testing.T) []release {
	t.Helper()
	releases, err := ParseChangelog(repoRoot)
	if err != nil {
		t.Fatalf("parsing CHANGELOG.md: %v", err)
	}
	return releases
}

func realChangelogPage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, changelogOut))
	if err != nil {
		t.Fatalf("reading the changelog page: %v", err)
	}
	return string(data)
}

func TestEveryReleaseHasAnArticleAndTheNewestIsCurrent(t *testing.T) {
	t.Parallel()
	if c := auditReleases(realReleases(t), realChangelogPage(t)); len(c) > 0 {
		t.Errorf("the changelog page disagrees with CHANGELOG.md:\n  %s\n\nrun: go run ./hack/sitegen -write",
			strings.Join(c, "\n  "))
	}
}

// The proof that the test above is worth having: break the page the way 3.3.3
// broke it and confirm the audit fails.
func TestRemovingAnArticleIsCaught(t *testing.T) {
	t.Parallel()
	releases := realReleases(t)
	page := realChangelogPage(t)

	newest := ""
	for _, r := range releases {
		if r.Released() {
			newest = r.Version
			break
		}
	}
	if newest == "" {
		t.Fatal("CHANGELOG.md documents no released version; this test is proving nothing")
	}

	broken := removeArticle(t, page, newest)
	if broken == page {
		t.Fatalf("could not remove the %s article; the markup changed and this test is proving nothing", newest)
	}

	complaints := auditReleases(releases, broken)
	if len(complaints) == 0 {
		t.Fatalf("the %s article was deleted from the page and the audit passed - "+
			"this is exactly the failure that shipped 3.3.3 to nobody", newest)
	}
	if !strings.Contains(strings.Join(complaints, "\n"), newest) {
		t.Errorf("the audit complained, but not about %s: %v", newest, complaints)
	}
}

func TestAnInventedReleaseIsCaught(t *testing.T) {
	t.Parallel()
	page := strings.Replace(realChangelogPage(t),
		`<h3 class="release-version">1.0.0</h3>`,
		`<h3 class="release-version">9.9.9</h3>`, 1)
	complaints := auditReleases(realReleases(t), page)
	if len(complaints) == 0 {
		t.Fatal("the page announced a release CHANGELOG.md does not document and the audit passed")
	}
}

func TestTheCurrentBadgeOnTheWrongReleaseIsCaught(t *testing.T) {
	t.Parallel()
	page := realChangelogPage(t)
	moved := strings.Replace(page, `<span class="release-pill">Current</span>`+"\n", "", 1)
	moved = strings.Replace(moved,
		`<h3 class="release-version">1.0.0</h3>`,
		`<h3 class="release-version">1.0.0</h3>`+"\n"+`<span class="release-pill">Current</span>`, 1)
	complaints := auditReleases(realReleases(t), moved)
	if len(complaints) == 0 {
		t.Fatal("the Current badge was moved to the oldest release and the audit passed")
	}
}

// removeArticle deletes one release article from the page, the way a person
// forgetting to write one leaves it absent.
func removeArticle(t *testing.T, page, version string) string {
	t.Helper()
	marker := `<h3 class="release-version">` + version + `</h3>`
	i := strings.Index(page, marker)
	if i < 0 {
		return page
	}
	start := strings.LastIndex(page[:i], `<article class="release">`)
	rest := strings.Index(page[i:], "</article>")
	if start < 0 || rest < 0 {
		return page
	}
	return page[:start] + page[i+rest+len("</article>"):]
}

func TestParseChangelogReadsEveryRelease(t *testing.T) {
	t.Parallel()
	releases := realReleases(t)
	if len(releases) < 2 {
		t.Fatalf("parsed %d sections from CHANGELOG.md", len(releases))
	}
	if releases[0].Version != unreleased {
		t.Errorf("the first section is %q, want %q - the page shows it as the in-progress article",
			releases[0].Version, unreleased)
	}

	// Every released section needs a date, or the article publishes a version
	// with no indication of when it shipped.
	for _, r := range releases {
		if !r.Released() && r.Date != "" {
			t.Errorf("[Unreleased] has a date: %q", r.Date)
		}
		if r.Released() && r.Date == "" {
			t.Errorf("%s has no date in CHANGELOG.md", r.Version)
		}
		if r.Released() && len(r.Groups) == 0 {
			t.Errorf("%s has no change groups; its article would be an empty box", r.Version)
		}
	}

	// The link reference definitions at the foot of the file are markdown
	// plumbing. They used to land in the last release's article as four bare
	// URLs.
	for _, r := range releases {
		for _, g := range r.Groups {
			for _, item := range g.Items {
				if strings.Contains(item, "compare/v") && strings.Contains(item, "...") {
					t.Errorf("%s: a link reference definition was published as a change: %q", r.Version, item)
				}
			}
		}
	}
}

func TestReleaseMarkupMatchesTheSite(t *testing.T) {
	t.Parallel()
	articles := RenderReleases(realReleases(t))
	for _, want := range []string{
		`<article class="release">`,
		`<div class="release-head">`,
		`<h3 class="release-version">`,
		`<span class="release-date">`,
		`<span class="release-pill">Current</span>`,
		`<span class="release-pill">In progress</span>`,
		`<div class="change-group">`,
		`<h4 class="added">Added</h4>`,
		`<h4 class="changed">Changed</h4>`,
		`<h4 class="fixed">Fixed</h4>`,
	} {
		if !strings.Contains(articles, want) {
			t.Errorf("the generated markup is missing %q, so the stylesheet will not style it", want)
		}
	}
	// A heading outside the Keep a Changelog set gets no class rather than a
	// wrong one: 3.0.0 has "Breaking changes".
	if !strings.Contains(articles, `<h4>Breaking changes</h4>`) {
		t.Error("a non-standard change heading lost its text or gained a class it has no style for")
	}
}

// The bug that made the whole page scroll sideways.
func TestACodeBlockInAReleaseNoteKeepsItsLines(t *testing.T) {
	t.Parallel()
	articles := RenderReleases(realReleases(t))
	if !strings.Contains(articles, "<pre>") {
		t.Skip("no release note currently carries a code block")
	}
	for _, block := range strings.Split(articles, "<pre>")[1:] {
		body := block[:strings.Index(block, "</pre>")]
		if !strings.Contains(body, "\n") {
			t.Errorf("a code block in a release note was flattened onto one line: %q\n"+
				"<pre> does not wrap, so one long line sets the minimum width of every release article and the page scrolls sideways", body)
		}
	}
}

func TestSpliceNeedsItsRegion(t *testing.T) {
	t.Parallel()
	if _, err := SpliceReleases([]byte("<html><body>no markers</body></html>"), "x"); err == nil {
		t.Error("splicing into a page with no generated region should be an error, not a silent no-op that leaves last month's articles published")
	}
	page := []byte("a" + releaseOpen + "old" + releaseClose + "b")
	out, err := SpliceReleases(page, "                new")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "old") || !strings.Contains(string(out), "new") {
		t.Errorf("the region was not replaced: %q", out)
	}
	if !strings.HasPrefix(string(out), "a") || !strings.HasSuffix(string(out), "b") {
		t.Errorf("content outside the region was disturbed: %q", out)
	}
}

func TestAnEmptyUnreleasedSectionIsNotPublished(t *testing.T) {
	t.Parallel()
	articles := RenderReleases([]release{
		{Version: unreleased},
		{Version: "1.0.0", Date: "2026-01-01", Groups: []changeGroup{{Kind: "Added", Items: []string{"A thing."}}}},
	})
	if strings.Contains(articles, unreleased) {
		t.Error("an empty [Unreleased] section was published as an article, promising work in progress and showing none")
	}
	if !strings.Contains(articles, `<span class="release-pill">Current</span>`) {
		t.Error("the only release is not badged Current")
	}
}
