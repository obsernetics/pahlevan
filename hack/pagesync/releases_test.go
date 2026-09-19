package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The changelog page carries one article per release, written as prose. Unlike
// the version strings scattered through the site, those articles are not
// marked spans, so pagesync had nothing to check and reported the site up to
// date while it was missing an entire release.
//
// That is exactly what happened with 3.3.3: the version strings updated,
// because markers own those, and the page went on showing 3.3.2 as the current
// release with no 3.3.3 article at all. A reader looking at the site would
// conclude 3.3.3 did not exist.
//
// So the two files have to agree: every released version in CHANGELOG.md needs
// an article, and the newest one is the one wearing the "Current" badge.

const (
	changelogPath = "../../CHANGELOG.md"
	sitePath      = "../../pages/changelog.html"
)

// releasedVersions lists the released versions in CHANGELOG.md, newest first.
// [Unreleased] is deliberately excluded: it is not a release, and the site
// shows it as an "In progress" article rather than a versioned one.
func releasedVersions(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(changelogPath)
	if err != nil {
		t.Fatalf("reading CHANGELOG.md: %v", err)
	}
	re := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("no released versions found in CHANGELOG.md; the heading format changed and this test is proving nothing")
	}
	return out
}

// siteReleases lists the versioned articles on the changelog page, in order.
func siteReleases(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(sitePath)
	if err != nil {
		t.Fatalf("reading the changelog page: %v", err)
	}
	re := regexp.MustCompile(`class="release-version">(\d+\.\d+\.\d+)<`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("no release articles found on the changelog page; the markup changed and this test is proving nothing")
	}
	return out
}

func TestEveryReleaseHasAnArticleOnTheSite(t *testing.T) {
	have := map[string]bool{}
	for _, v := range siteReleases(t) {
		have[v] = true
	}
	for _, v := range releasedVersions(t) {
		if !have[v] {
			t.Errorf("CHANGELOG.md documents %s but the changelog page has no article for it, "+
				"so the site tells readers that release does not exist.\n"+
				"Add an article to pages/changelog.html.", v)
		}
	}
}

func TestTheSiteDoesNotInventReleases(t *testing.T) {
	// The other direction: an article for a version the changelog does not
	// document is a release announced on the website and nowhere else, which
	// is how a phantom release gets seen.
	documented := map[string]bool{}
	for _, v := range releasedVersions(t) {
		documented[v] = true
	}
	for _, v := range siteReleases(t) {
		if !documented[v] {
			t.Errorf("the changelog page shows an article for %s, which CHANGELOG.md does not document", v)
		}
	}
}

func TestTheCurrentBadgeIsOnTheNewestRelease(t *testing.T) {
	b, err := os.ReadFile(sitePath)
	if err != nil {
		t.Fatalf("reading the changelog page: %v", err)
	}
	page := string(b)

	// Exactly one article may claim to be current. Two is a page that
	// contradicts itself; none is a page that will not say what to install.
	if n := strings.Count(page, `class="release-pill">Current<`); n != 1 {
		t.Fatalf("%d articles are badged Current, want exactly 1", n)
	}

	// The badge belongs to the article it appears inside, which is the last
	// release-version before it in the document.
	idx := strings.Index(page, `class="release-pill">Current<`)
	before := page[:idx]
	re := regexp.MustCompile(`class="release-version">([^<]+)<`)
	all := re.FindAllStringSubmatch(before, -1)
	if len(all) == 0 {
		t.Fatal("the Current badge is not inside any release article")
	}
	badged := all[len(all)-1][1]

	newest := releasedVersions(t)[0]
	if badged != newest {
		t.Errorf("the site badges %s as the current release, but the newest release in CHANGELOG.md is %s.\n"+
			"Readers are being pointed at an older version than the one that shipped.", badged, newest)
	}
}

func BenchmarkSiteReleaseScan(b *testing.B) {
	data, err := os.ReadFile(sitePath)
	if err != nil {
		b.Skipf("changelog page unavailable: %v", err)
	}
	re := regexp.MustCompile(`class="release-version">(\d+\.\d+\.\d+)<`)
	page := string(data)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.FindAllStringSubmatch(page, -1)
	}
}
