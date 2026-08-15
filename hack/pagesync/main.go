// Command pagesync keeps the GitHub Pages site consistent with the repository.
//
// The site duplicates facts that live elsewhere: benchmark numbers from
// docs/benchmarks/results.md, the release version, and the demo GIF. Duplicated
// facts drift, and this set drifted badly - the published page claimed Pahlevan
// blocked "4 / 4" attacks while the benchmark it linked to reported 25 of 26,
// because the page was written against a superseded run and nothing re-derived
// it.
//
// A stale marketing number is not a cosmetic problem for a security tool. It is
// the first thing an evaluator checks and the first thing that makes them
// distrust everything else on the page.
//
// So the page declares where each borrowed fact comes from, with a marker:
//
//	<!--pahlevan:sync attacks-blocked-->25 / 26<!--/pahlevan:sync-->
//
// and this program rewrites the span between the markers from the source. Run
// with -check in CI to fail on drift, or -write to fix it.
//
//	go run ./hack/pagesync -check
//	go run ./hack/pagesync -write
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	var (
		root  = flag.String("root", ".", "repository root")
		write = flag.Bool("write", false, "rewrite the pages in place")
		check = flag.Bool("check", false, "exit non-zero if the pages are stale")
	)
	flag.Parse()

	if *write == *check {
		fmt.Fprintln(os.Stderr, "pagesync: pass exactly one of -write or -check")
		os.Exit(2)
	}

	facts, err := Collect(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pagesync: %v\n", err)
		os.Exit(1)
	}

	stale, err := Apply(*root, facts, *write)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pagesync: %v\n", err)
		os.Exit(1)
	}

	if len(stale) == 0 {
		fmt.Println("pagesync: the site is up to date")
		return
	}
	if *write {
		fmt.Printf("pagesync: updated %d value(s)\n", len(stale))
		for _, s := range stale {
			fmt.Printf("  %s\n", s)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "pagesync: the published site is stale in %d place(s):\n", len(stale))
	for _, s := range stale {
		fmt.Fprintf(os.Stderr, "  %s\n", s)
	}
	fmt.Fprintln(os.Stderr, "\nrun: go run ./hack/pagesync -write")
	os.Exit(1)
}

// Collect reads every fact the site borrows from somewhere else.
//
// A missing source is an error rather than a skipped key: a marker whose source
// has been deleted or renamed would otherwise keep publishing whatever value it
// happened to contain, which is the failure this program exists to stop.
func Collect(root string) (map[string]string, error) {
	facts := map[string]string{}

	bench, err := os.ReadFile(filepath.Join(root, "docs", "benchmarks", "results.md"))
	if err != nil {
		return nil, fmt.Errorf("reading the benchmark report: %w", err)
	}
	if err := collectBenchmark(string(bench), facts); err != nil {
		return nil, err
	}

	version, err := releaseVersion(root)
	if err != nil {
		return nil, err
	}
	facts["version"] = version

	return facts, nil
}

// benchRow matches a totals row: | Pahlevan | 25/26 | 25/26 | 3/3 |
var benchRow = regexp.MustCompile(
	`(?m)^\|\s*\**(Pahlevan|Falco|Tetragon)\**\s*\|\s*(\d+/\d+)\s*\|\s*(\d+/\d+)\s*\|\s*(\d+/\d+)\s*\|`)

// resourceRow matches the agent resource row, whose first cell carries bold and
// a trailing word: | **Pahlevan** agent | 66.7 MiB | ... | 11.25 % |
var resourceRow = regexp.MustCompile(
	`(?m)^\|\s*\**(Pahlevan|Falco|Tetragon)\**[^|]*\|\s*([\d.]+ MiB)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|\s*([\d.]+ %)\s*\|`)

func collectBenchmark(md string, facts map[string]string) error {
	totals := benchRow.FindAllStringSubmatch(md, -1)
	if len(totals) < 3 {
		return fmt.Errorf(
			"the benchmark report has %d totals rows, want 3 (Pahlevan, Falco, Tetragon); "+
				"the table format changed and pagesync cannot read it", len(totals))
	}
	for _, m := range totals {
		tool := strings.ToLower(m[1])
		facts[tool+"-detected"] = spaceSlash(m[2])
		facts[tool+"-blocked"] = spaceSlash(m[3])
		facts[tool+"-benign"] = spaceSlash(m[4])
	}

	res := resourceRow.FindAllStringSubmatch(md, -1)
	if len(res) < 3 {
		return fmt.Errorf(
			"the benchmark report has %d resource rows, want 3; the table format changed", len(res))
	}
	for _, m := range res {
		tool := strings.ToLower(m[1])
		facts[tool+"-memory"] = m[2]
		facts[tool+"-cpu"] = m[3]
	}
	return nil
}

// spaceSlash renders 25/26 as "25 / 26", which is how the site reads.
func spaceSlash(s string) string {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return s
	}
	return parts[0] + " / " + parts[1]
}

// releaseVersion is the version the site tells people to pull.
//
// It comes from the Makefile rather than from `git describe`, because the site
// is built in CI from a checkout that may have no tags, and a version that
// silently becomes "v0.0.0-unknown" on the published page is worse than one
// that is a commit behind.
func releaseVersion(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		return "", fmt.Errorf("reading the Makefile: %w", err)
	}
	m := regexp.MustCompile(`(?m)^VERSION\?=\s*(v[0-9][^\s]*)`).FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("the Makefile has no VERSION?= line for pagesync to read")
	}
	return string(m[1]), nil
}

// marker matches one sync span and captures its key and current content.
var marker = regexp.MustCompile(
	`(?s)<!--\s*pahlevan:sync\s+([a-z0-9-]+)\s*-->(.*?)<!--\s*/pahlevan:sync\s*-->`)

// Apply rewrites every marked span. It returns a description of each value that
// was out of date.
func Apply(root string, facts map[string]string, write bool) ([]string, error) {
	pagesDir := filepath.Join(root, "pages")
	entries, err := os.ReadDir(pagesDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", pagesDir, err)
	}

	var stale []string
	seen := map[string]bool{}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".html" {
			continue
		}
		path := filepath.Join(pagesDir, e.Name())
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed directory in-tree
		if err != nil {
			return nil, err
		}

		var unknown []string
		out := marker.ReplaceAllFunc(data, func(match []byte) []byte {
			m := marker.FindSubmatch(match)
			key, current := string(m[1]), string(m[2])
			seen[key] = true
			want, ok := facts[key]
			if !ok {
				unknown = append(unknown, key)
				return match
			}
			if current == want {
				return match
			}
			stale = append(stale, fmt.Sprintf(
				"%s: %s is %q, should be %q", e.Name(), key, current, want))
			return []byte(fmt.Sprintf("<!--pahlevan:sync %s-->%s<!--/pahlevan:sync-->", key, want))
		})

		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, fmt.Errorf("%s references unknown sync keys: %s",
				e.Name(), strings.Join(unknown, ", "))
		}
		if write && !bytes.Equal(out, data) {
			if err := os.WriteFile(path, out, 0o644); err != nil { // #nosec G306 -- a published static site
				return nil, err
			}
		}
	}

	// The demo GIF is not a marker but is duplicated the same way, and the two
	// copies going out of sync means the site shows a demo of an older tool.
	gifStale, err := syncAsset(root, "docs/assets/demo.gif", "pages/assets/demo.gif", write)
	if err != nil {
		return nil, err
	}
	stale = append(stale, gifStale...)

	sort.Strings(stale)
	return stale, nil
}

// syncAsset keeps a published copy byte-identical to its source.
func syncAsset(root, src, dst string, write bool) ([]string, error) {
	srcPath := filepath.Join(root, src)
	dstPath := filepath.Join(root, dst)

	a, err := os.ReadFile(srcPath) // #nosec G304 -- fixed paths in-tree
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", src, err)
	}
	b, err := os.ReadFile(dstPath) // #nosec G304 -- fixed paths in-tree
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", dst, err)
	}
	if bytes.Equal(a, b) {
		return nil, nil
	}
	if write {
		if err := os.WriteFile(dstPath, a, 0o644); err != nil { // #nosec G306 -- a published static site
			return nil, err
		}
	}
	return []string{fmt.Sprintf("%s differs from %s (%d vs %d bytes)", dst, src, len(b), len(a))}, nil
}
