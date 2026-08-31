// Command pagesync keeps the GitHub Pages site consistent with the repository.
//
// The site duplicates facts that live elsewhere: the release version, the size
// of the benchmark suite, the ATT&CK coverage it claims. Duplicated facts
// drift, and this set drifted badly - the published page once claimed Pahlevan
// blocked "4 / 4" attacks while the report it linked to said something else
// entirely, because the page was written against a superseded run and nothing
// re-derived it.
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
	"strconv"
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

	if err := collectScenarios(root, facts); err != nil {
		return nil, err
	}

	version, err := releaseVersion(root)
	if err != nil {
		return nil, err
	}
	facts["version"] = version

	return facts, nil
}

// technique matches a MITRE ATT&CK technique id in a scenario header comment,
// including sub-techniques: T1003, T1003.008.
var technique = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)

// collectScenarios counts the benchmark suite from the scenario scripts
// themselves.
//
// Counted rather than copied, because the number on the page is a claim about
// coverage and a hand-typed one goes stale the first time somebody adds a
// scenario. Adding a file to the directory is what changes the published
// figure.
func collectScenarios(root string, facts map[string]string) error {
	dir := filepath.Join(root, "test", "benchmark", "scenarios")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading the scenario directory: %w", err)
	}

	attacks, benign := 0, 0
	techniques := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			// scenarios/benign/ holds the controls.
			if e.Name() != "benign" {
				continue
			}
			sub, err := os.ReadDir(filepath.Join(dir, "benign"))
			if err != nil {
				return fmt.Errorf("reading the benign scenario directory: %w", err)
			}
			for _, b := range sub {
				if filepath.Ext(b.Name()) == ".sh" {
					benign++
				}
			}
			continue
		}
		if filepath.Ext(e.Name()) != ".sh" {
			continue
		}
		attacks++

		// The technique ids live in the header comment of each script, which
		// is also where a reader looks for them. Parsing the same place the
		// reader reads means the two cannot disagree.
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a fixed directory in-tree
		if err != nil {
			return fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		for _, m := range technique.FindAllString(string(data), -1) {
			techniques[m] = true
		}
	}

	if attacks == 0 {
		return fmt.Errorf("no attack scenarios found in %s; the site would publish a zero", dir)
	}

	facts["attack-scenarios"] = strconv.Itoa(attacks)
	facts["benign-scenarios"] = strconv.Itoa(benign)
	facts["attack-techniques"] = strconv.Itoa(len(techniques))
	return nil
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
// markedFiles are the files outside pages/ that also borrow a fact.
//
// docs/packages.md is here because it is the page a reader copies install
// commands out of, and it spent an entire release telling people to pull an
// image tag that was two versions old. Nothing guarded it: pagesync only
// walked pages/, so the site stayed correct while the docs did not.
var markedFiles = []string{
	filepath.Join("docs", "packages.md"),
}

// Apply rewrites every marked span across pages/*.html and markedFiles.
func Apply(root string, facts map[string]string, write bool) ([]string, error) {
	pagesDir := filepath.Join(root, "pages")
	entries, err := os.ReadDir(pagesDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", pagesDir, err)
	}

	var targets []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".html" {
			targets = append(targets, filepath.Join("pages", e.Name()))
		}
	}
	for _, f := range markedFiles {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			targets = append(targets, f)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("checking %s: %w", f, err)
		}
	}

	var stale []string
	seen := map[string]bool{}

	for _, rel := range targets {
		path := filepath.Join(root, rel)
		name := rel
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed set of in-tree paths
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
				"%s: %s is %q, should be %q", name, key, current, want))
			return []byte(fmt.Sprintf("<!--pahlevan:sync %s-->%s<!--/pahlevan:sync-->", key, want))
		})

		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, fmt.Errorf("%s references unknown sync keys: %s",
				name, strings.Join(unknown, ", "))
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
