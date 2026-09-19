// Command sitegen generates the published parts of the GitHub Pages site.
//
// Two things on the site were maintained by hand and both went wrong in the
// same way.
//
// The twelve documents in docs/ were never published at all: the site linked
// out to the markdown on GitHub, so the documentation lived outside the
// website that advertises it.
//
// And the release articles on the changelog page were typed out, which is how
// 3.3.3 came to be documented in CHANGELOG.md and shown to nobody. The version
// strings updated, because pagesync owns those, so the page badged itself
// v3.3.3 while the newest article was still 3.3.2 - and
// `go run ./hack/pagesync -check` reported the site up to date, because prose
// is not a marked span.
//
// This program derives both from their sources, so the site cannot say
// something the repository does not. It deliberately does not touch the
// hand-designed landing page: generation is for content that is a
// transcription of another file, not for design.
//
//	go run ./hack/sitegen -check   # exit non-zero if the site is out of date
//	go run ./hack/sitegen -write   # regenerate it
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	var (
		root  = flag.String("root", ".", "repository root")
		write = flag.Bool("write", false, "regenerate the pages in place")
		check = flag.Bool("check", false, "exit non-zero if the generated pages are out of date")
	)
	flag.Parse()

	if *write == *check {
		fmt.Fprintln(os.Stderr, "sitegen: pass exactly one of -write or -check")
		os.Exit(2)
	}

	site, err := Build(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sitegen: %v\n", err)
		os.Exit(1)
	}

	stale, err := Apply(*root, site, *write)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sitegen: %v\n", err)
		os.Exit(1)
	}

	if len(stale) == 0 {
		fmt.Println("sitegen: the generated site is up to date")
		return
	}
	if *write {
		fmt.Printf("sitegen: updated %d file(s)\n", len(stale))
		for _, s := range stale {
			fmt.Printf("  %s\n", s)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "sitegen: the published site is out of date in %d place(s):\n", len(stale))
	for _, s := range stale {
		fmt.Fprintf(os.Stderr, "  %s\n", s)
	}
	fmt.Fprintln(os.Stderr, "\nrun: go run ./hack/sitegen -write")
	os.Exit(1)
}

// Site is every file this generator owns, keyed by path relative to the
// repository root.
type Site struct {
	Files map[string][]byte
}

// Build renders the whole generated site in memory.
//
// In memory, so that -check and -write do exactly the same work and can only
// disagree about whether to write the result. A checker that re-implements the
// generator is a checker that passes while the generator is broken.
func Build(root string) (*Site, error) {
	site := &Site{Files: map[string][]byte{}}

	docs, err := LoadDocs(root)
	if err != nil {
		return nil, err
	}

	assets := map[string]bool{}
	for _, d := range docs {
		html, err := renderDocPage(d)
		if err != nil {
			return nil, fmt.Errorf("rendering %s: %w", d.Source, err)
		}
		site.Files[d.Out] = html
		for _, a := range d.Page.Assets {
			assets[a] = true
		}
	}

	index, err := renderDocIndex(docs)
	if err != nil {
		return nil, fmt.Errorf("rendering the documentation index: %w", err)
	}
	site.Files[docsOut+"/index.html"] = index

	// Diagrams the docs embed have to be published with them. A page that
	// references an image the site does not serve still returns 200, so this
	// is not something a link checker or a failing build would report.
	for a := range assets {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(a))) // #nosec G304 -- a path taken from an in-tree markdown file, under docs/
		if err != nil {
			return nil, fmt.Errorf("a docs page references %s, which does not exist: %w", a, err)
		}
		site.Files[docsOut+strings.TrimPrefix(a, docsDir)] = data
	}

	releases, err := ParseChangelog(root)
	if err != nil {
		return nil, err
	}
	page, err := os.ReadFile(filepath.Join(root, changelogOut)) // #nosec G304 -- a fixed in-tree path
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", changelogOut, err)
	}
	spliced, err := SpliceReleases(page, RenderReleases(releases))
	if err != nil {
		return nil, err
	}
	site.Files[changelogOut] = spliced

	return site, nil
}

// Apply compares the generated site with what is on disk, writing it when
// asked. It returns one line per file that was out of date.
func Apply(root string, site *Site, write bool) ([]string, error) {
	var stale []string

	for rel, want := range site.Files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		have, err := os.ReadFile(path) // #nosec G304 -- paths this program generated
		switch {
		case os.IsNotExist(err):
			stale = append(stale, fmt.Sprintf("%s is missing", rel))
		case err != nil:
			return nil, err
		case !bytes.Equal(have, want):
			stale = append(stale, fmt.Sprintf("%s differs from its source (%d vs %d bytes)", rel, len(have), len(want)))
		default:
			continue
		}
		if !write {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, want, 0o644); err != nil { // #nosec G306 -- a published static site
			return nil, err
		}
	}

	orphans, err := findOrphans(root, site)
	if err != nil {
		return nil, err
	}
	for _, o := range orphans {
		stale = append(stale, fmt.Sprintf("%s is left over from a document that no longer exists", o))
		if write {
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(o))); err != nil {
				return nil, err
			}
		}
	}

	sort.Strings(stale)
	return stale, nil
}

// findOrphans lists files under pages/docs/ that the generator no longer
// produces.
//
// Deleting a document would otherwise leave its page published and still
// linked from anywhere that already pointed at it - a page describing a
// feature that has been removed is worse than no page, and nothing else in the
// repository would ever mention it again.
func findOrphans(root string, site *Site) ([]string, error) {
	dir := filepath.Join(root, filepath.FromSlash(docsOut))
	var orphans []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		slash := filepath.ToSlash(rel)
		if _, ok := site.Files[slash]; !ok {
			orphans = append(orphans, slash)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return orphans, nil
}
