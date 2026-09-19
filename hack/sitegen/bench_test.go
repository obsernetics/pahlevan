package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The generator runs on every pull request that touches docs/ and again before
// every deploy, so its cost is paid by people waiting for a review. These
// measure the two things that grow without anyone deciding to: the size of the
// largest document, and the number of releases in CHANGELOG.md.

// largestDoc finds the biggest markdown file rather than naming one, because
// the biggest one changes - api-reference.md is generated from the Go types
// and grows every time the CRD does.
func largestDoc(tb testing.TB) (string, []byte) {
	tb.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot, docsDir))
	if err != nil {
		tb.Fatal(err)
	}
	var name string
	var biggest int64
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			tb.Fatal(err)
		}
		if info.Size() > biggest {
			biggest, name = info.Size(), e.Name()
		}
	}
	if name == "" {
		tb.Fatal("no markdown in docs/")
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, docsDir, name))
	if err != nil {
		tb.Fatal(err)
	}
	return name, data
}

func BenchmarkConvertLargestDoc(b *testing.B) {
	name, src := largestDoc(b)
	b.Logf("converting docs/%s (%d bytes)", name, len(src))
	siblings := map[string]bool{"architecture": true, "quick-start": true}

	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Convert(src, siblings); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRenderLargestDocPage(b *testing.B) {
	name, src := largestDoc(b)
	page, err := Convert(src, nil)
	if err != nil {
		b.Fatal(err)
	}
	doc := Doc{Source: docsDir + "/" + name, Slug: slugOf(name), Page: page}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := renderDocPage(doc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseChangelog(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseChangelog(repoRoot); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRenderReleases(b *testing.B) {
	releases, err := ParseChangelog(repoRoot)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RenderReleases(releases)
	}
}

// The whole site: what a pull request actually waits for.
func BenchmarkBuildSite(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Build(repoRoot); err != nil {
			b.Fatal(err)
		}
	}
}

// -check on an unchanged tree, the path CI takes on most runs.
func BenchmarkCheck(b *testing.B) {
	site, err := Build(repoRoot)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Apply(repoRoot, site, false); err != nil {
			b.Fatal(err)
		}
	}
}
