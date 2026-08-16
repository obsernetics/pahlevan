package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleBenchmark = `# Results

### Totals

| Tool | Attacks detected | Attacks blocked | Benign false positives |
|---|--:|--:|--:|
| Pahlevan | 25/26 | 25/26 | 3/3 |
| Falco | 9/26 | 0/26 | 0/3 |
| Tetragon | 26/26 | 0/26 | 0/3 |

### Resource use

| Tool (agent) | memory.current | anon | kernel | page cache | peak | CPU idle | CPU under load |
|---|--:|--:|--:|--:|--:|--:|--:|
| **Pahlevan** agent | 66.7 MiB | 39.7 MiB | 20.2 MiB | 6.8 MiB | 67.0 MiB | 0.33 % | 11.25 % |
| **Falco** | 195.3 MiB | 45.5 MiB | 26.3 MiB | 123.5 MiB | 201.7 MiB | 0.39 % | 10.65 % |
| **Tetragon** | 78.2 MiB | 36.7 MiB | 38.1 MiB | 3.0 MiB | 118.8 MiB | 0.11 % | 7.77 % |
`

// fixture builds a throwaway repository with the shape pagesync expects.
func fixture(t *testing.T, page string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "benchmarks"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "assets"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pages", "assets"), 0o755))

	require.NoError(t, os.WriteFile(
		filepath.Join(root, "docs", "benchmarks", "results.md"), []byte(sampleBenchmark), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "Makefile"), []byte("VERSION?=v2.0.0\nIMG ?= x\n"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "pages", "index.html"), []byte(page), 0o600))
	// Identical by default, so a test that does not care about the asset does
	// not have to think about it.
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "docs", "assets", "demo.gif"), []byte("GIF89a"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "pages", "assets", "demo.gif"), []byte("GIF89a"), 0o600))
	return root
}

func TestCollectReadsTheBenchmarkTotals(t *testing.T) {
	facts, err := Collect(fixture(t, "<html></html>"))
	require.NoError(t, err)

	assert.Equal(t, "25 / 26", facts["pahlevan-blocked"])
	assert.Equal(t, "25 / 26", facts["pahlevan-detected"])
	assert.Equal(t, "3 / 3", facts["pahlevan-benign"])
	assert.Equal(t, "0 / 26", facts["falco-blocked"])
	assert.Equal(t, "9 / 26", facts["falco-detected"])
	assert.Equal(t, "26 / 26", facts["tetragon-detected"])
	assert.Equal(t, "66.7 MiB", facts["pahlevan-memory"])
	assert.Equal(t, "195.3 MiB", facts["falco-memory"])
	assert.Equal(t, "11.25 %", facts["pahlevan-cpu"])
	assert.Equal(t, "v2.0.0", facts["version"])
}

// The whole point: a page that has drifted from the benchmark must be reported,
// and reported with both values so the reader can see which way it drifted.
func TestCheckReportsDrift(t *testing.T) {
	root := fixture(t,
		`<p><!--pahlevan:sync pahlevan-blocked-->4 / 4<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, false)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Contains(t, stale[0], `"4 / 4"`)
	assert.Contains(t, stale[0], `"25 / 26"`)

	// -check must not touch the file.
	after, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(after), "4 / 4")
}

func TestWriteFixesDrift(t *testing.T) {
	root := fixture(t,
		`<p><!--pahlevan:sync pahlevan-blocked-->4 / 4<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, true)
	require.NoError(t, err)
	require.Len(t, stale, 1)

	after, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(after),
		"<!--pahlevan:sync pahlevan-blocked-->25 / 26<!--/pahlevan:sync-->")

	// Idempotent: a second pass finds nothing.
	stale, err = Apply(root, facts, true)
	require.NoError(t, err)
	assert.Empty(t, stale)
}

// A marker whose source has been deleted or renamed would otherwise keep
// publishing whatever value it happened to contain, which is exactly the
// failure this program exists to stop. It must be an error, not a skip.
func TestUnknownKeyIsAnError(t *testing.T) {
	root := fixture(t, `<p><!--pahlevan:sync made-up-key-->x<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	_, err = Apply(root, facts, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "made-up-key")
}

// Several markers for the same key on one page must all update. The benchmark
// number appears in both a table and the prose beneath it, and updating one
// would leave the page contradicting itself.
func TestRepeatedKeyIsUpdatedEverywhere(t *testing.T) {
	root := fixture(t, `<td><!--pahlevan:sync pahlevan-blocked-->4 / 4<!--/pahlevan:sync--></td>`+
		`<p><!--pahlevan:sync pahlevan-blocked-->old<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, true)
	require.NoError(t, err)
	assert.Len(t, stale, 2)

	after, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	require.NoError(t, err)
	assert.NotContains(t, string(after), "4 / 4")
	assert.NotContains(t, string(after), ">old<")
}

// The GIF is duplicated rather than marked, and the two copies going out of
// sync means the site shows a demo of an older tool.
func TestAssetDriftIsReported(t *testing.T) {
	root := fixture(t, "<html></html>")
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "docs", "assets", "demo.gif"), []byte("GIF89a-new"), 0o600))

	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, false)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Contains(t, stale[0], "demo.gif")

	_, err = Apply(root, facts, true)
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(root, "pages", "assets", "demo.gif"))
	require.NoError(t, err)
	assert.Equal(t, "GIF89a-new", string(got))
}

// A benchmark table that has been reformatted must fail loudly. Silently
// finding zero rows would leave every borrowed number frozen at whatever it was
// when the format last worked.
func TestReformattedBenchmarkTableIsAnError(t *testing.T) {
	root := fixture(t, "<html></html>")
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "docs", "benchmarks", "results.md"),
		[]byte("# Results\n\nNo tables here any more.\n"), 0o600))

	_, err := Collect(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "totals rows")
}

func TestMissingVersionIsAnError(t *testing.T) {
	root := fixture(t, "<html></html>")
	require.NoError(t, os.WriteFile(filepath.Join(root, "Makefile"), []byte("IMG ?= x\n"), 0o600))
	_, err := Collect(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VERSION")
}

// The real repository must be in sync. This is the test that actually keeps the
// published site honest between CI runs.
func TestRepositorySiteIsInSync(t *testing.T) {
	const root = "../.."
	if _, err := os.Stat(filepath.Join(root, "pages", "index.html")); err != nil {
		t.Skipf("not running in the repository: %v", err)
	}
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, false)
	require.NoError(t, err)
	assert.Empty(t, stale,
		"the published site is stale; run: go run ./hack/pagesync -write")
}

func TestSpaceSlash(t *testing.T) {
	assert.Equal(t, "25 / 26", spaceSlash("25/26"))
	assert.Equal(t, "3 / 3", spaceSlash("3/3"))
	assert.Equal(t, "nonsense", spaceSlash("nonsense"))
}

func BenchmarkCollect(b *testing.B) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, "pages", "index.html")); err != nil {
		b.Skip("not running in the repository")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Collect(root); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyCheck(b *testing.B) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, "pages", "index.html")); err != nil {
		b.Skip("not running in the repository")
	}
	facts, err := Collect(root)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Apply(root, facts, false); err != nil {
			b.Fatal(err)
		}
	}
}

// The landing page is where an evaluator decides whether to read further, and
// it is the artifact most likely to describe a version of the tool that no
// longer exists. pagesync keeps its *numbers* honest; nothing kept its
// *claims* honest, and it went a long way out of date - the page described
// file and egress enforcement while the tool had gained a process filter,
// destination naming, an OTLP pipeline and an offline policy explainer.
//
// A full prose check is not possible. What is checkable is that a capability
// the repository demonstrably ships is mentioned somewhere on the page: each
// entry below pairs a marker that proves the feature exists in the tree with a
// phrase the page must contain.
func TestTheSiteMentionsWhatTheToolShips(t *testing.T) {
	const root = "../.."
	page, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	if err != nil {
		t.Skipf("not running in the repository: %v", err)
	}
	text := strings.ToLower(string(page))

	for name, tc := range map[string]struct {
		// proof is a path that exists only when the feature does.
		proof string
		// phrases are alternatives; the page must contain at least one.
		phrases []string
	}{
		"process filter": {
			proof:   "pkg/ebpf/procfilter.go",
			phrases: []string{"processfilter", "who execs"},
		},
		"destination naming": {
			proof:   "internal/netmap/resolver.go",
			phrases: []string{"destinations have names", "prod/postgres"},
		},
		"otlp export": {
			proof:   "pkg/export/otlp.go",
			phrases: []string{"otlp", "loki"},
		},
		"policy explain": {
			proof:   "cmd/pahlevan/commands/policyexplain.go",
			phrases: []string{"policy explain"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(root, tc.proof)); err != nil {
				t.Skipf("%s is not present, so the page need not mention it", name)
			}
			for _, p := range tc.phrases {
				if strings.Contains(text, strings.ToLower(p)) {
					return
				}
			}
			t.Errorf("%s ships (%s exists) but pages/index.html does not mention it; "+
				"tried %v", name, tc.proof, tc.phrases)
		})
	}
}
