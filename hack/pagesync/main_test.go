package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two attack scenarios carrying three distinct technique ids between them, and
// one benign control. Written out rather than counted from the real directory
// so the expected numbers in these tests do not change every time somebody adds
// a scenario.
var sampleScenarios = map[string]string{
	"01-sensitive-file-read.sh": "#!/usr/bin/env sh\n# Technique: OS Credential Dumping (T1003.008)\nexit 0\n",
	"02-reverse-shell.sh":       "#!/usr/bin/env sh\n# Technique: T1059.004 and T1071\nexit 0\n",
}

// fixture builds a throwaway repository with the shape pagesync expects.
func fixture(t *testing.T, page string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "benchmarks"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "assets"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pages", "assets"), 0o755))

	require.NoError(t, os.MkdirAll(filepath.Join(root, "test", "benchmark", "scenarios", "benign"), 0o755))
	for name, body := range sampleScenarios {
		require.NoError(t, os.WriteFile(
			filepath.Join(root, "test", "benchmark", "scenarios", name), []byte(body), 0o600))
	}
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "test", "benchmark", "scenarios", "benign", "01-ok.sh"),
		[]byte("#!/usr/bin/env sh\nexit 0\n"), 0o600))
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

func TestCollectCountsTheScenarioSuite(t *testing.T) {
	facts, err := Collect(fixture(t, "<html></html>"))
	require.NoError(t, err)

	assert.Equal(t, "2", facts["attack-scenarios"])
	assert.Equal(t, "1", facts["benign-scenarios"])
	// T1003.008, T1059.004, T1071 - counted once each, across both files.
	assert.Equal(t, "3", facts["attack-techniques"])
	assert.Equal(t, "v2.0.0", facts["version"])
}

// The count must come from the directory, not from a number somebody typed.
// Adding a scenario is what changes the published figure.
func TestAddingAScenarioChangesTheCount(t *testing.T) {
	root := fixture(t, "<html></html>")
	before, err := Collect(root)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(
		filepath.Join(root, "test", "benchmark", "scenarios", "99-new.sh"),
		[]byte("#!/usr/bin/env sh\n# Technique: T9999\nexit 0\n"), 0o600))

	after, err := Collect(root)
	require.NoError(t, err)
	assert.Equal(t, "2", before["attack-scenarios"])
	assert.Equal(t, "3", after["attack-scenarios"])
	assert.Equal(t, "4", after["attack-techniques"])
}

// The whole point: a page that has drifted from the benchmark must be reported,
// and reported with both values so the reader can see which way it drifted.
func TestCheckReportsDrift(t *testing.T) {
	root := fixture(t,
		`<p><!--pahlevan:sync attack-scenarios-->4<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, false)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Contains(t, stale[0], `"4"`)
	assert.Contains(t, stale[0], `"2"`)

	// -check must not touch the file.
	after, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(after), ">4<")
}

func TestWriteFixesDrift(t *testing.T) {
	root := fixture(t,
		`<p><!--pahlevan:sync attack-scenarios-->4<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, true)
	require.NoError(t, err)
	require.Len(t, stale, 1)

	after, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(after),
		"<!--pahlevan:sync attack-scenarios-->2<!--/pahlevan:sync-->")

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
	root := fixture(t, `<td><!--pahlevan:sync attack-scenarios-->4<!--/pahlevan:sync--></td>`+
		`<p><!--pahlevan:sync attack-scenarios-->old<!--/pahlevan:sync--></p>`)
	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, true)
	require.NoError(t, err)
	assert.Len(t, stale, 2)

	after, err := os.ReadFile(filepath.Join(root, "pages", "index.html"))
	require.NoError(t, err)
	assert.NotContains(t, string(after), ">4<")
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

// A moved or emptied scenario directory must fail loudly. Silently finding zero
// would publish "0 attack scenarios", or worse, leave the previous number
// frozen on the page while the suite it describes no longer exists.
func TestAnEmptyScenarioDirectoryIsAnError(t *testing.T) {
	root := fixture(t, "<html></html>")
	for name := range sampleScenarios {
		require.NoError(t, os.Remove(filepath.Join(root, "test", "benchmark", "scenarios", name)))
	}
	_, err := Collect(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no attack scenarios")

	require.NoError(t, os.RemoveAll(filepath.Join(root, "test", "benchmark")))
	_, err = Collect(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scenario directory")
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

// Sub-techniques must count as themselves, not collapse into their parent, and
// a bare word that looks like an id must not be picked up.
func TestTechniquePattern(t *testing.T) {
	got := technique.FindAllString(
		"T1003.008 and T1003 and T1059.004, but not XT1234 or T12345", -1)
	assert.Equal(t, []string{"T1003.008", "T1003", "T1059.004"}, got)
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

// docs/packages.md is the page a reader copies install commands out of, and it
// spent a whole release telling people to pull an image tag two versions old.
// Nothing caught it because Apply only walked pages/. This asserts that files
// outside pages/ are covered now.
func TestMarkedFilesOutsidePagesAreChecked(t *testing.T) {
	root := fixture(t, "<html></html>")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "packages.md"),
		[]byte("Pull `<!--pahlevan:sync version-->v0.0.1<!--/pahlevan:sync-->`.\n"), 0o600))

	facts, err := Collect(root)
	require.NoError(t, err)

	stale, err := Apply(root, facts, false)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Contains(t, stale[0], "docs/packages.md",
		"a stale fact outside pages/ must be reported with the file it is in")
	assert.Contains(t, stale[0], "v0.0.1")
	assert.Contains(t, stale[0], "v2.0.0")

	_, err = Apply(root, facts, true)
	require.NoError(t, err)
	after, err := os.ReadFile(filepath.Join(root, "docs", "packages.md"))
	require.NoError(t, err)
	assert.Contains(t, string(after), "<!--pahlevan:sync version-->v2.0.0<!--/pahlevan:sync-->")
}

// A marked file that does not exist is skipped rather than failing the run, so
// removing a document does not break the sync for every other one.
func TestMissingMarkedFileIsSkipped(t *testing.T) {
	root := fixture(t, "<html></html>")
	facts, err := Collect(root)
	require.NoError(t, err)
	stale, err := Apply(root, facts, false)
	require.NoError(t, err, "an absent docs/packages.md must not fail the run")
	assert.Empty(t, stale)
}
