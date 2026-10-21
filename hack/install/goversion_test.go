package install

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The Go version is pinned in six workflow places and in go.mod's toolchain
// line, and nothing connected them.
//
// That matters because the pin is a security control, not a convenience. The
// scheduled Security job failed on GO-2026-6809, a crypto/x509 advisory present
// in the Go standard library up to go1.26.9 and fixed in go1.26.10. Every pin
// said 1.26.9, so every job compiled against the affected standard library. A
// single pin left behind on the next bump puts one job back on a vulnerable
// toolchain while the others look current, and govulncheck only runs in one job.

var (
	// A bare pin in a workflow: go-version: '1.26.10' or GO_VERSION: "1.26.10".
	workflowGoPin = regexp.MustCompile(`(?:go-version|GO_VERSION):\s*["']?(\d+\.\d+\.\d+)`)
	// go.mod's toolchain line.
	toolchainPin = regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)`)
)

// collectGoPins returns every pinned Go version, keyed by where it was found.
func collectGoPins(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}

	dirs := []string{".github/workflows", ".github/actions"}
	for _, d := range dirs {
		root := repoPath(d)
		_ = filepath.WalkDir(root, func(p string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil //nolint:nilerr // a missing directory is not a failure here
			}
			if ext := filepath.Ext(p); ext != ".yml" && ext != ".yaml" {
				return nil
			}
			b, rerr := os.ReadFile(p) // #nosec G304 -- fixed in-tree directories
			if rerr != nil {
				return nil
			}
			for _, m := range workflowGoPin.FindAllStringSubmatch(string(b), -1) {
				rel, _ := filepath.Rel(repoPath("."), p)
				out[m[1]] = append(out[m[1]], rel)
			}
			return nil
		})
	}

	b, err := os.ReadFile(repoPath("go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if m := toolchainPin.FindStringSubmatch(string(b)); m != nil {
		out[m[1]] = append(out[m[1]], "go.mod toolchain")
	}
	return out
}

func TestEveryGoVersionPinAgrees(t *testing.T) {
	pins := collectGoPins(t)
	if len(pins) == 0 {
		t.Fatal("found no Go version pins at all, so this guard is checking nothing; the pin syntax must have changed")
	}

	if len(pins) > 1 {
		versions := make([]string, 0, len(pins))
		for v := range pins {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		var detail strings.Builder
		for _, v := range versions {
			detail.WriteString("\n    " + v + ": " + strings.Join(pins[v], ", "))
		}
		t.Errorf("the Go version is pinned to %d different values, so some jobs compile against a different "+
			"standard library than others. The pin is a security control: GO-2026-6809 was a crypto/x509 advisory "+
			"fixed in a patch release, and a pin left behind keeps one job on the affected toolchain while the "+
			"others look current. Found:%s", len(pins), detail.String())
	}
}

// TestTheGoPinIsNotKnownVulnerable names the one advisory this repo actually
// tripped over. It is a floor, not a vulnerability database: govulncheck in the
// Security workflow is what finds new ones. This exists so a revert to the
// affected patch release fails here rather than waiting for the next scheduled
// scan.
func TestTheGoPinIsNotKnownVulnerable(t *testing.T) {
	const firstFixed = "1.26.10" // GO-2026-6809, crypto/x509

	for version, where := range collectGoPins(t) {
		if !strings.HasPrefix(version, "1.26.") {
			continue // a different minor line; the floor below does not apply
		}
		if goPatchLess(version, firstFixed) {
			t.Errorf("Go is pinned to %s in %s, which is below %s. GO-2026-6809 affects crypto/x509 in the "+
				"standard library up to 1.26.9 and is fixed in %s, and this project's own Security job failed "+
				"on it", version, strings.Join(where, ", "), firstFixed, firstFixed)
		}
	}
}

// goPatchLess compares two dotted versions on the same minor line.
func goPatchLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, nb := atoiOrZero(pa[i]), atoiOrZero(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return false
}

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func BenchmarkGoPinScan(b *testing.B) {
	raw, err := os.ReadFile(repoPath(".github/workflows/ci.yml"))
	if err != nil {
		b.Fatal(err)
	}
	s := string(raw)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if workflowGoPin.FindAllStringSubmatch(s, -1) == nil {
			b.Fatal("the pin syntax stopped matching")
		}
	}
}
