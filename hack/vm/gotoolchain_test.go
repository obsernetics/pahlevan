package vm

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/mod/semver"
)

// hack/vm/smoke is compiled and run inside the guest, by the guest's own Go.
// So its `go` directive is a constraint on the VM image, not just on CI, and
// nothing about the two lives in the same file.
//
// This guard exists because bumping golang.org/x/sys to fix CVE-2026-39824
// quietly moved the smoke module's directive from go 1.25.0 to go 1.26.0, which
// the guest's Go 1.25.13 cannot build. `go get` reports that as an upgrade, not
// a problem, and the failure would have surfaced only on the next VM run as a
// toolchain download in a guest that may have no network. Pinning x/sys to
// v0.47.0 fixed the CVE and left the directive alone.

var (
	goDirective = regexp.MustCompile(`(?m)^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	guestGo     = regexp.MustCompile(`GO_VERSION="\$\{PAHLEVAN_VM_GO_VERSION:-([0-9.]+)\}"`)
)

// canonical turns a Go version like "1.25" or "1.25.13" into a semver string.
func canonical(v string) string {
	s := "v" + v
	if semver.Canonical(s) == "" {
		// "v1.25" is valid to semver but not canonical; MajorMinor keeps it
		// comparable, which is all this guard needs.
		return semver.MajorMinor(s)
	}
	return semver.Canonical(s)
}

func readGuestGoVersion(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "hack/vm/env.sh"))
	if err != nil {
		t.Fatalf("reading hack/vm/env.sh: %v", err)
	}
	m := guestGo.FindSubmatch(b)
	if m == nil {
		t.Fatal("hack/vm/env.sh no longer declares GO_VERSION in the form this guard reads, " +
			"so nothing checks that the guest can build what the VM runs")
	}
	return string(m[1])
}

func TestTheGuestGoCanBuildTheSmokeModule(t *testing.T) {
	guest := readGuestGoVersion(t)

	b, err := os.ReadFile(filepath.Join(repoRoot, "hack/vm/smoke/go.mod"))
	if err != nil {
		t.Fatalf("reading hack/vm/smoke/go.mod: %v", err)
	}
	m := goDirective.FindSubmatch(b)
	if m == nil {
		t.Fatal("hack/vm/smoke/go.mod has no go directive")
	}
	needs := string(m[1])

	if semver.Compare(canonical(guest), canonical(needs)) < 0 {
		t.Errorf("hack/vm/smoke requires go %s but the VM provisions go %s (hack/vm/env.sh GO_VERSION). "+
			"That module is compiled inside the guest, so the build either fails or silently depends on the guest "+
			"downloading a toolchain, which needs network in the VM. Either pin the dependency that raised the "+
			"directive, or raise GO_VERSION and re-run `make vm-test`", needs, guest)
	}
}

// TestTheSmokeModuleHasNoKnownVulnerableXSys is the narrow guard for the
// finding that started this: the module lagged at x/sys v0.43.0, which
// CVE-2026-39824 fixes in v0.44.0, while the main module was already on v0.48.0.
// A second module is easy to forget, and Dependabot's gomod entry points at "/".
func TestTheSmokeModuleHasNoKnownVulnerableXSys(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "hack/vm/smoke/go.mod"))
	if err != nil {
		t.Fatalf("reading hack/vm/smoke/go.mod: %v", err)
	}
	m := regexp.MustCompile(`golang\.org/x/sys\s+(v[0-9][^\s]*)`).FindSubmatch(b)
	if m == nil {
		return // the dependency is gone, nothing to check
	}
	got := string(m[1])
	const fixed = "v0.44.0" // CVE-2026-39824
	if semver.Compare(got, fixed) < 0 {
		t.Errorf("hack/vm/smoke pins golang.org/x/sys %s, below the %s that fixes CVE-2026-39824. "+
			"This module is separate from the root one, so a root-only dependency update leaves it behind", got, fixed)
	}
}

func BenchmarkGoVersionGuards(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "hack/vm/smoke/go.mod"))
	if err != nil {
		b.Fatal(err)
	}
	env, err := os.ReadFile(filepath.Join(repoRoot, "hack/vm/env.sh"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if goDirective.FindSubmatch(raw) == nil || guestGo.FindSubmatch(env) == nil {
			b.Fatal("a guard input stopped matching")
		}
	}
}
