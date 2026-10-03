package release

import (
	"os/exec"
	"strings"
	"testing"
)

func TestLatestIsTheNewestBySemverNotByListOrder(t *testing.T) {
	// git tag --list sorts lexically, which puts v3.10.0 before v3.9.0. A
	// generator that took the last line would advertise the older release the
	// first time a minor reached double digits.
	p, err := Load(Fixed("v3.9.0", "v3.10.0", "v3.6.0", "v3.5.1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Latest(); got != "v3.10.0" {
		t.Errorf("Latest() = %q, want v3.10.0; version tags must be ordered by semver, not lexically", got)
	}
}

func TestLatestPrefersAReleaseOverItsPrerelease(t *testing.T) {
	p, err := Load(Fixed("v3.6.0", "v3.7.0-rc.1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Latest(); got != "v3.6.0" {
		t.Errorf("Latest() = %q, want v3.6.0; an unreleased candidate is not something to tell people to install", got)
	}
}

func TestHasAcceptsBothSpellings(t *testing.T) {
	p, err := Load(Fixed("v3.6.0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v3.6.0", "3.6.0", " 3.6.0 "} {
		if !p.Has(v) {
			t.Errorf("Has(%q) = false; CHANGELOG.md headings carry no leading v and tags do, so both must resolve", v)
		}
	}
	for _, v := range []string{"", "3.6.1", "v3.5.0"} {
		if p.Has(v) {
			t.Errorf("Has(%q) = true, but that version is not in the set", v)
		}
	}
}

func TestNoTagsIsAnErrorRatherThanAnEmptyAnswer(t *testing.T) {
	_, err := Load(Fixed())
	if err == nil {
		t.Fatal("Load with no tags returned no error; an empty set would let every caller silently " +
			"conclude nothing is published, which is the failure this package exists to prevent")
	}
	if !strings.Contains(err.Error(), "fetch-tags") {
		t.Errorf("the error should name the CI fix so it is actionable, got: %v", err)
	}
}

func TestNonReleaseTagsAreIgnoredNotFatal(t *testing.T) {
	p, err := Load(Fixed("vlatest", "v3", "v3.6", "v3.6.0", "nightly"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Latest(); got != "v3.6.0" {
		t.Errorf("Latest() = %q, want v3.6.0", got)
	}
	if p.Len() != 1 {
		t.Errorf("Len() = %d, want 1; a repo may carry tags that are not releases", p.Len())
	}
}

func TestDuplicateTagsCollapse(t *testing.T) {
	p, err := Load(Fixed("v3.6.0", "v3.6.0"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Len() != 1 {
		t.Errorf("Len() = %d, want 1", p.Len())
	}
}

func TestAllIsNewestFirstAndIsACopy(t *testing.T) {
	p, err := Load(Fixed("v3.5.0", "v3.6.0"))
	if err != nil {
		t.Fatal(err)
	}
	all := p.All()
	if len(all) != 2 || all[0] != "v3.6.0" {
		t.Fatalf("All() = %v, want newest first", all)
	}
	all[0] = "mutated"
	if p.Latest() != "v3.6.0" {
		t.Error("All() handed out the internal slice; a caller sorting it would corrupt the set")
	}
}

func TestGitTagsReadsTheRealRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	p, err := Load(GitTags(".."))
	if err != nil {
		t.Skipf("no tags in this checkout, which is legitimate for a shallow clone: %v", err)
	}
	if p.Len() == 0 {
		t.Fatal("Load returned no error but an empty set")
	}
	if !strings.HasPrefix(p.Latest(), "v") {
		t.Errorf("Latest() = %q, want a v-prefixed version", p.Latest())
	}
}

func BenchmarkLoad(b *testing.B) {
	tags := make([]string, 0, 256)
	for i := 0; i < 256; i++ {
		tags = append(tags, "v3."+string(rune('0'+i%10))+".0")
	}
	l := Fixed(tags...)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Load(l); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHas(b *testing.B) {
	p, err := Load(Fixed("v3.6.0", "v3.5.1", "v3.5.0", "v3.4.1"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Has("3.6.0") {
			b.Fatal("expected a hit")
		}
	}
}
