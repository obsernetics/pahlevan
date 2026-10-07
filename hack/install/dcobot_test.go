package install

import (
	"os"
	"strings"
	"testing"
)

// Dependabot authors a commit as
//
//	dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>
//
// and signs it off as
//
//	Signed-off-by: dependabot[bot] <support@github.com>
//
// Both addresses are GitHub's and neither is choosable, so a DCO check that
// compares author and sign-off exactly can never pass for a bot. Twelve
// dependency pull requests were closed unmerged because of that, and the
// updates were then redone by hand in batch branches, which is work the bot
// had already done correctly.
//
// The relaxation is narrow on purpose, and these guards pin both halves: a bot
// is matched on name so one bot cannot sign off another's work, and a human
// commit is still compared exactly.

func dcoScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(repoPath(".github/workflows/dco.yml"))
	if err != nil {
		t.Fatalf("reading .github/workflows/dco.yml: %v", err)
	}
	return string(b)
}

func TestTheDCOCheckAcceptsABotSignOff(t *testing.T) {
	s := dcoScript(t)

	if !strings.Contains(s, `*'[bot]')`) {
		t.Error("the DCO check has no case for a [bot] author. Dependabot's sign-off address differs from its " +
			"author address and neither is choosable, so every dependency pull request fails and the update " +
			"gets redone by hand")
	}
	// Matched on the exact assignment, not on the substring. The same text
	// appears in the human `expected=` line, so a looser check passed even with
	// the bot name-match gutted, which a mutation caught.
	if !strings.Contains(s, `expected_match="Signed-off-by: ${author_name} <"`) {
		t.Error("the bot branch does not build its match from the author NAME. Without that, any bot could " +
			"sign off for any other, or an empty prefix would accept any trailer at all")
	}
}

// TestTheDCOCheckStillComparesHumansExactly is the half that must not be lost.
// The whole point of the DCO is a person certifying the origin of their own
// contribution, so relaxing the bot case must not relax that.
func TestTheDCOCheckStillComparesHumansExactly(t *testing.T) {
	s := dcoScript(t)

	if !strings.Contains(s, `expected="Signed-off-by: ${author_name} <${author_email}>"`) {
		t.Error("the DCO check no longer builds the exact author identity, so a human commit could be signed " +
			"off by somebody else")
	}
	if !strings.Contains(s, `grep -qiFx "${expected}"`) {
		t.Error("the human comparison is no longer an exact, whole-line match. A substring match would accept " +
			"a sign-off that merely contains the author's name")
	}
	if !strings.Contains(s, "missing a Signed-off-by trailer") {
		t.Error("a commit with no sign-off at all is no longer reported, which is the case the DCO exists for")
	}
}

// TestTheSmokeModuleIsCoveredByDependabot closes the gap that let a known
// advisory sit in the second Go module. Dependabot's root gomod entry does not
// reach a nested module, so the only reason that CVE was found was a scanner
// looking at the file directly.
func TestTheSmokeModuleIsCoveredByDependabot(t *testing.T) {
	cfg := loadDependabot(t)

	var covered bool
	for _, u := range cfg.Updates {
		if u.Ecosystem == "gomod" && strings.TrimSuffix(u.Directory, "/") == "/hack/vm/smoke" {
			covered = true
		}
	}
	if !covered {
		t.Error("hack/vm/smoke is a separate Go module with no dependabot entry, so a root-only update leaves " +
			"it behind. That is how it came to pin a golang.org/x/sys with a known advisory while the root " +
			"module was four minors ahead")
	}

	// And the module must still be there to cover.
	if _, err := os.Stat(repoPath("hack/vm/smoke/go.mod")); err != nil {
		t.Errorf("hack/vm/smoke/go.mod is gone, so this guard and its dependabot entry are both stale: %v", err)
	}
}

func BenchmarkDCOScriptScan(b *testing.B) {
	raw, err := os.ReadFile(repoPath(".github/workflows/dco.yml"))
	if err != nil {
		b.Fatal(err)
	}
	s := string(raw)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !strings.Contains(s, `*'[bot]')`) || !strings.Contains(s, `grep -qiFx "${expected}"`) {
			b.Fatal("a guard input stopped matching")
		}
	}
}
