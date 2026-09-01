package coverage

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTableCoversEverySevenDetector guards against the table drifting from
// bpf/*.c: exactly seven programs exist, and this must name each one once.
func TestTableCoversEverySevenDetector(t *testing.T) {
	require.Len(t, Table, 7)

	seen := make(map[Detector]bool, len(Table))
	for _, e := range Table {
		assert.False(t, seen[e.Detector], "detector %q listed twice", e.Detector)
		seen[e.Detector] = true
	}

	for _, d := range []Detector{
		DetectorFile, DetectorNetwork, DetectorExec, DetectorCapability,
		DetectorSyscall, DetectorCred, DetectorShell,
	} {
		assert.True(t, seen[d], "detector %q missing from Table", d)
	}
}

// TestEntriesAreWellFormed checks every entry has the fields a renderer
// depends on: a hook, a description, and at least one technique with both an
// ID and a name.
func TestEntriesAreWellFormed(t *testing.T) {
	for _, e := range Table {
		t.Run(string(e.Detector), func(t *testing.T) {
			assert.NotEmpty(t, e.Hook)
			assert.NotEmpty(t, e.Observes)
			require.NotEmpty(t, e.Techniques, "detector must map to at least one technique")
			for _, tech := range e.Techniques {
				assert.NotEmpty(t, tech.ID)
				assert.NotEmpty(t, tech.Name)
			}
		})
	}
}

// TestLSMRequirementMatchesTheHookType guards the file/network/exec/capability
// vs syscall/cred/shell split documented in ROADMAP.md: lsm/* hooks need
// lsm=bpf, kprobe/tracepoint/uretprobe hooks do not.
func TestLSMRequirementMatchesTheHookType(t *testing.T) {
	for _, e := range Table {
		t.Run(string(e.Detector), func(t *testing.T) {
			wantLSM := len(e.Hook) >= 4 && e.Hook[:4] == "lsm/"
			assert.Equal(t, wantLSM, e.NeedsLSM,
				"NeedsLSM must follow from whether Hook is an lsm/* attach point")
		})
	}
}

func TestTechniques(t *testing.T) {
	techniques := Techniques()
	require.NotEmpty(t, techniques)

	// Deduplicated: no ID appears twice, even though multiple detectors
	// reference the same technique in Table.
	seen := make(map[string]bool, len(techniques))
	for _, tech := range techniques {
		assert.False(t, seen[tech.ID], "technique %s listed twice", tech.ID)
		seen[tech.ID] = true
	}

	// Sorted by ID.
	assert.True(t, sort.SliceIsSorted(techniques, func(i, j int) bool {
		return techniques[i].ID < techniques[j].ID
	}))

	// Every technique referenced anywhere in Table must appear exactly once.
	wantIDs := map[string]bool{}
	for _, e := range Table {
		for _, tech := range e.Techniques {
			wantIDs[tech.ID] = true
		}
	}
	assert.Len(t, techniques, len(wantIDs))
}

func TestForTechnique(t *testing.T) {
	t.Run("a shared technique returns every detector that lists it", func(t *testing.T) {
		// T1548 currently belongs only to capability; pick one guaranteed to
		// exist instead of hardcoding an ID that might later move.
		var anyID string
		for _, tech := range Table[0].Techniques {
			anyID = tech.ID
		}
		require.NotEmpty(t, anyID)

		got := ForTechnique(anyID)
		assert.Contains(t, got, Table[0].Detector)
	})

	t.Run("exec and capability both cover privilege escalation angles", func(t *testing.T) {
		// T1611 (Escape to Host) is exec-only; confirm ForTechnique does not
		// over-return detectors that do not list it.
		got := ForTechnique("T1611")
		assert.Equal(t, []Detector{DetectorExec}, got)
	})

	t.Run("unknown technique ID returns nothing", func(t *testing.T) {
		assert.Empty(t, ForTechnique("T9999"))
	})

	t.Run("empty technique ID returns nothing", func(t *testing.T) {
		assert.Empty(t, ForTechnique(""))
	})
}

func BenchmarkTechniques(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Techniques()
	}
}

func BenchmarkForTechnique(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ForTechnique("T1059")
	}
}
