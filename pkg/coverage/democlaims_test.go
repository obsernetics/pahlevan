package coverage

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The demo GIF on the README ends on a `pahlevan coverage` table. It is a
// recording, so the table is typed into docs/assets/demo.sh by hand rather
// than produced by the binary - and it had drifted into claiming seven ATT&CK
// techniques this package does not list, against hooks it attributed to the
// wrong detector.
//
// That is worse than a stale figure. The GIF is the first thing anyone sees,
// and a technique printed there is a claim that Pahlevan's data is evidence
// for it. Nothing was checking, because nothing connects a shell script to
// this table.
//
// These tests connect them. The demo may show fewer techniques than the table
// - a recording has finite width, and the point is to be legible - but it may
// never show one the table does not have, and it may never attribute a hook
// to techniques that belong to a different hook.

const demoShellScript = "../../docs/assets/demo.sh"

// demoCoverageLines pulls the coverage rows out of the recording script.
//
// The rows are `echo` lines listing a hook and its techniques. Terminal colour
// escapes are interleaved with the text - the recording highlights the two
// hooks that need no BPF LSM - so they are stripped before matching.
func demoCoverageRows(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(demoShellScript)
	if err != nil {
		t.Fatalf("reading the demo script: %v", err)
	}

	// ${B}, ${R}, ${GRY} and friends are the script's own colour variables.
	colour := regexp.MustCompile(`\$\{[A-Za-z_]+\}`)
	technique := regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)
	// A row names a hook: lsm/..., kprobe/..., uretprobe/... or tracepoint/...
	hook := regexp.MustCompile(`\b((?:lsm|kprobe|uretprobe|tracepoint)/[a-z_/]+)`)

	rows := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, "echo") {
			continue
		}
		clean := colour.ReplaceAllString(line, "")
		h := hook.FindStringSubmatch(clean)
		if h == nil {
			continue
		}
		ids := technique.FindAllString(clean, -1)
		if len(ids) == 0 {
			continue
		}
		rows[h[1]] = ids
	}
	if len(rows) == 0 {
		t.Fatalf("found no coverage rows in %s; the extraction is wrong and this test proves nothing", demoShellScript)
	}
	return rows
}

// hookAliases maps the short hook names the recording uses to the full names
// in Table. The recording shortens one: the full tracepoint name does not fit
// the column at the width the GIF is rendered.
var hookAliases = map[string]string{
	"tracepoint/sys_enter": "tracepoint/raw_syscalls/sys_enter",
}

func TestDemoClaimsNoTechniqueTheTableDoesNotHave(t *testing.T) {
	byHook := map[string]Entry{}
	for _, e := range Table {
		byHook[e.Hook] = e
	}

	for hook, ids := range demoCoverageRows(t) {
		full := hook
		if alias, ok := hookAliases[hook]; ok {
			full = alias
		}
		entry, ok := byHook[full]
		if !ok {
			t.Errorf("the demo shows hook %q, which is not in the coverage table; either the hook was renamed or the recording invented it", hook)
			continue
		}
		have := map[string]bool{}
		for _, tech := range entry.Techniques {
			have[tech.ID] = true
		}
		for _, id := range ids {
			if !have[id] {
				t.Errorf("the demo attributes %s to %s, but the coverage table does not: %s covers %v.\n"+
					"Either add the technique to pkg/coverage with a reason, or correct docs/assets/demo.sh - "+
					"a technique in the GIF is a claim about what Pahlevan's data is evidence for.",
					id, hook, full, techniqueIDs(entry))
			}
		}
	}
}

func TestDemoShowsEveryDetector(t *testing.T) {
	// The recording is the only place most people will ever see the full hook
	// list. Silently dropping one as hooks are added makes Pahlevan look
	// narrower than it is.
	rows := demoCoverageRows(t)
	shown := map[string]bool{}
	for hook := range rows {
		full := hook
		if alias, ok := hookAliases[hook]; ok {
			full = alias
		}
		shown[full] = true
	}
	for _, e := range Table {
		if !shown[e.Hook] {
			t.Errorf("the demo's coverage table omits %s (%s); a viewer would conclude Pahlevan does not have it",
				e.Hook, e.Detector)
		}
	}
}

func techniqueIDs(e Entry) []string {
	out := make([]string, 0, len(e.Techniques))
	for _, t := range e.Techniques {
		out = append(out, t.ID)
	}
	return out
}

func BenchmarkDemoCoverageRows(b *testing.B) {
	data, err := os.ReadFile(demoShellScript)
	if err != nil {
		b.Skipf("demo script unavailable: %v", err)
	}
	colour := regexp.MustCompile(`\$\{[A-Za-z_]+\}`)
	technique := regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = technique.FindAllString(colour.ReplaceAllString(string(data), ""), -1)
	}
}
