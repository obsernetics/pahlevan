package dashboard

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"
)

// A diagram is built from a container's command names and file paths, which is
// attacker-influenced text. Escaping is the whole of the defence, so it is
// asserted by parsing the result rather than by reading the code.
func TestDiagramsEscapeHostileText(t *testing.T) {
	hostile := `</text><script>fetch("//evil.example")</script>`

	docs := map[string]string{
		"flow": FlowSVG([]FlowStage{{Name: hostile, State: StateActive, Detail: hostile}}),
		"tree": ProcessTreeSVG([]*ProcessNode{{Comm: hostile, Count: 1, Denied: 1}}, false),
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(doc, "<script") {
				t.Fatalf("the %s diagram contains a script element: %s", name, doc)
			}
			var foundText bool
			decoder := xml.NewDecoder(strings.NewReader(doc))
			for {
				token, err := decoder.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("the %s diagram is not well-formed XML: %v", name, err)
				}
				switch tok := token.(type) {
				case xml.StartElement:
					if strings.EqualFold(tok.Name.Local, "script") {
						t.Fatalf("the %s diagram parsed to a script element", name)
					}
					for _, attr := range tok.Attr {
						if strings.EqualFold(attr.Name.Local, "style") {
							t.Fatalf("the %s diagram uses a style attribute, which the policy blocks", name)
						}
					}
				case xml.CharData:
					if strings.Contains(string(tok), hostile) {
						// The parser gave back the original characters, which
						// is exactly right: it means they were escaped in the
						// document and decoded as text, not as markup.
						foundText = true
					}
				}
			}
			if !foundText {
				t.Fatalf("the %s diagram did not carry the hostile string as text at all", name)
			}
		})
	}
}

func TestFlowSVGShowsEveryStage(t *testing.T) {
	stages := []FlowStage{
		{Name: "Selected", State: StateDone, Detail: "3 containers matched by the policy selector"},
		{Name: "Learning", State: StateDone, Detail: "200 syscalls, 40 paths, 3 destinations learned"},
		{Name: "Transition", State: StateFailed, Detail: "1 rollback out of 2 attempts: denial rate exceeded"},
		{Name: "Enforcing", State: StateActive, Detail: "3 containers enforcing, 4 denials since"},
	}
	doc := FlowSVG(stages)
	for _, stage := range stages {
		if !strings.Contains(doc, stage.Name) {
			t.Fatalf("the flow lost the %q stage", stage.Name)
		}
	}
	// The failed stage has to be distinguishable, or a profile that rolled
	// back twice looks like one that never had a problem.
	if !strings.Contains(doc, "flow-"+StateFailed) {
		t.Fatalf("the failed stage carries no class of its own: %s", doc)
	}
	if strings.Count(doc, "flow-arrow-head") != len(stages)-1 {
		t.Fatalf("the flow drew %d arrow heads for %d stages",
			strings.Count(doc, "flow-arrow-head"), len(stages))
	}
	assertWellFormed(t, doc)
}

func TestFlowSVGWithNoStages(t *testing.T) {
	doc := FlowSVG(nil)
	if !strings.Contains(doc, "no flow") {
		t.Fatalf("an empty flow rendered as %q rather than saying it is empty", doc)
	}
	assertWellFormed(t, doc)
}

func TestSurfaceSVGScalesAgainstItsLargestDimension(t *testing.T) {
	doc := SurfaceSVG(Surface{SyscallCount: 200, FileCount: 40, NetworkCount: 1, CapabilityCount: 0})
	assertWellFormed(t, doc)

	for _, label := range []string{"syscalls", "file paths", "destinations", "capabilities"} {
		if !strings.Contains(doc, label) {
			t.Fatalf("the surface diagram has no %q row", label)
		}
	}
	// A dimension with a single entry must still draw, or "one destination"
	// and "no destinations" look identical and they are opposite findings.
	if strings.Count(doc, "bar-fill") != 3 {
		t.Fatalf("the diagram drew %d bars for three non-zero dimensions", strings.Count(doc, "bar-fill"))
	}
}

func TestSurfaceSVGWithNothingLearned(t *testing.T) {
	doc := SurfaceSVG(Surface{})
	if !strings.Contains(doc, "nothing has been learned") {
		t.Fatalf("an empty surface rendered as %q, which reads as a workload with no behaviour "+
			"rather than one that has not been observed", doc)
	}
	assertWellFormed(t, doc)
}

func TestProcessTreeSVGDrawsTheLineage(t *testing.T) {
	tree := []*ProcessNode{{
		Comm: "nginx", Count: 10,
		Children: []*ProcessNode{{
			Comm: "sh", Count: 2,
			Children: []*ProcessNode{{Comm: "curl", Count: 2, Denied: 2}},
		}},
	}}
	doc := ProcessTreeSVG(tree, false)
	assertWellFormed(t, doc)

	for _, comm := range []string{"nginx", "sh", "curl"} {
		if !strings.Contains(doc, comm) {
			t.Fatalf("the tree lost %q", comm)
		}
	}
	if !strings.Contains(doc, "2 denied") {
		t.Fatalf("the tree does not mark the denied node: %s", doc)
	}
	if !strings.Contains(doc, "tree-dot-denied") {
		t.Fatal("the denied node is not visually distinguishable")
	}
	// Two connectors for three levels.
	if got := strings.Count(doc, "tree-line"); got != 2 {
		t.Fatalf("the tree drew %d connectors for a three-level lineage", got)
	}
}

func TestProcessTreeSVGSaysWhenItIsTruncated(t *testing.T) {
	doc := ProcessTreeSVG([]*ProcessNode{{Comm: "nginx", Count: 1}}, true)
	if !strings.Contains(doc, "truncated") {
		t.Fatal("a truncated tree did not say so, so it reads as the whole picture")
	}
	assertWellFormed(t, doc)
}

func TestProcessTreeSVGEmpty(t *testing.T) {
	doc := ProcessTreeSVG(nil, false)
	if !strings.Contains(doc, "no process activity") {
		t.Fatalf("an empty tree rendered as %q", doc)
	}
}

func TestDiagramsScaleToTheViewport(t *testing.T) {
	// Without a viewBox and a relative width the page scrolls sideways on a
	// phone instead of scaling the diagram.
	for name, doc := range map[string]string{
		"flow":    FlowSVG([]FlowStage{{Name: "Learning", State: StateActive}}),
		"surface": SurfaceSVG(Surface{FileCount: 3}),
		"tree":    ProcessTreeSVG([]*ProcessNode{{Comm: "nginx", Count: 1}}, false),
	} {
		if !strings.Contains(doc, "viewBox=") || !strings.Contains(doc, `width="100%"`) {
			t.Fatalf("the %s diagram does not scale: %s", name, doc)
		}
		if !strings.Contains(doc, "role=\"img\"") || !strings.Contains(doc, "<title>") {
			t.Fatalf("the %s diagram has no accessible name", name)
		}
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		width    int
		maxLines int
		want     []string
	}{
		{name: "empty", in: "", width: 10, maxLines: 2, want: nil},
		{name: "short", in: "one two", width: 10, maxLines: 2, want: []string{"one two"}},
		{
			name: "wraps on words", in: "the quick brown fox", width: 10, maxLines: 2,
			want: []string{"the quick", "brown fox"},
		},
		{
			// A rollback reason that does not fit has to read as truncated
			// rather than as a complete but odd sentence.
			name: "truncates", in: "a b c d e f g h i j k l m n o p", width: 6, maxLines: 2,
			want: []string{"a b c", "d e..."},
		},
		{
			name: "single long word is not broken mid-token", in: "supercalifragilistic", width: 6, maxLines: 2,
			want: []string{"supercalifragilistic"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wrap(tc.in, tc.width, tc.maxLines)
			if len(got) != len(tc.want) {
				t.Fatalf("wrap(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("wrap(%q) = %q, want %q", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestStateClassFallsBackToPending(t *testing.T) {
	// An unknown state must not produce an unstyled box, which draws as an
	// invisible stage.
	if got := stateClass("nonsense"); got != StatePending {
		t.Fatalf("stateClass(nonsense) = %q, want %q", got, StatePending)
	}
	for _, state := range []string{StateDone, StateActive, StatePending, StateFailed} {
		if got := stateClass(state); got != state {
			t.Fatalf("stateClass(%q) = %q", state, got)
		}
	}
}

// assertWellFormed proves the document is XML a browser's SVG parser will
// accept. An unbalanced tag renders as nothing at all.
func assertWellFormed(t *testing.T, doc string) {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader(doc))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("the diagram is not well-formed XML: %v\n%s", err, doc)
		}
	}
}

func TestFlowForReportsTheHistoryThatMatters(t *testing.T) {
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		summary       WorkloadSummary
		containers    []ContainerView
		wantStates    []string
		wantInDetails []string
	}{
		{
			name:       "nothing reported yet",
			summary:    WorkloadSummary{},
			wantStates: []string{StatePending, StatePending, StatePending, StatePending},
		},
		{
			name: "learning",
			summary: WorkloadSummary{
				Containers: PhaseCounts{Learning: 2, Total: 2},
				Surface:    Surface{SyscallCount: 12, FileCount: 3},
			},
			containers:    []ContainerView{{FirstSeen: &now}},
			wantStates:    []string{StateDone, StateActive, StatePending, StatePending},
			wantInDetails: []string{"12 syscalls"},
		},
		{
			name: "enforcing after a rollback",
			summary: WorkloadSummary{
				Containers: PhaseCounts{Enforcing: 1, Total: 1},
				Surface:    Surface{SyscallCount: 12, FileCount: 3},
				Rollbacks:  1,
				Denials:    DenialTotals{Total: 4},
			},
			containers: []ContainerView{
				{Attempts: 2, Rollbacks: 1, RollbackReason: "denial rate exceeded", EnforcingSince: &now},
			},
			wantStates:    []string{StateDone, StateDone, StateFailed, StateActive},
			wantInDetails: []string{"1 rollback out of 2 attempts", "denial rate exceeded", "4 denials"},
		},
		{
			name: "enforcing cleanly",
			summary: WorkloadSummary{
				Containers: PhaseCounts{Enforcing: 1, Total: 1},
				Surface:    Surface{SyscallCount: 9},
			},
			containers:    []ContainerView{{Attempts: 1, EnforcingSince: &now}},
			wantStates:    []string{StateDone, StateDone, StateDone, StateActive},
			wantInDetails: []string{"1 attempt, no rollback"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stages := flowFor(tc.summary, tc.containers)
			if len(stages) != 4 {
				t.Fatalf("flowFor produced %d stages", len(stages))
			}
			for i, want := range tc.wantStates {
				if stages[i].State != want {
					t.Fatalf("stage %q was %q, want %q", stages[i].Name, stages[i].State, want)
				}
			}
			joined := ""
			for _, s := range stages {
				joined += s.Detail + "\n"
			}
			for _, want := range tc.wantInDetails {
				if !strings.Contains(joined, want) {
					t.Fatalf("the flow details %q do not mention %q", joined, want)
				}
			}
		})
	}
}
