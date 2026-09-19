package cycle

import (
	"strings"
	"testing"
	"time"
)

func TestRequiredResolvesDeclaredAgainstDiscovered(t *testing.T) {
	hour := time.Hour
	day := 24 * time.Hour

	for _, tc := range []struct {
		name       string
		declared   time.Duration
		expr       string
		wantWindow time.Duration
		wantSource Source
		wantCycle  time.Duration
		why        string
	}{
		{
			name:       "no schedule leaves the declared minimum alone",
			declared:   50 * time.Minute,
			expr:       "",
			wantWindow: 50 * time.Minute,
			wantSource: SourceDeclared,
			why:        "most workloads have no cycle and must behave exactly as before",
		},
		{
			name:       "a nightly schedule raises a fifty minute window to a day",
			declared:   50 * time.Minute,
			expr:       "0 3 * * *",
			wantWindow: day,
			wantSource: SourceCycle,
			wantCycle:  day,
			why:        "this is the whole point - fifty minutes never contains 3am",
		},
		{
			name:       "a dense schedule never shortens the declared window",
			declared:   30 * time.Minute,
			expr:       "*/5 * * * *",
			wantWindow: 30 * time.Minute,
			wantSource: SourceDeclared,
			wantCycle:  5 * time.Minute,
			why:        "a five minute cycle is already inside the window; cutting it would learn less",
		},
		{
			name:       "a declared window longer than the cycle wins",
			declared:   3 * day,
			expr:       "0 3 * * *",
			wantWindow: 3 * day,
			wantSource: SourceDeclared,
			wantCycle:  day,
			why:        "the operator asked for longer and knows something this package does not",
		},
		{
			name:       "equal inputs are attributed to the declaration",
			declared:   hour,
			expr:       "0 * * * *",
			wantWindow: hour,
			wantSource: SourceDeclared,
			wantCycle:  hour,
			why:        "the schedule did not change anything, so it did not decide anything",
		},
		{
			name:       "a weekly schedule lands exactly on the ceiling",
			declared:   0,
			expr:       "0 3 * * 1",
			wantWindow: 7 * day,
			wantSource: SourceCycle,
			wantCycle:  7 * day,
			why:        "a week is inside MaxWindow, so the Monday report is learnable and is not a capped case",
		},
		{
			name:       "a monthly schedule is capped at a week",
			declared:   50 * time.Minute,
			expr:       "0 0 1 * *",
			wantWindow: MaxWindow,
			wantSource: SourceCap,
			wantCycle:  28 * day,
			why:        "waiting 28 days unprotected is worse than a week plus an operator who declares the monthly close",
		},
		{
			name:       "a yearly schedule is capped at a week too",
			declared:   50 * time.Minute,
			expr:       "@yearly",
			wantWindow: MaxWindow,
			wantSource: SourceCap,
			wantCycle:  365 * day,
			why:        "a 365 day learning window means the workload is never protected",
		},
		{
			name:       "a declared window beyond the ceiling is honoured",
			declared:   30 * day,
			expr:       "0 0 1 * *",
			wantWindow: 30 * day,
			wantSource: SourceCap,
			wantCycle:  28 * day,
			why:        "the ceiling constrains inference, not an explicit operator decision",
		},
		{
			name:       "a zero declaration with no schedule stays zero",
			declared:   0,
			expr:       "",
			wantWindow: 0,
			wantSource: SourceDeclared,
			why:        "this package adds a minimum, it does not invent one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Required(tc.declared, tc.expr)
			if err != nil {
				t.Fatalf("Required returned an error: %v", err)
			}
			if got.Window != tc.wantWindow {
				t.Fatalf("window = %v, want %v (%s)", got.Window, tc.wantWindow, tc.why)
			}
			if got.Source != tc.wantSource {
				t.Fatalf("source = %q, want %q (%s)", got.Source, tc.wantSource, tc.why)
			}
			if got.Cycle != tc.wantCycle {
				t.Fatalf("cycle = %v, want %v", got.Cycle, tc.wantCycle)
			}
			if got.Declared != tc.declared {
				t.Fatalf("declared = %v, want it reported back unchanged as %v", got.Declared, tc.declared)
			}
		})
	}
}

func TestRequiredNeverReturnsLessThanWasDeclared(t *testing.T) {
	// The invariant the controller depends on. Anything that lowers an
	// operator's window is a regression that shortens learning and causes the
	// false denials this package exists to prevent.
	declarations := []time.Duration{0, time.Minute, 50 * time.Minute, 24 * time.Hour, 90 * 24 * time.Hour}
	expressions := []string{"", "* * * * *", "*/5 * * * *", "0 * * * *", "0 3 * * *", "0 3 * * 1", "0 0 1 * *", "@yearly"}

	for _, declared := range declarations {
		for _, expr := range expressions {
			got, err := Required(declared, expr)
			if err != nil {
				t.Fatalf("Required(%v, %q): %v", declared, expr, err)
			}
			if got.Window < declared {
				t.Fatalf("Required(%v, %q) shortened the window to %v", declared, expr, got.Window)
			}
		}
	}
}

func TestRequiredCapsEveryInferredWindowAtTheCeiling(t *testing.T) {
	// The property behind the SourceCap cases: no schedule, however long its
	// cycle, can push an undeclared window past MaxWindow.
	for _, expr := range []string{"0 0 1 * *", "0 0 31 * *", "0 0 1 1 *", "@monthly", "@yearly"} {
		got, err := Required(0, expr)
		if err != nil {
			t.Fatalf("Required(0, %q): %v", expr, err)
		}
		if got.Window > MaxWindow {
			t.Fatalf("Required(0, %q) inferred %v, past the %v ceiling", expr, got.Window, MaxWindow)
		}
		if !got.Capped() {
			t.Fatalf("Required(0, %q) did not report being capped, so nobody is told to declare the rare operation", expr)
		}
	}
}

func TestRequiredReportsCappingEvenWhenTheDeclarationWins(t *testing.T) {
	// The operator declared a fortnight for unrelated reasons; the workload
	// still has a monthly cycle nobody will wait for, and that has to survive
	// into the status rather than being masked by the longer declaration.
	got, err := Required(14*24*time.Hour, "0 0 1 * *")
	if err != nil {
		t.Fatalf("Required returned an error: %v", err)
	}
	if !got.Capped() {
		t.Fatalf("requirement %+v does not report the uncovered monthly cycle", got)
	}
	if got.Window != 14*24*time.Hour {
		t.Fatalf("window = %v, want the declared fortnight", got.Window)
	}
}

func TestRequiredKeepsTheDeclaredWindowWhenTheScheduleWillNotParse(t *testing.T) {
	got, err := Required(50*time.Minute, "every night at three")
	if err == nil {
		t.Fatal("an unparseable schedule returned no error")
	}
	if !strings.Contains(err.Error(), "every night at three") {
		t.Fatalf("error %q does not name the schedule that failed", err)
	}
	if got.Window != 50*time.Minute || got.Source != SourceDeclared {
		t.Fatalf("requirement = %+v, want the declared fifty minutes preserved", got)
	}
	if got.Capped() {
		t.Fatal("a failed parse must not be reported as a capped cycle")
	}
}

func TestRequiredTreatsANegativeDeclarationAsUnset(t *testing.T) {
	// A negative duration is a caller bug. Carrying it into the comparison would
	// make it lose to everything and report a nonsensical Declared in the
	// status, so it is normalised once, here.
	got, err := Required(-time.Hour, "0 3 * * *")
	if err != nil {
		t.Fatalf("Required returned an error: %v", err)
	}
	if got.Declared != 0 {
		t.Fatalf("declared = %v, want it normalised to 0", got.Declared)
	}
	if got.Window != 24*time.Hour {
		t.Fatalf("window = %v, want the discovered daily cycle", got.Window)
	}
}

func TestMaxWindowIsAWeek(t *testing.T) {
	// Pinned deliberately: the ceiling is a documented promise about how long a
	// workload can sit unprotected, and changing it is a decision, not a tidy-up.
	if MaxWindow != 168*time.Hour {
		t.Fatalf("MaxWindow = %v, want 168h", MaxWindow)
	}
}
