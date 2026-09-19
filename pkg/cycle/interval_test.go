package cycle

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

func TestIntervalReportsTheShortestGapBetweenFirings(t *testing.T) {
	day := 24 * time.Hour

	for _, tc := range []struct {
		name string
		expr string
		want time.Duration
		why  string
	}{
		{
			name: "every five minutes",
			expr: "*/5 * * * *",
			want: 5 * time.Minute,
			why:  "a step value divides the hour evenly, so every gap is the step",
		},
		{
			name: "hourly on the hour",
			expr: "0 * * * *",
			want: time.Hour,
			why:  "the canonical hourly schedule",
		},
		{
			name: "nightly at three",
			expr: "0 3 * * *",
			want: day,
			why:  "the schedule this package exists for - the 3am batch that a fifty minute window never sees",
		},
		{
			name: "monday mornings",
			expr: "0 3 * * 1",
			want: 7 * day,
			why:  "a day-of-week schedule fires once a week, every week, with no month-length variation",
		},
		{
			name: "first of the month",
			expr: "0 0 1 * *",
			want: 28 * day,
			// The assertion is exact, not approximate: the gaps are 28, 29, 30
			// and 31 days, and the shortest of them is February of a non-leap
			// year - 28 days to the minute, because midnight to midnight is a
			// whole number of days in UTC. Asserting 28d rather than "about a
			// month" is what proves the sample spans a non-leap February.
			why: "the shortest month decides a monthly schedule",
		},
		{
			name: "twice a day as a list",
			expr: "0 3,15 * * *",
			want: 12 * time.Hour,
			why:  "03:00 to 15:00 is the shortest of the two gaps a list produces",
		},
		{
			name: "an uneven list",
			expr: "0 3,4,20 * * *",
			want: time.Hour,
			// 03:00 to 04:00 is an hour and 04:00 to 20:00 is sixteen. The
			// shortest gap is the tightest part of the rhythm, which is the
			// documented semantic and the reason this case is here.
			why: "an uneven list is decided by its tightest pair, not by its average",
		},
		{
			name: "a range of hours",
			expr: "0 9-17 * * *",
			want: time.Hour,
			why:  "a range expands to every hour in it",
		},
		{
			name: "a stepped range",
			expr: "0 0-23/6 * * *",
			want: 6 * time.Hour,
			why:  "a step inside a range steps by the step, not by one",
		},
		{
			name: "minutes stepped from an offset",
			expr: "7/20 * * * *",
			want: 20 * time.Minute,
			// Firings are :07, :27, :47, then :07 of the next hour - a 20
			// minute gap thrice over. The offset form is the one a hand-rolled
			// parser gets wrong, which is why the parser does the work.
			why: "an offset step wraps at the hour without shortening the gap",
		},
		{
			name: "every minute",
			expr: "* * * * *",
			want: time.Minute,
			why:  "the densest standard schedule there is",
		},
		{
			name: "the daily descriptor",
			expr: "@daily",
			want: day,
			why:  "a CronJob .spec.schedule may hold a descriptor instead of five fields",
		},
		{
			name: "the weekly descriptor",
			expr: "@weekly",
			want: 7 * day,
			why:  "descriptors resolve to the same intervals as their long forms",
		},
		{
			name: "an every-duration descriptor",
			expr: "@every 90m",
			want: 90 * time.Minute,
			why:  "a constant delay schedule has one gap and it is the delay",
		},
		{
			name: "an explicit timezone prefix",
			expr: "TZ=UTC 0 3 * * *",
			want: day,
			why:  "a CronJob with .spec.timeZone renders its schedule with a TZ prefix",
		},
		{
			name: "surrounding whitespace",
			expr: "  0 * * * *  ",
			want: time.Hour,
			why:  "a schedule copied out of a YAML block scalar can arrive padded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Interval(tc.expr)
			if err != nil {
				t.Fatalf("Interval(%q) returned an error: %v", tc.expr, err)
			}
			if got != tc.want {
				t.Fatalf("Interval(%q) = %v, want %v (%s)", tc.expr, got, tc.want, tc.why)
			}
		})
	}
}

func TestIntervalOfAYearlyScheduleIsAYear(t *testing.T) {
	// Not part of the table because the answer is not a single duration: the
	// shortest gap between 1 January and 1 January is a non-leap year, 365 days.
	// It is here to show that the sample reaches that far, and that the ceiling
	// in Required - not a truncated sample - is what keeps a yearly CronJob from
	// producing a yearlong learning window.
	got, err := Interval("@yearly")
	if err != nil {
		t.Fatalf("Interval(@yearly) returned an error: %v", err)
	}
	if want := 365 * 24 * time.Hour; got != want {
		t.Fatalf("Interval(@yearly) = %v, want %v", got, want)
	}
}

func TestIntervalRejectsExpressionsThatWillNotParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		expr string
	}{
		{name: "empty", expr: ""},
		{name: "only whitespace", expr: "   "},
		{name: "too few fields", expr: "0 3 * *"},
		{name: "six fields with seconds", expr: "0 0 3 * * *"},
		{name: "a minute out of range", expr: "99 * * * *"},
		{name: "an hour out of range", expr: "0 25 * * *"},
		{name: "a weekday that does not exist", expr: "0 3 * * 9"},
		{name: "a month name that does not exist", expr: "0 3 * SMARCH *"},
		{name: "an unknown descriptor", expr: "@fortnightly"},
		{name: "a bare word", expr: "nightly"},
		{name: "an inverted range", expr: "0 17-9 * * *"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Interval(tc.expr)
			if err == nil {
				t.Fatalf("Interval(%q) = %v, want an error", tc.expr, got)
			}
			if got != 0 {
				t.Fatalf("Interval(%q) returned %v alongside an error, want 0", tc.expr, got)
			}
			// The expression has to appear in the message: this error reaches an
			// operator as a policy condition, and "parse error" without the
			// schedule that failed sends them reading every CronJob they own.
			if tc.expr != "" && strings.TrimSpace(tc.expr) != "" && !strings.Contains(err.Error(), strings.TrimSpace(tc.expr)) {
				t.Fatalf("Interval(%q) error %q does not name the expression", tc.expr, err)
			}
		})
	}
}

func TestIntervalRejectsAScheduleThatNeverFires(t *testing.T) {
	// 30 February parses cleanly and fires never. Returning a zero duration with
	// no error would read downstream as "no cycle, enforce away", which is the
	// silent failure this rejects.
	got, err := Interval("0 0 30 2 *")
	if err == nil {
		t.Fatalf("Interval of an impossible date = %v, want an error", got)
	}
	if !strings.Contains(err.Error(), "no upcoming firings") {
		t.Fatalf("error %q does not say the schedule never fires", err)
	}
}

func TestIntervalIsIndependentOfWhenItIsCalled(t *testing.T) {
	// The window a workload gets must not depend on which node reconciled it or
	// what month it is - two agents disagreeing about the learning window for
	// the same policy is a bug nobody would find for weeks.
	for _, expr := range []string{"0 0 1 * *", "0 3 * * 1", "*/5 * * * *"} {
		first, err := Interval(expr)
		if err != nil {
			t.Fatalf("Interval(%q): %v", expr, err)
		}
		for i := 0; i < 3; i++ {
			again, err := Interval(expr)
			if err != nil {
				t.Fatalf("Interval(%q): %v", expr, err)
			}
			if again != first {
				t.Fatalf("Interval(%q) returned %v then %v", expr, first, again)
			}
		}
	}
}

func TestIntervalOfADayOfMonthScheduleThatSkipsMonths(t *testing.T) {
	// The 31st exists in seven months of the year, so the gaps run 31, 61 and 62
	// days. This is the case that sets sampleFirings: a short sample that
	// happened to start in March would report 61 days and quietly double the
	// window. The exact assertion is the point.
	got, err := Interval("0 0 31 * *")
	if err != nil {
		t.Fatalf("Interval returned an error: %v", err)
	}
	if want := 31 * 24 * time.Hour; got != want {
		t.Fatalf("Interval(0 0 31 * *) = %v, want %v", got, want)
	}
}

// stuckSchedule never advances. No cron expression can produce one - the parser
// clamps "@every 0s" to a second - but cron.Schedule is an interface, and the
// sampling loop has to be provably safe against an implementation that returns
// the time it was given.
type stuckSchedule struct{}

func (stuckSchedule) Next(t time.Time) time.Time { return t }

func TestSamplingTerminatesOnAScheduleThatNeverAdvances(t *testing.T) {
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = shortestGap(stuckSchedule{}, anchor)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shortestGap did not terminate on a schedule that never advances")
	}
	if !errors.Is(err, errFiresOnce) {
		t.Fatalf("error = %v, want errFiresOnce", err)
	}
}

func TestSamplingReportsAScheduleWithNoSecondFiring(t *testing.T) {
	// 29 February is the one real expression that can run out of firings:
	// robfig searches five years ahead, and 2096 to 2104 is eight. Starting the
	// sample just before that gap gives a schedule with a first firing and no
	// measurable interval, which must be an error rather than a zero duration.
	schedule, err := cron.ParseStandard("0 0 29 2 *")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := shortestGap(schedule, time.Date(2093, time.January, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, errFiresOnce) {
		t.Fatalf("error = %v, want errFiresOnce", err)
	}
}

func TestIntervalOfALeapDayScheduleIsFourYears(t *testing.T) {
	// From the package anchor there is a second firing, four years on, and the
	// sample stops cleanly when the parser's horizon runs out rather than
	// reporting the shortfall as an interval.
	got, err := Interval("0 0 29 2 *")
	if err != nil {
		t.Fatalf("Interval returned an error: %v", err)
	}
	if want := 1461 * 24 * time.Hour; got != want {
		t.Fatalf("Interval(0 0 29 2 *) = %v, want %v", got, want)
	}
}
