package cycle

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// sampleFirings is how many consecutive firings Interval asks the parsed
// schedule for before taking the minimum gap.
//
// The count is driven by the slowest schedule that still has to come out right:
// a day-of-month one. "0 0 1 * *" produces gaps of 28, 29, 30 and 31 days
// depending on the month and the year, and only a sample that spans more than
// four years is certain to contain a February of a non-leap year - the 28 day
// gap that is the true shortest interval. "0 0 31 * *" is worse: it fires in
// seven months of the year, so 64 firings is the first round number that covers
// it comfortably. 64 monthly firings is five and a third years; 64 yearly
// firings is 64 years.
//
// The cost of overshooting is small and bounded. The benchmark puts a whole
// 64 firing sample at roughly 70us for a five minute schedule and 270us for the
// monthly worst case, where the parser steps month by month across five years.
// That is paid once per schedule, not per event, and the answer is a pure
// function of the expression - a caller resolving it on every reconcile can
// memoise it by expression and pay nothing at all.
const sampleFirings = 64

// anchor is the instant the sampling walk starts from.
//
// It is fixed rather than time.Now() so that Interval is a pure function of its
// expression: the same schedule yields the same window on every node, on every
// reconcile, and in tests that would otherwise fail in February. The year is a
// leap year, so a sample that starts here sees a 29 day February first and the
// 28 day ones that follow, rather than depending on which way the sample
// happens to straddle a leap year.
var anchor = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)

// Interval reports the shortest interval between consecutive firings of a
// standard 5-field cron expression - "*/5 * * * *" is 5 minutes, "0 3 * * 1" is
// 7 days. Descriptors ("@daily", "@every 90m") and a leading "TZ="/"CRON_TZ="
// are accepted too, because that is what a CronJob's .spec.schedule may hold.
//
// The interval is computed by asking the parsed schedule for successive Next
// times and taking the smallest gap, rather than by reasoning about the
// expression itself. Reasoning about the text is where this goes wrong: step
// values, lists, ranges, day-of-month combined with day-of-week, and the fact
// that months are not the same length each mean a hand-rolled analysis is a
// source of subtly wrong windows. Asking the parser costs microseconds and
// cannot disagree with the scheduler that will actually run the job.
//
// A known and deliberate limitation: the shortest gap describes the tightest
// part of an irregular schedule, and so is a minimum rather than a guarantee.
// For "0 3,15 * * *" this returns 12h, and a window of 12h that opens at 03:01
// will not see a firing until 15:00 - 13h59m later. Guaranteeing an observation
// would mean waiting the longest gap instead, which for a monthly schedule is
// 31 days and blows straight through MaxWindow, so it would buy nothing but a
// longer unprotected period. The shortest gap is the useful quantity: it is the
// workload's rhythm, and a window that long turns "learned nothing about the
// cycle" into "learned the cycle in the overwhelming majority of cases".
func Interval(cronExpr string) (time.Duration, error) {
	expr := strings.TrimSpace(cronExpr)
	if expr == "" {
		return 0, fmt.Errorf("cron expression is empty")
	}

	schedule, err := cron.ParseStandard(expr)
	if err != nil {
		return 0, fmt.Errorf("parse cron expression %q: %w", expr, err)
	}

	gap, err := shortestGap(schedule, anchor)
	if err != nil {
		return 0, fmt.Errorf("cron expression %q %w", expr, err)
	}
	return gap, nil
}

// errNeverFires is a syntactically valid expression that is never satisfiable,
// such as "0 0 30 2 *". Saying so beats returning a zero duration that a caller
// would read as "no cycle" and quietly enforce against.
var errNeverFires = errors.New("has no upcoming firings")

// errFiresOnce is a schedule with a first firing and no second one to measure a
// gap against. Same reasoning: no interval is not the same as no cycle.
var errFiresOnce = errors.New("fires at most once, so it has no interval")

// shortestGap does the sampling. It is separate from Interval so that a test
// can hand it a schedule and a starting point directly - the branches below
// that handle a schedule running out of firings or failing to advance are
// reachable from a real cron expression only at the very edge of the parser's
// own search horizon, and a defensive branch nobody can exercise is a defensive
// branch nobody can trust.
func shortestGap(schedule cron.Schedule, start time.Time) (time.Duration, error) {
	prev := schedule.Next(start)
	if prev.IsZero() {
		// robfig reports "never" as the zero time.
		return 0, errNeverFires
	}

	shortest := time.Duration(0)
	// The loop is bounded by sampleFirings, and it also stops early on a
	// schedule that runs out of firings or stops advancing, so no schedule can
	// make this spin.
	for i := 1; i < sampleFirings; i++ {
		next := schedule.Next(prev)
		if next.IsZero() {
			break
		}
		gap := next.Sub(prev)
		if gap <= 0 {
			// A schedule that does not advance would otherwise contribute a
			// zero interval, which downstream would read as "no cycle".
			break
		}
		if shortest == 0 || gap < shortest {
			shortest = gap
		}
		prev = next
	}

	if shortest == 0 {
		return 0, errFiresOnce
	}
	return shortest, nil
}
