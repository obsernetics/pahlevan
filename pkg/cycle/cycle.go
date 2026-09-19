// Package cycle makes a learning window long enough to have seen a workload's
// full rhythm.
//
// Learning is a window of wall-clock time, typically well under an hour. That
// is enough for a workload whose behaviour is the same minute to minute: a web
// server opens the same files, makes the same syscalls and talks to the same
// services in its first five minutes as it does in its fifth week, so a short
// window captures it.
//
// It is wrong for a workload with a cycle. A nightly batch job, a weekly
// certificate renewal, a Monday-only report: none of that work happens during a
// fifty minute window that starts at 14:10 on a Wednesday, so none of it is in
// the baseline, and enforcement then refuses the very thing the workload exists
// to do. The failure is worse than a false alert, because it happens at 3am, to
// the run nobody is watching, in a workload that had been enforcing cleanly for
// days.
//
// Pahlevan had no notion of periodicity at all - it would auto-transition to
// enforcement fifty minutes into the life of a pod whose owning CronJob fires
// once a day. This package supplies the missing notion in three pieces:
//
//   - Interval reports the shortest gap between consecutive firings of a cron
//     expression, which is how long you must watch to be sure of having seen one.
//   - Find walks a pod's owner chain to the CronJob that schedules it, so the
//     period is discovered rather than declared.
//   - Required resolves the two against each other, and against a ceiling.
//
// Nothing here imports the policy API types, so it can be exercised on its own.
package cycle

import (
	"fmt"
	"time"
)

// MaxWindow caps any learning window this package infers from a schedule.
//
// Without a cap, a quarterly or @yearly CronJob would imply a learning window
// of months, and a workload that is learning is a workload that is not being
// enforced. Inferring a 365 day window does not make the workload safe on day
// 366 - it makes it unprotected for a year, which is strictly worse than the
// short window the cap produces plus an operator who knows about the gap.
//
// A week is the longest cycle worth waiting through: it covers the nightly
// batch, the weekly report and the weekly certificate renewal, which are the
// periodic behaviours that actually show up in practice. Beyond a week the
// right answer is not a longer window - it is for the operator to declare the
// rare operation explicitly (learningConfig.expectedBehavior), so the baseline
// contains the monthly close without anybody waiting a month for it.
//
// The cap constrains inference only. An operator who explicitly declares a
// window longer than a week gets it: the cap exists to stop this package from
// silently disabling protection, not to overrule a deliberate choice.
const MaxWindow = 7 * 24 * time.Hour

// Source records which input decided a Requirement, so a controller can say why
// a workload is still learning instead of leaving an operator to guess.
type Source string

const (
	// SourceDeclared means the operator's declared minimum was already at least
	// as long as the discovered cycle, or there was no cycle to discover.
	SourceDeclared Source = "declared"
	// SourceCycle means a discovered schedule was longer than the declared
	// minimum and raised the window.
	SourceCycle Source = "cycle"
	// SourceCap means the discovered schedule was longer than MaxWindow and was
	// clamped to it. This is the case worth surfacing to an operator: their
	// workload has a cycle this package will not wait for, and the periodic
	// behaviour needs declaring by hand.
	SourceCap Source = "cap"
)

// Requirement is the resolved minimum learning window plus enough context to
// explain it.
type Requirement struct {
	// Window is the effective minimum learning duration. It is never shorter
	// than Declared.
	Window time.Duration
	// Declared is the minimum the operator asked for, unchanged.
	Declared time.Duration
	// Cycle is the shortest interval between firings of the discovered
	// schedule, or zero when there is no schedule. This is the raw observation,
	// before the cap - a Cycle of 720h with a Window of 168h is exactly the
	// situation SourceCap describes.
	Cycle time.Duration
	// Source names the input that decided Window.
	Source Source
}

// Capped reports whether the discovered cycle was longer than this package is
// willing to wait for. When it is true the workload has periodic behaviour that
// the learning window will not observe, and the operator needs to declare that
// behaviour explicitly rather than trust the baseline to have caught it.
func (r Requirement) Capped() bool {
	return r.Source == SourceCap
}

// Required resolves the effective minimum learning window from what the
// operator declared and what a discovered cron expression implies.
//
// Precedence, in order:
//
//  1. The declared minimum is a floor. It is an explicit operator decision and
//     nothing here lowers it, including MaxWindow.
//  2. A discovered schedule can only raise the window, never lower it. A
//     workload owned by an every-five-minutes CronJob does not get its
//     operator's thirty minute window cut to five.
//  3. The contribution of the schedule is clamped to MaxWindow, so inference
//     cannot push a workload into indefinite learning.
//
// An empty cronExpr means no schedule was discovered, which is the normal case
// for most workloads: the declared minimum is returned unchanged with no error.
//
// When cronExpr is set but unparseable, the returned Requirement still carries
// the declared minimum alongside the error. A caller that logs the error and
// carries on therefore behaves exactly as it did before this package existed,
// rather than falling back to a zero window and enforcing immediately.
func Required(declared time.Duration, cronExpr string) (Requirement, error) {
	req := Requirement{Window: declared, Declared: declared, Source: SourceDeclared}
	if declared < 0 {
		// A negative declared minimum is a caller bug, not a request to enforce
		// in the past. Treat it as unset rather than propagating it into a
		// comparison where it would lose to everything.
		req.Window = 0
		req.Declared = 0
		declared = 0
	}
	if cronExpr == "" {
		return req, nil
	}

	cycle, err := Interval(cronExpr)
	if err != nil {
		return req, fmt.Errorf("resolve learning window for schedule %q: %w", cronExpr, err)
	}
	req.Cycle = cycle

	contribution := cycle
	capped := false
	if contribution > MaxWindow {
		contribution = MaxWindow
		capped = true
	}
	if contribution > req.Window {
		req.Window = contribution
		req.Source = SourceCycle
	}
	if capped {
		// Report the cap even when the declared minimum happened to win, so the
		// "this workload has a cycle nobody will wait for" signal survives an
		// operator who declared a long window for unrelated reasons.
		req.Source = SourceCap
	}
	return req, nil
}
