package netpol

import (
	"fmt"
	"strings"
)

// Review before apply.
//
// The dangerous case is not a new policy: a new policy at least announces
// itself. It is a generated policy that has the same name as one somebody
// already wrote, where applying replaces rules a human reasoned about with
// rules derived from a fifty minute window. That replacement is invisible in
// the YAML, which says only what the new policy is, never what it displaces.
//
// So the command can be asked what it would change, and this is what answers.

// Change is what applying one generated policy would do to the cluster.
type Change struct {
	Namespace string
	Name      string
	// Created is true when nothing of that name exists yet.
	Created bool
	// Lines is the rendered diff, empty when the policy is identical to what
	// is already there.
	Lines []DiffLine
}

// Changed reports whether applying this would alter anything.
func (c Change) Changed() bool { return c.Created || len(c.Lines) > 0 }

// DiffLine is one line of a unified-ish diff.
type DiffLine struct {
	// Op is ' ', '-' or '+'.
	Op   byte
	Text string
}

// String renders a line the way a diff is read.
func (d DiffLine) String() string { return string(d.Op) + " " + d.Text }

// Diff compares two rendered manifests line by line.
//
// It is a longest-common-subsequence diff rather than a set difference: a set
// difference reports a moved rule as a delete and an insert in unrelated
// places, and a reviewer reading that cannot tell a reordering from a
// rewrite. Context lines around each change are kept so the output can be read
// without the original beside it.
func Diff(old, current string) []DiffLine {
	a := splitLines(old)
	b := splitLines(current)
	if len(a) == 0 && len(b) == 0 {
		return nil
	}

	lcs := lcsTable(a, b)
	var all []DiffLine
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			all = append(all, DiffLine{' ', a[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			all = append(all, DiffLine{'-', a[i]})
			i++
		default:
			all = append(all, DiffLine{'+', b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		all = append(all, DiffLine{'-', a[i]})
	}
	for ; j < len(b); j++ {
		all = append(all, DiffLine{'+', b[j]})
	}
	return contextOnly(all, diffContext)
}

// diffContext is how many unchanged lines are kept either side of a change.
// Three is what everybody's eye is trained on from every other diff they read.
const diffContext = 3

// lcsTable is the standard dynamic-programming table, built backwards so
// lcs[i][j] is the length of the longest common subsequence of a[i:] and b[j:].
func lcsTable(a, b []string) [][]int {
	table := make([][]int, len(a)+1)
	for i := range table {
		table[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
				continue
			}
			table[i][j] = max(table[i+1][j], table[i][j+1])
		}
	}
	return table
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// contextOnly drops runs of unchanged lines longer than 2*n, leaving n either
// side of every change. A manifest is mostly unchanged, and a diff that prints
// all of it is a diff nobody reads to the end.
func contextOnly(lines []DiffLine, n int) []DiffLine {
	keep := make([]bool, len(lines))
	changed := false
	for i, l := range lines {
		if l.Op == ' ' {
			continue
		}
		changed = true
		for j := i - n; j <= i+n; j++ {
			if j >= 0 && j < len(lines) {
				keep[j] = true
			}
		}
	}
	if !changed {
		return nil
	}
	out := make([]DiffLine, 0, len(lines))
	skipped := false
	for i, l := range lines {
		if !keep[i] {
			skipped = true
			continue
		}
		if skipped {
			out = append(out, DiffLine{' ', "..."})
			skipped = false
		}
		out = append(out, l)
	}
	return out
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// RenderChanges writes the review of what applying would displace.
func RenderChanges(changes []Change) string {
	var b strings.Builder
	quiet := 0
	for _, c := range changes {
		switch {
		case c.Created:
			fmt.Fprintf(&b, "+ %s/%s is new\n", c.Namespace, c.Name)
		case len(c.Lines) == 0:
			quiet++
			continue
		default:
			fmt.Fprintf(&b, "~ %s/%s already exists and would be replaced:\n", c.Namespace, c.Name)
			for _, l := range c.Lines {
				fmt.Fprintf(&b, "    %s\n", l.String())
			}
		}
		fmt.Fprintln(&b)
	}
	if quiet > 0 {
		fmt.Fprintf(&b, "%d policy(s) already match what would be generated.\n", quiet)
	}
	if b.Len() == 0 {
		return "Applying this would change nothing.\n"
	}
	return b.String()
}
