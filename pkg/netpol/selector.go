package netpol

import (
	"sort"
	"strings"
)

// A NetworkPolicy selects pods by label, and a baseline records pods by name.
// The gap between those two is where a generated policy stops being a record
// of what happened and starts being a claim about what is allowed.
//
// The claim is wrong in one direction only, and it is the dangerous one. Every
// label set derived from a group of pods selects at least those pods; the
// question is what else it selects. In a namespace where "app=api" is on the
// API deployment and on its debug sidecar deployment and on last quarter's
// canary, a rule built from watching the first one permits traffic to all
// three. Nobody watched the other two. The policy now says they may be talked
// to, on the authority of evidence that is not about them.
//
// So the rule this file enforces is: a label set may be written into a policy
// only if, applied to the namespace as it actually is, it selects exactly the
// pods it was derived from and nothing else. When it does not, Selector says
// which pods broke it, and the generator reports that instead of emitting a
// rule that quietly means more than it can support.

// volatileLabels are labels a generated selector must never contain.
//
// Each is rewritten by a controller, so a policy naming one matches the pods
// it was generated from and nothing afterwards. That failure is worse than an
// over-wide selector because it is invisible: the policy applies cleanly, it
// selects zero pods the morning after a rollout, and a policy that selects
// zero pods enforces nothing at all.
var volatileLabels = map[string]bool{
	// Rewritten by the Deployment controller on every rollout.
	"pod-template-hash": true,
	// The same, for DaemonSet and StatefulSet revisions.
	"controller-revision-hash": true,
	// Unique per replica, so it can only ever name one pod.
	"statefulset.kubernetes.io/pod-name": true,
	"apps.kubernetes.io/pod-index":       true,
	// Unique per Job, and a CronJob makes a new Job per firing - which is
	// exactly the workload pkg/cycle exists for.
	"controller-uid":                     true,
	"batch.kubernetes.io/controller-uid": true,
	"job-name":                           true,
	"batch.kubernetes.io/job-name":       true,
}

// Selector is the outcome of trying to name a set of pods by label.
//
// A Selector is only usable when OK reports true. The zero value is not
// usable, which is the right default for an inference that has not been made.
type Selector struct {
	// Labels is the derived set. It is empty when the pods share nothing
	// durable, which happens more often than it sounds: a bare pod, or a
	// StatefulSet whose only shared label was filtered as volatile.
	Labels map[string]string

	// Extra names the pods Labels would select that were not in the set it
	// was derived from, in namespace/name form. A non-empty Extra is the whole
	// reason this package exists: it is the difference between the policy and
	// the evidence, stated in pods rather than in a warning nobody can check.
	Extra []string

	// Volatile names label keys that were dropped because a controller
	// rewrites them. It is reported rather than silently applied, because
	// dropping the only label that distinguished two workloads is how Extra
	// becomes non-empty and the reason is not otherwise visible.
	Volatile []string
}

// OK reports whether this selector can be written into a policy.
func (s Selector) OK() bool { return len(s.Labels) > 0 && len(s.Extra) == 0 }

// Reason explains an unusable selector in one line, for a report.
func (s Selector) Reason() string {
	switch {
	case s.OK():
		return ""
	case len(s.Labels) == 0:
		return "the observed pods share no durable label, so no podSelector can name them"
	default:
		return "a podSelector on " + s.String() + " would also select " +
			strings.Join(s.Extra, ", ") + ", which were never observed"
	}
}

// String renders the labels the way a selector is normally written, in key
// order so two runs produce the same text.
func (s Selector) String() string {
	if len(s.Labels) == 0 {
		return "<none>"
	}
	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+s.Labels[k])
	}
	return strings.Join(parts, ",")
}

// selectorFor derives a label set naming exactly want, checked against all.
//
// want is the pods the rule is about; all is every pod in their namespace, as
// the cluster has it. The second argument is not optional: without it there is
// no way to know what the derived labels would also catch, and a selector that
// has not been checked is a guess. Callers with no roster must not call this -
// Generate reports the subject instead.
func selectorFor(want, all []Pod) Selector {
	if len(want) == 0 {
		return Selector{}
	}

	labels, volatile := commonLabels(want)
	s := Selector{Labels: labels, Volatile: volatile}
	if len(labels) == 0 {
		return s
	}

	inWant := make(map[string]bool, len(want))
	for _, p := range want {
		inWant[p.Key()] = true
	}
	for _, p := range all {
		if inWant[p.Key()] {
			continue
		}
		if matches(labels, p.Labels) {
			s.Extra = append(s.Extra, p.Key())
		}
	}
	sort.Strings(s.Extra)
	return s
}

// commonLabels is the durable label set shared by every pod in pods: same key,
// same value, everywhere. A key present on some pods and not others cannot be
// in the selector, because the selector has to select all of them.
func commonLabels(pods []Pod) (map[string]string, []string) {
	if len(pods) == 0 {
		return nil, nil
	}

	var dropped []string
	shared := make(map[string]string, len(pods[0].Labels))
	for k, v := range pods[0].Labels {
		if volatileLabels[k] {
			dropped = append(dropped, k)
			continue
		}
		shared[k] = v
	}
	for _, p := range pods[1:] {
		for k, v := range shared {
			if got, ok := p.Labels[k]; !ok || got != v {
				delete(shared, k)
			}
		}
	}
	if len(shared) == 0 {
		shared = nil
	}
	sort.Strings(dropped)
	return shared, dropped
}

// matches reports whether a pod's labels satisfy every entry in sel, which is
// what matchLabels means.
func matches(sel, labels map[string]string) bool {
	for k, v := range sel {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}
