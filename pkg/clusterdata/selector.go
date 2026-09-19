package clusterdata

import (
	"sort"
	"strings"

	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

// FormatSelector renders a workload selector the way an operator writes one on
// a kubectl command line, e.g. `app=web,tier in (edge,front)`.
//
// It is a display string, not a parseable one. The point is that an operator
// scanning a policy list can tell at a glance which policy covers the workload
// they are looking at; dumping the Go struct or a JSON blob into a table cell
// cannot answer that question at terminal width.
//
// An empty selector renders as "<all pods>" rather than as an empty cell,
// because a PahlevanPolicy with no selector covers every pod in its namespace.
// That is the single most consequential thing a selector can say, and a blank
// cell says it the least.
func FormatSelector(s policyv1beta1.WorkloadSelector) string {
	parts := formatLabelParts(s.MatchLabels, s.MatchExpressions)

	// The namespace selector widens a policy past its own namespace, so it is
	// shown as a prefix rather than folded in with the pod terms: `ns:` in
	// front is the difference between "the web pods here" and "the web pods
	// everywhere".
	if ns := s.NamespaceSelector; ns != nil {
		if nsParts := formatLabelParts(ns.MatchLabels, ns.MatchExpressions); len(nsParts) > 0 {
			parts = append([]string{"ns:" + strings.Join(nsParts, ",")}, parts...)
		}
	}

	if len(parts) == 0 {
		return "<all pods>"
	}
	return strings.Join(parts, ",")
}

func formatLabelParts(matchLabels map[string]string, exprs []policyv1beta1.LabelSelectorRequirement) []string {
	parts := make([]string, 0, len(matchLabels)+len(exprs))

	// Sorted, because Go map iteration order is random and an unsorted
	// selector string makes a policy appear to change on every refresh.
	keys := make([]string, 0, len(matchLabels))
	for k := range matchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+matchLabels[k])
	}

	for _, e := range exprs {
		parts = append(parts, formatRequirement(e))
	}
	return parts
}

func formatRequirement(e policyv1beta1.LabelSelectorRequirement) string {
	switch e.Operator {
	case policyv1beta1.LabelSelectorOpIn:
		return e.Key + " in (" + strings.Join(e.Values, ",") + ")"
	case policyv1beta1.LabelSelectorOpNotIn:
		return e.Key + " notin (" + strings.Join(e.Values, ",") + ")"
	case policyv1beta1.LabelSelectorOpExists:
		return e.Key
	case policyv1beta1.LabelSelectorOpDoesNotExist:
		return "!" + e.Key
	default:
		// An unknown operator is shown verbatim rather than dropped. The enum
		// refuses these at apply time now, but objects written before the enum
		// existed are still stored, and silently omitting a term makes a policy
		// look broader or narrower than it is.
		if len(e.Values) > 0 {
			return e.Key + " " + string(e.Operator) + " (" + strings.Join(e.Values, ",") + ")"
		}
		return e.Key + " " + string(e.Operator)
	}
}
