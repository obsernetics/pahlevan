/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"testing"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func TestMatchesSelector(t *testing.T) {
	cases := []struct {
		name     string
		labels   map[string]string
		selector policyv1alpha1.LabelSelector
		want     bool
	}{
		{"empty selector matches all", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{}, true},
		{"empty selector matches nil labels", nil, policyv1alpha1.LabelSelector{}, true},
		{"nil labels miss matchLabels", nil, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, false},
		{"matchLabels hit", map[string]string{"app": "web"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, true},
		{"matchLabels miss wrong value", map[string]string{"app": "db"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, false},
		{"matchLabels miss missing key", map[string]string{"other": "x"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, false},
		{"matchLabels extra pod labels ignored", map[string]string{"app": "web", "extra": "z"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, true},
		{"matchLabels multi-key hit", map[string]string{"app": "web", "tier": "fe"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web", "tier": "fe"}}, true},
		{"matchLabels multi-key one miss", map[string]string{"app": "web", "tier": "be"}, policyv1alpha1.LabelSelector{MatchLabels: map[string]string{"app": "web", "tier": "fe"}}, false},

		{"In hit", map[string]string{"tier": "fe"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe", "be"}}}}, true},
		{"In miss missing key", map[string]string{"x": "y"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe"}}}}, false},
		{"In miss wrong value", map[string]string{"tier": "db"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe"}}}}, false},
		{"In empty values never matches", map[string]string{"tier": "fe"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{}}}}, false},

		{"NotIn hit absent key", map[string]string{"x": "y"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"fe"}}}}, true},
		{"NotIn hit present but not in values", map[string]string{"tier": "db"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"fe"}}}}, true},
		{"NotIn miss present in values", map[string]string{"tier": "fe"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"fe"}}}}, false},

		{"Exists hit", map[string]string{"tier": "x"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists}}}, true},
		{"Exists miss", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists}}}, false},
		{"Exists miss nil labels", nil, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists}}}, false},

		{"DoesNotExist hit", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpDoesNotExist}}}, true},
		{"DoesNotExist hit nil labels", nil, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpDoesNotExist}}}, true},
		{"DoesNotExist miss", map[string]string{"tier": "x"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpDoesNotExist}}}, false},

		{
			"matchLabels and matchExpressions both satisfied",
			map[string]string{"app": "web", "tier": "fe"},
			policyv1alpha1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
					{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe", "be"}},
				},
			},
			true,
		},
		{
			"matchLabels satisfied but matchExpressions fails",
			map[string]string{"app": "web", "tier": "cache"},
			policyv1alpha1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
				MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
					{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe", "be"}},
				},
			},
			false,
		},
		{
			"multiple matchExpressions ANDed - all satisfied",
			map[string]string{"tier": "fe", "env": "prod"},
			policyv1alpha1.LabelSelector{
				MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
					{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists},
					{Key: "env", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"staging"}},
				},
			},
			true,
		},
		{
			"multiple matchExpressions ANDed - one fails",
			map[string]string{"tier": "fe", "env": "staging"},
			policyv1alpha1.LabelSelector{
				MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
					{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpExists},
					{Key: "env", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"staging"}},
				},
			},
			false,
		},
		{"unknown operator falls through as satisfied", map[string]string{"a": "b"}, policyv1alpha1.LabelSelector{MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{{Key: "tier", Operator: policyv1alpha1.LabelSelectorOperator("Bogus")}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesSelector(tc.labels, tc.selector); got != tc.want {
				t.Errorf("matchesSelector(%v, %+v) = %v, want %v", tc.labels, tc.selector, got, tc.want)
			}
		})
	}
}

func BenchmarkMatchesSelector(b *testing.B) {
	labels := map[string]string{"app": "web", "tier": "fe", "env": "prod"}
	selector := policyv1alpha1.LabelSelector{
		MatchLabels: map[string]string{"app": "web"},
		MatchExpressions: []policyv1alpha1.LabelSelectorRequirement{
			{Key: "tier", Operator: policyv1alpha1.LabelSelectorOpIn, Values: []string{"fe", "be"}},
			{Key: "env", Operator: policyv1alpha1.LabelSelectorOpNotIn, Values: []string{"staging"}},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchesSelector(labels, selector)
	}
}
