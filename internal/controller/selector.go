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
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// matchesSelector reports whether labels satisfy every matchLabels entry and
// every matchExpressions requirement in selector. An empty selector matches
// everything.
//
// All three reconcilers (PahlevanPolicy, ContainerLearner, AttackSurface)
// need the identical decision - a policy's target set cannot depend on which
// controller happens to be asking - so this is the one implementation they
// share rather than three copies that could drift.
func matchesSelector(labels map[string]string, selector policyv1alpha1.LabelSelector) bool {
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}

	for _, expr := range selector.MatchExpressions {
		labelValue, exists := labels[expr.Key]

		switch expr.Operator {
		case policyv1alpha1.LabelSelectorOpIn:
			if !exists {
				return false
			}
			found := false
			for _, value := range expr.Values {
				if labelValue == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case policyv1alpha1.LabelSelectorOpNotIn:
			if exists {
				for _, value := range expr.Values {
					if labelValue == value {
						return false
					}
				}
			}
		case policyv1alpha1.LabelSelectorOpExists:
			if !exists {
				return false
			}
		case policyv1alpha1.LabelSelectorOpDoesNotExist:
			if exists {
				return false
			}
		}
	}

	return true
}
