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

package commands

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

func TestCreatePolicyFromFlags(t *testing.T) {
	policy, err := createPolicyFromFlags("30s", "blocking", "app=web,tier=frontend", "prod")
	if err != nil {
		t.Fatalf("createPolicyFromFlags returned error: %v", err)
	}

	if policy.Namespace != "prod" {
		t.Errorf("namespace = %q, want prod", policy.Namespace)
	}
	if policy.Kind != "PahlevanPolicy" {
		t.Errorf("kind = %q, want PahlevanPolicy", policy.Kind)
	}
	if policy.Spec.EnforcementConfig.Mode != policyv1alpha1.EnforcementModeBlocking {
		t.Errorf("mode = %q, want Blocking", policy.Spec.EnforcementConfig.Mode)
	}
	if !policy.Spec.EnforcementConfig.BlockUnknown {
		t.Errorf("BlockUnknown should be true for blocking mode")
	}
	if policy.Spec.LearningConfig.Duration == nil || policy.Spec.LearningConfig.Duration.Duration != 30*time.Second {
		t.Errorf("duration = %v, want 30s", policy.Spec.LearningConfig.Duration)
	}
	if policy.Spec.Selector.MatchLabels["app"] != "web" || policy.Spec.Selector.MatchLabels["tier"] != "frontend" {
		t.Errorf("selector match labels = %v, want app=web,tier=frontend", policy.Spec.Selector.MatchLabels)
	}
}

func TestParseEnforcementMode(t *testing.T) {
	cases := map[string]policyv1alpha1.EnforcementMode{
		"off":        policyv1alpha1.EnforcementModeOff,
		"monitoring": policyv1alpha1.EnforcementModeMonitoring,
		"blocking":   policyv1alpha1.EnforcementModeBlocking,
	}
	for in, want := range cases {
		got, err := parseEnforcementMode(in)
		if err != nil {
			t.Errorf("parseEnforcementMode(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseEnforcementMode(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := parseEnforcementMode("bogus"); err == nil {
		t.Errorf("parseEnforcementMode(bogus) should return an error")
	}
}

func TestParseSelector(t *testing.T) {
	labels, err := parseSelector("a=1,b=2")
	if err != nil {
		t.Fatalf("parseSelector error: %v", err)
	}
	if labels["a"] != "1" || labels["b"] != "2" {
		t.Errorf("parseSelector = %v, want a=1,b=2", labels)
	}
	if _, err := parseSelector("invalid-no-equals"); err == nil {
		t.Errorf("parseSelector should reject entries without '='")
	}
}

// TestDryRunCreate verifies that a server-side dry-run create (DryRunAll) does
// not persist the object, while a normal create does.
func TestDryRunCreate(t *testing.T) {
	scheme := cli.GetScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	policy, err := createPolicyFromFlags("5m", "monitoring", "app=demo", "default")
	if err != nil {
		t.Fatalf("createPolicyFromFlags error: %v", err)
	}
	policy.Name = "dry-run-policy"

	ctx := context.Background()

	// Dry-run create must not persist.
	if err := fakeClient.Create(ctx, policy.DeepCopy(), crclient.DryRunAll); err != nil {
		t.Fatalf("dry-run create failed: %v", err)
	}
	got := &policyv1alpha1.PahlevanPolicy{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "dry-run-policy", Namespace: "default"}, got)
	if err == nil {
		t.Fatalf("dry-run create must not persist the object, but it was found")
	}

	// Real create must persist.
	if err := fakeClient.Create(ctx, policy.DeepCopy()); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: "dry-run-policy", Namespace: "default"}, got); err != nil {
		t.Fatalf("expected policy to be persisted after real create: %v", err)
	}
}

func TestValidatePolicy(t *testing.T) {
	valid, err := createPolicyFromFlags("1m", "monitoring", "app=x", "ns")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	valid.Name = "ok"
	if err := validatePolicy(valid); err != nil {
		t.Errorf("validatePolicy(valid) unexpected error: %v", err)
	}

	missingName := valid.DeepCopy()
	missingName.Name = ""
	if err := validatePolicy(missingName); err == nil {
		t.Errorf("validatePolicy should fail when name is empty")
	}
}
