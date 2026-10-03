package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// The CEL rule the CRD must carry. Written out here rather than derived, so a
// change to the generated schema has to be made deliberately in both places.
const wantIngressCELRule = "!has(self.ingressRules) || size(self.ingressRules) == 0"

func ingressSpec(rules ...policyv1alpha1.NetworkRule) policyv1alpha1.PahlevanPolicySpec {
	return policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking,
		},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{IngressRules: rules},
	}
}

// An ingress rule that survives admission must still be named, word for word,
// by the translation the agent runs. Both surfaces say the same sentence so an
// operator who met the refusal at apply time recognises it in a log.
func TestIngressRuleWarnsWithTheRefusalMessage(t *testing.T) {
	_, warnings := Translate("p", ingressSpec(policyv1alpha1.NetworkRule{}), time.Now())
	assert.Contains(t, warnings, IngressNotEnforced,
		"the ingress warning must be the shared refusal sentence, not a paraphrase of it")
}

// The warning says what is wrong and what to do instead. A warning that only
// names the hook leaves the operator with no next step, which is how an
// unenforced field stays unenforced.
func TestIngressRefusalMessageNamesTheReasonAndTheAlternative(t *testing.T) {
	for _, want := range []string{
		"ingressRules",
		"not enforced",
		"socket_connect",
		"outbound connections only",
		"Kubernetes NetworkPolicy",
	} {
		assert.Contains(t, IngressNotEnforced, want)
	}
	// "ignored" alone was the old wording and it understated the case: the
	// field is refused now, and the sentence has to say so.
	assert.Contains(t, IngressNotEnforced, "refused")
}

// An ingress rule must never put anything in the kernel allow-sets. Half of it
// reaching the data plane would be worse than none, because the policy would
// then be partly true.
func TestIngressRuleSeedsNothing(t *testing.T) {
	d, _ := Translate("p", ingressSpec(policyv1alpha1.NetworkRule{
		Ports: []policyv1alpha1.NetworkPort{{Port: i32(8080)}},
		Peers: []policyv1alpha1.NetworkPeer{{
			IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.7/32"},
		}},
	}), time.Now())

	assert.Empty(t, d.Overrides.AllowedDestinations)
	assert.Empty(t, d.Overrides.DeniedDestinations)
	assert.Empty(t, d.Overrides.SelectorDestinations)
}

func TestDeclaresIngress(t *testing.T) {
	tests := []struct {
		name string
		spec policyv1alpha1.PahlevanPolicySpec
		want bool
	}{
		{"no network policy at all", policyv1alpha1.PahlevanPolicySpec{}, false},
		{"a network policy with no ingress rules",
			policyv1alpha1.PahlevanPolicySpec{
				NetworkPolicy: &policyv1alpha1.NetworkPolicy{
					EgressRules: []policyv1alpha1.NetworkRule{{}},
				},
			}, false},
		// An explicitly empty list asked for no ingress rule, so there is
		// nothing to refuse and nothing to report. Reporting it anyway would
		// be a condition an operator cannot clear.
		{"an explicitly empty ingress list",
			policyv1alpha1.PahlevanPolicySpec{
				NetworkPolicy: &policyv1alpha1.NetworkPolicy{
					IngressRules: []policyv1alpha1.NetworkRule{},
				},
			}, false},
		{"one ingress rule", ingressSpec(policyv1alpha1.NetworkRule{}), true},
		{"several ingress rules",
			ingressSpec(policyv1alpha1.NetworkRule{}, policyv1alpha1.NetworkRule{}), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, DeclaresIngress(tc.spec))
		})
	}
}

// --------------------------------------------------------------------------
// The CRD's own refusal
// --------------------------------------------------------------------------

// repoFile resolves a path relative to the repository root.
func repoFile(tb testing.TB, rel string) string {
	tb.Helper()
	return filepath.Join("..", "..", filepath.FromSlash(rel))
}

// crdVersionSchemas returns every served version of the PahlevanPolicy CRD,
// keyed by version name, from the generated manifest.
func crdVersionSchemas(tb testing.TB) map[string]map[string]interface{} {
	tb.Helper()
	path := repoFile(tb, "config/crd/policy.pahlevan.io_pahlevanpolicies.yaml")
	data, err := os.ReadFile(path) // #nosec G304 -- a fixed in-tree path
	require.NoError(tb, err, "config/crd must hold the generated PahlevanPolicy CRD")

	var crd struct {
		Spec struct {
			Versions []struct {
				Name   string                 `json:"name"`
				Served bool                   `json:"served"`
				Schema map[string]interface{} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	require.NoError(tb, yaml.Unmarshal(data, &crd))

	out := map[string]map[string]interface{}{}
	for _, v := range crd.Spec.Versions {
		if !v.Served {
			continue
		}
		out[v.Name] = v.Schema
	}
	require.NotEmpty(tb, out, "the CRD must serve at least one version")
	return out
}

// networkPolicySchema digs out the networkPolicy property of one version.
func networkPolicySchema(tb testing.TB, schema map[string]interface{}) map[string]interface{} {
	tb.Helper()
	node := schema
	for _, step := range []string{"openAPIV3Schema", "properties", "spec", "properties", "networkPolicy"} {
		next, ok := node[step].(map[string]interface{})
		require.True(tb, ok, "the CRD schema has no %s", step)
		node = next
	}
	return node
}

// This is the test that makes the refusal real.
//
// The CEL rule lives in a kubebuilder marker, so nothing in Go references it
// and nothing would notice it being dropped: the field would go back to being
// accepted and ignored, which is the defect it was added to close. The message
// is duplicated in the marker because a marker cannot reference a constant, so
// drift between the two is the other way this quietly stops working.
func TestCRDRefusesIngressRules(t *testing.T) {
	for version, schema := range crdVersionSchemas(t) {
		t.Run(version, func(t *testing.T) {
			np := networkPolicySchema(t, schema)

			raw, ok := np["x-kubernetes-validations"].([]interface{})
			require.True(t, ok,
				"networkPolicy in %s carries no x-kubernetes-validations, so the API server "+
					"accepts ingressRules and nothing enforces them", version)

			var rules, messages []string
			for _, v := range raw {
				entry, ok := v.(map[string]interface{})
				require.True(t, ok)
				if r, ok := entry["rule"].(string); ok {
					rules = append(rules, r)
				}
				if m, ok := entry["message"].(string); ok {
					messages = append(messages, m)
				}
			}

			assert.Contains(t, rules, wantIngressCELRule,
				"the CEL rule that refuses ingressRules is missing from %s", version)
			assert.Contains(t, messages, IngressNotEnforced,
				"the CEL message in %s has drifted from policy.IngressNotEnforced; the two are "+
					"the same sentence on purpose", version)
		})
	}
}

// install.yaml is the path docs/packages.md recommends for production, so the
// refusal has to be in the shipped manifest and not only in config/crd. The
// chart's copy is covered by hack/install, which diffs it against config/crd.
func TestShippedManifestsCarryTheIngressRefusal(t *testing.T) {
	for _, rel := range []string{
		"install.yaml",
		"charts/pahlevan-operator/crds/policy.pahlevan.io_pahlevanpolicies.yaml",
	} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(repoFile(t, rel)) // #nosec G304 -- a fixed in-tree path
			require.NoError(t, err)
			body := string(data)
			assert.Contains(t, body, wantIngressCELRule,
				"%s does not refuse ingressRules; regenerate it", rel)
			// The YAML wraps long lines, so the message is checked by a phrase
			// that survives folding rather than by the whole sentence.
			assert.True(t, strings.Contains(body, "socket_connect LSM hook"),
				"%s does not explain why ingressRules is refused", rel)
		})
	}
}

// --------------------------------------------------------------------------
// Benchmarks
// --------------------------------------------------------------------------

func BenchmarkDeclaresIngress(b *testing.B) {
	spec := ingressSpec(policyv1alpha1.NetworkRule{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !DeclaresIngress(spec) {
			b.Fatal("expected a declared ingress rule")
		}
	}
}

func BenchmarkTranslateWithIngressRules(b *testing.B) {
	rules := make([]policyv1alpha1.NetworkRule, 16)
	for i := range rules {
		rules[i] = policyv1alpha1.NetworkRule{
			Ports: []policyv1alpha1.NetworkPort{{Port: i32(int32(8000 + i))}},
			Peers: []policyv1alpha1.NetworkPeer{{
				IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.7/32"},
			}},
		}
	}
	spec := ingressSpec(rules...)
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, warnings := Translate("p", spec, now); len(warnings) == 0 {
			b.Fatal("expected the refusal warning")
		}
	}
}
