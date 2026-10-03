package policy

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// celProgram compiles the CRD's validation rule the way an API server would.
func celProgram(tb testing.TB) cel.Program {
	tb.Helper()
	env, err := cel.NewEnv(cel.Variable("self", cel.DynType))
	require.NoError(tb, err)

	ast, issues := env.Compile(wantIngressCELRule)
	require.NoError(tb, issues.Err(),
		"the CRD's validation rule is not valid CEL, so an API server would reject the whole CRD")
	prg, err := env.Program(ast)
	require.NoError(tb, err)
	return prg
}

// This evaluates the rule rather than only matching its text.
//
// TestCRDRefusesIngressRules proves the generated CRD carries the sentence we
// wrote. It cannot prove the sentence is valid CEL, or that it means what the
// message next to it claims. A rule that fails to compile makes the API server
// reject the CRD at install time; a rule that compiles but is inverted lets
// every ingress rule through while the schema looks like it is guarding
// something. Both are failures only a real cluster would find, which is the
// same "nobody finds out" shape as the defect being fixed.
func TestCRDIngressRuleIsValidCELAndRefusesWhatItShould(t *testing.T) {
	prg := celProgram(t)
	rule := map[ref.Val]ref.Val{}

	tests := []struct {
		name string
		self map[string]interface{}
		want bool
	}{
		{"no ingressRules key at all",
			map[string]interface{}{"egressRules": []interface{}{rule}}, true},
		{"an explicitly empty ingressRules list",
			map[string]interface{}{"ingressRules": []interface{}{}}, true},
		{"one ingress rule",
			map[string]interface{}{"ingressRules": []interface{}{rule}}, false},
		{"several ingress rules",
			map[string]interface{}{"ingressRules": []interface{}{rule, rule, rule}}, false},
		{"ingress rules alongside egress rules",
			map[string]interface{}{
				"ingressRules": []interface{}{rule},
				"egressRules":  []interface{}{rule},
			}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := prg.Eval(map[string]interface{}{"self": tc.self})
			require.NoError(t, err)
			assert.Equal(t, types.Bool(tc.want), out,
				"the rule must accept a networkPolicy without ingress rules and refuse one with them")
		})
	}
}

// The rule runs in the API server's request path, on every write to every
// policy, so its cost is worth knowing.
func BenchmarkCRDIngressRuleEval(b *testing.B) {
	prg := celProgram(b)
	self := map[string]interface{}{
		"ingressRules": []interface{}{map[ref.Val]ref.Val{}},
	}
	activation := map[string]interface{}{"self": self}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := prg.Eval(activation); err != nil {
			b.Fatal(err)
		}
	}
}
