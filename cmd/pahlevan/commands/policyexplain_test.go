package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

const minimalPolicy = `apiVersion: policy.pahlevan.io/v1alpha1
kind: PahlevanPolicy
metadata:
  name: demo
  namespace: prod
spec:
  selector:
    matchLabels:
      app: demo
  learningConfig:
    duration: "5m"
    autoTransition: true
  enforcementConfig:
    mode: Blocking
  selfHealing:
    enabled: true
    rollbackThreshold: 3
    rollbackWindow: "5m"
`

// The command exists so an author can see what a policy does before applying
// it. The mode, the window and the self-healing settings are the three
// decisions that matter most, so all three have to appear.
func TestExplainPrintsTheDecision(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, minimalPolicy), false))

	got := out.String()
	assert.Contains(t, got, "prod/demo")
	assert.Contains(t, got, "Blocking")
	assert.Contains(t, got, "denied in-kernel with EPERM")
	assert.Contains(t, got, "5m0s")
	assert.Contains(t, got, "after 3 denials")
	// With no allow or deny lists, the enforced set is purely learned, and the
	// output should say so rather than printing an empty section.
	assert.Contains(t, got, "entirely what the")
	assert.Contains(t, got, "Every part of this policy can be enforced")
}

// The warnings are the reason the command exists. An operator who never applies
// the policy still needs to know an ingress rule does nothing.
func TestExplainReportsWhatCannotBeEnforced(t *testing.T) {
	body := minimalPolicy + `  networkPolicy:
    ingressRules:
    - ports:
      - port: 80
`
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))

	got := out.String()
	assert.Contains(t, got, "will NOT be enforced")
	assert.Contains(t, got, "egress only")
	assert.Contains(t, got, "doing less than it says")
}

// --strict is for CI, where a policy that quietly does less than it says should
// fail the build rather than be merged.
func TestExplainStrictFailsOnUnenforceableParts(t *testing.T) {
	body := minimalPolicy + `  networkPolicy:
    ingressRules:
    - ports:
      - port: 80
`
	var out bytes.Buffer
	err := runPolicyExplain(&out, writePolicy(t, body), true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be enforced")

	// And a clean policy must pass under --strict.
	out.Reset()
	assert.NoError(t, runPolicyExplain(&out, writePolicy(t, minimalPolicy), true))
}

// A field the CRD does not have is pruned by the API server rather than
// rejected, so the policy applies cleanly and does less than it says. This is
// the one place an author can find out.
func TestExplainRejectsUnknownFields(t *testing.T) {
	body := strings.Replace(minimalPolicy, "  learningConfig:", "  learning:", 1)
	var out bytes.Buffer
	err := runPolicyExplain(&out, writePolicy(t, body), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
	assert.Contains(t, out.String(), "pruned")
}

// A policy file commonly holds several documents, and explaining only the first
// would quietly ignore the rest.
func TestExplainHandlesEveryDocument(t *testing.T) {
	second := strings.Replace(minimalPolicy, "name: demo", "name: second", 1)
	body := minimalPolicy + "---\n" + second

	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))
	assert.Contains(t, out.String(), "prod/demo")
	assert.Contains(t, out.String(), "prod/second")
}

// Non-policy documents in the same file are skipped rather than being an error:
// an example that ships a Deployment alongside its policy is normal.
func TestExplainSkipsOtherKinds(t *testing.T) {
	body := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n---\n" + minimalPolicy
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))
	assert.Contains(t, out.String(), "prod/demo")
}

func TestExplainErrorsWithNoPolicies(t *testing.T) {
	body := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
	var out bytes.Buffer
	err := runPolicyExplain(&out, writePolicy(t, body), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PahlevanPolicy documents")
}

func TestExplainErrorsOnAMissingFile(t *testing.T) {
	var out bytes.Buffer
	err := runPolicyExplain(&out, filepath.Join(t.TempDir(), "absent.yaml"), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading")
}

// Off means the policy governs nothing, and the output must not imply otherwise
// - reading "Blocking" off a policy that is switched off is the kind of
// misreading that ends with an unprotected workload.
func TestExplainDescribesOffAndMonitoring(t *testing.T) {
	for mode, want := range map[string]string{
		"Off":        "governs nothing",
		"Monitoring": "denials are counted, nothing is blocked",
	} {
		t.Run(mode, func(t *testing.T) {
			// Quoted, deliberately. Unquoted Off is a YAML 1.1 boolean, which is
			// the trap the next test covers - and which this test fell into
			// when it was first written.
			body := strings.Replace(minimalPolicy, "mode: Blocking", `mode: "`+mode+`"`, 1)
			var out bytes.Buffer
			require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))
			assert.Contains(t, out.String(), want)
		})
	}
}

// Self-healing being off is worth stating plainly: it is the difference between
// a bad baseline that recovers and one that stays bad.
func TestExplainSaysWhenSelfHealingIsOff(t *testing.T) {
	body := strings.Replace(minimalPolicy, "    enabled: true", "    enabled: false", 1)
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))
	assert.Contains(t, out.String(), "a wrong baseline stays wrong")
}

// The process filter is the newest mechanism and the easiest to get wrong, so
// the output has to show which dimensions are actually live.
func TestExplainShowsTheProcessFilter(t *testing.T) {
	body := minimalPolicy + `  syscallPolicy:
    processFilter:
      parentProcesses: ["supervisord"]
      users: ["10001"]
`
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))
	got := out.String()
	assert.Contains(t, got, "Process filter (parent,uid)")
	assert.Contains(t, got, "supervisord")
	assert.Contains(t, got, "10001")
}

// Reads and writes are separate allow-set entries, and the output must show
// them separately or an operator cannot tell which one a path got.
func TestExplainSeparatesReadsFromWrites(t *testing.T) {
	body := minimalPolicy + `  filePolicy:
    readOnlyPaths: ["/etc/config"]
    writeAllowedPaths: ["/tmp"]
`
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))
	got := out.String()
	assert.Contains(t, got, "allow  read          /etc/config")
	assert.Contains(t, got, "deny   write         /etc/config")
	assert.Contains(t, got, "allow  write         /tmp")
}

func TestSplitYAMLDocuments(t *testing.T) {
	assert.Len(t, splitYAMLDocuments([]byte("a: 1")), 1)
	assert.Len(t, splitYAMLDocuments([]byte("a: 1\n---\nb: 2")), 2)
	// A leading separator must not produce an empty leading document.
	assert.Len(t, splitYAMLDocuments([]byte("---\na: 1\n---\nb: 2")), 2)
	assert.Empty(t, splitYAMLDocuments([]byte("\n\n")))
}

// Every example in the repository must survive `policy explain`. The command is
// the only place the translation is visible without a cluster, so an example it
// cannot read is one nobody can check.
func TestEveryExampleExplains(t *testing.T) {
	const dir = "../../../examples"
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("examples not present: %v", err)
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".yaml" {
			return err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a fixed directory in-tree
		if err != nil {
			return err
		}
		if !strings.Contains(string(data), "kind: PahlevanPolicy") {
			return nil
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			var out bytes.Buffer
			// Not --strict: several examples legitimately use constructs the
			// data plane cannot represent, and say so in their comments. What
			// must not happen is the command failing to read them at all.
			assert.NoError(t, runPolicyExplain(&out, path, false))
			assert.NotEmpty(t, out.String())
		})
		return nil
	})
	require.NoError(t, err)
}

func BenchmarkExplain(b *testing.B) {
	path := filepath.Join(b.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(minimalPolicy), 0o600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		if err := runPolicyExplain(&out, path, false); err != nil {
			b.Fatal(err)
		}
	}
}

// `mode: Off` unquoted is a YAML 1.1 boolean. It arrives as "false", the
// controller does not recognize it, and the policy the author meant to switch
// off keeps running as Monitoring. Explaining the policy is the one place they
// can find that out before it happens.
//
// This test exists because the test above fell into it.
func TestExplainCatchesTheUnquotedOffTrap(t *testing.T) {
	body := strings.Replace(minimalPolicy, "mode: Blocking", "mode: Off", 1)
	var out bytes.Buffer
	require.NoError(t, runPolicyExplain(&out, writePolicy(t, body), false))

	got := out.String()
	assert.Contains(t, got, "unquoted Off or On")
	assert.Contains(t, got, "Monitoring")

	// And --strict must fail on it: a policy that silently does the opposite of
	// what it says is exactly what a CI gate is for.
	assert.Error(t, runPolicyExplain(&bytes.Buffer{}, writePolicy(t, body), true))
}
