package v1alpha1

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// The examples are documentation people copy. A field that does not exist in
// the CRD is not a harmless typo there: the user gets an apply error against a
// file the project told them to use, and the natural conclusion is that the
// tool is broken rather than the example.
//
// Nothing checked these before. They were written by hand against a spec that
// has changed repeatedly, and a strict decode is the cheapest way to keep them
// honest - it fails on any key the Go type does not have.

const examplesDir = "../../../../examples"

// exampleDocs walks the examples tree and returns every YAML document, tagged
// with where it came from so a failure names the file rather than a byte offset.
func exampleDocs(t *testing.T) map[string][][]byte {
	t.Helper()
	out := map[string][][]byte{}
	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- walking a fixed directory in-tree
		if err != nil {
			return err
		}
		for _, doc := range splitYAML(data) {
			if len(bytes.TrimSpace(doc)) == 0 {
				continue
			}
			out[path] = append(out[path], doc)
		}
		return nil
	})
	require.NoError(t, err, "the examples directory must be readable")
	require.NotEmpty(t, out, "no examples found; the path is probably wrong")
	return out
}

// splitYAML splits a multi-document file on the document separator. A full YAML
// parser would also do this, but it would parse the document as part of doing
// so, and the point here is to hand each one to a strict decoder untouched.
func splitYAML(data []byte) [][]byte {
	var docs [][]byte
	var cur []byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Equal(bytes.TrimRight(line, " \t\r"), []byte("---")) {
			docs = append(docs, cur)
			cur = nil
			continue
		}
		cur = append(cur, line...)
		cur = append(cur, '\n')
	}
	return append(docs, cur)
}

type typeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// Every PahlevanPolicy in the examples must decode strictly. Unknown fields are
// the failure this catches: a spec key that was renamed, or one that was
// invented for the example and never implemented.
func TestExamplePoliciesDecodeStrictly(t *testing.T) {
	for path, docs := range exampleDocs(t) {
		for i, doc := range docs {
			var tm typeMeta
			if err := yaml.Unmarshal(doc, &tm); err != nil {
				t.Errorf("%s doc %d: not valid YAML: %v", path, i, err)
				continue
			}
			if tm.Kind != "PahlevanPolicy" {
				continue
			}
			t.Run(filepath.Base(path), func(t *testing.T) {
				var p PahlevanPolicy
				err := yaml.UnmarshalStrict(doc, &p)
				require.NoError(t, err, "%s doc %d does not match the CRD schema", path, i)

				assert.Equal(t, GroupVersion.String(), p.APIVersion,
					"an example must name the API version the CRD actually serves")
				assert.NotEmpty(t, p.Name, "a policy without a name cannot be applied")
			})
		}
	}
}

// A policy that selects nothing governs nothing. An example that does that is
// worse than no example: it applies cleanly and then does not work, and the
// user has no error to search for.
func TestExamplePoliciesSelectSomething(t *testing.T) {
	for path, docs := range exampleDocs(t) {
		for _, doc := range docs {
			var tm typeMeta
			if yaml.Unmarshal(doc, &tm) != nil || tm.Kind != "PahlevanPolicy" {
				continue
			}
			var p PahlevanPolicy
			if yaml.UnmarshalStrict(doc, &p) != nil {
				continue // reported by the strict test
			}
			t.Run(filepath.Base(path)+"/"+p.Name, func(t *testing.T) {
				sel := p.Spec.Selector
				assert.True(t,
					len(sel.MatchLabels) > 0 || len(sel.MatchExpressions) > 0,
					"%s selects no workloads, so it would apply cleanly and do nothing", p.Name)
			})
		}
	}
}

// Blocking is the mode that can break a workload. An example that enables it
// without self-healing is telling the reader to skip the safety net, which is
// not the practice this project should be documenting.
func TestBlockingExamplesEnableSelfHealing(t *testing.T) {
	for path, docs := range exampleDocs(t) {
		for _, doc := range docs {
			var tm typeMeta
			if yaml.Unmarshal(doc, &tm) != nil || tm.Kind != "PahlevanPolicy" {
				continue
			}
			var p PahlevanPolicy
			if yaml.UnmarshalStrict(doc, &p) != nil {
				continue
			}
			if p.Spec.EnforcementConfig.Mode != EnforcementModeBlocking {
				continue
			}
			t.Run(filepath.Base(path)+"/"+p.Name, func(t *testing.T) {
				assert.True(t, p.Spec.SelfHealing.Enabled,
					"%s in %s blocks without self-healing; a bad baseline would stay bad",
					p.Name, filepath.Base(path))
			})
		}
	}
}

// Every YAML file in the tree must parse, whatever its kind. The observability
// examples are plain Kubernetes objects rather than policies, and a broken one
// fails the same way for the user.
func TestEveryExampleFileParses(t *testing.T) {
	for path, docs := range exampleDocs(t) {
		for i, doc := range docs {
			var obj map[string]interface{}
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				t.Errorf("%s doc %d: %v", path, i, err)
				continue
			}
			if len(obj) == 0 {
				continue
			}
			assert.NotEmpty(t, obj["kind"], "%s doc %d has no kind", path, i)
			assert.NotEmpty(t, obj["apiVersion"], "%s doc %d has no apiVersion", path, i)
		}
	}
}

// The README is the index into this directory. An example nobody links to is
// one nobody finds.
func TestEveryExampleIsMentionedInTheReadme(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join(examplesDir, "README.md"))
	require.NoError(t, err)
	text := string(readme)

	for path := range exampleDocs(t) {
		rel, err := filepath.Rel(examplesDir, path)
		require.NoError(t, err)
		base := filepath.Base(rel)
		assert.True(t, strings.Contains(text, rel) || strings.Contains(text, base),
			"examples/%s is not mentioned in examples/README.md", rel)
	}
}

func BenchmarkStrictDecodeExample(b *testing.B) {
	data, err := os.ReadFile(filepath.Join(examplesDir, "quickstart", "simple-policy.yaml"))
	if err != nil {
		b.Skip("example not present")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p PahlevanPolicy
		_ = yaml.UnmarshalStrict(data, &p)
	}
}
