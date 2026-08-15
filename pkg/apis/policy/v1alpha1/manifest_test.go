package v1alpha1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// installManifest is the all-in-one manifest the README tells people to apply.
const installManifest = "../../../../install.yaml"

type schemaNode map[string]interface{}

// walkSchema visits every node of an OpenAPI v3 schema, reporting the JSON-ish
// path of each so a failure names the offending field rather than the file.
func walkSchema(node interface{}, path string, visit func(schemaNode, string)) {
	switch n := node.(type) {
	case map[string]interface{}:
		visit(n, path)
		for k, v := range n {
			walkSchema(v, path+"."+k, visit)
		}
	case []interface{}:
		for i, v := range n {
			walkSchema(v, path+"["+itoa(i)+"]", visit)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func loadInstallDocs(t *testing.T) []map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(installManifest))
	require.NoError(t, err, "install.yaml must exist: the README tells users to kubectl apply it")

	var docs []map[string]interface{}
	for _, chunk := range strings.Split(string(raw), "\n---") {
		if strings.TrimSpace(chunk) == "" {
			continue
		}
		var doc map[string]interface{}
		require.NoError(t, yaml.Unmarshal([]byte(chunk), &doc),
			"every document in install.yaml must be valid YAML")
		if len(doc) > 0 {
			docs = append(docs, doc)
		}
	}
	require.NotEmpty(t, docs)
	return docs
}

// Every schema node the API server structurally validates must declare a type.
//
// This shipped broken: LabelSelector.NamespaceSelector referred to
// LabelSelector, and controller-gen cannot express infinite recursion, so it
// truncated the chain into five nodes carrying a description and no type. The
// API server rejects those with "must have a type", and because install.yaml
// is applied as one stream, the CRD failed partway through and left a
// half-installed cluster. Nothing in the build caught it, because the manifest
// is only ever validated by a real API server.
func TestInstallManifestCRDsAreStructurallyValid(t *testing.T) {
	var checked int
	var problems []string

	for _, doc := range loadInstallDocs(t) {
		if doc["kind"] != "CustomResourceDefinition" {
			continue
		}
		name, _ := doc["metadata"].(map[string]interface{})["name"].(string)
		spec, _ := doc["spec"].(map[string]interface{})
		versions, _ := spec["versions"].([]interface{})
		require.NotEmpty(t, versions, "CRD %s declares no versions", name)

		for _, v := range versions {
			ver, _ := v.(map[string]interface{})
			verName, _ := ver["name"].(string)
			schema, _ := ver["schema"].(map[string]interface{})
			root := schema["openAPIV3Schema"]
			require.NotNil(t, root, "CRD %s/%s has no schema", name, verName)
			checked++

			walkSchema(root, name+"/"+verName, func(n schemaNode, path string) {
				if _, hasDesc := n["description"]; !hasDesc {
					return
				}
				if _, hasType := n["type"]; hasType {
					return
				}
				// These are the legitimate ways to describe a node without a
				// concrete type.
				for _, escape := range []string{
					"$ref", "allOf", "anyOf", "oneOf", "not",
					"x-kubernetes-preserve-unknown-fields",
					"x-kubernetes-int-or-string",
				} {
					if _, ok := n[escape]; ok {
						return
					}
				}
				problems = append(problems, path)
			})
		}
	}

	require.NotZero(t, checked, "expected install.yaml to contain CRD schemas")
	require.Empty(t, problems,
		"these schema nodes have a description but no type, and the API server "+
			"will reject the CRD: %v", problems)
}

// The CRDs the manifest ships must be the ones the code defines. A drifted
// manifest installs a schema that rejects the objects the controllers write.
func TestInstallManifestShipsEveryCRD(t *testing.T) {
	want := map[string]bool{
		"pahlevanpolicies.policy.pahlevan.io":  false,
		"containerprofiles.policy.pahlevan.io": false,
		"attacksurfaces.policy.pahlevan.io":    false,
	}
	for _, doc := range loadInstallDocs(t) {
		if doc["kind"] != "CustomResourceDefinition" {
			continue
		}
		meta, _ := doc["metadata"].(map[string]interface{})
		name, _ := meta["name"].(string)
		if _, expected := want[name]; expected {
			want[name] = true
		}
	}
	for name, found := range want {
		require.True(t, found, "install.yaml is missing the %s CRD", name)
	}
}

// Every document needs apiVersion and kind, or kubectl apply rejects the whole
// stream.
func TestInstallManifestDocumentsAreApplyable(t *testing.T) {
	for i, doc := range loadInstallDocs(t) {
		require.NotEmpty(t, doc["apiVersion"], "document %d has no apiVersion", i)
		require.NotEmpty(t, doc["kind"], "document %d has no kind", i)
	}
}
