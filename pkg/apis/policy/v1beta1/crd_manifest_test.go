package v1beta1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// A multi-version CRD has exactly one storage version. The API server refuses
// a CRD with none and refuses one with two, so getting this wrong is not a
// subtle degradation: `kubectl apply -f install.yaml` fails partway through and
// leaves a cluster with some of the CRDs installed and some not.
//
// It is also the kind of thing that breaks by accident. controller-gen picks
// the storage version from a +kubebuilder:storageversion marker, so adding a
// version and forgetting the marker, or copying a types file and bringing the
// marker with it, both produce a manifest that only a real API server rejects.

const crdDir = "../../../../config/crd"

type crdFile struct {
	path string
	obj  map[string]interface{}
}

func loadCRDs(t *testing.T) []crdFile {
	t.Helper()
	entries, err := os.ReadDir(crdDir)
	require.NoError(t, err, "config/crd must exist: it is what `make manifests` writes and what install.yaml is built from")

	var out []crdFile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(crdDir, e.Name())) // #nosec G304 -- a fixed directory in-tree
		require.NoError(t, err)
		var obj map[string]interface{}
		require.NoError(t, yaml.Unmarshal(data, &obj), "%s must be valid YAML", e.Name())
		if obj["kind"] != "CustomResourceDefinition" {
			continue
		}
		out = append(out, crdFile{path: e.Name(), obj: obj})
	}
	require.Len(t, out, 3, "the project has three CRDs: PahlevanPolicy, ContainerProfile, AttackSurface")
	return out
}

func versionsOf(t *testing.T, c crdFile) []map[string]interface{} {
	t.Helper()
	spec, ok := c.obj["spec"].(map[string]interface{})
	require.True(t, ok, "%s has no spec", c.path)
	raw, ok := spec["versions"].([]interface{})
	require.True(t, ok, "%s has no versions", c.path)
	var out []map[string]interface{}
	for _, v := range raw {
		m, ok := v.(map[string]interface{})
		require.True(t, ok)
		out = append(out, m)
	}
	return out
}

func TestExactlyOneStorageVersionAndItIsV1Beta1(t *testing.T) {
	for _, c := range loadCRDs(t) {
		t.Run(c.path, func(t *testing.T) {
			var storage []string
			for _, v := range versionsOf(t, c) {
				name, _ := v["name"].(string)
				if v["storage"] == true {
					storage = append(storage, name)
				}
			}
			require.Len(t, storage, 1,
				"a CRD must have exactly one version with storage: true; %s has %v", c.path, storage)
			assert.Equal(t, "v1beta1", storage[0],
				"the graduation makes v1beta1 the stored version; %s stores %s", c.path, storage[0])
		})
	}
}

// Both versions stay served for the deprecation window. Un-serving v1alpha1 in
// the same release that introduced v1beta1 would break every existing client
// at upgrade time, which is the thing a deprecation window exists to avoid.
func TestBothVersionsAreServedAndV1Alpha1IsDeprecated(t *testing.T) {
	for _, c := range loadCRDs(t) {
		t.Run(c.path, func(t *testing.T) {
			seen := map[string]map[string]interface{}{}
			for _, v := range versionsOf(t, c) {
				name, _ := v["name"].(string)
				seen[name] = v
			}
			require.Contains(t, seen, "v1alpha1", "%s must keep serving v1alpha1", c.path)
			require.Contains(t, seen, "v1beta1", "%s must serve v1beta1", c.path)

			assert.Equal(t, true, seen["v1alpha1"]["served"], "v1alpha1 must stay served")
			assert.Equal(t, true, seen["v1beta1"]["served"], "v1beta1 must be served")
			assert.Equal(t, false, seen["v1alpha1"]["storage"], "v1alpha1 must no longer be the storage version")

			assert.Equal(t, true, seen["v1alpha1"]["deprecated"],
				"v1alpha1 must be marked deprecated, which is what makes kubectl warn")
			warning, _ := seen["v1alpha1"]["deprecationWarning"].(string)
			assert.Contains(t, warning, "v1beta1",
				"the deprecation warning has to name the version to move to, or it "+
					"tells a user their API is going away and not where it went")
		})
	}
}

// Every version the CRD serves needs a schema. A version entry with no schema
// is accepted by controller-gen and rejected by the API server.
func TestEveryServedVersionHasASchema(t *testing.T) {
	for _, c := range loadCRDs(t) {
		for _, v := range versionsOf(t, c) {
			name, _ := v["name"].(string)
			schema, ok := v["schema"].(map[string]interface{})
			require.True(t, ok, "%s/%s has no schema", c.path, name)
			require.NotNil(t, schema["openAPIV3Schema"], "%s/%s has an empty schema", c.path, name)
		}
	}
}

// install.yaml is what the quickstart tells people to apply, and it is built by
// concatenating config/crd. If it were regenerated from a stale tree it would
// install a single-version CRD, and every v1beta1 object would be rejected with
// "no matches for kind" - an error that points at the client rather than at the
// manifest that caused it.
func TestInstallManifestCarriesBothVersions(t *testing.T) {
	data, err := os.ReadFile("../../../../install.yaml")
	require.NoError(t, err)

	var crds int
	for _, chunk := range strings.Split(string(data), "\n---") {
		var obj map[string]interface{}
		if yaml.Unmarshal([]byte(chunk), &obj) != nil || obj["kind"] != "CustomResourceDefinition" {
			continue
		}
		crds++
		name, _ := obj["metadata"].(map[string]interface{})["name"].(string)
		spec, _ := obj["spec"].(map[string]interface{})
		versions, _ := spec["versions"].([]interface{})

		var storage []string
		served := map[string]bool{}
		for _, v := range versions {
			m, _ := v.(map[string]interface{})
			vn, _ := m["name"].(string)
			if m["served"] == true {
				served[vn] = true
			}
			if m["storage"] == true {
				storage = append(storage, vn)
			}
		}
		assert.True(t, served["v1alpha1"], "%s in install.yaml does not serve v1alpha1", name)
		assert.True(t, served["v1beta1"], "%s in install.yaml does not serve v1beta1", name)
		assert.Equal(t, []string{"v1beta1"}, storage, "%s in install.yaml stores the wrong version", name)
	}
	assert.Equal(t, 3, crds, "install.yaml must carry all three CRDs")
}
