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

// ---------------------------------------------------------------------------
// Declared expected behavior: the half of the validation the API server does
// ---------------------------------------------------------------------------

// A kubebuilder marker is a comment until controller-gen turns it into schema,
// and a marker that does not reach the CRD fails silently in the direction that
// matters: the API server accepts the object, translation refuses the entry,
// and the operator's declaration does nothing.
//
// These are declarations rather than ordinary rules, which makes it worse than
// usual. The whole point of the field is to cover an operation nobody has ever
// observed, so a declaration that was accepted and quietly dropped is not
// discovered by testing - it is discovered when the nightly job is denied.
// Rejecting the object at apply time is the only feedback loop that closes
// before that.

// schemaAt walks the named version's schema to a dotted path, where a segment
// is a property name, "items" descends into an array's element schema, and the
// leaf is returned as it appears in the manifest.
func schemaAt(t *testing.T, c crdFile, version, path string) map[string]interface{} {
	t.Helper()
	var node map[string]interface{}
	for _, v := range versionsOf(t, c) {
		if v["name"] == version {
			schema, _ := v["schema"].(map[string]interface{})
			node, _ = schema["openAPIV3Schema"].(map[string]interface{})
		}
	}
	require.NotNil(t, node, "%s has no %s schema", c.path, version)

	for _, seg := range strings.Split(path, ".") {
		if seg == "items" {
			next, ok := node["items"].(map[string]interface{})
			require.True(t, ok, "%s: no items under %s", c.path, path)
			node = next
			continue
		}
		props, ok := node["properties"].(map[string]interface{})
		require.True(t, ok, "%s: no properties while walking to %s", c.path, path)
		next, ok := props[seg].(map[string]interface{})
		require.True(t, ok, "%s: %s is not in the schema at %s", c.path, seg, path)
		node = next
	}
	return node
}

func policyCRD(t *testing.T) crdFile {
	t.Helper()
	for _, c := range loadCRDs(t) {
		if strings.Contains(c.path, "pahlevanpolicies") {
			return c
		}
	}
	t.Fatal("the PahlevanPolicy CRD is missing from config/crd")
	return crdFile{}
}

func TestDeclaredBehaviorValidationReachesTheSchema(t *testing.T) {
	c := policyCRD(t)
	const root = "spec.learningConfig.expectedBehavior"

	t.Run("an empty declaration is rejected", func(t *testing.T) {
		// `expectedBehavior: {}` is almost always a half-written block, and
		// accepting it lets an operator believe a rare operation is covered
		// when nothing was written down at all.
		assert.EqualValues(t, 1, schemaAt(t, c, "v1beta1", root)["minProperties"])
	})

	t.Run("a path must be absolute and non-empty", func(t *testing.T) {
		// Enforcement keys on the path the kernel resolves, so a relative path
		// can never match anything.
		path := schemaAt(t, c, "v1beta1", root+".files.items.path")
		assert.Equal(t, "^/", path["pattern"])
		assert.EqualValues(t, 1, path["minLength"])

		// And a file entry without a path declares nothing at all.
		items := schemaAt(t, c, "v1beta1", root+".files.items")
		assert.Contains(t, items["required"], "path")
	})

	t.Run("an executable must be absolute and non-empty", func(t *testing.T) {
		execs := schemaAt(t, c, "v1beta1", root+".executables.items")
		assert.Equal(t, "^/", execs["pattern"])
		assert.EqualValues(t, 1, execs["minLength"])
	})

	t.Run("a port is bounded to the port space", func(t *testing.T) {
		// A port is 16 bits on the wire and this field is an int32, so without
		// bounds 70000 would be accepted and truncated into port 4464 - a rule
		// that looks applied and permits something nobody asked for.
		port := schemaAt(t, c, "v1beta1", root+".networkDestinations.items.port")
		assert.EqualValues(t, 1, port["minimum"])
		assert.EqualValues(t, 65535, port["maximum"])
	})

	t.Run("a destination needs both an address and a port", func(t *testing.T) {
		items := schemaAt(t, c, "v1beta1", root+".networkDestinations.items")
		assert.Contains(t, items["required"], "cidr")
		assert.Contains(t, items["required"], "port")
		assert.EqualValues(t, 1,
			schemaAt(t, c, "v1beta1", root+".networkDestinations.items.cidr")["minLength"])
	})

	t.Run("a protocol is one of two values, listed once", func(t *testing.T) {
		proto := schemaAt(t, c, "v1beta1", root+".networkDestinations.items.protocol")
		assert.Equal(t, []interface{}{"TCP", "UDP"}, proto["enum"])
		// Not inside an allOf: an enum repeated on both the field and its named
		// type validates identically and reads as a generator bug.
		assert.NotContains(t, proto, "allOf")
	})
}

// The field exists in one version only, and that has to be visible in the
// manifest rather than only in the Go types. A v1alpha1 policy carrying an
// expectedBehavior block is not rejected by the API server - unknown fields in
// a custom resource are pruned, not refused - so it applies cleanly, reports no
// error, and declares nothing.
func TestDeclaredBehaviorIsNotServedOnV1Alpha1(t *testing.T) {
	c := policyCRD(t)
	learning := schemaAt(t, c, "v1alpha1", "spec.learningConfig")
	props, ok := learning["properties"].(map[string]interface{})
	require.True(t, ok)
	assert.NotContains(t, props, "expectedBehavior",
		"v1alpha1 must not advertise a field its conversion cannot carry")

	profile := crdFile{}
	for _, f := range loadCRDs(t) {
		if strings.Contains(f.path, "containerprofiles") {
			profile = f
		}
	}
	require.NotEmpty(t, profile.path)
	for version, wantDeclared := range map[string]bool{"v1alpha1": false, "v1beta1": true} {
		status := schemaAt(t, profile, version, "status")
		statusProps, ok := status["properties"].(map[string]interface{})
		require.True(t, ok)
		for _, field := range []string{
			"declaredFiles", "declaredNetworkDestinations",
			"declaredExecutables", "declaredCapabilities",
		} {
			if wantDeclared {
				assert.Contains(t, statusProps, field, "%s must report %s", version, field)
				continue
			}
			assert.NotContains(t, statusProps, field,
				"%s must not advertise %s: it has nowhere to carry it", version, field)
		}
	}
}
