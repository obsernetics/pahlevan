package v1alpha1

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

// The round-trip tests prove the converter carries what it is asked to carry.
// They cannot prove that the v1beta1 types still describe the same API,
// because a field deleted from both the type and the converter round-trips
// perfectly - it just is not there any more.
//
// This is the test for that. It walks both versions by reflection, compares
// the sets of JSON paths, and requires every difference to be written down.
// The failure it exists to prevent is a field quietly disappearing in the
// graduation and nobody noticing until a user's policy stops doing something.

// jsonPaths returns every JSON path reachable from t, with "[]" marking a
// list. Types from k8s.io are leaves: their shape is not this project's to
// change, and recursing into ObjectMeta would drown the comparison.
func jsonPaths(t reflect.Type) map[string]bool {
	out := map[string]bool{}
	var walk func(t reflect.Type, prefix string, depth int)
	walk = func(t reflect.Type, prefix string, depth int) {
		if depth > 20 {
			panic("jsonPaths: recursion deeper than any of these types go: " + prefix)
		}
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			walk(t.Elem(), prefix+"[]", depth+1)
			return
		}
		if t.Kind() != reflect.Struct || strings.HasPrefix(t.PkgPath(), "k8s.io/") {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue // inlined TypeMeta, and anything deliberately hidden
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out[path] = true
			ft := f.Type
			for ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Map {
				continue // map values are scalars in these types
			}
			walk(f.Type, path, depth+1)
		}
	}
	walk(t, "", 0)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// coveredByDrop reports whether a path is an IntentionallyDropped entry or
// lives underneath one. Dropping a struct drops everything inside it, and
// listing each descendant would turn a six-line list into a forty-line one
// that nobody reads.
func coveredByDrop(path string) bool {
	for dropped := range IntentionallyDropped {
		if path == dropped ||
			strings.HasPrefix(path, dropped+".") ||
			strings.HasPrefix(path, dropped+"[") {
			return true
		}
	}
	return false
}

func TestEveryV1Alpha1FieldIsCarriedOrDocumented(t *testing.T) {
	kinds := []struct {
		name  string
		alpha reflect.Type
		beta  reflect.Type
	}{
		{"PahlevanPolicy", reflect.TypeOf(PahlevanPolicy{}), reflect.TypeOf(v1beta1.PahlevanPolicy{})},
		{"ContainerProfile", reflect.TypeOf(ContainerProfile{}), reflect.TypeOf(v1beta1.ContainerProfile{})},
		{"AttackSurface", reflect.TypeOf(AttackSurface{}), reflect.TypeOf(v1beta1.AttackSurface{})},
	}

	allAlpha := map[string]bool{}
	allBeta := map[string]bool{}

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			alpha := jsonPaths(k.alpha)
			beta := jsonPaths(k.beta)
			require.NotEmpty(t, alpha, "the walker found no fields, so it is broken rather than the API being empty")

			for p := range alpha {
				allAlpha[p] = true
			}
			for p := range beta {
				allBeta[p] = true
			}

			var undocumented []string
			for _, p := range sortedKeys(alpha) {
				if beta[p] || coveredByDrop(p) {
					continue
				}
				undocumented = append(undocumented, p)
			}
			assert.Empty(t, undocumented,
				"these v1alpha1 fields are not in v1beta1 and not in IntentionallyDropped. "+
					"A field that vanishes in a graduation without a written reason is the "+
					"exact thing this test exists to stop: %v", undocumented)

			var unexplained []string
			for _, p := range sortedKeys(beta) {
				if alpha[p] {
					continue
				}
				if _, ok := IntentionallyAdded[p]; ok {
					continue
				}
				unexplained = append(unexplained, p)
			}
			assert.Empty(t, unexplained,
				"these v1beta1 fields have no v1alpha1 counterpart and no entry in "+
					"IntentionallyAdded. A graduation is not the place to add a field "+
					"nothing sets: %v", unexplained)
		})
	}

	// A stale entry is as misleading as a missing one: it claims a loss that
	// is not happening, and the next reader stops trusting the list.
	for path := range IntentionallyDropped {
		assert.True(t, allAlpha[path], "IntentionallyDropped names %q, which is not a v1alpha1 field", path)
		assert.False(t, allBeta[path], "IntentionallyDropped names %q, which v1beta1 does carry", path)
	}
	for path := range IntentionallyAdded {
		assert.True(t, allBeta[path], "IntentionallyAdded names %q, which is not a v1beta1 field", path)
		assert.False(t, allAlpha[path], "IntentionallyAdded names %q, which v1alpha1 already has", path)
	}
}

// Every reason has to say what the field did, because the audience for this
// list is somebody whose policy stopped working and who needs to know whether
// that field was the cause.
func TestDroppedFieldsCarryARealReason(t *testing.T) {
	require.NotEmpty(t, IntentionallyDropped)
	for path, reason := range IntentionallyDropped {
		assert.GreaterOrEqual(t, len(reason), 40, "%s: the reason is too short to be one", path)
		assert.NotContains(t, strings.ToLower(reason), "tidy", "%s: taste is not a reason", path)
	}
}

// The two versions have to describe the same group, or a conversion webhook
// would be converting between unrelated resources.
func TestVersionsShareTheGroup(t *testing.T) {
	assert.Equal(t, GroupVersion.Group, v1beta1.GroupVersion.Group)
	assert.Equal(t, "v1alpha1", GroupVersion.Version)
	assert.Equal(t, "v1beta1", v1beta1.GroupVersion.Version)
}
