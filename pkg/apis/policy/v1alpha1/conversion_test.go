package v1alpha1

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	v1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

// A conversion that silently drops a field is the failure that makes an API
// graduation dangerous: the object applies, the controller reconciles, and the
// thing the user asked for is simply not there. Nothing in a build catches it,
// because a missing assignment in a converter compiles.
//
// So these tests do not spot-check a handful of fields. They fill every field
// in the v1alpha1 types with a value derived from its own path, convert to the
// hub and back, and compare with reflect.DeepEqual. A converter that forgets a
// field fails with the path of the field it forgot.

// ---------------------------------------------------------------------------
// Exhaustive filling
// ---------------------------------------------------------------------------

// filler builds fully-populated values by reflection.
//
// With a nil rng it is exhaustive and deterministic: every pointer is
// allocated, every slice and map gets entries, and every scalar gets a
// non-zero value. That is the mode the round-trip tests use, because "every
// field is set" is what makes a dropped field visible.
//
// With an rng it produces varied shapes - nil pointers, nil slices, empty
// slices - which is what the fuzz target needs, because nil and empty are
// different objects to the API server and a converter can confuse them.
type filler struct {
	rng *rand.Rand
	n   int
}

var (
	timeType         = reflect.TypeOf(metav1.Time{})
	durationType     = reflect.TypeOf(metav1.Duration{})
	objectMetaType   = reflect.TypeOf(metav1.ObjectMeta{})
	rawExtensionType = reflect.TypeOf(runtime.RawExtension{})
)

func (f *filler) next() int {
	f.n++
	return f.n
}

func (f *filler) chance(pct int) bool {
	if f.rng == nil {
		return true
	}
	return f.rng.Intn(100) < pct
}

func (f *filler) count() int {
	if f.rng == nil {
		return 2
	}
	return f.rng.Intn(3)
}

// fill populates v. path is used to derive string values so that a mismatch in
// a DeepEqual diff names the field that moved.
func (f *filler) fill(v reflect.Value, path string) {
	switch v.Type() {
	case timeType:
		// Seconds resolution, and no monotonic reading: metav1.Time serializes
		// as RFC3339 and a converter is allowed to round-trip through that.
		v.Set(reflect.ValueOf(metav1.NewTime(time.Unix(int64(1700000000+f.next()), 0).UTC())))
		return
	case durationType:
		v.Set(reflect.ValueOf(metav1.Duration{Duration: time.Duration(f.next()) * time.Second}))
		return
	case rawExtensionType:
		// Raw and Object are both json:"-"; RawExtension carries its own
		// marshalling. Object holds a decoded runtime.Object, which no
		// generated or hand-written converter can construct without a scheme,
		// so it stays nil and Raw carries the payload.
		v.Set(reflect.ValueOf(runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{%q:%d}`, path, f.next()))}))
		return
	case objectMetaType:
		v.Set(reflect.ValueOf(metav1.ObjectMeta{
			Name:        "policy-" + fmt.Sprint(f.next()),
			Namespace:   "team-" + fmt.Sprint(f.next()),
			UID:         "1a2b3c",
			Generation:  int64(f.next()),
			Labels:      map[string]string{"app": "checkout"},
			Annotations: map[string]string{"pahlevan.io/note": path},
			Finalizers:  []string{"pahlevan.io/finalizer"},
		}))
		return
	}

	switch v.Kind() {
	case reflect.Ptr:
		if !f.chance(75) {
			v.Set(reflect.Zero(v.Type()))
			return
		}
		v.Set(reflect.New(v.Type().Elem()))
		f.fill(v.Elem(), path)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			sf := v.Type().Field(i)
			if sf.PkgPath != "" { // unexported
				continue
			}
			f.fill(v.Field(i), path+"."+sf.Name)
		}
	case reflect.Slice:
		n := f.count()
		if f.rng != nil && n == 0 && f.chance(50) {
			v.Set(reflect.Zero(v.Type())) // nil, not empty
			return
		}
		s := reflect.MakeSlice(v.Type(), n, n)
		for i := 0; i < n; i++ {
			f.fill(s.Index(i), fmt.Sprintf("%s[%d]", path, i))
		}
		v.Set(s)
	case reflect.Map:
		n := f.count()
		if f.rng != nil && n == 0 && f.chance(50) {
			v.Set(reflect.Zero(v.Type()))
			return
		}
		m := reflect.MakeMap(v.Type())
		for i := 0; i < n; i++ {
			k := reflect.New(v.Type().Key()).Elem()
			f.fill(k, fmt.Sprintf("%s.key%d", path, i))
			val := reflect.New(v.Type().Elem()).Elem()
			f.fill(val, fmt.Sprintf("%s.val%d", path, i))
			m.SetMapIndex(k, val)
		}
		v.Set(m)
	case reflect.String:
		v.SetString(fmt.Sprintf("%s#%d", path, f.next()))
	case reflect.Bool:
		v.SetBool(f.chance(50))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(f.next()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(f.next()))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(f.next()))
	default:
		// Interfaces and funcs. Nothing in these API types has one, and a new
		// one would need a decision here rather than a silent zero.
		panic("filler: unsupported kind " + v.Kind().String() + " at " + path)
	}
}

func filledPolicy(rng *rand.Rand) *PahlevanPolicy {
	p := &PahlevanPolicy{}
	(&filler{rng: rng}).fill(reflect.ValueOf(p).Elem(), "PahlevanPolicy")
	p.TypeMeta = metav1.TypeMeta{}
	return p
}

func filledProfile(rng *rand.Rand) *ContainerProfile {
	p := &ContainerProfile{}
	(&filler{rng: rng}).fill(reflect.ValueOf(p).Elem(), "ContainerProfile")
	p.TypeMeta = metav1.TypeMeta{}
	return p
}

func filledSurface(rng *rand.Rand) *AttackSurface {
	s := &AttackSurface{}
	(&filler{rng: rng}).fill(reflect.ValueOf(s).Elem(), "AttackSurface")
	s.TypeMeta = metav1.TypeMeta{}
	return s
}

// The filler must actually fill. If it silently skipped a branch, every
// round-trip test below would pass against a mostly-empty object and prove
// nothing, which is the failure mode of a test that fills by hand.
func TestFillerLeavesNothingZero(t *testing.T) {
	p := filledPolicy(nil)
	var zeros []string
	var walk func(v reflect.Value, path string)
	walk = func(v reflect.Value, path string) {
		switch v.Type() {
		case timeType, durationType, rawExtensionType, objectMetaType:
			assert.False(t, v.IsZero(), "%s is zero", path)
			return
		}
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				zeros = append(zeros, path)
				return
			}
			walk(v.Elem(), path)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).PkgPath != "" {
					continue
				}
				walk(v.Field(i), path+"."+v.Type().Field(i).Name)
			}
		case reflect.Slice, reflect.Map:
			if v.Len() == 0 {
				zeros = append(zeros, path)
				return
			}
			if v.Kind() == reflect.Slice {
				walk(v.Index(0), path+"[0]")
			}
		case reflect.Bool:
			// Deliberately allowed to be false.
		default:
			if v.IsZero() {
				zeros = append(zeros, path)
			}
		}
	}
	walk(reflect.ValueOf(p).Elem().FieldByName("Spec"), "spec")
	walk(reflect.ValueOf(p).Elem().FieldByName("Status"), "status")
	require.Empty(t, zeros, "the filler left these unset, so the round-trip tests would not cover them: %v", zeros)
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

// normalizeDropped applies, by hand, exactly what IntentionallyDropped says
// happens to a v1alpha1 object that goes through v1beta1 and back. Everything
// else must survive untouched, and the tests below compare against this rather
// than against a hand-maintained list of fields to ignore, so a converter that
// drops anything not listed here fails.
func normalizeDropped(p *PahlevanPolicy) {
	// status.enforcementStatus.blockedSyscalls: always zero in practice, and
	// v1beta1 does not carry it.
	if p.Status.EnforcementStatus != nil {
		p.Status.EnforcementStatus.BlockedSyscalls = 0
	}
	// spec.enforcementConfig.exceptions[].temporary: derived from expiresAt.
	for i := range p.Spec.EnforcementConfig.Exceptions {
		ex := &p.Spec.EnforcementConfig.Exceptions[i]
		ex.Temporary = ex.ExpiresAt != nil
	}
	// spec.networkPolicy.{egress,ingress}Rules[].peers[].{namespaceSelector,
	// podSelector}.namespaceSelector: a namespace selector in a position where
	// nothing reads one.
	if np := p.Spec.NetworkPolicy; np != nil {
		for _, rules := range [][]NetworkRule{np.EgressRules, np.IngressRules} {
			for i := range rules {
				for j := range rules[i].Peers {
					peer := &rules[i].Peers[j]
					if peer.NamespaceSelector != nil {
						peer.NamespaceSelector.NamespaceSelector = nil
					}
					if peer.PodSelector != nil {
						peer.PodSelector.NamespaceSelector = nil
					}
				}
			}
		}
	}
}

func roundTripPolicy(t testing.TB, src *PahlevanPolicy) *PahlevanPolicy {
	t.Helper()
	var hub v1beta1.PahlevanPolicy
	require.NoError(t, src.ConvertTo(&hub))
	var back PahlevanPolicy
	require.NoError(t, back.ConvertFrom(&hub))
	return &back
}

func TestPahlevanPolicyRoundTripsEveryField(t *testing.T) {
	src := filledPolicy(nil)
	back := roundTripPolicy(t, src)

	want := src.DeepCopy()
	normalizeDropped(want)

	require.Equal(t, want, back,
		"a field did not survive v1alpha1 -> v1beta1 -> v1alpha1. Every string "+
			"value is its own field path, so the diff names it. If the loss is "+
			"deliberate, it belongs in IntentionallyDropped and in normalizeDropped.")
	require.True(t, reflect.DeepEqual(want, back))
}

func TestContainerProfileRoundTripsEveryField(t *testing.T) {
	src := filledProfile(nil)
	var hub v1beta1.ContainerProfile
	require.NoError(t, src.ConvertTo(&hub))
	var back ContainerProfile
	require.NoError(t, back.ConvertFrom(&hub))

	require.Equal(t, src, &back, "ContainerProfile loses nothing in either direction")
	require.True(t, reflect.DeepEqual(src, &back))
}

func TestAttackSurfaceRoundTripsEveryField(t *testing.T) {
	src := filledSurface(nil)
	var hub v1beta1.AttackSurface
	require.NoError(t, src.ConvertTo(&hub))
	var back AttackSurface
	require.NoError(t, back.ConvertFrom(&hub))

	require.Equal(t, src, &back, "AttackSurface loses nothing in either direction")
	require.True(t, reflect.DeepEqual(src, &back))
}

// The hub is the storage version, so the direction that matters for stored
// objects is v1beta1 -> v1alpha1 -> v1beta1. It is lossless for the two kinds
// with no dropped fields, and for PahlevanPolicy it loses only what a v1beta1
// object cannot express in v1alpha1 - which, given v1beta1 adds no fields, is
// nothing.
func TestHubRoundTripsThroughTheSpoke(t *testing.T) {
	src := filledPolicy(nil)
	var hub v1beta1.PahlevanPolicy
	require.NoError(t, src.ConvertTo(&hub))

	var spoke PahlevanPolicy
	require.NoError(t, spoke.ConvertFrom(&hub))
	var again v1beta1.PahlevanPolicy
	require.NoError(t, spoke.ConvertTo(&again))

	require.Equal(t, hub, again,
		"a stored v1beta1 object changed by being read as v1alpha1 and written back")
}

// Randomized shapes: nil pointers, nil slices and empty slices, which are
// three different things in a Kubernetes object and which a converter that
// reallocates unconditionally would flatten into one.
func TestRoundTripWithRandomShapes(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- test shape generation
		src := filledPolicy(rng)
		back := roundTripPolicy(t, src)
		want := src.DeepCopy()
		normalizeDropped(want)
		if !reflect.DeepEqual(want, back) {
			t.Fatalf("seed %d did not round-trip:\nwant %#v\ngot  %#v", seed, want, back)
		}
	}
}

// go test -fuzz=FuzzPolicyRoundTrip ./pkg/apis/policy/v1alpha1
func FuzzPolicyRoundTrip(f *testing.F) {
	for _, seed := range []int64{0, 1, 7, 1 << 20, -3} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- fuzz shape generation
		src := filledPolicy(rng)
		back := roundTripPolicy(t, src)
		want := src.DeepCopy()
		normalizeDropped(want)
		if !reflect.DeepEqual(want, back) {
			t.Fatalf("seed %d did not round-trip", seed)
		}
	})
}

// ---------------------------------------------------------------------------
// The dropped list is exactly the set of fields that are dropped
// ---------------------------------------------------------------------------

// A list of known losses is only worth having if it is neither short nor
// padded. Short means a field is being dropped with no explanation, which is
// the dangerous case. Padded means a field is listed as lost when it is not,
// which teaches readers to ignore the list.
//
// Each case here sets exactly one of the listed fields on an otherwise empty
// policy and asserts the round trip changes it. Together with
// TestPahlevanPolicyRoundTripsEveryField, which asserts nothing else changes,
// the two bracket the list from both sides.
func TestEveryDroppedFieldIsActuallyDropped(t *testing.T) {
	// Egress and ingress get their own cases rather than one object carrying
	// both, so a converter that handled only one of the two rule lists fails
	// the case for the list it missed instead of hiding behind the other.
	peerPolicy := func(egress bool, set func(*NetworkPeer)) *PahlevanPolicy {
		peer := NetworkPeer{}
		set(&peer)
		rules := []NetworkRule{{Peers: []NetworkPeer{peer}}}
		np := &NetworkPolicy{}
		if egress {
			np.EgressRules = rules
		} else {
			np.IngressRules = rules
		}
		return &PahlevanPolicy{Spec: PahlevanPolicySpec{NetworkPolicy: np}}
	}
	nested := func() *LabelSelector {
		return &LabelSelector{NamespaceSelector: &NamespaceSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "prod"},
		}}
	}

	cases := []struct {
		path string
		obj  *PahlevanPolicy
	}{
		{
			path: "spec.enforcementConfig.exceptions[].temporary",
			obj: &PahlevanPolicy{Spec: PahlevanPolicySpec{EnforcementConfig: EnforcementConfig{
				// Temporary with no expiry: the combination that never expired.
				Exceptions: []EnforcementException{{Type: ExceptionTypeFile, Temporary: true}},
			}}},
		},
		{
			path: "spec.networkPolicy.egressRules[].peers[].namespaceSelector.namespaceSelector",
			obj:  peerPolicy(true, func(p *NetworkPeer) { p.NamespaceSelector = nested() }),
		},
		{
			path: "spec.networkPolicy.egressRules[].peers[].podSelector.namespaceSelector",
			obj:  peerPolicy(true, func(p *NetworkPeer) { p.PodSelector = nested() }),
		},
		{
			path: "spec.networkPolicy.ingressRules[].peers[].namespaceSelector.namespaceSelector",
			obj:  peerPolicy(false, func(p *NetworkPeer) { p.NamespaceSelector = nested() }),
		},
		{
			path: "spec.networkPolicy.ingressRules[].peers[].podSelector.namespaceSelector",
			obj:  peerPolicy(false, func(p *NetworkPeer) { p.PodSelector = nested() }),
		},
		{
			path: "status.enforcementStatus.blockedSyscalls",
			obj: &PahlevanPolicy{Status: PahlevanPolicyStatus{
				EnforcementStatus: &EnforcementStatus{BlockedSyscalls: 12},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			reason, listed := IntentionallyDropped[tc.path]
			require.True(t, listed, "%s is dropped but not documented", tc.path)
			require.GreaterOrEqual(t, len(reason), 40,
				"the reason for dropping %s has to say what the field did", tc.path)

			back := roundTripPolicy(t, tc.obj)
			assert.False(t, reflect.DeepEqual(tc.obj, back),
				"%s is documented as dropped but survived the round trip, so the "+
					"entry in IntentionallyDropped is stale", tc.path)
		})
	}

	require.Len(t, IntentionallyDropped, len(cases),
		"every entry in IntentionallyDropped needs a case here proving it is real")
}

// ---------------------------------------------------------------------------
// Behaviour that is deliberately not a straight copy
// ---------------------------------------------------------------------------

func TestTemporaryIsDerivedFromExpiry(t *testing.T) {
	expiry := metav1.NewTime(time.Unix(1700000000, 0).UTC())
	cases := []struct {
		name          string
		in            EnforcementException
		wantTemporary bool
	}{
		{"expiry present, flag set", EnforcementException{Temporary: true, ExpiresAt: &expiry}, true},
		{
			// The v1alpha1 bug: enforcement applied an expiry only when
			// temporary was also true, so this exception never lapsed. After
			// the round trip it is temporary, which is what the author wrote
			// down and what v1beta1 acts on.
			"expiry present, flag unset", EnforcementException{ExpiresAt: &expiry}, true,
		},
		{"no expiry, flag set", EnforcementException{Temporary: true}, false},
		{"no expiry, no flag", EnforcementException{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &PahlevanPolicy{Spec: PahlevanPolicySpec{
				EnforcementConfig: EnforcementConfig{Exceptions: []EnforcementException{tc.in}},
			}}
			back := roundTripPolicy(t, src)
			assert.Equal(t, tc.wantTemporary, back.Spec.EnforcementConfig.Exceptions[0].Temporary)
			assert.Equal(t, tc.in.ExpiresAt, back.Spec.EnforcementConfig.Exceptions[0].ExpiresAt)
		})
	}
}

// nil and empty are different objects on the wire: nil is omitted and empty
// serializes as []. A converter that rebuilt every slice unconditionally would
// turn a nil into an empty one and make every reconcile a write.
func TestNilAndEmptyAreNotInterchanged(t *testing.T) {
	src := &PahlevanPolicy{Spec: PahlevanPolicySpec{
		Selector:      LabelSelector{MatchLabels: map[string]string{}},
		SyscallPolicy: &SyscallPolicy{AllowedSyscalls: []string{}, DeniedSyscalls: nil},
	}}
	back := roundTripPolicy(t, src)

	require.NotNil(t, back.Spec.Selector.MatchLabels)
	assert.Empty(t, back.Spec.Selector.MatchLabels)
	require.NotNil(t, back.Spec.SyscallPolicy.AllowedSyscalls)
	assert.Empty(t, back.Spec.SyscallPolicy.AllowedSyscalls)
	assert.Nil(t, back.Spec.SyscallPolicy.DeniedSyscalls)
}

// The converted object must not share memory with its source. Aliasing here
// would mean a controller mutating the converted copy also mutated the object
// in the informer cache, which is the kind of bug that shows up as a
// resourceVersion conflict on an unrelated line.
func TestConversionDoesNotAlias(t *testing.T) {
	src := filledPolicy(nil)
	var hub v1beta1.PahlevanPolicy
	require.NoError(t, src.ConvertTo(&hub))

	before := *src.Spec.LearningConfig.MinSamples
	*hub.Spec.LearningConfig.MinSamples = before + 1
	hub.Spec.Selector.MatchLabels["injected"] = "yes"
	hub.Spec.SyscallPolicy.AllowedSyscalls[0] = "mutated"

	assert.Equal(t, before, *src.Spec.LearningConfig.MinSamples)
	assert.NotContains(t, src.Spec.Selector.MatchLabels, "injected")
	assert.NotEqual(t, "mutated", src.Spec.SyscallPolicy.AllowedSyscalls[0])
}

func TestEmptyObjectsConvertWithoutAllocatingSubstructures(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"policy", func(t *testing.T) {
			back := roundTripPolicy(t, &PahlevanPolicy{})
			assert.Equal(t, &PahlevanPolicy{}, back)
		}},
		{"profile", func(t *testing.T) {
			var hub v1beta1.ContainerProfile
			require.NoError(t, (&ContainerProfile{}).ConvertTo(&hub))
			var back ContainerProfile
			require.NoError(t, back.ConvertFrom(&hub))
			assert.Equal(t, ContainerProfile{}, back)
		}},
		{"surface", func(t *testing.T) {
			var hub v1beta1.AttackSurface
			require.NoError(t, (&AttackSurface{}).ConvertTo(&hub))
			var back AttackSurface
			require.NoError(t, back.ConvertFrom(&hub))
			assert.Equal(t, AttackSurface{}, back)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
//
// Conversion runs on every read and every write of a non-storage version once
// a conversion webhook is serving, so its cost is per-request rather than
// per-reconcile. ReportAllocs because the allocation count is what a converter
// regresses on first.
// ---------------------------------------------------------------------------

func BenchmarkConvertPolicyToHub(b *testing.B) {
	src := filledPolicy(nil)
	dst := &v1beta1.PahlevanPolicy{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := src.ConvertTo(dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConvertPolicyFromHub(b *testing.B) {
	src := filledPolicy(nil)
	hub := &v1beta1.PahlevanPolicy{}
	if err := src.ConvertTo(hub); err != nil {
		b.Fatal(err)
	}
	dst := &PahlevanPolicy{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := dst.ConvertFrom(hub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConvertProfileToHub(b *testing.B) {
	src := filledProfile(nil)
	dst := &v1beta1.ContainerProfile{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := src.ConvertTo(dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConvertProfileFromHub(b *testing.B) {
	src := filledProfile(nil)
	hub := &v1beta1.ContainerProfile{}
	if err := src.ConvertTo(hub); err != nil {
		b.Fatal(err)
	}
	dst := &ContainerProfile{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := dst.ConvertFrom(hub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConvertAttackSurfaceToHub(b *testing.B) {
	src := filledSurface(nil)
	dst := &v1beta1.AttackSurface{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := src.ConvertTo(dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConvertAttackSurfaceFromHub(b *testing.B) {
	src := filledSurface(nil)
	hub := &v1beta1.AttackSurface{}
	if err := src.ConvertTo(hub); err != nil {
		b.Fatal(err)
	}
	dst := &AttackSurface{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := dst.ConvertFrom(hub); err != nil {
			b.Fatal(err)
		}
	}
}

// A round trip is what a client that reads v1alpha1 and writes it back pays.
func BenchmarkPolicyRoundTrip(b *testing.B) {
	src := filledPolicy(nil)
	hub := &v1beta1.PahlevanPolicy{}
	dst := &PahlevanPolicy{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := src.ConvertTo(hub); err != nil {
			b.Fatal(err)
		}
		if err := dst.ConvertFrom(hub); err != nil {
			b.Fatal(err)
		}
	}
}
