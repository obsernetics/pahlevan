package clusterdata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	return s
}

func fakeClient(t *testing.T, objs ...client.Object) client.WithWatch {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
}

// countingClient counts List calls so a cache test can assert the client was
// not touched, rather than inferring it from timing.
type countingClient struct {
	client.WithWatch
	lists atomic.Int64
}

func newCountingClient(inner client.WithWatch, cc *countingClient) client.WithWatch {
	return interceptor.NewClient(inner, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			cc.lists.Add(1)
			return c.List(ctx, list, opts...)
		},
	})
}

// failingListClient fails every List with err, which is how a transient API
// blip looks to this package.
func failingListClient(inner client.WithWatch, err error) client.WithWatch {
	return interceptor.NewClient(inner, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			return err
		},
	})
}

func ptrInt32(v int32) *int32 { return &v }
func ptrBool(v bool) *bool    { return &v }

var testNow = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

func fixedClock() Option { return WithClock(func() time.Time { return testNow }) }

func created(ago time.Duration) metav1.Time {
	return metav1.NewTime(testNow.Add(-ago))
}

func newReader(t *testing.T, c client.Client, opts ...Option) *Reader {
	t.Helper()
	r, err := New(c, append([]Option{fixedClock()}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// policy mapping
// ---------------------------------------------------------------------------

func fullPolicy() *policyv1beta1.PahlevanPolicy {
	return &policyv1beta1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "web",
			Namespace:         "prod",
			CreationTimestamp: created(3 * time.Hour),
		},
		Spec: policyv1beta1.PahlevanPolicySpec{
			Selector: policyv1beta1.WorkloadSelector{
				MatchLabels: map[string]string{"app": "web", "tier": "front"},
				MatchExpressions: []policyv1beta1.LabelSelectorRequirement{
					{Key: "env", Operator: policyv1beta1.LabelSelectorOpIn, Values: []string{"prod", "stage"}},
				},
			},
			EnforcementConfig: policyv1beta1.EnforcementConfig{
				Mode: policyv1beta1.EnforcementModeBlocking,
			},
		},
		Status: policyv1beta1.PahlevanPolicyStatus{
			Phase: policyv1beta1.PolicyPhaseEnforcing,
			LearningStatus: &policyv1beta1.LearningStatus{
				SamplesCollected: 4211,
				Progress:         ptrInt32(100),
			},
			EnforcementStatus: &policyv1beta1.EnforcementStatus{
				BlockedFileAccess:         3,
				BlockedNetworkConnections: 4,
				BlockedExecs:              1,
				BlockedCapabilities:       2,
				BlockedTotal:              10,
				EnforcingContainers:       7,
				TotalContainers:           9,
			},
		},
	}
}

// barePolicy is what the API server holds one second after kubectl apply: a
// spec and nothing else.
func barePolicy() *policyv1beta1.PahlevanPolicy {
	return &policyv1beta1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh", Namespace: "prod"},
	}
}

func TestAPolicyWithAFullStatusMapsEveryFieldTheConsoleShows(t *testing.T) {
	r := newReader(t, fakeClient(t, fullPolicy()))

	got, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 policy, got %d", len(got))
	}
	p := got[0]

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"Namespace", p.Namespace, "prod"},
		{"Name", p.Name, "web"},
		{"Phase", p.Phase, "Enforcing"},
		{"Enforcement", p.Enforcement, "Blocking"},
		{"Selector", p.Selector, "app=web,tier=front,env in (prod,stage)"},
		{"LearningProgress", p.LearningProgress, 100},
		{"HasLearningProgress", p.HasLearningProgress, true},
		{"SamplesCollected", p.SamplesCollected, int64(4211)},
		{"ContainersEnforcing", p.ContainersEnforcing, 7},
		{"ContainersTotal", p.ContainersTotal, 9},
		{"Denials", p.Denials, int64(10)},
		{"Age", p.Age, 3 * time.Hour},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

func TestAPolicyWithNoStatusAtAllStillProducesARow(t *testing.T) {
	r := newReader(t, fakeClient(t, barePolicy()))

	got, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 policy, got %d", len(got))
	}
	p := got[0]

	if p.Phase != unknown {
		t.Errorf("Phase = %q, want %q", p.Phase, unknown)
	}
	if p.Enforcement != unknown {
		t.Errorf("Enforcement = %q, want %q", p.Enforcement, unknown)
	}
	if p.Selector != "<all pods>" {
		t.Errorf("Selector = %q, want %q", p.Selector, "<all pods>")
	}
	if p.HasLearningProgress {
		t.Error("HasLearningProgress is true for a policy that reports no progress; a missing progress must not render as 0%")
	}
	if p.SamplesCollected != 0 || p.Denials != 0 || p.ContainersTotal != 0 {
		t.Errorf("counts from a nil status are not zero: %+v", p)
	}
	if p.Age != 0 {
		t.Errorf("Age = %v for an object with no creation timestamp, want 0", p.Age)
	}
}

func TestPolicyEnforcementLabelSaysWhatIsActuallyEnforced(t *testing.T) {
	cases := []struct {
		name string
		cfg  policyv1beta1.EnforcementConfig
		want string
	}{
		{
			name: "a blocking policy reads as blocking",
			cfg:  policyv1beta1.EnforcementConfig{Mode: policyv1beta1.EnforcementModeBlocking},
			want: "Blocking",
		},
		{
			name: "alert-only says so, because nothing is being blocked",
			cfg:  policyv1beta1.EnforcementConfig{Mode: policyv1beta1.EnforcementModeBlocking, AlertOnly: true},
			want: "Blocking (alert only)",
		},
		{
			name: "blockUnknown=false says so, because it downgrades the policy",
			cfg:  policyv1beta1.EnforcementConfig{Mode: policyv1beta1.EnforcementModeBlocking, BlockUnknown: ptrBool(false)},
			want: "Blocking (unknown allowed)",
		},
		{
			name: "blockUnknown=true is the default and adds nothing",
			cfg:  policyv1beta1.EnforcementConfig{Mode: policyv1beta1.EnforcementModeBlocking, BlockUnknown: ptrBool(true)},
			want: "Blocking",
		},
		{
			name: "an unset mode is reported as unknown rather than guessed",
			cfg:  policyv1beta1.EnforcementConfig{},
			want: unknown,
		},
		{
			name: "an off policy reads as off",
			cfg:  policyv1beta1.EnforcementConfig{Mode: policyv1beta1.EnforcementModeOff},
			want: "Off",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := enforcementLabel(tc.cfg); got != tc.want {
				t.Errorf("enforcementLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAPolicyDenialCountIsNeverLessThanItsBreakdown(t *testing.T) {
	// An older agent writes the per-signal counters without the total. Showing
	// the zero total next to four blocked connections reads as a broken console.
	es := &policyv1beta1.EnforcementStatus{
		BlockedNetworkConnections: 4,
		BlockedFileAccess:         3,
	}
	if got := denialTotal(es); got != 7 {
		t.Errorf("denialTotal = %d, want 7", got)
	}
	es.BlockedTotal = 20
	if got := denialTotal(es); got != 20 {
		t.Errorf("denialTotal = %d, want 20 when the reported total is larger", got)
	}
}

func TestAnOutOfRangePercentageIsClampedSoAProgressBarCannotOverrunItsRow(t *testing.T) {
	pol := barePolicy()
	pol.Status.LearningStatus = &policyv1beta1.LearningStatus{Progress: ptrInt32(413)}
	r := newReader(t, fakeClient(t, pol))

	got, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if got[0].LearningProgress != 100 {
		t.Errorf("LearningProgress = %d, want 100", got[0].LearningProgress)
	}
}

func TestAFutureCreationTimestampDoesNotProduceANegativeAge(t *testing.T) {
	pol := barePolicy()
	pol.CreationTimestamp = metav1.NewTime(testNow.Add(time.Hour))
	r := newReader(t, fakeClient(t, pol))

	got, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if got[0].Age != 0 {
		t.Errorf("Age = %v for a clock-skewed object, want 0", got[0].Age)
	}
}

// ---------------------------------------------------------------------------
// profile mapping
// ---------------------------------------------------------------------------

func fullProfile() *policyv1beta1.ContainerProfile {
	return &policyv1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pod-abc-3c1a9b2f4e5d",
			Namespace:         "prod",
			CreationTimestamp: created(90 * time.Minute),
		},
		Spec: policyv1beta1.ContainerProfileSpec{
			PodName:     "web-7f8d9",
			ContainerID: "containerd://3c1a9b2f4e5d6789aaaa",
			Node:        "node-1",
			PolicyRef:   "web",
		},
		Status: policyv1beta1.ContainerProfileStatus{
			Phase:                       policyv1beta1.ProfilePhaseEnforcing,
			LearnedFiles:                []string{"/etc/passwd", "/app/config"},
			LearnedNetworkDestinations:  []string{"10.0.0.1:443"},
			LearnedSyscalls:             []int64{0, 1, 2, 3},
			LearnedCapabilities:         []string{"NET_BIND_SERVICE"},
			DeclaredFiles:               []string{"/var/backups/nightly (write)"},
			DeclaredNetworkDestinations: []string{"10.0.0.9:5432"},
			DeclaredExecutables:         []string{"/usr/bin/logrotate"},
			DeclaredCapabilities:        []string{"CHOWN"},
			FileCount:                   2,
			NetworkCount:                1,
			SyscallCount:                4,
			RollbackCount:               0,
			DenialCount:                 0,
		},
	}
}

func TestAProfileWithAFullStatusMapsEveryFieldTheConsoleShows(t *testing.T) {
	r := newReader(t, fakeClient(t, fullProfile()))

	got, err := r.Profiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 profile, got %d", len(got))
	}
	p := got[0]

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"Namespace", p.Namespace, "prod"},
		{"Name", p.Name, "pod-abc-3c1a9b2f4e5d"},
		{"Pod", p.Pod, "web-7f8d9"},
		{"Container", p.Container, "3c1a9b2f4e5d"},
		{"Node", p.Node, "node-1"},
		{"Phase", p.Phase, "Enforcing"},
		{"Files", p.Files, 2},
		{"Network", p.Network, 1},
		{"Syscalls", p.Syscalls, 4},
		{"Capabilities", p.Capabilities, 1},
		{"Declared", p.Declared, 4},
		{"Rollbacks", p.Rollbacks, 0},
		{"Denials", p.Denials, 0},
		{"Confidence", p.Confidence, 0.9},
		{"Age", p.Age, 90 * time.Minute},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

func TestAProfileWithNoStatusAndNoSpecDetailStillProducesARow(t *testing.T) {
	r := newReader(t, fakeClient(t, &policyv1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "prod"},
	}))

	got, err := r.Profiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	p := got[0]

	for field, val := range map[string]string{"Pod": p.Pod, "Container": p.Container, "Node": p.Node, "Phase": p.Phase} {
		if val != unknown {
			t.Errorf("%s = %q, want %q", field, val, unknown)
		}
	}
	if p.Files+p.Network+p.Syscalls+p.Capabilities+p.Declared != 0 {
		t.Errorf("counts from an empty status are not zero: %+v", p)
	}
	if p.Confidence != 0 {
		t.Errorf("Confidence = %v for a profile with no learned signal, want 0", p.Confidence)
	}
}

func TestAProfileCountIsTakenFromWhicheverSourceIsNotAnUndercount(t *testing.T) {
	prof := fullProfile()
	// The agent trimmed the list to keep the object under the size limit, so
	// the count is larger than the list it summarizes.
	prof.Status.FileCount = 9000
	r := newReader(t, fakeClient(t, prof))

	got, err := r.Profiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if got[0].Files != 9000 {
		t.Errorf("Files = %d, want 9000 (the reported count, which exceeds the trimmed list)", got[0].Files)
	}

	// And the other way round: a status written without counts at all.
	prof2 := fullProfile()
	prof2.Status.FileCount = 0
	prof2.Status.NetworkCount = 0
	prof2.Status.SyscallCount = 0
	r2 := newReader(t, fakeClient(t, prof2))
	got2, err := r2.Profiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if got2[0].Files != 2 || got2[0].Network != 1 || got2[0].Syscalls != 4 {
		t.Errorf("counts fell back wrongly when the count fields were unset: %+v", got2[0])
	}
}

func TestProfileConfidenceFallsAsTheEvidenceAgainstTheBaselineAccumulates(t *testing.T) {
	cases := []struct {
		name string
		in   Profile
		want float64
	}{
		{
			name: "an enforcing profile with no rollbacks is trusted but never certain",
			in:   Profile{Phase: "Enforcing", Files: 5},
			want: 0.9,
		},
		{
			name: "a learning profile is provisional",
			in:   Profile{Phase: "Learning", Files: 5},
			want: 0.5,
		},
		{
			name: "one rollback costs a fifth",
			in:   Profile{Phase: "Enforcing", Files: 5, Rollbacks: 1},
			want: 0.7,
		},
		{
			name: "a denial under enforcement means learning missed something",
			in:   Profile{Phase: "Enforcing", Files: 5, Denials: 12},
			want: 0.8,
		},
		{
			name: "confidence never goes below zero however many rollbacks",
			in:   Profile{Phase: "Enforcing", Files: 5, Rollbacks: 9},
			want: 0,
		},
		{
			name: "no learned signal means no baseline to be confident in",
			in:   Profile{Phase: "Enforcing"},
			want: 0,
		},
		{
			name: "an unreported phase is not evidence of anything",
			in:   Profile{Phase: unknown, Files: 5},
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := profileConfidence(tc.in); got != tc.want {
				t.Errorf("profileConfidence = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAContainerIDIsShortenedToSomethingAColumnCanHold(t *testing.T) {
	cases := map[string]string{
		"containerd://3c1a9b2f4e5d6789": "3c1a9b2f4e5d",
		"docker://abcdef":               "abcdef",
		"3c1a9b2f4e5d6789":              "3c1a9b2f4e5d",
		"":                              unknown,
	}
	for in, want := range cases {
		if got := shortContainerID(in); got != want {
			t.Errorf("shortContainerID(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// attack surface mapping
// ---------------------------------------------------------------------------

func fullSurface() *policyv1beta1.AttackSurface {
	return &policyv1beta1.AttackSurface{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "web",
			Namespace:         "prod",
			CreationTimestamp: created(24 * time.Hour),
		},
		Spec: policyv1beta1.AttackSurfaceSpec{
			PolicyRef: "web",
			Workload: &policyv1beta1.WorkloadReference{
				APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Namespace: "prod",
			},
		},
		Status: policyv1beta1.AttackSurfaceStatus{
			ExposedPorts:  []int32{80, 443},
			WritableFiles: []string{"/tmp", "/var/run"},
			Capabilities:  []string{"NET_BIND_SERVICE", "CHOWN"},
			RiskScore:     ptrInt32(62),
			LastAnalysis:  &metav1.Time{Time: testNow.Add(-10 * time.Minute)},
		},
	}
}

func TestAnAttackSurfaceWithAFullStatusMapsEveryFieldTheConsoleShows(t *testing.T) {
	r := newReader(t, fakeClient(t, fullSurface()))

	got, err := r.AttackSurfaces(context.Background())
	if err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 surface, got %d", len(got))
	}
	a := got[0]

	if a.Namespace != "prod" || a.Name != "web" {
		t.Errorf("identity = %s/%s, want prod/web", a.Namespace, a.Name)
	}
	if a.Workload != "Deployment/web" {
		t.Errorf("Workload = %q, want %q", a.Workload, "Deployment/web")
	}
	if !a.HasRiskScore || a.RiskScore != 62 {
		t.Errorf("RiskScore = %d (has=%v), want 62 (has=true)", a.RiskScore, a.HasRiskScore)
	}
	if len(a.ExposedPorts) != 2 || a.ExposedPortTotal != 2 {
		t.Errorf("ExposedPorts = %v (total %d), want 2 ports", a.ExposedPorts, a.ExposedPortTotal)
	}
	if len(a.WritablePaths) != 2 || a.WritablePathTotal != 2 {
		t.Errorf("WritablePaths = %v (total %d), want 2 paths", a.WritablePaths, a.WritablePathTotal)
	}
	if len(a.Capabilities) != 2 || a.CapabilityTotal != 2 {
		t.Errorf("Capabilities = %v (total %d), want 2", a.Capabilities, a.CapabilityTotal)
	}
	if !a.HasLastAnalysis || !a.LastAnalysis.Equal(testNow.Add(-10*time.Minute)) {
		t.Errorf("LastAnalysis = %v (has=%v)", a.LastAnalysis, a.HasLastAnalysis)
	}
	if a.Age != 24*time.Hour {
		t.Errorf("Age = %v, want 24h", a.Age)
	}
}

func TestAnAttackSurfaceWithNoStatusAndNoWorkloadStillProducesARow(t *testing.T) {
	r := newReader(t, fakeClient(t, &policyv1beta1.AttackSurface{
		ObjectMeta: metav1.ObjectMeta{Name: "unanalyzed", Namespace: "prod"},
	}))

	got, err := r.AttackSurfaces(context.Background())
	if err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	a := got[0]

	if a.HasRiskScore {
		t.Error("HasRiskScore is true for an unanalyzed surface; an unscored surface must not render as a reassuring 0")
	}
	if a.HasLastAnalysis {
		t.Error("HasLastAnalysis is true for a surface that has never been analyzed")
	}
	if a.Workload != unknown {
		t.Errorf("Workload = %q, want %q", a.Workload, unknown)
	}
	if a.ExposedPorts != nil || a.WritablePaths != nil || a.Capabilities != nil {
		t.Errorf("empty status produced non-nil slices: %+v", a)
	}
}

func TestAnAttackSurfaceFallsBackToItsPolicyWhenTheWorkloadIsUnset(t *testing.T) {
	s := fullSurface()
	s.Spec.Workload = nil
	r := newReader(t, fakeClient(t, s))

	got, err := r.AttackSurfaces(context.Background())
	if err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	if got[0].Workload != "policy/web" {
		t.Errorf("Workload = %q, want %q", got[0].Workload, "policy/web")
	}
}

func TestAHugeWritablePathListIsTruncatedButItsRealSizeIsStillReported(t *testing.T) {
	s := fullSurface()
	s.Status.WritableFiles = make([]string, 9000)
	for i := range s.Status.WritableFiles {
		s.Status.WritableFiles[i] = fmt.Sprintf("/data/%d", i)
	}
	r := newReader(t, fakeClient(t, s))

	got, err := r.AttackSurfaces(context.Background())
	if err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	if len(got[0].WritablePaths) != maxFieldItems {
		t.Errorf("rendered %d paths, want the cap of %d", len(got[0].WritablePaths), maxFieldItems)
	}
	if got[0].WritablePathTotal != 9000 {
		t.Errorf("WritablePathTotal = %d, want 9000; a truncated list that does not say so misleads the reader",
			got[0].WritablePathTotal)
	}
}

// ---------------------------------------------------------------------------
// selector formatting
// ---------------------------------------------------------------------------

func TestASelectorIsRenderedTheWayAnOperatorWritesOne(t *testing.T) {
	cases := []struct {
		name string
		in   policyv1beta1.WorkloadSelector
		want string
	}{
		{
			name: "an empty selector says it covers everything rather than nothing",
			in:   policyv1beta1.WorkloadSelector{},
			want: "<all pods>",
		},
		{
			name: "match labels are sorted so the string does not change between refreshes",
			in: policyv1beta1.WorkloadSelector{
				MatchLabels: map[string]string{"tier": "front", "app": "web", "env": "prod"},
			},
			want: "app=web,env=prod,tier=front",
		},
		{
			name: "every expression operator has a spelling",
			in: policyv1beta1.WorkloadSelector{
				MatchExpressions: []policyv1beta1.LabelSelectorRequirement{
					{Key: "a", Operator: policyv1beta1.LabelSelectorOpIn, Values: []string{"1", "2"}},
					{Key: "b", Operator: policyv1beta1.LabelSelectorOpNotIn, Values: []string{"3"}},
					{Key: "c", Operator: policyv1beta1.LabelSelectorOpExists},
					{Key: "d", Operator: policyv1beta1.LabelSelectorOpDoesNotExist},
				},
			},
			want: "a in (1,2),b notin (3),c,!d",
		},
		{
			name: "a namespace selector is shown as a prefix, because it widens the policy",
			in: policyv1beta1.WorkloadSelector{
				MatchLabels: map[string]string{"app": "web"},
				NamespaceSelector: &policyv1beta1.NamespaceSelector{
					MatchLabels: map[string]string{"kubernetes.io/metadata.name": "prod"},
				},
			},
			want: "ns:kubernetes.io/metadata.name=prod,app=web",
		},
		{
			name: "an empty namespace selector adds nothing",
			in: policyv1beta1.WorkloadSelector{
				MatchLabels:       map[string]string{"app": "web"},
				NamespaceSelector: &policyv1beta1.NamespaceSelector{},
			},
			want: "app=web",
		},
		{
			name: "an operator from before the enum is shown verbatim rather than dropped",
			in: policyv1beta1.WorkloadSelector{
				MatchExpressions: []policyv1beta1.LabelSelectorRequirement{
					{Key: "a", Operator: "Gt", Values: []string{"3"}},
					{Key: "b", Operator: "Weird"},
				},
			},
			want: "a Gt (3),b Weird",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatSelector(tc.in); got != tc.want {
				t.Errorf("FormatSelector = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ordering, bounding
// ---------------------------------------------------------------------------

func TestRowsComeBackSortedSoTheTableDoesNotReshuffleUnderTheCursor(t *testing.T) {
	objs := []client.Object{
		&policyv1beta1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "zeta", Namespace: "prod"}},
		&policyv1beta1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "prod"}},
		&policyv1beta1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "dev"}},
	}
	r := newReader(t, fakeClient(t, objs...))

	got, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	want := []string{"dev/alpha", "prod/alpha", "prod/zeta"}
	for i, w := range want {
		if key := got[i].Namespace + "/" + got[i].Name; key != w {
			t.Errorf("row %d = %s, want %s", i, key, w)
		}
	}
}

func TestAListLongerThanTheLimitIsCutAndReportedAsTruncated(t *testing.T) {
	var objs []client.Object
	for i := 0; i < 10; i++ {
		objs = append(objs, &policyv1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p%02d", i), Namespace: "prod"},
		})
	}
	r := newReader(t, fakeClient(t, objs...), WithListLimit(4))

	got, err := r.Profiles(context.Background())
	if err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d profiles, want the limit of 4", len(got))
	}
	if !r.Truncated(ViewProfiles) {
		t.Error("Truncated(profiles) is false after a capped list; the operator would not know they are seeing a prefix")
	}
	if r.Truncated(ViewPolicies) {
		t.Error("Truncated(policies) is true for a view that was never read")
	}
}

func TestTheListLimitCannotBeSetToUnbounded(t *testing.T) {
	r := newReader(t, fakeClient(t), WithListLimit(0))
	if r.Limit() != DefaultListLimit {
		t.Errorf("Limit = %d after WithListLimit(0), want the default %d; zero means unbounded to the API server",
			r.Limit(), DefaultListLimit)
	}
	r = newReader(t, fakeClient(t), WithListLimit(-5))
	if r.Limit() != DefaultListLimit {
		t.Errorf("Limit = %d after a negative limit, want the default %d", r.Limit(), DefaultListLimit)
	}
}

func TestTheListIsBoundedAtTheApiServerAndNotOnlyInTheClient(t *testing.T) {
	var sawLimit int64
	inner := fakeClient(t)
	c := interceptor.NewClient(inner, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			var o client.ListOptions
			for _, opt := range opts {
				opt.ApplyToList(&o)
			}
			sawLimit = o.Limit
			return cl.List(ctx, list, opts...)
		},
	})
	r := newReader(t, c, WithListLimit(7))
	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if sawLimit != 7 {
		t.Errorf("the List was issued with limit %d, want 7; without it the server sends the whole collection", sawLimit)
	}
}

func TestTheReturnedSliceIsACopySoACallerSortingItCannotCorruptTheCache(t *testing.T) {
	objs := []client.Object{
		&policyv1beta1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "prod"}},
		&policyv1beta1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "prod"}},
	}
	r := newReader(t, fakeClient(t, objs...), WithTTL(time.Hour))

	first, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	first[0].Name = "clobbered"

	second, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if second[0].Name != "a" {
		t.Errorf("the cache was mutated through a returned slice: got %q", second[0].Name)
	}
}

// ---------------------------------------------------------------------------
// cache
// ---------------------------------------------------------------------------

func TestASecondReadInsideTheTtlDoesNotTouchTheApiServer(t *testing.T) {
	var counter countingClient
	c := newCountingClient(fakeClient(t, fullPolicy(), fullProfile(), fullSurface()), &counter)

	now := testNow
	r := newReader(t, c, WithTTL(2*time.Second), WithClock(func() time.Time { return now }))

	for i := 0; i < 5; i++ {
		if _, err := r.Policies(context.Background()); err != nil {
			t.Fatalf("Policies: %v", err)
		}
	}
	if got := counter.lists.Load(); got != 1 {
		t.Fatalf("%d List calls for 5 reads inside the TTL, want 1", got)
	}

	// Each view caches independently: reading profiles must not be served from
	// the policy cache, and must not invalidate it either.
	if _, err := r.Profiles(context.Background()); err != nil {
		t.Fatalf("Profiles: %v", err)
	}
	if _, err := r.AttackSurfaces(context.Background()); err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	if got := counter.lists.Load(); got != 3 {
		t.Fatalf("%d List calls after reading all three views once, want 3", got)
	}
}

func TestAReadAfterTheTtlHasPassedGoesBackToTheApiServer(t *testing.T) {
	var counter countingClient
	c := newCountingClient(fakeClient(t, fullPolicy()), &counter)

	now := testNow
	r := newReader(t, c, WithTTL(2*time.Second), WithClock(func() time.Time { return now }))

	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	now = now.Add(1900 * time.Millisecond)
	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if got := counter.lists.Load(); got != 1 {
		t.Fatalf("%d List calls just inside the TTL, want 1", got)
	}

	now = now.Add(200 * time.Millisecond)
	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if got := counter.lists.Load(); got != 2 {
		t.Fatalf("%d List calls after the TTL expired, want 2", got)
	}
}

func TestAZeroTtlDisablesTheCacheForOneShotCallers(t *testing.T) {
	var counter countingClient
	c := newCountingClient(fakeClient(t, fullPolicy()), &counter)
	r := newReader(t, c, WithTTL(0))

	for i := 0; i < 3; i++ {
		if _, err := r.Policies(context.Background()); err != nil {
			t.Fatalf("Policies: %v", err)
		}
	}
	if got := counter.lists.Load(); got != 3 {
		t.Fatalf("%d List calls with caching disabled, want 3", got)
	}
}

func TestInvalidateForcesTheNextReadBackToTheApiServer(t *testing.T) {
	var counter countingClient
	c := newCountingClient(fakeClient(t, fullPolicy()), &counter)
	r := newReader(t, c, WithTTL(time.Hour))

	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	r.Invalidate()
	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if got := counter.lists.Load(); got != 2 {
		t.Fatalf("%d List calls across an Invalidate, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// stale on error
// ---------------------------------------------------------------------------

func TestAFailedRefreshReturnsTheLastGoodDataAlongsideTheError(t *testing.T) {
	inner := fakeClient(t, fullPolicy())
	blip := errors.New("etcdserver: request timed out")
	var fail atomic.Bool

	c := interceptor.NewClient(inner, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if fail.Load() {
				return blip
			}
			return cl.List(ctx, list, opts...)
		},
	})
	r := newReader(t, c, WithTTL(0))

	good, err := r.Policies(context.Background())
	if err != nil || len(good) != 1 {
		t.Fatalf("first read: %d rows, err %v", len(good), err)
	}

	fail.Store(true)
	stale, err := r.Policies(context.Background())
	if err == nil {
		t.Fatal("a failed refresh returned no error; the operator would read stale data believing it is current")
	}
	if !errors.Is(err, blip) {
		t.Errorf("the underlying error was not preserved: %v", err)
	}
	if len(stale) != 1 || stale[0].Name != "web" {
		t.Errorf("a failed refresh blanked the screen: got %+v", stale)
	}
}

func TestAFirstReadThatFailsHasNoStaleDataToOfferAndSaysSo(t *testing.T) {
	c := failingListClient(fakeClient(t), errors.New("boom"))
	r := newReader(t, c, WithTTL(0))

	got, err := r.Policies(context.Background())
	if err == nil {
		t.Fatal("want an error from a failing first read")
	}
	if got != nil {
		t.Errorf("want no rows when nothing was ever read successfully, got %+v", got)
	}
}

func TestAFailedRefreshDoesNotOverwriteTheCacheSoTheNextReadStillHasData(t *testing.T) {
	inner := fakeClient(t, fullProfile())
	var fail atomic.Bool
	c := interceptor.NewClient(inner, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if fail.Load() {
				return errors.New("transient")
			}
			return cl.List(ctx, list, opts...)
		},
	})
	r := newReader(t, c, WithTTL(0))

	if _, err := r.Profiles(context.Background()); err != nil {
		t.Fatalf("first read: %v", err)
	}
	fail.Store(true)
	for i := 0; i < 3; i++ {
		rows, err := r.Profiles(context.Background())
		if err == nil {
			t.Fatal("want an error while the client is failing")
		}
		if len(rows) != 1 {
			t.Fatalf("read %d after failure returned %d rows, want the last good 1", i, len(rows))
		}
	}
}

// ---------------------------------------------------------------------------
// cancellation
// ---------------------------------------------------------------------------

func TestAnAlreadyCanceledContextReturnsImmediatelyWithoutListing(t *testing.T) {
	var counter countingClient
	c := newCountingClient(fakeClient(t, fullPolicy()), &counter)
	r := newReader(t, c, WithTTL(0))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	var err error
	go func() {
		_, err = r.Policies(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Policies did not return promptly on a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
	if ReasonOf(err) != ReasonCanceled {
		t.Errorf("ReasonOf = %v, want ReasonCanceled", ReasonOf(err))
	}
	if got := counter.lists.Load(); got != 0 {
		t.Errorf("%d List calls on a canceled context, want 0", got)
	}
}

func TestACanceledContextStillHandsBackTheLastGoodData(t *testing.T) {
	r := newReader(t, fakeClient(t, fullSurface()), WithTTL(0))

	if _, err := r.AttackSurfaces(context.Background()); err != nil {
		t.Fatalf("first read: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rows, err := r.AttackSurfaces(ctx)
	if err == nil {
		t.Fatal("want an error for a canceled read")
	}
	if len(rows) != 1 {
		t.Errorf("a canceled read blanked the screen: got %d rows", len(rows))
	}
}

func TestAnExpiredDeadlineIsReportedAsCancellationNotAsAClusterOutage(t *testing.T) {
	r := newReader(t, fakeClient(t), WithTTL(0))
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	_, err := r.Policies(ctx)
	if ReasonOf(err) != ReasonCanceled {
		t.Errorf("ReasonOf = %v, want ReasonCanceled; the caller's own budget ran out, the cluster is not down",
			ReasonOf(err))
	}
}

// ---------------------------------------------------------------------------
// distinguishable failures
// ---------------------------------------------------------------------------

func TestEachWayOfFailingProducesAMessageThatSendsTheReaderSomewhereDifferent(t *testing.T) {
	gvr := schema.GroupResource{Group: "policy.pahlevan.io", Resource: "pahlevanpolicies"}

	cases := []struct {
		name       string
		err        error
		wantReason Reason
		wantIn     []string
	}{
		{
			name:       "the CRDs are not installed",
			err:        &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: gvr.Group, Kind: "PahlevanPolicy"}},
			wantReason: ReasonCRDsMissing,
			wantIn:     []string{"CRDs are not installed", "kubectl apply"},
		},
		{
			name:       "the caller is not allowed to list",
			err:        apierrors.NewForbidden(gvr, "", errors.New("no")),
			wantReason: ReasonForbidden,
			wantIn:     []string{"not allowed to list", "RBAC"},
		},
		{
			name:       "the credentials were rejected outright",
			err:        apierrors.NewUnauthorized("token expired"),
			wantReason: ReasonUnauthorized,
			wantIn:     []string{"credentials were rejected"},
		},
		{
			name:       "the API server is unreachable",
			err:        errors.New("dial tcp 10.0.0.1:6443: connect: connection refused"),
			wantReason: ReasonUnreachable,
			wantIn:     []string{"could not be reached"},
		},
		{
			name:       "the server is too busy to answer",
			err:        apierrors.NewServiceUnavailable("overloaded"),
			wantReason: ReasonUnreachable,
			wantIn:     []string{"could not be reached"},
		},
		{
			name:       "the client was built without the Pahlevan types",
			err:        errors.New(`no kind is registered for the type v1beta1.PahlevanPolicyList in scheme`),
			wantReason: ReasonSchemeMissing,
			wantIn:     []string{"not registered in the client's scheme", "clusterdata.NewScheme"},
		},
		{
			name:       "an error this package cannot attribute is still shown",
			err:        errors.New("something else entirely"),
			wantReason: ReasonUnknown,
			wantIn:     []string{"something else entirely"},
		},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := failingListClient(fakeClient(t), tc.err)
			r := newReader(t, c, WithTTL(0))

			_, err := r.Policies(context.Background())
			if err == nil {
				t.Fatal("want an error")
			}
			if got := ReasonOf(err); got != tc.wantReason {
				t.Fatalf("ReasonOf = %v, want %v (message: %v)", got, tc.wantReason, err)
			}
			msg := err.Error()
			for _, want := range tc.wantIn {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q does not contain %q", msg, want)
				}
			}
			if !strings.Contains(msg, "pahlevanpolicies") && tc.wantReason != ReasonUnknown {
				t.Errorf("message %q does not name the resource, so the reader cannot tell which RBAC rule to fix", msg)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("the underlying error is not retrievable with errors.Is: %v", err)
			}
			// Two different causes producing the same sentence would defeat
			// the whole point of classifying them.
			if prev, dup := seen[msg]; dup {
				t.Errorf("the message for %q is identical to the one for %q", tc.name, prev)
			}
			seen[msg] = tc.name
		})
	}
}

func TestAReaderCannotBeBuiltWithoutAClientAndSaysWhyInOneSentence(t *testing.T) {
	r, err := New(nil)
	if r != nil {
		t.Error("New returned a Reader for a nil client")
	}
	if ReasonOf(err) != ReasonNoClient {
		t.Fatalf("ReasonOf = %v, want ReasonNoClient", ReasonOf(err))
	}
	for _, want := range []string{"no kubeconfig", "KUBECONFIG"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not mention %q", err.Error(), want)
		}
	}
}

func TestReadingThroughAReaderWithNoClientFailsInsteadOfPanicking(t *testing.T) {
	var r Reader // deliberately not constructed through New
	for _, fn := range []func(context.Context) ([]Policy, error){r.Policies} {
		if _, err := fn(context.Background()); ReasonOf(err) != ReasonNoClient {
			t.Errorf("want ReasonNoClient from a zero Reader, got %v", err)
		}
	}
	if _, err := r.Profiles(context.Background()); ReasonOf(err) != ReasonNoClient {
		t.Errorf("Profiles on a zero Reader: %v", err)
	}
	if _, err := r.AttackSurfaces(context.Background()); ReasonOf(err) != ReasonNoClient {
		t.Errorf("AttackSurfaces on a zero Reader: %v", err)
	}
}

func TestAClientWithoutThePahlevanTypesRegisteredIsNotMistakenForAClusterMissingTheCrds(t *testing.T) {
	// A scheme with nothing in it is exactly what a binary that forgot to
	// register the API group has. Telling its operator to install CRDs that are
	// already installed sends them to the wrong place entirely.
	empty := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	r := newReader(t, empty, WithTTL(0))

	_, err := r.Policies(context.Background())
	if err == nil {
		t.Fatal("want an error listing through a client with an empty scheme")
	}
	if got := ReasonOf(err); got != ReasonSchemeMissing {
		t.Fatalf("ReasonOf = %v, want ReasonSchemeMissing (message: %v)", got, err)
	}
}

func TestReasonOfIsUnknownForNoError(t *testing.T) {
	if got := ReasonOf(nil); got != ReasonUnknown {
		t.Errorf("ReasonOf(nil) = %v, want ReasonUnknown", got)
	}
}

func TestEveryReasonHasItsOwnName(t *testing.T) {
	names := map[string]Reason{}
	for _, r := range []Reason{
		ReasonUnknown, ReasonNoClient, ReasonCRDsMissing, ReasonSchemeMissing,
		ReasonForbidden, ReasonUnauthorized, ReasonUnreachable, ReasonCanceled,
	} {
		if prev, dup := names[r.String()]; dup {
			t.Errorf("Reason %d and %d share the name %q", r, prev, r.String())
		}
		names[r.String()] = r
	}
	if got := Reason(99).String(); got != "unknown" {
		t.Errorf("an unnamed reason reads as %q, want %q", got, "unknown")
	}
}

func TestAnErrorWithNoResourceAndNoCauseStillReadsAsASentence(t *testing.T) {
	e := &Error{}
	if got := e.Error(); got != "failed to list Pahlevan resources" {
		t.Errorf("Error() = %q", got)
	}
}

// ---------------------------------------------------------------------------
// read-only
// ---------------------------------------------------------------------------

func TestThisPackageContainsNoWriteVerbAtAll(t *testing.T) {
	// A console is an inspection tool. This is asserted against the source
	// rather than against behavior because the failure it prevents is a future
	// edit, not a current bug: the moment a write call appears here, a stray
	// keybinding is one refactor away from mutating a policy in production.
	forbidden := []string{
		".Create(", ".Update(", ".Patch(", ".Delete(", ".DeleteAllOf(",
		".Apply(", ".Status()", ".SubResource(",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		checked++
		for _, f := range forbidden {
			if strings.Contains(string(src), f) {
				t.Errorf("%s contains %q: pkg/clusterdata must never be able to change cluster state", name, f)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files were checked, so this test proves nothing")
	}
}

// fakeBuilder is shared with the benchmarks, which cannot use the *testing.T
// helpers above.
func fakeBuilder(s *runtime.Scheme, objs []client.Object) client.WithWatch {
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

// ---------------------------------------------------------------------------
// remaining branches
// ---------------------------------------------------------------------------

func TestTheReaderReportsTheTtlAndLimitItIsRunningWith(t *testing.T) {
	r := newReader(t, fakeClient(t), WithTTL(5*time.Second), WithListLimit(11))
	if r.TTL() != 5*time.Second {
		t.Errorf("TTL = %v, want 5s", r.TTL())
	}
	if r.Limit() != 11 {
		t.Errorf("Limit = %d, want 11", r.Limit())
	}
	def := newReader(t, fakeClient(t))
	if def.TTL() != DefaultTTL || def.Limit() != DefaultListLimit {
		t.Errorf("defaults are %v/%d, want %v/%d", def.TTL(), def.Limit(), DefaultTTL, DefaultListLimit)
	}
	if WithClock(nil); newReader(t, fakeClient(t), WithClock(nil)).now == nil {
		t.Error("WithClock(nil) cleared the clock; it must be ignored rather than leave a nil func to call")
	}
}

func TestTruncationIsTrackedPerViewAndUnknownViewsReportFalse(t *testing.T) {
	var objs []client.Object
	for i := 0; i < 5; i++ {
		objs = append(objs,
			&policyv1beta1.AttackSurface{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("s%d", i), Namespace: "prod"}},
			&policyv1beta1.PahlevanPolicy{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p%d", i), Namespace: "prod"}},
		)
	}
	r := newReader(t, fakeClient(t, objs...), WithListLimit(2))

	if _, err := r.AttackSurfaces(context.Background()); err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	if _, err := r.Policies(context.Background()); err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if !r.Truncated(ViewAttackSurfaces) || !r.Truncated(ViewPolicies) {
		t.Error("a capped list did not report truncation")
	}
	if r.Truncated(View("nonsense")) {
		t.Error("an unknown view reported truncation")
	}

	// A list that fits reports no truncation, so the console does not warn
	// about a prefix it is not showing.
	full := newReader(t, fakeClient(t, objs...), WithListLimit(100))
	if _, err := full.AttackSurfaces(context.Background()); err != nil {
		t.Fatalf("AttackSurfaces: %v", err)
	}
	if full.Truncated(ViewAttackSurfaces) {
		t.Error("an uncapped list reported truncation")
	}
}

func TestAttackSurfaceReadsFailDistinguishablyToo(t *testing.T) {
	// The three views classify errors through the same path; this asserts the
	// surfaces view is wired to it rather than returning a raw client error.
	c := failingListClient(fakeClient(t), apierrors.NewForbidden(
		schema.GroupResource{Group: "policy.pahlevan.io", Resource: "attacksurfaces"}, "", errors.New("no")))
	r := newReader(t, c, WithTTL(0))

	_, err := r.AttackSurfaces(context.Background())
	if ReasonOf(err) != ReasonForbidden {
		t.Fatalf("ReasonOf = %v, want ReasonForbidden", ReasonOf(err))
	}
	if !strings.Contains(err.Error(), "attacksurfaces") {
		t.Errorf("message %q does not name the resource", err.Error())
	}

	c2 := failingListClient(fakeClient(t), errors.New("connection refused"))
	r2 := newReader(t, c2, WithTTL(0))
	if _, err := r2.Profiles(context.Background()); !strings.Contains(err.Error(), "containerprofiles") {
		t.Errorf("profile error %q does not name the resource", err.Error())
	}
}

func TestAWorkloadWithNoKindIsStillNamed(t *testing.T) {
	cases := []struct {
		name string
		ref  *policyv1beta1.WorkloadReference
		pol  string
		want string
	}{
		{"kind and name", &policyv1beta1.WorkloadReference{Kind: "DaemonSet", Name: "agent"}, "", "DaemonSet/agent"},
		{"name only", &policyv1beta1.WorkloadReference{Name: "agent"}, "", "agent"},
		{"an empty reference falls through to the policy", &policyv1beta1.WorkloadReference{}, "web", "policy/web"},
		{"nothing at all", nil, "", unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := workloadLabel(tc.ref, tc.pol); got != tc.want {
				t.Errorf("workloadLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestANegativePercentageIsClampedToZero(t *testing.T) {
	if got := clampPercent(-7); got != 0 {
		t.Errorf("clampPercent(-7) = %d, want 0", got)
	}
	if got := clampPercent(42); got != 42 {
		t.Errorf("clampPercent(42) = %d, want 42", got)
	}
}

func TestClassifyingNilIsNotAnError(t *testing.T) {
	if err := classify(nil, "pahlevanpolicies"); err != nil {
		t.Errorf("classify(nil) = %v, want nil", err)
	}
}

func TestReasonOfReadsAnErrorThatNeverPassedThroughThisPackage(t *testing.T) {
	// The console also shows errors from client construction, which this
	// package never wrapped.
	if got := ReasonOf(errors.New("invalid configuration: no configuration has been provided")); got != ReasonNoClient {
		t.Errorf("ReasonOf = %v, want ReasonNoClient", got)
	}
	if got := ReasonOf(fmt.Errorf("wrapped: %w", &Error{Reason: ReasonCRDsMissing})); got != ReasonCRDsMissing {
		t.Errorf("ReasonOf through a wrap = %v, want ReasonCRDsMissing", got)
	}
}

func TestEveryShapeOfClusterFailureIsAttributedToTheRightCause(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Reason
	}{
		{"a dial timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, ReasonUnreachable},
		{"a server timeout", apierrors.NewTimeoutError("busy", 1), ReasonUnreachable},
		{"a request timeout", apierrors.NewServerTimeout(schema.GroupResource{Resource: "x"}, "list", 1), ReasonUnreachable},
		{"rate limiting", apierrors.NewTooManyRequests("slow down", 1), ReasonUnreachable},
		{"an internal server error", apierrors.NewInternalError(errors.New("boom")), ReasonUnreachable},
		{"a tls handshake timeout", errors.New("net/http: TLS handshake timeout"), ReasonUnreachable},
		{"an unresolvable host", errors.New("dial tcp: lookup api: no such host"), ReasonUnreachable},
		{"a reset connection", errors.New("read tcp: connection reset by peer"), ReasonUnreachable},
		{"a kind the server does not serve", errors.New(`no matches for kind "PahlevanPolicy" in version "v1beta1"`), ReasonCRDsMissing},
		{"a resource the server cannot find", errors.New("the server could not find the requested resource"), ReasonCRDsMissing},
		{"a resource type the server does not have", errors.New("the server doesn't have a resource type \"pahlevanpolicies\""), ReasonCRDsMissing},
		{"a type missing from the scheme", errors.New("v1beta1.PahlevanPolicyList is not registered in scheme"), ReasonSchemeMissing},
		{"a discovery failure", errors.New("failed to get api group resources"), ReasonSchemeMissing},
		{"an unreadable kubeconfig", errors.New("stat /home/x/.kube/config: no such file"), ReasonNoClient},
		{"a cancellation", context.Canceled, ReasonCanceled},
		{"an expired deadline", context.DeadlineExceeded, ReasonCanceled},
		{"something unattributable", errors.New("???"), ReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyReason(tc.err); got != tc.want {
				t.Errorf("classifyReason(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestAnUnattributedErrorStillCarriesTheResourceAndTheCause(t *testing.T) {
	e := &Error{Reason: ReasonUnknown, Resource: "containerprofiles", Err: errors.New("odd")}
	msg := e.Error()
	if !strings.Contains(msg, "containerprofiles") || !strings.Contains(msg, "odd") {
		t.Errorf("Error() = %q, want it to name both the resource and the cause", msg)
	}
	if !errors.Is(e, e.Err) {
		t.Error("Unwrap does not reach the cause")
	}
}

func TestACanceledReadSaysSoWithoutSoundingLikeAnOutage(t *testing.T) {
	e := &Error{Reason: ReasonCanceled, Resource: "pahlevanpolicies", Err: context.Canceled}
	msg := e.Error()
	if !strings.Contains(msg, "canceled") || !strings.Contains(msg, "pahlevanpolicies") {
		t.Errorf("Error() = %q, want it to say the read was canceled and name the resource", msg)
	}
	for _, alarming := range []string{"not allowed", "could not be reached", "not installed"} {
		if strings.Contains(msg, alarming) {
			t.Errorf("a cancellation message contains %q", alarming)
		}
	}
}

func TestNewSchemeRegistersEveryKindThisPackageLists(t *testing.T) {
	s, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	for _, obj := range []runtime.Object{
		&policyv1beta1.PahlevanPolicyList{},
		&policyv1beta1.ContainerProfileList{},
		&policyv1beta1.AttackSurfaceList{},
	} {
		if _, _, err := s.ObjectKinds(obj); err != nil {
			t.Errorf("%T is not registered: %v", obj, err)
		}
	}
}

func TestAPolicyReportsHowMuchOfItsAllowSetWasDeclaredRatherThanLearned(t *testing.T) {
	pol := fullPolicy()
	pol.Spec.LearningConfig.ExpectedBehavior = &policyv1beta1.ExpectedBehavior{
		Files:               []policyv1beta1.ExpectedFile{{Path: "/var/backups/nightly", Write: true}},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{{CIDR: "10.0.0.9/32", Port: 5432}},
		Executables:         []string{"/usr/bin/logrotate"},
		Capabilities:        []string{"CHOWN"},
	}
	r := newReader(t, fakeClient(t, pol))

	got, err := r.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if got[0].Declarations != 4 {
		t.Errorf("Declarations = %d, want 4", got[0].Declarations)
	}

	// The block is optional, and absent on almost every policy.
	bare := newReader(t, fakeClient(t, barePolicy()))
	rows, err := bare.Policies(context.Background())
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}
	if rows[0].Declarations != 0 {
		t.Errorf("Declarations = %d for a policy with no expectedBehavior, want 0", rows[0].Declarations)
	}
}
