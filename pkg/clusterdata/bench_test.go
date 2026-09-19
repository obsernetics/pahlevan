package clusterdata

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

// benchObjects builds a cluster the size a console actually has to survive:
// enough profiles that an unbounded list would be the wrong thing to do.
func benchObjects(b *testing.B, n int) []client.Object {
	b.Helper()
	objs := make([]client.Object, 0, n*2)
	for i := 0; i < n; i++ {
		objs = append(objs, &policyv1beta1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:              fmt.Sprintf("pod-%05d", i),
				Namespace:         fmt.Sprintf("ns-%02d", i%20),
				CreationTimestamp: metav1.NewTime(testNow.Add(-time.Duration(i) * time.Minute)),
			},
			Spec: policyv1beta1.ContainerProfileSpec{
				PodName:     fmt.Sprintf("web-%05d", i),
				ContainerID: fmt.Sprintf("containerd://%048d", i),
				Node:        fmt.Sprintf("node-%02d", i%50),
			},
			Status: policyv1beta1.ContainerProfileStatus{
				Phase:                      policyv1beta1.ProfilePhaseEnforcing,
				LearnedFiles:               []string{"/etc/passwd", "/app/config", "/tmp/x"},
				LearnedNetworkDestinations: []string{"10.0.0.1:443"},
				LearnedSyscalls:            []int64{0, 1, 2, 3, 4, 5},
				LearnedCapabilities:        []string{"CHOWN"},
				FileCount:                  3,
				NetworkCount:               1,
				SyscallCount:               6,
			},
		})
		objs = append(objs, &policyv1beta1.PahlevanPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:              fmt.Sprintf("policy-%05d", i),
				Namespace:         fmt.Sprintf("ns-%02d", i%20),
				CreationTimestamp: metav1.NewTime(testNow.Add(-time.Hour)),
			},
			Spec: policyv1beta1.PahlevanPolicySpec{
				Selector: policyv1beta1.WorkloadSelector{
					MatchLabels: map[string]string{"app": "web", "tier": "front"},
					MatchExpressions: []policyv1beta1.LabelSelectorRequirement{
						{Key: "env", Operator: policyv1beta1.LabelSelectorOpIn, Values: []string{"prod"}},
					},
				},
				EnforcementConfig: policyv1beta1.EnforcementConfig{Mode: policyv1beta1.EnforcementModeBlocking},
			},
			Status: policyv1beta1.PahlevanPolicyStatus{
				Phase:             policyv1beta1.PolicyPhaseEnforcing,
				LearningStatus:    &policyv1beta1.LearningStatus{SamplesCollected: 100, Progress: ptrInt32(100)},
				EnforcementStatus: &policyv1beta1.EnforcementStatus{EnforcingContainers: 2, TotalContainers: 2},
			},
		})
	}
	return objs
}

// BenchmarkPoliciesCold measures what an operator waits for when the cache is
// empty: the list, the mapping and the sort.
func BenchmarkPoliciesCold(b *testing.B) {
	c := benchClient(b)
	r := benchReader(b, c)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Invalidate()
		if _, err := r.Policies(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPoliciesCached measures what every keypress after the first costs.
// This is the number that has to stay small: the console re-asks on redraw.
func BenchmarkPoliciesCached(b *testing.B) {
	c := benchClient(b)
	r := benchReader(b, c)
	ctx := context.Background()
	if _, err := r.Policies(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Policies(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProfilesCold(b *testing.B) {
	c := benchClient(b)
	r := benchReader(b, c)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Invalidate()
		if _, err := r.Profiles(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProfilesCached(b *testing.B) {
	c := benchClient(b)
	r := benchReader(b, c)
	ctx := context.Background()
	if _, err := r.Profiles(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Profiles(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormatSelector(b *testing.B) {
	sel := policyv1beta1.WorkloadSelector{
		MatchLabels: map[string]string{"app": "web", "tier": "front", "env": "prod"},
		MatchExpressions: []policyv1beta1.LabelSelectorRequirement{
			{Key: "release", Operator: policyv1beta1.LabelSelectorOpIn, Values: []string{"canary", "stable"}},
			{Key: "debug", Operator: policyv1beta1.LabelSelectorOpDoesNotExist},
		},
		NamespaceSelector: &policyv1beta1.NamespaceSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "prod"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatSelector(sel)
	}
}

func benchClient(b *testing.B) client.Client {
	b.Helper()
	s, err := NewScheme()
	if err != nil {
		b.Fatal(err)
	}
	return fakeBuilder(s, benchObjects(b, 1000))
}

func benchReader(b *testing.B, c client.Client) *Reader {
	b.Helper()
	r, err := New(c, WithClock(func() time.Time { return testNow }), WithTTL(time.Hour))
	if err != nil {
		b.Fatal(err)
	}
	return r
}
