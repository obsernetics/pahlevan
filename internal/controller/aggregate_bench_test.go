package controller

import (
	"context"
	"fmt"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The roll-up runs on every enforcement reconcile and lists every profile in
// the namespace, so it needs to stay cheap at fleet scale.
func BenchmarkAggregateProfiles(b *testing.B) {
	policy := samplePolicy("p1", "default", nil)
	objs := make([]client.Object, 0, 500)
	for i := 0; i < 500; i++ {
		objs = append(objs, profileFor(fmt.Sprintf("c%d", i), "default", "p1", "Enforcing", 3, 2, 1, 0, 0))
	}
	c := newFakeClient(b, objs...)
	r := &PahlevanPolicyReconciler{Client: c, Scheme: testScheme(b)}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := r.aggregateProfiles(ctx, policy); err != nil {
			b.Fatal(err)
		}
	}
}
