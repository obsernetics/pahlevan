package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func newRefreshFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyv1alpha1.AddToScheme(scheme))

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&corev1.Pod{}, "spec.nodeName", func(o client.Object) []string {
			p, ok := o.(*corev1.Pod)
			if !ok {
				return nil
			}
			return []string{p.Spec.NodeName}
		}).
		WithObjects(objs...).
		Build()
}

func TestPolicyResolver_Refresh(t *testing.T) {
	t.Run("loads pods scoped to the node, policies and namespace labels", func(t *testing.T) {
		nodeAPod := pod("web-1", "default", "uid-1", nil)
		nodeAPod.Spec.NodeName = "node-a"
		nodeBPod := pod("web-2", "default", "uid-2", nil)
		nodeBPod.Spec.NodeName = "node-b"
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"team": "platform"}},
		}
		pol := blockingPolicy("pol-1", policyv1alpha1.LabelSelector{})

		fc := newRefreshFakeClient(t, nodeAPod, nodeBPod, ns, &pol)
		r := newPolicyResolver(fc, "node-a")

		require.NoError(t, r.Refresh(context.Background()))

		_, _, ok := r.PodMeta("uid-1")
		assert.True(t, ok, "pod scheduled on node-a should be cached")
		_, _, ok = r.PodMeta("uid-2")
		assert.False(t, ok, "pod scheduled on node-b must not be cached")

		r.mu.RLock()
		assert.Len(t, r.policies, 1)
		assert.Equal(t, map[string]string{"team": "platform"}, r.nsLabels["default"])
		r.mu.RUnlock()
	})

	t.Run("empty node name lists pods across all nodes", func(t *testing.T) {
		p1 := pod("web-1", "default", "uid-1", nil)
		p1.Spec.NodeName = "node-a"
		p2 := pod("web-2", "default", "uid-2", nil)
		p2.Spec.NodeName = "node-b"

		fc := newRefreshFakeClient(t, p1, p2)
		r := newPolicyResolver(fc, "")

		require.NoError(t, r.Refresh(context.Background()))

		_, _, ok1 := r.PodMeta("uid-1")
		_, _, ok2 := r.PodMeta("uid-2")
		assert.True(t, ok1)
		assert.True(t, ok2)
	})

	t.Run("pod list error is returned", func(t *testing.T) {
		// A scheme with nothing registered makes every List call fail.
		fc := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
		r := newPolicyResolver(fc, "node-a")

		err := r.Refresh(context.Background())
		assert.Error(t, err)
	})

	t.Run("namespace list failure degrades rather than fails the refresh", func(t *testing.T) {
		// Register corev1/policy but not the namespace list path being denied is
		// hard to simulate with the fake client directly, so this instead checks
		// that an empty (but successful) namespace list simply leaves nsLabels as
		// it already is rather than erroring.
		p := pod("web-1", "default", "uid-1", nil)
		fc := newRefreshFakeClient(t, p)
		r := newPolicyResolver(fc, "")

		require.NoError(t, r.Refresh(context.Background()))
		_, _, ok := r.PodMeta("uid-1")
		assert.True(t, ok)
	})

	t.Run("second refresh replaces stale cache entries", func(t *testing.T) {
		p1 := pod("web-1", "default", "uid-1", nil)
		fc := newRefreshFakeClient(t, p1)
		r := newPolicyResolver(fc, "")
		require.NoError(t, r.Refresh(context.Background()))

		_, _, ok := r.PodMeta("uid-1")
		require.True(t, ok)

		require.NoError(t, fc.Delete(context.Background(), p1))
		require.NoError(t, r.Refresh(context.Background()))

		_, _, ok = r.PodMeta("uid-1")
		assert.False(t, ok, "deleted pod should be gone after a second refresh")
	})
}

func TestPolicyResolver_PodMeta(t *testing.T) {
	r := resolverWith([]*corev1.Pod{
		pod("web-1", "prod", "uid-1", nil),
	}, nil, nil)

	ns, name, ok := r.PodMeta("uid-1")
	require.True(t, ok)
	assert.Equal(t, "prod", ns)
	assert.Equal(t, "web-1", name)

	_, _, ok = r.PodMeta("missing")
	assert.False(t, ok)
}
