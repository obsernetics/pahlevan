package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func podWithStatuses(uid string, main, init, ephemeral []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod", UID: types.UID(uid)},
		Status: corev1.PodStatus{
			ContainerStatuses:          main,
			InitContainerStatuses:      init,
			EphemeralContainerStatuses: ephemeral,
		},
	}
}

func status(name, id, image string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, ContainerID: id, Image: image}
}

// Kubernetes reports containerID as "<runtime>://<id>" while the cgroup path
// yields the bare id, so the scheme has to come off before comparing.
func TestContainerDetailStripsTheRuntimeScheme(t *testing.T) {
	const id = "abc123def456"
	for _, prefix := range []string{"containerd://", "cri-o://", "docker://", ""} {
		t.Run(prefix, func(t *testing.T) {
			r := resolverWith([]*corev1.Pod{
				podWithStatuses("uid-1", []corev1.ContainerStatus{
					status("nginx", prefix+id, "nginx:1.27"),
				}, nil, nil),
			}, nil, nil)

			name, image, ok := r.ContainerDetail("uid-1", id)
			require.True(t, ok)
			assert.Equal(t, "nginx", name)
			assert.Equal(t, "nginx:1.27", image)
		})
	}
}

// A denial during init is exactly the kind of thing worth attributing
// precisely, so init and ephemeral containers are searched too.
func TestContainerDetailFindsInitAndEphemeralContainers(t *testing.T) {
	r := resolverWith([]*corev1.Pod{
		podWithStatuses("uid-1",
			[]corev1.ContainerStatus{status("nginx", "containerd://main", "nginx:1.27")},
			[]corev1.ContainerStatus{status("migrate", "containerd://init", "migrate:v2")},
			[]corev1.ContainerStatus{status("debug", "containerd://eph", "busybox:1.36")},
		),
	}, nil, nil)

	for _, tc := range []struct{ id, wantName, wantImage string }{
		{"main", "nginx", "nginx:1.27"},
		{"init", "migrate", "migrate:v2"},
		{"eph", "debug", "busybox:1.36"},
	} {
		name, image, ok := r.ContainerDetail("uid-1", tc.id)
		require.True(t, ok, "container %s should resolve", tc.id)
		assert.Equal(t, tc.wantName, name)
		assert.Equal(t, tc.wantImage, image)
	}
}

// ImageID is digest-pinned and more useful, but it is empty until the image is
// pulled, so it is the fallback rather than the primary.
func TestContainerDetailFallsBackToImageID(t *testing.T) {
	cs := status("nginx", "containerd://abc", "")
	cs.ImageID = "sha256:deadbeef"
	r := resolverWith([]*corev1.Pod{
		podWithStatuses("uid-1", []corev1.ContainerStatus{cs}, nil, nil),
	}, nil, nil)

	_, image, ok := r.ContainerDetail("uid-1", "abc")
	require.True(t, ok)
	assert.Equal(t, "sha256:deadbeef", image)
}

func TestContainerDetailMisses(t *testing.T) {
	r := resolverWith([]*corev1.Pod{
		podWithStatuses("uid-1", []corev1.ContainerStatus{
			status("nginx", "containerd://abc", "nginx:1.27"),
		}, nil, nil),
	}, nil, nil)

	// The pod cgroup carries no container id.
	_, _, ok := r.ContainerDetail("uid-1", "")
	assert.False(t, ok, "an empty container id cannot resolve")

	_, _, ok = r.ContainerDetail("uid-1", "notthere")
	assert.False(t, ok)

	_, _, ok = r.ContainerDetail("unknown-pod", "abc")
	assert.False(t, ok)
}

func TestRuntimeContainerID(t *testing.T) {
	assert.Equal(t, "abc", runtimeContainerID("containerd://abc"))
	assert.Equal(t, "abc", runtimeContainerID("abc"))
	assert.Equal(t, "", runtimeContainerID(""))
	// Only the first scheme separator is significant.
	assert.Equal(t, "a://b", runtimeContainerID("docker://a://b"))
}

func BenchmarkContainerDetail(b *testing.B) {
	r := resolverWith([]*corev1.Pod{
		podWithStatuses("uid-1", []corev1.ContainerStatus{
			status("sidecar", "containerd://s", "envoy:v1"),
			status("nginx", "containerd://abc", "nginx:1.27"),
		}, nil, nil),
	}, nil, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = r.ContainerDetail("uid-1", "abc")
	}
}
