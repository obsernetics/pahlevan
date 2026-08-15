package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
)

// Filtering has to be expressed to the server, not applied locally: on a busy
// node the observation stream dwarfs the denials, and shipping all of it to
// discard it at the client wastes the resource the API exists to conserve.
func TestBuildSubscribeRequest(t *testing.T) {
	req, err := buildSubscribeRequest(&eventsOptions{
		types:       []string{"file", "process"},
		denialsOnly: true,
		pod:         "prod/nginx-7c9b4",
	})
	require.NoError(t, err)

	assert.True(t, req.GetDenialsOnly())
	assert.Equal(t, "prod", req.GetNamespace())
	assert.Equal(t, "nginx-7c9b4", req.GetPod())
	assert.Equal(t, []apiv1alpha1.EventType{
		apiv1alpha1.EventType_EVENT_TYPE_FILE,
		apiv1alpha1.EventType_EVENT_TYPE_PROCESS,
	}, req.GetTypes())
}

// A bare pod name has no namespace, and inventing one would silently filter
// out everything.
func TestBuildSubscribeRequestBarePodName(t *testing.T) {
	req, err := buildSubscribeRequest(&eventsOptions{pod: "nginx-7c9b4"})
	require.NoError(t, err)
	assert.Empty(t, req.GetNamespace())
	assert.Equal(t, "nginx-7c9b4", req.GetPod())
}

func TestBuildSubscribeRequestEmpty(t *testing.T) {
	req, err := buildSubscribeRequest(&eventsOptions{})
	require.NoError(t, err)
	assert.Empty(t, req.GetTypes())
	assert.False(t, req.GetDenialsOnly())
	assert.Empty(t, req.GetPod())
}

// A typo must fail before connecting, not silently subscribe to everything.
func TestBuildSubscribeRequestRejectsUnknownType(t *testing.T) {
	_, err := buildSubscribeRequest(&eventsOptions{types: []string{"fille"}})
	require.Error(t, err)
}

func TestEventTypeToProtoRoundTrip(t *testing.T) {
	for _, name := range []string{"syscall", "file", "network", "process", "capability"} {
		req, err := buildSubscribeRequest(&eventsOptions{types: []string{name}})
		require.NoError(t, err, name)
		require.Len(t, req.GetTypes(), 1)
		assert.NotEqual(t, apiv1alpha1.EventType_EVENT_TYPE_UNSPECIFIED, req.GetTypes()[0],
			"%s must have a wire representation", name)
	}
}

// --grpc and --file must print the same shape, or a pipeline cannot move
// between them without rewriting its parsers.
func TestProtoEventToJSONMatchesTheFileShape(t *testing.T) {
	ev := &apiv1alpha1.Event{
		Version:   "pahlevan.io/v1alpha1",
		Type:      apiv1alpha1.EventType_EVENT_TYPE_PROCESS,
		Action:    apiv1alpha1.Action_ACTION_DENY,
		Timestamp: "2026-08-15T12:00:00Z",
		CgroupId:  42,
		Process:   &apiv1alpha1.ProcessInfo{Pid: 400, Comm: "nc"},
		Kubernetes: &apiv1alpha1.KubernetesRef{
			Namespace: "prod", Pod: "nginx-7c9b4", Node: "node-1",
			Image: "nginx:1.27", WorkloadKind: "Deployment", WorkloadName: "nginx",
			Labels: map[string]string{"app": "nginx"},
		},
		Detail: &apiv1alpha1.Event_Exec{Exec: &apiv1alpha1.ExecInfo{
			Binary: "/usr/bin/nc", Args: []string{"nc", "-e", "/bin/sh"},
			CommandLine: "nc -e /bin/sh", AncestryChain: "nginx -> sh -> nc",
		}},
	}

	out := protoEventToJSON(ev)
	assert.Equal(t, "process", out["type"])
	assert.Equal(t, "deny", out["action"])
	assert.Equal(t, "pahlevan.io/v1alpha1", out["version"])

	kube := out["kubernetes"].(map[string]interface{})
	assert.Equal(t, "prod", kube["namespace"])
	assert.Equal(t, "nginx:1.27", kube["image"])
	assert.Equal(t, "Deployment", kube["workloadKind"])
	assert.Equal(t, map[string]string{"app": "nginx"}, kube["labels"])

	exec := out["exec"].(map[string]interface{})
	assert.Equal(t, []string{"nc", "-e", "/bin/sh"}, exec["args"])
	assert.Equal(t, "nc -e /bin/sh", exec["commandLine"])
	assert.Equal(t, "nginx -> sh -> nc", exec["ancestryChain"])
	assert.NotContains(t, exec, "argsTruncated", "a complete command line must not claim truncation")
}

// Empty attribution must not produce a kubernetes block full of empty strings.
func TestProtoEventToJSONOmitsEmptyAttribution(t *testing.T) {
	out := protoEventToJSON(&apiv1alpha1.Event{
		Type:   apiv1alpha1.EventType_EVENT_TYPE_FILE,
		Action: apiv1alpha1.Action_ACTION_OBSERVE,
		Detail: &apiv1alpha1.Event_File{File: &apiv1alpha1.FileInfo{Path: "/etc/passwd"}},
	})
	assert.NotContains(t, out, "kubernetes")
	assert.Equal(t, "observe", out["action"])

	file := out["file"].(map[string]interface{})
	assert.Equal(t, "/etc/passwd", file["path"])
	assert.Equal(t, false, file["write"])
}

func TestProtoEventToJSONNil(t *testing.T) {
	assert.Nil(t, protoEventToJSON(nil))
}

func BenchmarkProtoEventToJSON(b *testing.B) {
	ev := &apiv1alpha1.Event{
		Type: apiv1alpha1.EventType_EVENT_TYPE_PROCESS, Action: apiv1alpha1.Action_ACTION_DENY,
		Process:    &apiv1alpha1.ProcessInfo{Pid: 400, Comm: "nc"},
		Kubernetes: &apiv1alpha1.KubernetesRef{Namespace: "prod", Pod: "p", Image: "nginx:1.27"},
		Detail: &apiv1alpha1.Event_Exec{Exec: &apiv1alpha1.ExecInfo{
			Binary: "/usr/bin/nc", Args: []string{"nc", "-e", "/bin/sh"},
		}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = protoEventToJSON(ev)
	}
}
