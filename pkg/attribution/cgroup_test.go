package attribution

import "testing"

func TestParseCgroupPath(t *testing.T) {
	const cid = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	tests := []struct {
		name        string
		path        string
		wantOK      bool
		wantPodUID  string
		wantCID     string
		wantRuntime string
		wantQoS     string
	}{
		{
			name:        "systemd containerd besteffort",
			path:        "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1234abcd_5678_90ef_1234_567890abcdef.slice/cri-containerd-" + cid + ".scope",
			wantOK:      true,
			wantPodUID:  "1234abcd-5678-90ef-1234-567890abcdef",
			wantCID:     cid,
			wantRuntime: "containerd",
			wantQoS:     "besteffort",
		},
		{
			name:        "systemd crio burstable",
			path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234abcd_5678_90ef_1234_567890abcdef.slice/crio-" + cid + ".scope",
			wantOK:      true,
			wantPodUID:  "1234abcd-5678-90ef-1234-567890abcdef",
			wantCID:     cid,
			wantRuntime: "crio",
			wantQoS:     "burstable",
		},
		{
			name:        "cgroupfs driver guaranteed",
			path:        "/kubepods/pod1234abcd-5678-90ef-1234-567890abcdef/" + cid,
			wantOK:      true,
			wantPodUID:  "1234abcd-5678-90ef-1234-567890abcdef",
			wantCID:     cid,
			wantRuntime: "",
			wantQoS:     "",
		},
		{
			name:       "pod cgroup without container (systemd)",
			path:       "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1234abcd_5678_90ef_1234_567890abcdef.slice",
			wantOK:     true,
			wantPodUID: "1234abcd-5678-90ef-1234-567890abcdef",
			wantCID:    "",
			wantQoS:    "besteffort",
		},
		{
			name:   "non-pod system slice",
			path:   "/system.slice/kubelet.service",
			wantOK: false,
		},
		{
			name:   "root cgroup",
			path:   "/",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, ok := ParseCgroupPath(tc.path)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (ref=%+v)", ok, tc.wantOK, ref)
			}
			if !tc.wantOK {
				return
			}
			if ref.PodUID != tc.wantPodUID {
				t.Errorf("PodUID = %q, want %q", ref.PodUID, tc.wantPodUID)
			}
			if ref.ContainerID != tc.wantCID {
				t.Errorf("ContainerID = %q, want %q", ref.ContainerID, tc.wantCID)
			}
			if ref.Runtime != tc.wantRuntime {
				t.Errorf("Runtime = %q, want %q", ref.Runtime, tc.wantRuntime)
			}
			if ref.QoSClass != tc.wantQoS {
				t.Errorf("QoSClass = %q, want %q", ref.QoSClass, tc.wantQoS)
			}
		})
	}
}
