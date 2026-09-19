package dashboard

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func TestSurfaceOfRendersSyscallNames(t *testing.T) {
	// The profile stores syscall numbers because that is what the kernel
	// enforces on. A number is not something an operator can judge.
	st := &policyv1alpha1.ContainerProfileStatus{
		LearnedSyscalls: []int64{0, 1, -1},
		LearnedFiles:    []string{"/etc/passwd"},
		FileCount:       9,
	}
	s := surfaceOf(st)
	for _, name := range s.Syscalls {
		if strings.HasPrefix(name, "-") {
			t.Fatalf("a negative syscall number reached the view as %q", name)
		}
	}
	if len(s.Syscalls) != 2 {
		t.Fatalf("surfaceOf rendered %v, want the two valid numbers", s.Syscalls)
	}
	// The status counter is the more complete number when the list was
	// trimmed by the agent.
	if s.FileCount != 9 {
		t.Fatalf("FileCount was %d, want the status's 9", s.FileCount)
	}
	if !s.Truncated {
		t.Fatal("a surface whose count exceeds its list did not report itself truncated, so the " +
			"page would read as a complete profile")
	}
}

func TestSurfaceSampleIsBounded(t *testing.T) {
	paths := make([]string, SurfaceSampleLimit*2)
	for i := range paths {
		paths[i] = "/tmp/file"
	}
	s := surfaceOf(&policyv1alpha1.ContainerProfileStatus{LearnedFiles: paths})
	if len(s.Files) != SurfaceSampleLimit {
		t.Fatalf("the sample held %d paths, want %d", len(s.Files), SurfaceSampleLimit)
	}
	if s.FileCount != len(paths) {
		t.Fatalf("the count was %d, want the full %d", s.FileCount, len(paths))
	}
}

func TestMergeSurfaceUnionsReplicas(t *testing.T) {
	// A Deployment's replicas learn separately. Showing one replica's profile
	// as the workload's surface would hide whatever the others needed.
	dst := surfaceOf(&policyv1alpha1.ContainerProfileStatus{
		LearnedFiles: []string{"/a", "/b"}, FileCount: 2,
	})
	mergeSurface(&dst, surfaceOf(&policyv1alpha1.ContainerProfileStatus{
		LearnedFiles: []string{"/b", "/c"}, FileCount: 2,
	}))
	if len(dst.Files) != 3 {
		t.Fatalf("the merged surface held %v, want the union of three paths", dst.Files)
	}
	for i := 1; i < len(dst.Files); i++ {
		if dst.Files[i-1] >= dst.Files[i] {
			t.Fatalf("the merged surface is not ordered: %v; two page loads would disagree", dst.Files)
		}
	}
}

func TestSummaryPhase(t *testing.T) {
	tests := []struct {
		name   string
		counts PhaseCounts
		want   string
	}{
		{name: "nothing reported", counts: PhaseCounts{}, want: "Unknown"},
		{name: "all enforcing", counts: PhaseCounts{Enforcing: 3, Total: 3}, want: "Enforcing"},
		{name: "all learning", counts: PhaseCounts{Learning: 3, Total: 3}, want: "Learning"},
		{
			// Half a Deployment enforcing and half still learning is a rollout
			// halfway through, which is exactly when somebody is looking.
			name: "mixed", counts: PhaseCounts{Enforcing: 1, Learning: 2, Total: 3}, want: "Mixed",
		},
		{name: "any failure wins", counts: PhaseCounts{Enforcing: 3, Failed: 1, Total: 4}, want: "Failed"},
		{name: "initializing", counts: PhaseCounts{Initializing: 2, Total: 2}, want: "Initializing"},
		{
			name:   "enforcing alongside containers that have not reported",
			counts: PhaseCounts{Enforcing: 1, Initializing: 1, Total: 2},
			want:   "Enforcing",
		},
		{
			name:   "learning alongside containers that have not reported",
			counts: PhaseCounts{Learning: 1, Initializing: 1, Total: 2},
			want:   "Learning",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summaryPhase(tc.counts); got != tc.want {
				t.Fatalf("summaryPhase(%+v) = %q, want %q", tc.counts, got, tc.want)
			}
		})
	}
}

func TestPhaseCountsAddPhase(t *testing.T) {
	var c PhaseCounts
	for _, phase := range []string{"Learning", "learning", "Enforcing", "Failed", "RollingBack", "", "Initializing"} {
		c.addPhase(phase)
	}
	if c.Total != 7 || c.Learning != 2 || c.Enforcing != 1 || c.Failed != 2 || c.Initializing != 2 {
		t.Fatalf("addPhase produced %+v", c)
	}
}

func TestWorkloadOf(t *testing.T) {
	tests := []struct {
		name    string
		profile policyv1alpha1.ContainerProfile
		want    WorkloadKey
	}{
		{
			name: "owning workload",
			profile: policyv1alpha1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"},
				Spec: policyv1alpha1.ContainerProfileSpec{
					Workload: &policyv1alpha1.WorkloadReference{Kind: "Deployment", Name: "api", Namespace: "prod"},
				},
			},
			want: WorkloadKey{Namespace: "prod", Kind: "Deployment", Name: "api"},
		},
		{
			// A profile whose owner could not be resolved is still something
			// an operator can look up; dropping it would hide a container that
			// is actually being enforced.
			name: "falls back to the pod",
			profile: policyv1alpha1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"},
				Spec:       policyv1alpha1.ContainerProfileSpec{PodName: "api-0"},
			},
			want: WorkloadKey{Namespace: "prod", Kind: "Pod", Name: "api-0"},
		},
		{
			name: "falls back to the profile",
			profile: policyv1alpha1.ContainerProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "prod"},
			},
			want: WorkloadKey{Namespace: "prod", Kind: "ContainerProfile", Name: "orphan"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := workloadOf(&tc.profile); got != tc.want {
				t.Fatalf("workloadOf = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPhaseOfDoesNotInventLearning(t *testing.T) {
	// An empty phase is a profile the agent has created but not yet reported
	// on. Calling that "Learning" would overstate what is happening.
	if got := phaseOf(""); got != "Unknown" {
		t.Fatalf("phaseOf(empty) = %q, want Unknown", got)
	}
	if got := phaseOf("Enforcing"); got != "Enforcing" {
		t.Fatalf("phaseOf(Enforcing) = %q", got)
	}
}

func TestPluralise(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{{0, "0 denials"}, {1, "1 denial"}, {2, "2 denials"}} {
		if got := pluralise(tc.n, "denial", "denials"); got != tc.want {
			t.Fatalf("pluralise(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestWorkloadKeyString(t *testing.T) {
	k := WorkloadKey{Namespace: "prod", Kind: "Deployment", Name: "api"}
	if k.String() != "prod/Deployment/api" {
		t.Fatalf("WorkloadKey.String = %q", k.String())
	}
	if k.Empty() {
		t.Fatal("a complete key reported itself empty")
	}
	for _, empty := range []WorkloadKey{{}, {Namespace: "prod"}, {Name: "api"}} {
		if !empty.Empty() {
			t.Fatalf("%+v did not report itself empty, so it could reach a cluster-wide read", empty)
		}
	}
}
