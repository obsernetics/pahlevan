package dashboard

import (
	"context"
	"sync"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// authenticatedReactor is the minimal TokenReview answer, for the tests that
// build their own clientset rather than using newFakeAuth.
func authenticatedReactor() k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
		review.Status = authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User:          authenticationv1.UserInfo{Username: testUser},
		}
		return true, review, nil
	}
}

func k8sRef(ns, workload string) *export.KubernetesRef {
	return &export.KubernetesRef{
		Namespace:    ns,
		Pod:          workload + "-0",
		Container:    workload,
		Node:         "node-1",
		WorkloadKind: "Deployment",
		WorkloadName: workload,
		Image:        "example.test/" + workload + ":1",
	}
}

// execDenial is a denied exec with ancestry, which is the event the process
// tree and the denial reason are both built from.
func execDenial(ns, workload, binary string, ancestry []string) *export.Event {
	e := &export.Event{
		Version:    export.SchemaVersion,
		Timestamp:  export.Timestamp(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
		Type:       export.EventTypeProcess,
		Action:     export.ActionDeny,
		Process:    export.ProcessInfo{PID: 4242, Comm: "curl"},
		Kubernetes: k8sRef(ns, workload),
		Exec:       &export.ExecInfo{Binary: binary},
	}
	// Ancestry is nearest ancestor first on the wire, so the caller's
	// oldest-first list is reversed here.
	for i := len(ancestry) - 1; i >= 0; i-- {
		e.Exec.Ancestry = append(e.Exec.Ancestry, export.AncestorInfo{PID: uint32(100 + i), Comm: ancestry[i]})
	}
	return e
}

func fileEvent(ns, workload, path string, denied bool) *export.Event {
	action := export.ActionObserve
	if denied {
		action = export.ActionDeny
	}
	return &export.Event{
		Version:    export.SchemaVersion,
		Timestamp:  export.Timestamp(time.Date(2026, 1, 1, 12, 0, 1, 0, time.UTC)),
		Type:       export.EventTypeFile,
		Action:     action,
		Process:    export.ProcessInfo{PID: 7, Comm: "nginx", ParentComm: "pause"},
		Kubernetes: k8sRef(ns, workload),
		File:       &export.FileInfo{Path: path, SyscallName: "read"},
	}
}

func TestStoreCountsBySignal(t *testing.T) {
	store := NewStore(StoreOptions{})
	store.Add(fileEvent(visibleNS, "api", "/etc/passwd", false))
	store.Add(fileEvent(visibleNS, "api", "/etc/shadow", true))
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx"}))

	act, ok := store.Activity(WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "api"})
	if !ok {
		t.Fatal("the store has no activity for the workload it was just given events for")
	}
	if act.Counts.Files != 2 || act.Counts.Execs != 1 || act.Counts.Total != 3 {
		t.Fatalf("counts were %+v", act.Counts)
	}
	if act.Counts.Denials != 2 {
		t.Fatalf("the store counted %d denials, want 2", act.Counts.Denials)
	}
	if act.Node != "node-1" || act.Image == "" {
		t.Fatalf("the activity lost its attribution: %+v", act)
	}
}

// An event whose pod could not be resolved has no namespace, so there is no
// authorisation decision that can be made about it. Filing it under a
// placeholder would eventually show it to somebody.
func TestStoreDropsUnattributedEvents(t *testing.T) {
	store := NewStore(StoreOptions{})
	store.Add(&export.Event{Type: export.EventTypeFile, Process: export.ProcessInfo{Comm: "x"}})
	store.Add(&export.Event{
		Type:       export.EventTypeFile,
		Kubernetes: &export.KubernetesRef{PodUID: "abc"},
	})

	if got := store.Stats(); got.Workloads != 0 || got.Unattributed != 2 {
		t.Fatalf("stats were %+v, want 0 workloads and 2 unattributed", got)
	}
	if len(store.Snapshot()) != 0 {
		t.Fatal("an unattributed event reached a workload snapshot")
	}
}

func TestKeyForEvent(t *testing.T) {
	tests := []struct {
		name  string
		ref   *export.KubernetesRef
		want  WorkloadKey
		wantK bool
	}{
		{name: "no attribution", ref: nil, wantK: false},
		{name: "no namespace", ref: &export.KubernetesRef{Pod: "api-0"}, wantK: false},
		{
			name:  "workload",
			ref:   &export.KubernetesRef{Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Pod: "api-0"},
			want:  WorkloadKey{Namespace: "prod", Kind: "Deployment", Name: "api"},
			wantK: true,
		},
		{
			name:  "bare pod",
			ref:   &export.KubernetesRef{Namespace: "prod", Pod: "api-0"},
			want:  WorkloadKey{Namespace: "prod", Kind: "Pod", Name: "api-0"},
			wantK: true,
		},
		{
			name:  "namespace only",
			ref:   &export.KubernetesRef{Namespace: "prod"},
			wantK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := KeyForEvent(&export.Event{Kubernetes: tc.ref})
			if ok != tc.wantK || got != tc.want {
				t.Fatalf("KeyForEvent = %+v, %v; want %+v, %v", got, ok, tc.want, tc.wantK)
			}
		})
	}
}

func TestDenialReasons(t *testing.T) {
	// The reason is what points an operator at the fix. Each of these names
	// the allow-set that refused the operation, because Pahlevan denies by
	// omission: there is never a rule to go and look for.
	tests := []struct {
		name        string
		event       *export.Event
		wantKind    string
		wantSubject string
		wantReason  string
	}{
		{
			name:        "file",
			event:       &export.Event{File: &export.FileInfo{Path: "/etc/shadow", SyscallName: "read"}},
			wantKind:    "file",
			wantSubject: "/etc/shadow",
			wantReason:  "the path is not in this container's learned file allow-set for read",
		},
		{
			name: "network with a name",
			event: &export.Event{Network: &export.NetworkInfo{
				DestinationIP: "10.0.0.5", DestinationPort: 5432, DestinationName: "prod/postgres",
			}},
			wantKind:    "network",
			wantSubject: "prod/postgres (10.0.0.5:5432)",
			wantReason:  "the destination is not in this container's learned egress allow-set",
		},
		{
			name:        "exec",
			event:       &export.Event{Exec: &export.ExecInfo{Binary: "/usr/bin/nc"}},
			wantKind:    "exec",
			wantSubject: "/usr/bin/nc",
			wantReason:  "the binary is not in this container's learned executable allow-set",
		},
		{
			name:        "breakout",
			event:       &export.Event{Exec: &export.ExecInfo{Binary: "/proc/self/exe", Breakout: true}},
			wantKind:    "exec",
			wantSubject: "/proc/self/exe",
			wantReason: "the exec ran with a working directory outside its own mount namespace, " +
				"which is the container-breakout signature",
		},
		{
			name:        "capability",
			event:       &export.Event{Capability: &export.CapabilityInfo{Name: "SYS_ADMIN"}},
			wantKind:    "capability",
			wantSubject: "SYS_ADMIN",
			wantReason:  "the capability is not in this container's learned capability set",
		},
		{
			name:        "syscall",
			event:       &export.Event{Syscall: &export.SyscallInfo{Name: "ptrace"}},
			wantKind:    "syscall",
			wantSubject: "ptrace",
			wantReason:  "the syscall is not in this container's learned syscall allow-set",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, subject, reason := denialSubjectAndReason(tc.event)
			if kind != tc.wantKind || subject != tc.wantSubject || reason != tc.wantReason {
				t.Fatalf("got (%q, %q, %q), want (%q, %q, %q)",
					kind, subject, reason, tc.wantKind, tc.wantSubject, tc.wantReason)
			}
		})
	}
}

func TestStoreDenialRingKeepsTheNewest(t *testing.T) {
	store := NewStore(StoreOptions{MaxDenials: 3})
	for i := 0; i < 10; i++ {
		e := fileEvent(visibleNS, "api", "/tmp/"+string(rune('a'+i)), true)
		e.Timestamp = export.Timestamp(time.Date(2026, 1, 1, 12, 0, i, 0, time.UTC))
		store.Add(e)
	}
	act, _ := store.Activity(WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "api"})
	if len(act.Denials) != 3 {
		t.Fatalf("the ring held %d denials, want 3", len(act.Denials))
	}
	// Newest first: an operator reading a denial list reads the top of it.
	if act.Denials[0].Subject != "/tmp/j" || act.Denials[2].Subject != "/tmp/h" {
		t.Fatalf("the ring returned %q..%q, want /tmp/j../tmp/h",
			act.Denials[0].Subject, act.Denials[2].Subject)
	}
	if act.Counts.Denials != 10 {
		t.Fatalf("the counter reported %d denials; the ring bounds what is kept, not what happened",
			act.Counts.Denials)
	}
}

func TestStoreEvictsTheLeastRecentlySeenWorkload(t *testing.T) {
	store := NewStore(StoreOptions{MaxWorkloads: 2})
	for i, name := range []string{"first", "second", "third"} {
		e := fileEvent(visibleNS, name, "/etc/passwd", false)
		e.Timestamp = export.Timestamp(time.Date(2026, 1, 1, 12, 0, i*10, 0, time.UTC))
		store.Add(e)
	}
	if got := store.Stats(); got.Workloads != 2 || got.Evicted != 1 {
		t.Fatalf("stats were %+v, want 2 workloads and 1 eviction", got)
	}
	if _, ok := store.Activity(WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "first"}); ok {
		t.Fatal("the oldest workload survived eviction while a newer one was dropped")
	}
}

func TestProcessTreeFromAncestry(t *testing.T) {
	store := NewStore(StoreOptions{})
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))
	store.Add(fileEvent(visibleNS, "api", "/etc/passwd", false))

	act, _ := store.Activity(WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "api"})
	if len(act.Processes) != 2 {
		t.Fatalf("the tree had %d roots, want nginx from the exec and pause from the file event", len(act.Processes))
	}
	nginx := act.Processes[0]
	if nginx.Comm != "nginx" {
		t.Fatalf("the busiest root was %q, want nginx", nginx.Comm)
	}
	if len(nginx.Children) != 1 || nginx.Children[0].Comm != "sh" {
		t.Fatalf("nginx's children were %+v, want sh", nginx.Children)
	}
	curl := nginx.Children[0].Children
	if len(curl) != 1 || curl[0].Comm != "curl" || curl[0].Count != 2 || curl[0].Denied != 2 {
		t.Fatalf("the leaf was %+v, want curl seen twice and denied twice", curl)
	}
}

func TestProcessTreeFallsBackToTheParentComm(t *testing.T) {
	// A workload that has not execed anything since the dashboard started must
	// not show an empty tree, which reads as "nothing is running".
	store := NewStore(StoreOptions{})
	store.Add(fileEvent(visibleNS, "api", "/etc/passwd", false))

	act, _ := store.Activity(WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "api"})
	if len(act.Processes) != 1 || act.Processes[0].Comm != "pause" {
		t.Fatalf("the tree was %+v, want a pause root", act.Processes)
	}
	if len(act.Processes[0].Children) != 1 || act.Processes[0].Children[0].Comm != "nginx" {
		t.Fatalf("the tree's second level was %+v, want nginx", act.Processes[0].Children)
	}
}

func TestProcessTreeIsBounded(t *testing.T) {
	store := NewStore(StoreOptions{MaxProcesses: 4})
	for i := 0; i < 50; i++ {
		store.Add(execDenial(visibleNS, "api", "/usr/bin/x", []string{"root", "gen" + string(rune('a'+i%26))}))
	}
	act, _ := store.Activity(WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "api"})
	if !act.ProcessesTruncated {
		t.Fatal("the tree hit its ceiling without saying so, which reads as a workload that " +
			"stopped spawning things")
	}
	counted := 0
	var walk func([]*ProcessNode)
	walk = func(ns []*ProcessNode) {
		for _, n := range ns {
			counted++
			walk(n.Children)
		}
	}
	walk(act.Processes)
	if counted > 4 {
		t.Fatalf("the tree grew to %d nodes past a ceiling of 4", counted)
	}
}

func TestStoreSnapshotIsACopy(t *testing.T) {
	// Handing out the live structures would let a handler read a tree while
	// the event pipeline rewrites it.
	store := NewStore(StoreOptions{})
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx"}))

	first := store.Snapshot()
	first[0].Counts.Denials = 999
	first[0].Processes[0].Comm = "tampered"

	second := store.Snapshot()
	if second[0].Counts.Denials != 1 || second[0].Processes[0].Comm != "nginx" {
		t.Fatalf("mutating a snapshot changed the store: %+v", second[0])
	}
}

func TestStoreIsSafeForConcurrentUse(t *testing.T) {
	store := NewStore(StoreOptions{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				store.Add(fileEvent(visibleNS, "api", "/etc/passwd", j%3 == 0))
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = store.Snapshot()
				_ = store.Stats()
				_ = store.Namespaces()
			}
		}()
	}
	wg.Wait()
	if got := store.Stats().Workloads; got != 1 {
		t.Fatalf("concurrent writers produced %d workloads, want 1", got)
	}
}

func TestStoreSatisfiesTheExportSink(t *testing.T) {
	// Plugging into the same pipeline as the file and webhook sinks is what
	// makes the dashboard and a SIEM see the same event with the same
	// attribution, instead of two representations drifting apart.
	var sink export.Exporter = NewStore(StoreOptions{})
	if err := sink.Export(context.Background(), []*export.Event{
		fileEvent(visibleNS, "api", "/etc/passwd", true),
		nil,
	}); err != nil {
		t.Fatalf("Export returned %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close returned %v", err)
	}
	store := sink.(*Store)
	if got := store.Stats().Workloads; got != 1 {
		t.Fatalf("the sink recorded %d workloads, want 1", got)
	}
	if got := store.Namespaces(); len(got) != 1 || got[0] != visibleNS {
		t.Fatalf("Namespaces returned %v", got)
	}
}

func TestStoreSinkName(t *testing.T) {
	// The name identifies the sink in the export pipeline's logs and metrics;
	// a nameless sink shows up as an anonymous drop counter.
	if got := NewStore(StoreOptions{}).Name(); got != "dashboard" {
		t.Fatalf("Store.Name = %q", got)
	}
}

func TestProcessChain(t *testing.T) {
	tests := []struct {
		name  string
		event *export.Event
		want  []string
	}{
		{
			name:  "no comm at all",
			event: &export.Event{},
			want:  []string{"?"},
		},
		{
			name: "exec ancestry wins",
			event: &export.Event{
				Process: export.ProcessInfo{Comm: "curl", ParentComm: "sh"},
				Exec: &export.ExecInfo{Ancestry: []export.AncestorInfo{
					{Comm: "sh"}, {Comm: "nginx"},
				}},
			},
			want: []string{"nginx", "sh", "curl"},
		},
		{
			name: "ancestry entries with no name are skipped",
			event: &export.Event{
				Process: export.ProcessInfo{Comm: "curl"},
				Exec:    &export.ExecInfo{Ancestry: []export.AncestorInfo{{Comm: ""}, {Comm: "nginx"}}},
			},
			want: []string{"nginx", "curl"},
		},
		{
			// The rendered chain is the fallback when the structured ancestry
			// did not survive whatever produced the event.
			name: "rendered chain",
			event: &export.Event{
				Process: export.ProcessInfo{Comm: "curl"},
				Exec:    &export.ExecInfo{AncestryChain: "nginx -> sh -> curl"},
			},
			want: []string{"nginx", "sh", "curl"},
		},
		{
			name: "parent comm",
			event: &export.Event{
				Process: export.ProcessInfo{Comm: "nginx", ParentComm: "pause"},
			},
			want: []string{"pause", "nginx"},
		},
		{
			// A process whose parent has the same name is one process, not a
			// two-deep chain of itself.
			name: "self parent collapses",
			event: &export.Event{
				Process: export.ProcessInfo{Comm: "nginx", ParentComm: "nginx"},
			},
			want: []string{"nginx"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := processChain(tc.event)
			if len(got) != len(tc.want) {
				t.Fatalf("processChain = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("processChain = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
