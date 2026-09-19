package tui

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// fakeCluster is the fixture the cluster views are driven from. It exists so
// the console can be tested without an API server: a screen that can only be
// exercised against a live cluster is a screen that is never exercised.
type fakeCluster struct {
	policies []Policy
	profiles []Profile
	surfaces []AttackSurface
	err      error

	mu    sync.Mutex
	calls []string
	block chan struct{}
}

func (f *fakeCluster) record(name string) {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
}

func (f *fakeCluster) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeCluster) Policies(context.Context) ([]Policy, error) {
	f.record("Policies")
	return f.policies, f.err
}

func (f *fakeCluster) Profiles(context.Context) ([]Profile, error) {
	f.record("Profiles")
	return f.profiles, f.err
}

func (f *fakeCluster) AttackSurfaces(context.Context) ([]AttackSurface, error) {
	f.record("AttackSurfaces")
	return f.surfaces, f.err
}

func fixtureCluster() *fakeCluster {
	return &fakeCluster{
		policies: []Policy{
			{
				Namespace: "prod", Name: "api", Phase: "Enforcing", Mode: "Blocking",
				Selector: "app=api", Containers: 6, Enforcing: 6, Denials: 14,
				Workloads: []string{"Deployment/api"},
				Rules: []string{
					"file read /etc/nginx/nginx.conf",
					"file read /usr/share/nginx/html/index.html",
					"network tcp 10.96.0.10:53",
					"exec /usr/sbin/nginx",
					"capability CAP_NET_BIND_SERVICE",
				},
				Updated: time.Date(2026, 9, 19, 11, 58, 0, 0, time.UTC),
			},
			{
				Namespace: "prod", Name: "payments", Phase: "Learning", Mode: "Monitoring",
				Selector: "app=payments", Learning: true, Progress: 62,
				Containers: 4, Enforcing: 0,
				Workloads:  []string{"Deployment/payments"},
				Rules:      []string{"file read /etc/ssl/certs/ca-certificates.crt"},
			},
			{
				Namespace: "kube-system", Name: "cni", Phase: "Failed", Mode: "Blocking",
				Selector: "k8s-app=cni", Containers: 3, Enforcing: 1, Denials: 208,
			},
		},
		profiles: []Profile{
			{
				Namespace: "prod", Name: "api-7c9b4-nginx", Node: "node-1", Container: "nginx",
				Phase: "Enforcing", Syscalls: 48, Files: 112, Network: 6, Execs: 3, Capabilities: 1,
				Denials: 14, FirstSeen: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC),
				EnforcingSince: time.Date(2026, 9, 19, 10, 30, 0, 0, time.UTC),
			},
			{
				Namespace: "prod", Name: "payments-5f8-app", Node: "node-2", Container: "app",
				Phase: "Learning", Syscalls: 31, Files: 74, Network: 9, Execs: 2, Capabilities: 0,
			},
		},
		surfaces: []AttackSurface{
			{
				Namespace: "prod", Name: "api", Risk: 72,
				Ports:         []int32{80, 443, 9090},
				Syscalls:      []string{"ptrace", "mount", "setuid"},
				WritableFiles: []string{"/var/run/secrets/kubernetes.io/serviceaccount/token", "/tmp"},
				Capabilities:  []string{"CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"},
				Analyzed:      time.Date(2026, 9, 19, 11, 55, 0, 0, time.UTC),
			},
			{
				Namespace: "prod", Name: "payments", Risk: 18,
				Ports: []int32{8443},
			},
		},
	}
}

// deliver runs a command the way the Bubble Tea runtime would and feeds the
// result back into Update, so a test can watch a fetch land.
func deliver(m *Model, cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	switch msg := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			deliver(m, c)
		}
	default:
		m.Update(msg)
	}
}

// drainCluster fetches everything and applies it, leaving the model in the
// state it would be in a second after opening.
func drainCluster(m *Model) { deliver(m, m.refreshAll()) }

func TestClusterIsAReadOnlyInterface(t *testing.T) {
	// The console is the thing an operator opens while an incident is in
	// progress. If it could write, a mistyped key could turn enforcement off
	// at the worst possible moment, so the only door into the cluster is an
	// interface with nothing but readers on it.
	typ := reflect.TypeOf((*Cluster)(nil)).Elem()
	if got := typ.NumMethod(); got != 3 {
		t.Fatalf("the Cluster interface has %d methods, want 3 readers", got)
	}
	forbidden := []string{"set", "update", "create", "delete", "patch", "apply", "write", "enforce", "rollback"}
	for i := 0; i < typ.NumMethod(); i++ {
		meth := typ.Method(i)
		lower := strings.ToLower(meth.Name)
		for _, verb := range forbidden {
			if strings.HasPrefix(lower, verb) {
				t.Errorf("Cluster.%s looks like a writer; the console must not be able to change the cluster", meth.Name)
			}
		}
		ft := meth.Type
		if ft.NumIn() != 1 || ft.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
			t.Errorf("Cluster.%s takes %d arguments; a reader takes a context and nothing else", meth.Name, ft.NumIn())
		}
		if ft.NumOut() != 2 || ft.Out(0).Kind() != reflect.Slice ||
			ft.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
			t.Errorf("Cluster.%s does not return a list and an error", meth.Name)
		}
	}
}

func TestTheConsoleDoesNotImportAKubernetesClient(t *testing.T) {
	// Everything the cluster views need arrives through the Cluster
	// interface. A client-go import here would drag a scheme, a rest config
	// and a write path into a package whose whole contract is that it cannot
	// change anything.
	banned := []string{
		"k8s.io/client-go",
		"sigs.k8s.io/controller-runtime",
		"k8s.io/api/",
		"k8s.io/apimachinery",
		"github.com/obsernetics/pahlevan/pkg/apis",
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			for _, imp := range file.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				for _, b := range banned {
					if strings.HasPrefix(path, b) {
						t.Errorf("%s imports %q; the console reads the cluster through the Cluster interface, not a client", name, path)
					}
				}
			}
			_ = ast.Print
		}
	}
}

func TestANilClusterSaysSoRatherThanShowingAnEmptyCluster(t *testing.T) {
	// `--replay` has no cluster. An empty table would read as "this cluster
	// has no policies", which is a very different statement from "I was never
	// given a cluster to ask".
	m := sized(New(Options{}), 120, 30)
	for _, v := range []View{ViewOverview, ViewPolicies, ViewProfiles, ViewSurface} {
		m.view = v
		m.clampCursor()
		out := m.View()
		if !strings.Contains(out, "no cluster") {
			t.Errorf("%v does not say there is no cluster:\n%s", v, out)
		}
	}
	// And nothing is fetched, so there is no command to run and nothing to
	// nil-dereference on the way.
	if cmd := m.refreshAll(); cmd != nil {
		t.Error("a nil cluster still issued a fetch")
	}
	if cmd := m.refreshStale(); cmd != nil {
		t.Error("a nil cluster still issued a refresh")
	}
}

func TestAFailedFetchShowsInThePaneAndKeepsTheConsoleRunning(t *testing.T) {
	broken := fixtureCluster()
	broken.err = errors.New("Get \"https://10.96.0.1/apis\": connection refused")
	m := sized(New(Options{Cluster: broken}), 120, 30)
	drainCluster(m)

	if m.policies.err == nil {
		t.Fatal("the failed fetch was not recorded")
	}
	m.view = ViewPolicies
	m.clampCursor()
	out := m.View()
	if !strings.Contains(out, "connection refused") {
		t.Errorf("the policies pane does not say why it is empty:\n%s", out)
	}
	if !strings.Contains(out, "stale") {
		t.Errorf("the pane title does not mark the data as stale:\n%s", out)
	}
	// The console keeps working: events still arrive and the frame still draws.
	feed(m, ev("file", true, "python3", "prod", "Deployment", "api"))
	if m.total != 1 {
		t.Error("the console stopped ingesting events after a failed fetch")
	}
	if m.quitting {
		t.Error("a failed fetch quit the program")
	}
}

func TestAFailedRefreshKeepsWhatWasAlreadyRead(t *testing.T) {
	// Stale data with a visible error beats an empty screen: during an
	// incident the last known phase of a policy is worth more than a blank.
	c := fixtureCluster()
	m := sized(New(Options{Cluster: c}), 120, 30)
	drainCluster(m)
	if len(m.policies.items) != 3 {
		t.Fatalf("the fixture loaded %d policies, want 3", len(m.policies.items))
	}

	c.err = errors.New("etcdserver: request timed out")
	drainCluster(m)
	if len(m.policies.items) != 3 {
		t.Errorf("a failed refresh dropped the %d policies already read", len(m.policies.items))
	}
	if m.policies.err == nil {
		t.Error("the failure was not recorded alongside the stale data")
	}
}

func TestAFetchNeverBlocksUpdate(t *testing.T) {
	// Update runs on the same goroutine as the event stream, the clock and
	// the keyboard. A cluster read inside it would freeze all three, and the
	// first symptom an operator sees is a console they think has died.
	c := fixtureCluster()
	c.block = make(chan struct{})
	defer close(c.block)

	m := sized(New(Options{Cluster: c}), 120, 30)
	done := make(chan tea.Cmd, 1)
	go func() {
		_, cmd := m.Update(keyMsg("r"))
		done <- cmd
	}()

	select {
	case cmd := <-done:
		if cmd == nil {
			t.Fatal("r returned no command, so nothing would be fetched")
		}
		// Running the command is what blocks, on its own goroutine.
		go deliver(m, cmd)
	case <-time.After(2 * time.Second):
		t.Fatal("Update blocked on a cluster read")
	}

	// The console stays responsive while the read is outstanding.
	press(m, "2")
	if m.view != ViewPolicies {
		t.Error("the keyboard stopped working while a fetch was in flight")
	}
	_ = m.View()
}

func TestRefreshSkipsWhatIsAlreadyInFlight(t *testing.T) {
	// The refresh rides the one-second clock tick. Without the in-flight
	// guard, an API server that takes ten seconds to answer would be sent ten
	// more requests while it was thinking about the first.
	c := fixtureCluster()
	m := sized(New(Options{Cluster: c}), 120, 30)
	m.policies.loading = true
	m.profiles.loading = true
	m.surfaces.loading = true

	if cmd := m.refreshStale(); cmd != nil {
		t.Error("a refresh was issued while every read was already in flight")
	}
	if got := c.called(); len(got) != 0 {
		t.Errorf("the cluster was called %v despite the reads in flight", got)
	}
}

func TestOnlyStaleResourcesAreReRead(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	c := fixtureCluster()
	m := New(Options{Cluster: c, Now: func() time.Time { return now }})
	m.policies.fetched = now.Add(-refreshEvery - time.Second)
	m.profiles.fetched = now
	m.surfaces.fetched = now

	deliver(m, m.refreshStale())
	got := c.called()
	if len(got) != 1 || got[0] != "Policies" {
		t.Errorf("the refresh called %v, want only the stale Policies read", got)
	}
}

func TestTheClusterViewsRenderWhatTheFixtureReturned(t *testing.T) {
	m := sized(New(Options{Cluster: fixtureCluster()}), 200, 40)
	drainCluster(m)

	for _, tc := range []struct {
		view View
		want []string
	}{
		{ViewOverview, []string{"policies", "learning", "enforcing", "62%"}},
		{ViewPolicies, []string{"payments", "Learning", "Monitoring", "Failed", "6/6"}},
		{ViewProfiles, []string{"api-7c9b4-nginx", "node-1", "Enforcing", "112"}},
		{ViewSurface, []string{"api", "72", "ptrace", "CAP_SYS_ADMIN"}},
	} {
		t.Run(tc.view.String(), func(t *testing.T) {
			m.view = tc.view
			m.clampCursor()
			out := m.View()
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("the %v view does not show %q:\n%s", tc.view, want, out)
				}
			}
		})
	}
}

func TestThePolicyDetailPaneShowsTheResolvedRules(t *testing.T) {
	m := sized(New(Options{Cluster: fixtureCluster()}), 200, 40)
	drainCluster(m)
	m.view = ViewPolicies
	// The list is sorted by namespace and name, so prod/api is the second row.
	m.cursors[ViewPolicies] = 1
	m.clampCursor()

	out := m.View()
	if !strings.Contains(out, "RESOLVED RULES") {
		t.Fatalf("the policy detail pane has no rules section:\n%s", out)
	}
	if !strings.Contains(out, "/etc/nginx/nginx.conf") {
		t.Errorf("the detail pane does not list the first resolved rule:\n%s", out)
	}
	// A policy with no rules resolved yet must say so rather than show a gap.
	m.cursors[ViewPolicies] = 0 // kube-system/cni
	m.clampCursor()
	if out := m.View(); !strings.Contains(out, "none resolved yet") {
		t.Errorf("a policy with no rules renders an empty section:\n%s", out)
	}
}

func TestClusterListsAreReplacedNotAccumulated(t *testing.T) {
	// A view that appended every fetch would grow without bound on a console
	// left open overnight, which is exactly how these are used.
	c := fixtureCluster()
	m := sized(New(Options{Cluster: c}), 120, 30)
	for i := 0; i < 20; i++ {
		drainCluster(m)
	}
	if got := len(m.policies.items); got != 3 {
		t.Errorf("20 refreshes left %d policies, want the 3 the cluster has", got)
	}
	if got := len(m.profiles.items); got != 2 {
		t.Errorf("20 refreshes left %d profiles, want 2", got)
	}
	if got := len(m.surfaces.items); got != 2 {
		t.Errorf("20 refreshes left %d attack surfaces, want 2", got)
	}
}

func TestDrivingEveryKeyOnEveryViewOnlyEverReads(t *testing.T) {
	// The property the console promises: whatever you press, wherever you
	// are, the cluster is only ever read from.
	c := fixtureCluster()
	m := sized(New(Options{Cluster: c}), 120, 30)
	drainCluster(m)

	for _, v := range allViews {
		m.view = v
		m.clampCursor()
		for _, k := range []string{
			"j", "k", "g", "G", "pgdown", "pgup", "enter", "esc", " ", "c", "r",
			"tab", "shift+tab", "1", "7", "?", "/", "a", "enter",
		} {
			press(m, k)
			_ = m.View()
		}
	}
	for _, name := range c.called() {
		switch name {
		case "Policies", "Profiles", "AttackSurfaces":
		default:
			t.Errorf("the console called %s, which is not a read", name)
		}
	}
	if m.quitting {
		t.Error("driving the keyboard quit the console")
	}
}

// BenchmarkFetchToRenderPolicies measures the whole path a refresh takes:
// the command runs, the message lands, and the pane redraws.
func BenchmarkFetchToRenderPolicies(b *testing.B) {
	m := sized(New(Options{Cluster: fixtureCluster()}), 120, 40)
	m.view = ViewPolicies
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deliver(m, fetchPolicies(context.Background(), m.cluster))
		_ = m.View()
	}
}

func BenchmarkFetchToRenderProfiles(b *testing.B) {
	m := sized(New(Options{Cluster: fixtureCluster()}), 120, 40)
	m.view = ViewProfiles
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deliver(m, fetchProfiles(context.Background(), m.cluster))
		_ = m.View()
	}
}

func BenchmarkFetchToRenderSurfaces(b *testing.B) {
	m := sized(New(Options{Cluster: fixtureCluster()}), 120, 40)
	m.view = ViewSurface
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deliver(m, fetchSurfaces(context.Background(), m.cluster))
		_ = m.View()
	}
}
