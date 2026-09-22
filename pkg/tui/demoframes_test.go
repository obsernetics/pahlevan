package tui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/obsernetics/pahlevan/pkg/export"
)

// The demo GIF shows the console. It is a recording, so it cannot run a live
// cluster, and the last time a recording hand-drew a screen from this tool it
// drifted into claiming ATT&CK techniques the tool did not have.
//
// So the frames are rendered by the real renderer, from a fixture, and written
// to docs/assets/console. The demo prints those files. This test fails when
// they no longer match what the console draws, which is the moment the GIF
// would start showing a screen the tool does not produce.
//
// Regenerate with:  UPDATE_DEMO_FRAMES=1 go test ./pkg/tui/ -run TestDemoFrames

const (
	demoFramesDir = "../../docs/assets/console"

	// The GIF's terminal, measured by recording `tput cols; tput lines` with
	// the tape's own settings: 1200x820 at a 20px font. A frame one column
	// wider than this wraps, and every box border in it breaks.
	demoCols = 84
	demoRows = 24
)

// demoFrames is the order the recording steps through, one keypress apart.
var demoFrames = []struct {
	name string
	view View
}{
	{"overview", ViewOverview},
	{"policies", ViewPolicies},
	{"workloads", ViewWorkloads},
	{"events", ViewEvents},
	{"flows", ViewFlows},
	{"coverage", ViewCoverage},
}

// demoModel is populated with a clock that does not move. The status line
// prints elapsed time, and a frame that says "1s" on a slow machine and "0s"
// on a fast one would make this guard fail for no reason.
func demoModel(t testing.TB) *Model {
	t.Helper()
	fixed := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	m := New(Options{
		Capacity:   64,
		Cluster:    fixtureCluster(),
		SourceName: "node-1:9090",
		Now:        func() time.Time { return fixed },
	})
	sized(m, demoCols, demoRows)
	for _, e := range demoStream() {
		feed(m, e)
	}
	drainCluster(m)
	return m
}

// demoStream is what a real workload looks like to the console: a web server
// and an API doing their ordinary work, which is allowed, and an attacker who
// has a shell in one of them, whose every step is refused.
//
// The shared test fixture uses one path for every file event, which is right
// for a unit test and wrong for a demo: it filled the recorded screen with
// "allow  read /etc/shadow", which reads as Pahlevan permitting exactly the
// thing it exists to stop.
func demoStream() []export.Event {
	at := func(sec int) export.Timestamp {
		return export.Timestamp(time.Date(2026, 9, 19, 12, 0, sec, 0, time.UTC))
	}
	k := func(ns, kind, name string) *export.KubernetesRef {
		return &export.KubernetesRef{Namespace: ns, WorkloadKind: kind, WorkloadName: name,
			Pod: name + "-7c9b4", Node: "node-1"}
	}
	web, api := k("prod", "Deployment", "web"), k("prod", "Deployment", "api")
	allow, deny := export.ActionObserve, export.ActionDeny
	file := func(sec int, a export.Action, comm, path, op string, ref *export.KubernetesRef) export.Event {
		return export.Event{Timestamp: at(sec), Type: export.EventTypeFile, Action: a,
			Process: export.ProcessInfo{Comm: comm}, Kubernetes: ref,
			File: &export.FileInfo{Path: path, SyscallName: op}}
	}
	// A real network event carries both the address the kernel saw and the
	// identity the cluster gave it. The events view shows the address, because
	// that is what was observed; the flows view folds by the identity, because
	// that is what a policy is written against. The fixture has to carry both,
	// or the recording would show one of those views doing the other's job.
	netw := func(sec int, a export.Action, comm, ip, name, kind string, port uint16,
		ref *export.KubernetesRef,
	) export.Event {
		return export.Event{Timestamp: at(sec), Type: export.EventTypeNetwork, Action: a,
			Process: export.ProcessInfo{Comm: comm}, Kubernetes: ref,
			Network: &export.NetworkInfo{
				DestinationIP: ip, DestinationPort: port, Protocol: "TCP",
				DestinationName: name, DestinationKind: kind,
			}}
	}
	exec := func(sec int, a export.Action, comm, bin string, ref *export.KubernetesRef) export.Event {
		return export.Event{Timestamp: at(sec), Type: export.EventTypeProcess, Action: a,
			Process: export.ProcessInfo{Comm: comm}, Kubernetes: ref,
			Exec: &export.ExecInfo{Binary: bin}}
	}
	capa := func(sec int, comm, name string, ref *export.KubernetesRef) export.Event {
		return export.Event{Timestamp: at(sec), Type: export.EventTypeCapability, Action: deny,
			Process: export.ProcessInfo{Comm: comm}, Kubernetes: ref,
			Capability: &export.CapabilityInfo{Name: name}}
	}
	return []export.Event{
		file(1, allow, "nginx", "/etc/nginx/nginx.conf", "read", web),
		file(2, allow, "nginx", "/srv/www/index.html", "read", web),
		netw(3, allow, "python3", "10.104.22.9", "prod/postgres", "service", 5432, api),
		file(4, allow, "python3", "/app/config.yaml", "read", api),
		netw(5, allow, "python3", "10.104.31.4", "prod/redis", "service", 6379, api),
		file(6, allow, "nginx", "/var/log/nginx/access.log", "write", web),
		exec(7, allow, "python3", "/usr/bin/python3", api),
		file(8, allow, "nginx", "/srv/www/app.js", "read", web),
		netw(9, allow, "python3", "10.104.22.9", "prod/postgres", "service", 5432, api),
		file(10, allow, "nginx", "/srv/www/style.css", "read", web),
		// The attacker, with a shell in the API pod.
		file(11, deny, "sh", "/etc/shadow", "read", api),
		exec(12, deny, "sh", "/tmp/xmrig", api),
		netw(13, deny, "sh", "203.0.113.7", "", "", 4444, api),
		capa(14, "sh", "CAP_SYS_ADMIN", api),
		file(15, deny, "sh", "/etc/passwd", "write", api),
		file(16, allow, "nginx", "/srv/www/index.html", "read", web),
		netw(17, allow, "python3", "10.104.22.9", "prod/postgres", "service", 5432, api),
	}
}

func renderDemoFrame(t testing.TB, v View) string {
	t.Helper()
	m := demoModel(t)
	m.setView(v)
	m.clampCursor()
	return m.View()
}

func TestDemoFramesAreCurrent(t *testing.T) {
	// Colour is forced so the recording shows the palette an operator sees.
	// Without it the renderer detects that a test is not a terminal and
	// strips every style, and the frames would be colourless.
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI256)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	update := os.Getenv("UPDATE_DEMO_FRAMES") == "1"
	if update {
		if err := os.MkdirAll(demoFramesDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, f := range demoFrames {
		got := renderDemoFrame(t, f.view)
		path := filepath.Join(demoFramesDir, f.name+".ansi")

		if w := lipgloss.Width(firstLineOf(got)); w > demoCols {
			t.Errorf("%s renders %d columns wide; the recording's terminal is %d, so it would wrap", f.name, w, demoCols)
		}

		if update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v\nregenerate with: UPDATE_DEMO_FRAMES=1 go test ./pkg/tui/ -run TestDemoFrames", path, err)
		}
		if string(want) != got {
			t.Errorf("%s no longer matches what the console draws, so the demo GIF would show a screen the tool does not produce.\n"+
				"regenerate with: UPDATE_DEMO_FRAMES=1 go test ./pkg/tui/ -run TestDemoFrames", path)
		}
	}
}

func firstLineOf(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
