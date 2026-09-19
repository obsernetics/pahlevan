package commands

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
	"github.com/obsernetics/pahlevan/pkg/tui"
)

// neutralTerminalEnv clears every environment signal that forces the plain
// path, so a case that is meant to test one reason is not silently passing
// because of another one inherited from whoever ran the tests.
func neutralTerminalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CI", "")
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
}

func uiEvent(typ export.EventType, denied bool, comm string, k *export.KubernetesRef) export.Event {
	e := export.Event{
		Version:    export.SchemaVersion,
		Timestamp:  export.Timestamp(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)),
		Type:       typ,
		Action:     export.ActionObserve,
		Process:    export.ProcessInfo{PID: 1, Comm: comm},
		Kubernetes: k,
	}
	if denied {
		e.Action = export.ActionDeny
	}
	switch typ {
	case export.EventTypeFile:
		e.File = &export.FileInfo{Path: "/etc/shadow", SyscallName: "read"}
	case export.EventTypeNetwork:
		e.Network = &export.NetworkInfo{DestinationIP: "203.0.113.7", DestinationPort: 4444, Protocol: "TCP"}
	case export.EventTypeProcess:
		e.Exec = &export.ExecInfo{Binary: "/tmp/xmrig"}
	case export.EventTypeCapability:
		e.Capability = &export.CapabilityInfo{Name: "CAP_SYS_ADMIN"}
	case export.EventTypeSyscall:
		e.Syscall = &export.SyscallInfo{Name: "ptrace", Number: 101}
	}
	return e
}

func TestInteractiveRefusesToDrawWhenNothingIsWatching(t *testing.T) {
	// A program that writes escape codes into a pipe is worse than one with no
	// interface at all: it corrupts the file the pipeline was collecting. Every
	// reason to fall back is checked here, one case per reason, so a change
	// that drops one of them fails on that case and not on a lucky default.
	regular := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(regular)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	for _, tc := range []struct {
		name string
		env  func(t *testing.T)
		opts *uiOptions
		out  io.Writer
	}{
		{
			name: "the operator asked for plain output",
			opts: &uiOptions{noTUI: true},
			out:  os.Stdout,
		},
		{
			name: "running under CI",
			env:  func(t *testing.T) { t.Setenv("CI", "true") },
			opts: &uiOptions{},
			out:  os.Stdout,
		},
		{
			name: "NO_COLOR asks for plain text",
			env:  func(t *testing.T) { t.Setenv("NO_COLOR", "1") },
			opts: &uiOptions{},
			out:  os.Stdout,
		},
		{
			name: "a terminal that cannot address a cursor",
			env:  func(t *testing.T) { t.Setenv("TERM", "dumb") },
			opts: &uiOptions{},
			out:  os.Stdout,
		},
		{
			name: "the writer is not a file at all",
			opts: &uiOptions{},
			out:  &bytes.Buffer{},
		},
		{
			name: "output is redirected into a regular file",
			opts: &uiOptions{},
			out:  f,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			neutralTerminalEnv(t)
			if tc.env != nil {
				tc.env(t)
			}
			assert.False(t, interactive(tc.opts, tc.out),
				"the view must fall back to plain output")
		})
	}
}

func TestRedirectingToDevNullIsNotATerminal(t *testing.T) {
	// /dev/null is a character device, so a mode test called it a terminal and
	// `pahlevan ui > /dev/null` then died trying to open a TTY that is not
	// there. The question being asked is whether the descriptor is a terminal,
	// which is not the same as whether it is a character device.
	dev, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no character device to test against: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })

	neutralTerminalEnv(t)
	assert.False(t, interactive(&uiOptions{}, dev),
		"redirecting to /dev/null must fall back rather than try to draw")
}

func TestInteractiveDrawsOnARealTerminal(t *testing.T) {
	// Without a case that returns true, every check above would pass on a
	// function changed to return false unconditionally. A pty is the only
	// honest way to get one.
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })

	neutralTerminalEnv(t)
	assert.True(t, interactive(&uiOptions{}, ptmx),
		"a real terminal must draw, or the fallback checks prove nothing")
}

func TestRunPlainPrintsAStableSummaryWithNoEscapeCodes(t *testing.T) {
	// This is the guarantee that scripts do not break. A single escape byte in
	// this output is a broken grep in somebody's pipeline, and it would arrive
	// silently: the summary still looks right on the screen of whoever added it.
	events := []export.Event{
		uiEvent(export.EventTypeFile, false, "nginx", &export.KubernetesRef{
			Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Pod: "api-aaaa"}),
		uiEvent(export.EventTypeFile, false, "nginx", &export.KubernetesRef{
			Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Pod: "api-bbbb"}),
		uiEvent(export.EventTypeFile, true, "python3", &export.KubernetesRef{
			Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Pod: "api-aaaa"}),
		uiEvent(export.EventTypeNetwork, false, "curl", &export.KubernetesRef{
			Namespace: "kube-system", Pod: "cni-abc"}),
		uiEvent(export.EventTypeProcess, false, "sh", nil),
	}
	events[4].CgroupID = 4242

	var buf bytes.Buffer
	src := &tui.SliceSource{Events: events, Name: "capture.jsonl"}
	require.NoError(t, runPlain(context.Background(), src, &buf))
	out := buf.String()

	assert.NotContains(t, out, "\x1b", "the plain summary must contain no ANSI escape byte")

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 9)
	assert.Equal(t, "source\tcapture.jsonl", lines[0])
	assert.Equal(t, "events\t5", lines[1])
	assert.Equal(t, "denied\t1", lines[2])
	assert.Equal(t, "workloads\t3", lines[3])
	assert.Equal(t, "", lines[4])
	assert.Equal(t,
		[]string{"WORKLOAD", "FILE", "NET", "EXEC", "CAP", "SYSCALL", "DENIED"},
		strings.Fields(lines[5]))

	// Rows are sorted so two runs over the same capture diff cleanly.
	assert.Equal(t, [][]string{
		{"cgroup:4242", "0", "0", "1", "0", "0", "0"},
		{"kube-system/Pod/cni-abc", "0", "1", "0", "0", "0", "0"},
		{"prod/Deployment/api", "3", "0", "0", "0", "0", "1"},
	}, [][]string{
		strings.Fields(lines[6]),
		strings.Fields(lines[7]),
		strings.Fields(lines[8]),
	})
}

func TestRunPlainReportsASourceFailureRatherThanPrintingAnEmptySummary(t *testing.T) {
	// A summary of zero events from a capture that failed to read looks
	// exactly like a quiet node, which is the wrong conclusion to hand someone.
	var buf bytes.Buffer
	src := &tui.ReaderSource{R: strings.NewReader("not json\n"), Name: "capture.jsonl"}
	err := runPlain(context.Background(), src, &buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capture.jsonl")
}

func TestWorkloadKeyForMatchesTheInteractiveViewsGrouping(t *testing.T) {
	// The plain summary and the drawn view have separate implementations of
	// the same grouping. If they drift, the same capture names the same
	// workload two different ways depending on whether stdout is a terminal.
	for _, tc := range []struct {
		name string
		e    export.Event
		want string
	}{
		{
			name: "a full workload attribution",
			e: uiEvent(export.EventTypeFile, false, "nginx", &export.KubernetesRef{
				Namespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", Pod: "api-aaaa"}),
			want: "prod/Deployment/api",
		},
		{
			name: "a pod with no owning workload",
			e: uiEvent(export.EventTypeFile, false, "sh", &export.KubernetesRef{
				Namespace: "kube-system", Pod: "cni-abc"}),
			want: "kube-system/Pod/cni-abc",
		},
		{
			name: "a reference carrying neither a workload nor a pod",
			e: uiEvent(export.EventTypeFile, false, "sh", &export.KubernetesRef{
				Namespace: "prod", Node: "node-1"}),
			want: "cgroup:99",
		},
		{
			name: "no Kubernetes attribution at all",
			e:    uiEvent(export.EventTypeFile, false, "sh", nil),
			want: "cgroup:99",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.e
			e.CgroupID = 99
			assert.Equal(t, tc.want, workloadKeyFor(e))

			// Cross-check against the model itself: the workloads screen is
			// where the interactive side spells the key out.
			m := tui.New(tui.Options{})
			m.Update(tea.WindowSizeMsg{Width: 200, Height: 40})
			m.Update(tui.EventMsg{Event: e})
			// The number keys address the tab order, so the digit for the
			// workloads screen is derived from the view constant rather than
			// written out: a screen inserted before it moves the digit, and a
			// hardcoded "2" then silently asserts against a different table.
			workloadsKey := strconv.Itoa(int(tui.ViewWorkloads) + 1)
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(workloadsKey)})
			assert.Contains(t, m.View(), tc.want,
				"the interactive view groups this event under a different name")
		})
	}
}

func TestProtoEventToExportCarriesEveryDetailVariant(t *testing.T) {
	// One missing case here is one event type that renders as a blank line in
	// the view while the agent is reporting it perfectly well.
	for _, tc := range []struct {
		name   string
		in     *apiv1alpha1.Event
		verify func(t *testing.T, got export.Event)
	}{
		{
			name: "a syscall",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_SYSCALL, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_Syscall{Syscall: &apiv1alpha1.SyscallInfo{Number: 101, Name: "ptrace"}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.Syscall)
				assert.Equal(t, uint64(101), got.Syscall.Number)
				assert.Equal(t, "ptrace", got.Syscall.Name)
				assert.Equal(t, export.EventTypeSyscall, got.Type)
			},
		},
		{
			name: "a file read",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_FILE, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_File{File: &apiv1alpha1.FileInfo{Path: "/etc/shadow", Flags: 3}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.File)
				assert.Equal(t, "/etc/shadow", got.File.Path)
				// Read and write are separate allow-set entries in the kernel,
				// so a view that called both "open" would hide the difference.
				assert.Equal(t, "read", got.File.SyscallName)
				assert.Equal(t, uint32(3), got.File.Flags)
			},
		},
		{
			name: "a file write",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_FILE, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_File{File: &apiv1alpha1.FileInfo{Path: "/etc/shadow", Write: true}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.File)
				assert.Equal(t, "write", got.File.SyscallName)
			},
		},
		{
			name: "a connection to an address nothing claims",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_NETWORK, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_Network{Network: &apiv1alpha1.NetworkInfo{
					DestinationIp: "203.0.113.7", DestinationPort: 4444,
					Protocol: "TCP", Direction: "egress",
				}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.Network)
				assert.Equal(t, "203.0.113.7", got.Network.DestinationIP)
				assert.Equal(t, uint16(4444), got.Network.DestinationPort)
				assert.Equal(t, "TCP", got.Network.Protocol)
				assert.Equal(t, "egress", got.Network.Direction)
			},
		},
		{
			name: "a connection the cluster can name",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_NETWORK, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_Network{Network: &apiv1alpha1.NetworkInfo{
					DestinationIp: "10.104.22.9", DestinationPort: 5432,
					Protocol: "TCP", DestinationName: "prod/postgres",
				}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.Network)
				// "denied connect to prod/postgres" is something an operator
				// can act on; the address is a lookup they have to go and do.
				assert.Equal(t, "prod/postgres", got.Network.DestinationIP)
			},
		},
		{
			name: "an exec with its ancestry",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_PROCESS, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_Exec{Exec: &apiv1alpha1.ExecInfo{
					Binary: "/usr/bin/nc", AncestryChain: "nginx -> sh -> nc",
				}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.Exec)
				assert.Equal(t, "/usr/bin/nc", got.Exec.Binary)
				assert.Equal(t, "nginx -> sh -> nc", got.Exec.AncestryChain)
			},
		},
		{
			name: "a capability check",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_CAPABILITY, Timestamp: "2026-09-19T12:00:00Z",
				Detail: &apiv1alpha1.Event_Capability{Capability: &apiv1alpha1.CapabilityInfo{
					Number: 21, Name: "CAP_SYS_ADMIN",
				}},
			},
			verify: func(t *testing.T, got export.Event) {
				require.NotNil(t, got.Capability)
				assert.Equal(t, uint32(21), got.Capability.Number)
				assert.Equal(t, "CAP_SYS_ADMIN", got.Capability.Name)
			},
		},
		{
			name: "an event with no detail at all",
			in: &apiv1alpha1.Event{
				Type: apiv1alpha1.EventType_EVENT_TYPE_FILE, Timestamp: "2026-09-19T12:00:00Z",
			},
			verify: func(t *testing.T, got export.Event) {
				assert.Nil(t, got.File)
				assert.Nil(t, got.Network)
				assert.Nil(t, got.Exec)
				assert.Nil(t, got.Capability)
				assert.Nil(t, got.Syscall)
				assert.Equal(t, export.EventTypeFile, got.Type)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := protoEventToExport(tc.in)
			tc.verify(t, got)
		})
	}
}

func TestProtoEventToExportCarriesTheEnvelopeAroundTheDetail(t *testing.T) {
	got := protoEventToExport(&apiv1alpha1.Event{
		Version:   export.SchemaVersion,
		Type:      apiv1alpha1.EventType_EVENT_TYPE_PROCESS,
		Action:    apiv1alpha1.Action_ACTION_DENY,
		Timestamp: "2026-09-19T12:00:00.5Z",
		CgroupId:  4242,
		Process: &apiv1alpha1.ProcessInfo{
			Pid: 400, Tgid: 400, Uid: 0, Gid: 0, Comm: "nc", Ppid: 1, ParentComm: "sh",
		},
		Kubernetes: &apiv1alpha1.KubernetesRef{
			Namespace: "prod", Pod: "api-aaaa", Container: "app", Node: "node-1",
			WorkloadKind: "Deployment", WorkloadName: "api",
		},
		Detail: &apiv1alpha1.Event_Exec{Exec: &apiv1alpha1.ExecInfo{Binary: "/usr/bin/nc"}},
	})

	assert.Equal(t, export.SchemaVersion, got.Version)
	assert.Equal(t, export.EventTypeProcess, got.Type)
	assert.True(t, got.Denied(), "a denial that renders as an observation is the wrong verdict")
	assert.Equal(t, uint64(4242), got.CgroupID)
	assert.Equal(t, "nc", got.Process.Comm)
	// A denied open attributed only to "nc" says what was refused and not who
	// tried; the parent is what makes it a finding.
	assert.Equal(t, "sh", got.Process.ParentComm)
	require.NotNil(t, got.Kubernetes)
	assert.Equal(t, "prod", got.Kubernetes.Namespace)
	assert.Equal(t, "node-1", got.Kubernetes.Node)
	assert.Equal(t, "app", got.Kubernetes.Container)
	assert.Equal(t,
		time.Date(2026, 9, 19, 12, 0, 0, 500000000, time.UTC),
		got.Timestamp.Time().UTC())
}

func TestProtoEventToExportKeepsAnEventWithAnUnreadableTimestamp(t *testing.T) {
	// The rest of the event is still true. Dropping it would mean a denial
	// goes unseen because an agent formatted one field badly.
	before := time.Now()
	got := protoEventToExport(&apiv1alpha1.Event{
		Type:      apiv1alpha1.EventType_EVENT_TYPE_FILE,
		Action:    apiv1alpha1.Action_ACTION_DENY,
		Timestamp: "yesterday afternoon",
		Process:   &apiv1alpha1.ProcessInfo{Comm: "python3"},
		Detail:    &apiv1alpha1.Event_File{File: &apiv1alpha1.FileInfo{Path: "/etc/shadow"}},
	})
	after := time.Now()

	require.NotNil(t, got.File)
	assert.Equal(t, "/etc/shadow", got.File.Path)
	assert.Equal(t, "python3", got.Process.Comm)
	assert.True(t, got.Denied())

	ts := got.Timestamp.Time()
	assert.False(t, ts.IsZero(), "a zero stamp would sort the event to the top of the list forever")
	assert.False(t, ts.Before(before) || ts.After(after),
		"an unparseable stamp should fall back to now, got %v", ts)
}

func TestProtoEventToExportOnANilEvent(t *testing.T) {
	// The gRPC stream can hand back a nil message on a shutdown race, and a
	// nil dereference there takes down the terminal with the connection.
	got := protoEventToExport(nil)
	assert.Equal(t, export.Event{}, got)
}

func TestBuildSourceChoosesWhereEventsComeFrom(t *testing.T) {
	t.Run("the default is the agent on this node", func(t *testing.T) {
		src, closeSrc, err := buildSource(&uiOptions{grpcAddr: "localhost:9090"})
		require.NoError(t, err)
		require.NotNil(t, closeSrc)
		defer closeSrc()
		require.IsType(t, &grpcSource{}, src)
		assert.Equal(t, "localhost:9090", src.Describe(),
			"the status line has to say which agent is not answering")
	})

	t.Run("a replay file needs no cluster", func(t *testing.T) {
		// This is what makes a UI bug reproducible from a bug report.
		path := filepath.Join(t.TempDir(), "capture.jsonl")
		require.NoError(t, os.WriteFile(path, []byte(
			`{"version":"pahlevan.io/v1alpha1","timestamp":"2026-09-19T12:00:00Z",`+
				`"type":"file","action":"deny","file":{"path":"/etc/shadow"}}`+"\n"), 0o600))

		src, closeSrc, err := buildSource(&uiOptions{replay: path})
		require.NoError(t, err)
		rs, ok := src.(*tui.ReaderSource)
		require.True(t, ok, "a replay must read the file, not dial anything")
		assert.Equal(t, path, src.Describe())

		out := make(chan export.Event, 4)
		require.NoError(t, rs.Run(context.Background(), out))
		require.Len(t, out, 1)
		got := <-out
		assert.True(t, got.Denied())

		// The returned closer owns the file handle; a UI that ran for hours
		// without it would hold a descriptor per replay.
		closeSrc()
		f, ok := rs.R.(*os.File)
		require.True(t, ok)
		_, err = f.Read(make([]byte, 1))
		assert.Error(t, err, "the replay file was left open")
	})

	t.Run("a replay file that is not there names itself", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-such-capture.jsonl")
		src, closeSrc, err := buildSource(&uiOptions{replay: missing})
		require.Error(t, err)
		assert.Nil(t, src)
		assert.Nil(t, closeSrc)
		assert.Contains(t, err.Error(), missing,
			"an error that does not name the file leaves the operator guessing at a typo")
	})

	t.Run("a dash replays standard input", func(t *testing.T) {
		src, closeSrc, err := buildSource(&uiOptions{replay: "-"})
		require.NoError(t, err)
		require.NotNil(t, closeSrc)
		defer closeSrc()
		rs, ok := src.(*tui.ReaderSource)
		require.True(t, ok)
		assert.Same(t, os.Stdin, rs.R, "'-' must read the pipe, not a file named '-'")
		assert.Equal(t, "stdin", src.Describe())
	})
}

func TestNewUICommandWiring(t *testing.T) {
	cmd := NewUICommand()
	assert.Equal(t, "ui", cmd.Use)
	for _, name := range []string{"grpc", "replay", "capacity", "no-tui"} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "the %s flag is missing", name)
	}
	assert.Equal(t, "localhost:9090", cmd.Flags().Lookup("grpc").DefValue)
	// The view is a reader. A flag that changed a mode or a policy would make
	// it the thing that turns enforcement off during an incident.
	for _, name := range []string{"mode", "enforce", "policy"} {
		assert.Nil(t, cmd.Flags().Lookup(name), "the read-only view must not expose %s", name)
	}
}

// BenchmarkProtoEventToExport runs the per-event conversion on the gRPC path.
// It is paid once per event on a stream that can carry thousands a second.
func BenchmarkProtoEventToExport(b *testing.B) {
	ev := &apiv1alpha1.Event{
		Version:   export.SchemaVersion,
		Type:      apiv1alpha1.EventType_EVENT_TYPE_FILE,
		Action:    apiv1alpha1.Action_ACTION_DENY,
		Timestamp: "2026-09-19T12:00:00Z",
		CgroupId:  4242,
		Process:   &apiv1alpha1.ProcessInfo{Pid: 400, Comm: "python3", Ppid: 1, ParentComm: "sh"},
		Kubernetes: &apiv1alpha1.KubernetesRef{
			Namespace: "prod", Pod: "api-aaaa", Node: "node-1",
			WorkloadKind: "Deployment", WorkloadName: "api",
		},
		Detail: &apiv1alpha1.Event_File{File: &apiv1alpha1.FileInfo{Path: "/etc/shadow"}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = protoEventToExport(ev)
	}
}

func TestRunUITakesThePlainPathWhenItCannotDraw(t *testing.T) {
	// The end to end shape of the pipeline case: a replay into a writer that
	// is not a terminal has to produce the summary and never a screen, because
	// `pahlevan ui --replay x | tee report.txt` is a documented usage.
	neutralTerminalEnv(t)
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(
		`{"version":"pahlevan.io/v1alpha1","timestamp":"2026-09-19T12:00:00Z","type":"file",`+
			`"action":"deny","process":{"pid":1,"comm":"python3","uid":0},`+
			`"file":{"path":"/etc/shadow"},`+
			`"kubernetes":{"namespace":"prod","pod":"api-aaaa","workloadKind":"Deployment","workloadName":"api"}}`+"\n"), 0o600))

	var out, errOut bytes.Buffer
	require.NoError(t, runUI(context.Background(), &uiOptions{replay: path}, &out, &errOut))

	got := out.String()
	assert.NotContains(t, got, "\x1b", "the piped path must never write an escape code")
	assert.Contains(t, got, "events\t1")
	assert.Contains(t, got, "denied\t1")
	assert.Contains(t, got, "prod/Deployment/api")
	assert.Empty(t, errOut.String())
}

func TestRunUIFailsBeforeDrawingWhenTheReplayFileIsMissing(t *testing.T) {
	// The failure has to land before the alternate screen is entered, or the
	// error message is painted over and then wiped on exit.
	neutralTerminalEnv(t)
	missing := filepath.Join(t.TempDir(), "no-such-capture.jsonl")
	var out bytes.Buffer
	err := runUI(context.Background(), &uiOptions{replay: missing}, &out, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)
	assert.Empty(t, out.String())
}

func TestRunUIToleratesANilContext(t *testing.T) {
	// cmd.Context() is nil for a command executed without one, and a nil
	// context reaching a select is a panic rather than a message.
	neutralTerminalEnv(t)
	var out bytes.Buffer
	require.NoError(t, runUI(nil, &uiOptions{replay: os.DevNull}, &out, &out)) //nolint:staticcheck // the nil is the case under test
	assert.Contains(t, out.String(), "events\t0")
}
