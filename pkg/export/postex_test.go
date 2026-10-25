package export

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
)

// execEvent builds the envelope an exec produces, with the ancestry a caller
// wants to assert on. nearestFirst matches ExecInfo.Ancestry's ordering.
func execEvent(binary, comm, parent string, nearestFirst ...string) *Event {
	ev := &Event{
		Version:   SchemaVersion,
		Timestamp: Timestamp(time.Unix(0, 0)),
		Type:      EventTypeProcess,
		Action:    ActionObserve,
		Process:   ProcessInfo{PID: 42, Comm: comm, PPID: 41, ParentComm: parent},
		Exec:      &ExecInfo{Binary: binary},
	}
	for i, name := range nearestFirst {
		ev.Exec.Ancestry = append(ev.Exec.Ancestry, AncestorInfo{PID: uint32(40 - i), Comm: name})
	}
	return ev
}

// fileEvent builds the envelope a file open produces. write selects the bit
// the LSM hook sets for an open that requested write access.
func fileEvent(path string, write bool) *Event {
	var flags uint32
	if write {
		flags = writeFlagBit
	}
	return &Event{
		Version:   SchemaVersion,
		Timestamp: Timestamp(time.Unix(0, 0)),
		Type:      EventTypeFile,
		Action:    ActionObserve,
		Process:   ProcessInfo{PID: 42, Comm: "php-fpm"},
		File:      &FileInfo{Path: path, Flags: flags},
	}
}

// The web shell exec shape. Each case is a lineage the kernel can actually
// report, and the assertion is on the lineage alone: the binary is an ordinary
// shell in every one of them, so a rule that looked only at what was execed
// would answer the same for the positive and the negative cases.
func TestServerSpawnedShellRecognisesTheWebShellLineage(t *testing.T) {
	cases := []struct {
		name string
		ev   *Event
		want bool
	}{
		{
			// The PHP2Shell post-exploitation shape: the worker that handled
			// the request runs a command. No new file, no connect yet.
			name: "php-fpm execs sh directly",
			ev:   execEvent("/bin/sh", "sh", "php-fpm"),
			want: true,
		},
		{
			// php-fpm renames its workers, and the kernel caps comm at 15
			// characters plus the terminator, so this is what arrives. An
			// exact match on "php-fpm" would miss every worker.
			name: "php-fpm worker with a truncated process title",
			ev:   execEvent("/bin/sh", "sh", "php-fpm: pool w"),
			want: true,
		},
		{
			name: "apache2 execs bash",
			ev:   execEvent("/bin/bash", "bash", "apache2"),
			want: true,
		},
		{
			// CVE-2026-12569 drops JSP shells into Windchill, which runs on a
			// JVM, so the server process reports as java.
			name: "a JVM server execs sh",
			ev:   execEvent("/bin/sh", "sh", "java"),
			want: true,
		},
		{
			// Plex Media Server, truncated by the kernel. The Plex2Shell chain
			// ends in this process running commands.
			name: "Plex Media Server execs sh",
			ev:   execEvent("/bin/sh", "sh", "Plex Media Serv"),
			want: true,
		},
		{
			// The second command an attacker runs is a grandchild of the
			// server. Keying on the immediate parent alone would report the
			// first command and miss every one after it.
			name: "an interpreter two levels below nginx",
			ev:   execEvent("/usr/bin/python3", "python3", "sh", "sh", "nginx"),
			want: true,
		},
		{
			name: "perl below httpd",
			ev:   execEvent("/usr/bin/perl", "perl", "sh", "sh", "httpd"),
			want: true,
		},
		{
			// A shell started by a shell is an operator in a kubectl exec, or
			// the image's own entrypoint wrapper. Reporting it would bury the
			// signal in the noise it exists to rise above.
			name: "a shell started by a shell",
			ev:   execEvent("/bin/sh", "sh", "bash", "bash"),
			want: false,
		},
		{
			// A Node server forking a worker execs node from node. Treating
			// node as both the server and the interpreter would report every
			// worker on every scale-up.
			name: "a server re-execing itself",
			ev:   execEvent("/usr/bin/node", "node", "node", "node"),
			want: false,
		},
		{
			// nginx's master process starting a worker. The parent is a
			// server; the child is not a shell, so there is nothing to report.
			name: "nginx forking a worker",
			ev:   execEvent("/usr/sbin/nginx", "nginx", "nginx"),
			want: false,
		},
		{
			// The ordinary case this must stay quiet on: a server running the
			// non-shell helpers it was built to run.
			name: "nginx execing a helper binary",
			ev:   execEvent("/usr/bin/openssl", "openssl", "nginx"),
			want: false,
		},
		{
			name: "no ancestry at all",
			ev:   execEvent("/bin/sh", "sh", ""),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ev.HasSignalAfterDetect(SignalServerSpawnedShell)
			assert.Equal(t, tc.want, got,
				"lineage %v execing %s", ancestorComms(tc.ev), tc.ev.Exec.Binary)
		})
	}
}

// HasSignalAfterDetect runs the detector and reports one signal, so a table
// test reads as a statement about the event rather than about the plumbing.
func (e *Event) HasSignalAfterDetect(s Signal) bool {
	for _, got := range DetectSignals(e) {
		if got == s {
			return true
		}
	}
	return false
}

// An envelope that has been through JSON or gRPC keeps the rendered chain and
// loses the structured ancestry, because that is the field the wire format
// carries. The detector has to read both or the signal exists only inside the
// agent that produced it.
func TestServerSpawnedShellReadsTheRenderedAncestryChain(t *testing.T) {
	ev := execEvent("/usr/bin/python3", "python3", "")
	ev.Exec.Ancestry = nil
	ev.Exec.AncestryChain = "php-fpm -> sh -> python3"

	assert.True(t, ev.HasSignalAfterDetect(SignalServerSpawnedShell),
		"the chain names php-fpm as the oldest ancestor and it has to be read")
}

// A process exit carries no binary and no lineage. Reading it as an exec would
// report the shape on the shell's own teardown, doubling every finding.
func TestServerSpawnedShellIgnoresAnExit(t *testing.T) {
	ev := execEvent("", "sh", "php-fpm")
	ev.Exec.Exited = true

	assert.Empty(t, DetectSignals(ev))
}

// comm is still the parent's name until an exec completes, so an event
// captured in bprm_check_security can carry "php-fpm" as the comm while Binary
// already names the shell. Trusting comm alone misses exactly the event the
// hook exists to catch.
func TestServerSpawnedShellUsesTheBinaryWhenCommIsStale(t *testing.T) {
	ev := execEvent("/bin/sh", "php-fpm", "php-fpm", "php-fpm")

	assert.True(t, ev.HasSignalAfterDetect(SignalServerSpawnedShell))
}

// The web shell drop shape. Both halves are required, and the cases prove it
// from each side: the same filename outside a document root is quiet, and the
// same directory with a non-script filename is quiet.
func TestWebShellWriteRecognisesAScriptDroppedIntoADocumentRoot(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		write bool
		want  bool
	}{
		{"php into the nginx document root", "/usr/share/nginx/html/.x.php", true, true},
		{"php into /var/www", "/var/www/html/uploads/shell.php", true, true},
		{"phtml into /srv/http", "/srv/http/img/t.phtml", true, true},
		{
			// CVE-2026-12569: hex-named JSP files under Windchill's login
			// directory, reported with that directory in mixed case.
			name: "jsp into the Windchill login directory",
			path: "/opt/ptc/Windchill/login/a1b2c3d4e5f60718.jsp", write: true, want: true,
		},
		{"jsp into a Tomcat webapps tree", "/usr/local/tomcat/webapps/ROOT/x.jsp", true, true},
		{
			// The upload-then-rename bypass: the write lands under a suffixed
			// name and the rename follows. The write is the observable event.
			name: "a double extension", path: "/var/www/html/shell.php.bak", write: true, want: true,
		},
		{
			// A read is how a web server serves its own content, on every
			// request. Reporting it would make the signal fire continuously.
			name: "reading a php file the server serves", path: "/var/www/html/index.php", write: false, want: false,
		},
		{
			// Staging, not a planted shell: nothing serves /tmp.
			name: "a php file written to /tmp", path: "/tmp/shell.php", write: true, want: false,
		},
		{
			// An upload directory receiving an upload. This is what a document
			// root is for.
			name: "an image written to the document root", path: "/var/www/html/uploads/logo.png", write: true, want: false,
		},
		{
			name: "a log written inside the document root", path: "/var/www/html/access.log", write: true, want: false,
		},
		{"an empty path", "", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := fileEvent(tc.path, tc.write)
			assert.Equal(t, tc.want, ev.HasSignalAfterDetect(SignalWebShellWrite))
		})
	}
}

// Annotate is the only entry point the export path calls, so the field it sets
// and the counter it bumps are what every downstream behaviour depends on.
func TestAnnotateSetsTheSignalsOnTheEnvelope(t *testing.T) {
	ev := execEvent("/bin/sh", "sh", "php-fpm")
	Annotate(ev)

	assert.Equal(t, []Signal{SignalServerSpawnedShell}, ev.Signals)
	assert.True(t, ev.Signalled())
	assert.True(t, ev.HasSignal(SignalServerSpawnedShell))
	assert.False(t, ev.HasSignal(SignalWebShellWrite))
	assert.Equal(t, "server-spawned-shell", ev.SignalNames())
}

func TestAnnotateLeavesAnOrdinaryEventAlone(t *testing.T) {
	ev := fileEvent("/etc/nginx/nginx.conf", false)
	Annotate(ev)

	assert.Empty(t, ev.Signals)
	assert.False(t, ev.Signalled())
	assert.Equal(t, "", ev.SignalNames())
}

func TestSignalHelpersTolerateANilEvent(t *testing.T) {
	var ev *Event
	assert.Nil(t, DetectSignals(ev))
	assert.False(t, ev.Signalled())
	assert.False(t, ev.HasSignal(SignalServerSpawnedShell))
	assert.Equal(t, "", ev.SignalNames())
	Annotate(ev) // must not panic
}

// The first of the four behaviours that make the lineage load-bearing rather
// than decorative. Without it a signalled event never reaches a sink on the
// configuration where the signal is the only thing there is to report.
func TestDenialsOnlyFilterKeepsASignalledObservation(t *testing.T) {
	f := Filter{DenialsOnly: true}

	signalled := execEvent("/bin/sh", "sh", "php-fpm")
	Annotate(signalled)
	require.True(t, signalled.Signalled())
	assert.True(t, f.Allow(signalled),
		"a web shell exec that the kernel allowed is exactly what a node without the BPF LSM reports")

	ordinary := execEvent("/usr/bin/openssl", "openssl", "nginx")
	Annotate(ordinary)
	assert.False(t, f.Allow(ordinary), "an ordinary observation must still be filtered out")
}

// The second: the notifier's own selection, which drops every observation.
func TestSelectFindingsDeliversASignalledObservation(t *testing.T) {
	signalled := execEvent("/bin/sh", "sh", "php-fpm")
	Annotate(signalled)
	ordinary := execEvent("/usr/bin/openssl", "openssl", "nginx")
	Annotate(ordinary)

	got := selectFindings([]*Event{ordinary, signalled}, false, nil)

	require.Len(t, got, 1)
	assert.True(t, got[0].HasSignal(SignalServerSpawnedShell))
}

// The third: deduplication. A container whose entrypoint is a shell wrapper
// produces an allowed exec of /bin/sh seconds after it starts, and a key that
// ignored the signal would let that one suppress the web shell for the whole
// window.
func TestFindingKeySeparatesASignalledExecFromABenignOne(t *testing.T) {
	benign := execEvent("/bin/sh", "sh", "bash", "bash")
	Annotate(benign)
	require.False(t, benign.Signalled(), "the fixture has to be the benign shape")

	webshell := execEvent("/bin/sh", "sh", "php-fpm")
	Annotate(webshell)
	require.True(t, webshell.Signalled())

	assert.NotEqual(t, FindingKey(benign), FindingKey(webshell),
		"both are an allowed exec of /bin/sh in the same workload, so only the signal tells them apart")

	d := newDedupe(time.Hour)
	assert.True(t, d.allow(FindingKey(benign)))
	assert.True(t, d.allow(FindingKey(webshell)),
		"the entrypoint's shell must not suppress the web shell")
}

// The fourth: severity. At DEBUG the record is inside the full behavioural
// trace and every sampling rule in the collector drops it.
func TestSeverityOfASignalledObservationIsRaised(t *testing.T) {
	signalled := execEvent("/bin/sh", "sh", "php-fpm")
	Annotate(signalled)
	assert.Equal(t, otellog.SeverityWarn, severityOf(signalled))

	ordinary := execEvent("/usr/bin/openssl", "openssl", "nginx")
	Annotate(ordinary)
	assert.Equal(t, otellog.SeverityDebug, severityOf(ordinary))
}

func TestOTLPRecordCarriesTheSignals(t *testing.T) {
	sink, proc := newTestSink(t, true)
	ev := fileEvent("/var/www/html/.x.php", true)
	Annotate(ev)
	require.True(t, ev.Signalled())

	require.NoError(t, sink.Export(context.Background(), []*Event{ev}))
	require.Len(t, proc.records, 1, "a signalled observation must survive the sink's denials-only mode")

	assert.Equal(t, `["web-shell-write"]`, attrsOf(t, proc.records[0])["pahlevan.signals"])
}

func TestSlackLineNamesTheSignal(t *testing.T) {
	ev := execEvent("/bin/sh", "sh", "php-fpm")
	ev.Exec.CommandLine = "sh -c id"
	Annotate(ev)

	line := slackLine(ev)

	assert.Contains(t, line, "signal: server-spawned-shell")
	assert.Contains(t, line, "php-fpm -> sh", "the lineage is the finding, so it has to be in the message")
}

func TestBatchSummaryNamesASignalWithNoDenial(t *testing.T) {
	ev := execEvent("/bin/sh", "sh", "php-fpm")
	Annotate(ev)

	assert.Equal(t, "Pahlevan flagged 1 post-exploitation signal on node-1",
		batchSummary([]*Event{ev}, 0, "node-1"))

	// A denial still leads, and an unsignalled batch still reads as before.
	assert.Equal(t, "Pahlevan denied 2 operations on node-1",
		batchSummary([]*Event{ev}, 2, "node-1"))
	plain := fileEvent("/etc/nginx/nginx.conf", false)
	Annotate(plain)
	assert.Equal(t, "Pahlevan observed 1 operation on node-1",
		batchSummary([]*Event{plain}, 0, "node-1"))
}

// writeFlagBit is copied from pkg/ebpf rather than imported, so that the copy
// cannot drift unnoticed. The existing assertion is in the Linux tests; this
// one guards the detector's own use of it.
func TestWebShellWriteUsesTheWriteFlagBit(t *testing.T) {
	ev := fileEvent("/var/www/html/.x.php", false)
	ev.File.Flags = 0x40000000
	assert.True(t, ev.HasSignalAfterDetect(SignalWebShellWrite))

	ev.File.Flags = 0x00000001 // O_WRONLY, which is not the bit the hook sets
	assert.False(t, ev.HasSignalAfterDetect(SignalWebShellWrite))
}

// Degenerate inputs, which arrive in practice: a truncated ring-buffer record
// leaves an empty comm, and a path captured mid-resolution can be a bare "/"
// or ".". None of these may panic and none may be read as a signal.
func TestSignalsOnDegenerateInput(t *testing.T) {
	t.Run("a binary that is only a separator falls back to comm", func(t *testing.T) {
		ev := execEvent("/", "sh", "php-fpm")
		assert.True(t, ev.HasSignalAfterDetect(SignalServerSpawnedShell),
			"the comm still names a shell, so the fallback has to be taken")
	})

	t.Run("a binary that is only a dot falls back to comm", func(t *testing.T) {
		ev := execEvent(".", "sh", "php-fpm")
		assert.True(t, ev.HasSignalAfterDetect(SignalServerSpawnedShell))
	})

	t.Run("an exec with neither a binary nor a comm", func(t *testing.T) {
		ev := execEvent("", "", "php-fpm")
		assert.Empty(t, DetectSignals(ev), "nothing names the child, so nothing can be concluded")
	})

	t.Run("an exec with no parent name at all", func(t *testing.T) {
		ev := execEvent("/bin/sh", "sh", "")
		ev.Exec.Ancestry = []AncestorInfo{{PID: 1, Comm: ""}}
		assert.Empty(t, DetectSignals(ev))
	})

	t.Run("an empty comm names nothing", func(t *testing.T) {
		// Asserted directly because ancestorComms filters empty names out
		// before serverRuntime ever sees one. The guard is for any later
		// caller that does not, and an empty comm matching a prefix would be
		// the worst possible default.
		assert.False(t, serverRuntime(""))
		assert.False(t, shellLike(""))
	})

	t.Run("a dotfile whose whole name is an unknown extension", func(t *testing.T) {
		// path.Ext(".bak") is ".bak", so trimming it leaves nothing. The
		// double-extension check has to stop rather than index into an empty
		// string.
		ev := fileEvent("/var/www/html/.bak", true)
		assert.Empty(t, DetectSignals(ev))
	})

	t.Run("a dotfile whose whole name is a script extension", func(t *testing.T) {
		ev := fileEvent("/var/www/html/.php", true)
		assert.True(t, ev.HasSignalAfterDetect(SignalWebShellWrite))
	})
}

// The invariant that keeps a server re-exec quiet without a special case.
//
// serverSpawnedShell asks two questions in order: is this exec shell-like, and
// is a server above it. If one comm could answer yes to both, a server forking
// a worker through execve would report itself, and the detector would fire on
// every scale-up of the workload it is supposed to be watching. Adding node to
// the interpreter list, or php to the server list, is exactly the edit that
// would do it, and both are plausible edits: node is a server, php is an
// interpreter, and `php -S` is a web server.
func TestServerAndShellNameListsAreDisjoint(t *testing.T) {
	for comm := range shellComms {
		assert.False(t, serverRuntime(comm),
			"%q counts as both a shell and a request-serving process, so a server execing a worker would report itself", comm)
	}
	for comm := range interpreterComms {
		assert.False(t, serverRuntime(comm),
			"%q counts as both an interpreter and a request-serving process, so a server execing a worker would report itself", comm)
	}
	for comm := range serverComms {
		assert.False(t, shellLike(comm),
			"%q counts as both a request-serving process and a shell", comm)
	}
}

func BenchmarkDetectSignalsExecMatch(b *testing.B) {
	ev := execEvent("/usr/bin/python3", "python3", "sh", "sh", "php-fpm")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectSignals(ev)
	}
}

func BenchmarkDetectSignalsExecNoMatch(b *testing.B) {
	// The shape of nearly every event on a busy node: an exec that is not a
	// shell. This is the path that must cost nothing.
	ev := execEvent("/usr/sbin/nginx", "nginx", "nginx", "nginx")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectSignals(ev)
	}
}

func BenchmarkDetectSignalsFileMatch(b *testing.B) {
	ev := fileEvent("/usr/local/tomcat/webapps/ROOT/x.jsp", true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectSignals(ev)
	}
}

func BenchmarkDetectSignalsFileNoMatch(b *testing.B) {
	ev := fileEvent("/var/log/nginx/access.log", true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DetectSignals(ev)
	}
}

func BenchmarkAnnotate(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := execEvent("/bin/sh", "sh", "php-fpm")
		Annotate(ev)
	}
}
