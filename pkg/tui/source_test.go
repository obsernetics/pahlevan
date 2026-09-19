package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// collect runs a source to completion with room for everything it produces,
// which is what the Stream goroutine does without a Bubble Tea loop attached.
func collect(t *testing.T, src Source) ([]export.Event, error) {
	t.Helper()
	out := make(chan export.Event, 8192)
	err := src.Run(context.Background(), out)
	close(out)
	var got []export.Event
	for e := range out {
		got = append(got, e)
	}
	return got, err
}

// jsonLines renders events in the format the file sink writes and
// `pahlevan events` prints. A replay that cannot read that format cannot
// reproduce anything from a bug report.
func jsonLines(evs ...export.Event) string {
	var b strings.Builder
	for _, e := range evs {
		raw, err := json.Marshal(e)
		if err != nil {
			panic(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestSliceSourceDeliversEveryEventAndThenStops(t *testing.T) {
	src := &SliceSource{Events: []export.Event{
		ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api"),
		ev(export.EventTypeNetwork, true, "curl", "prod", "Deployment", "api"),
		ev(export.EventTypeProcess, false, "sh", "prod", "Deployment", "api"),
	}}

	got, err := collect(t, src)
	if err != nil {
		t.Fatalf("a replay of a fixed slice failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("delivered %d events, want 3", len(got))
	}
	for i := range got {
		if got[i].Type != src.Events[i].Type {
			t.Errorf("event %d is %v, want %v: order must be preserved", i, got[i].Type, src.Events[i].Type)
		}
	}
}

func TestSliceSourceStopsDeliveringWhenTheContextIsCancelled(t *testing.T) {
	// Quitting the UI cancels the context. A source that keeps producing after
	// that leaks a goroutine, and in the gRPC case a connection with it.
	ctx, cancel := context.WithCancel(context.Background())
	src := &SliceSource{Events: make([]export.Event, 5000)}

	out := make(chan export.Event) // unbuffered, so delivery is observable
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()

	for i := 0; i < 3; i++ {
		<-out
	}
	cancel()

	// Keep receiving so a send that raced the cancel cannot deadlock the
	// source before it notices the context is done.
	delivered := make(chan int, 1)
	drained := make(chan struct{})
	go func() {
		n := 3
		for range out {
			n++
		}
		delivered <- n
		close(drained)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancellation is an orderly end, not a failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the source did not return after its context was cancelled")
	}
	close(out)
	<-drained

	if n := <-delivered; n >= len(src.Events) {
		t.Errorf("the source delivered all %d events despite being cancelled at 3", n)
	}
}

func TestSliceSourceDescribesItself(t *testing.T) {
	// The status line is the only place that says where nothing is arriving
	// from, so an unnamed source still has to say something actionable.
	named := &SliceSource{Name: "events.jsonl", Events: make([]export.Event, 2)}
	if got := named.Describe(); got != "events.jsonl" {
		t.Errorf("Describe is %q, want the name it was given", got)
	}
	unnamed := &SliceSource{Events: make([]export.Event, 7)}
	if got := unnamed.Describe(); got != "7 replayed events" {
		t.Errorf("Describe is %q, want a count of what it holds", got)
	}
	empty := &SliceSource{}
	if got := empty.Describe(); got != "0 replayed events" {
		t.Errorf("Describe is %q for an empty source", got)
	}
}

func TestReaderSourceDecodesTheJSONLinesFormatTheSinksWrite(t *testing.T) {
	file := ev(export.EventTypeFile, true, "python3", "prod", "Deployment", "api")
	net := ev(export.EventTypeNetwork, false, "curl", "kube-system", "DaemonSet", "cni")
	src := &ReaderSource{R: strings.NewReader(jsonLines(file, net)), Name: "capture.jsonl"}

	got, err := collect(t, src)
	if err != nil {
		t.Fatalf("decoding a well formed capture failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d events, want 2", len(got))
	}
	if got[0].Type != export.EventTypeFile || !got[0].Denied() {
		t.Errorf("the first event lost its type or its verdict: %+v", got[0])
	}
	if got[0].File == nil || got[0].File.Path != "/etc/shadow" {
		t.Errorf("the file detail did not survive the round trip: %+v", got[0].File)
	}
	if got[1].Kubernetes == nil || got[1].Kubernetes.WorkloadName != "cni" {
		t.Errorf("the attribution did not survive the round trip: %+v", got[1].Kubernetes)
	}
	if !got[0].Timestamp.Time().Equal(file.Timestamp.Time()) {
		t.Errorf("the timestamp shifted: %v, want %v", got[0].Timestamp, file.Timestamp)
	}
	if n := src.Malformed(); n != 0 {
		t.Errorf("a clean file reported %d malformed records", n)
	}
}

func TestReaderSourceReturnsNilAtEndOfFile(t *testing.T) {
	// Reaching the end of a capture is how every replay finishes. Reporting it
	// as an error would put "error" in the status line of a session that did
	// exactly what was asked.
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"an empty file", ""},
		{"nothing but whitespace", "\n\n   \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &ReaderSource{R: strings.NewReader(tc.in)}
			got, err := collect(t, src)
			if err != nil {
				t.Errorf("reading %s returned %v, want nil", tc.name, err)
			}
			if len(got) != 0 {
				t.Errorf("decoded %d events from %s", len(got), tc.name)
			}
		})
	}
}

func TestReaderSourceToleratesRecordsItCannotInterpret(t *testing.T) {
	// A record with a stamp that will not parse is one bad line, not a broken
	// file. Discarding everything around it would throw away the capture
	// somebody attached to a bug report.
	good := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	const bad = "{\"timestamp\":\"not-a-timestamp\"}\n"

	for _, tc := range []struct {
		name      string
		badCount  int
		wantErr   bool
		wantGood  int
		wantCount int
	}{
		{"one bad record among good ones", 1, false, 2, 1},
		{"exactly the tolerated number", maxMalformedLines, false, 2, maxMalformedLines},
		{"one more than the tolerated number", maxMalformedLines + 1, true, 1, maxMalformedLines + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			b.WriteString(jsonLines(good))
			b.WriteString(strings.Repeat(bad, tc.badCount))
			b.WriteString(jsonLines(good))

			src := &ReaderSource{R: strings.NewReader(b.String()), Name: "capture.jsonl"}
			got, err := collect(t, src)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("%d malformed records were accepted silently", tc.badCount)
				}
				// The message has to name the count and the file, because the
				// operator's next move is to go and look at that file.
				if !strings.Contains(err.Error(), fmt.Sprintf("%d malformed records", tc.wantCount)) {
					t.Errorf("the error does not name the count: %v", err)
				}
				if !strings.Contains(err.Error(), "capture.jsonl") {
					t.Errorf("the error does not name the file: %v", err)
				}
			} else if err != nil {
				t.Fatalf("%d malformed records should have been tolerated: %v", tc.badCount, err)
			}

			if len(got) != tc.wantGood {
				t.Errorf("delivered %d good events, want %d", len(got), tc.wantGood)
			}
			if n := src.Malformed(); n != tc.wantCount {
				t.Errorf("Malformed is %d, want %d", n, tc.wantCount)
			}
		})
	}
}

func TestASyntaxErrorCostsOneRecordNotTheRestOfTheFile(t *testing.T) {
	// A streaming json.Decoder latches a syntax error: every later Decode
	// returns the same error without consuming input. Used that way, one bad
	// line ended the replay, reported itself as 33 malformed records, and threw
	// away everything after it - including the case the tolerance was written
	// for, a capture truncated mid-write, which is how these files normally
	// end. Scanning line by line is what makes a bad record cost one record.
	good := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	for _, tc := range []struct {
		name     string
		bad      string
		wantGood int
	}{
		{"a line that is not JSON at all", "not json\n", 2},
		{"a record truncated mid-write", "{\"version\":", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := jsonLines(good) + tc.bad + jsonLines(good)
			if tc.wantGood == 1 {
				// Truncation is the end of the file; there is no record after it.
				in = jsonLines(good) + tc.bad
			}
			src := &ReaderSource{R: strings.NewReader(in), Name: "capture.jsonl"}
			got, err := collect(t, src)

			if err != nil {
				t.Fatalf("one malformed record ended the replay: %v", err)
			}
			if len(got) != tc.wantGood {
				t.Errorf("delivered %d events, want %d", len(got), tc.wantGood)
			}
			if n := src.Malformed(); n != 1 {
				t.Errorf("Malformed is %d, want 1 for a single bad record", n)
			}
		})
	}
}

func TestAnOverlongRecordIsReportedWithoutLosingWhatCameBefore(t *testing.T) {
	// argv is attacker-influenced, so a record can be arbitrarily long. The
	// reader caps it, and the cap has to be a reported error rather than a
	// silent truncation that would change what the operator reads.
	good := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	in := jsonLines(good) + strings.Repeat("x", maxRecordBytes+1) + "\n"
	src := &ReaderSource{R: strings.NewReader(in), Name: "capture.jsonl"}
	got, err := collect(t, src)

	if err == nil {
		t.Fatal("an overlong record was accepted silently")
	}
	if !strings.Contains(err.Error(), "capture.jsonl") {
		t.Errorf("the error does not name the file: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("delivered %d events, want the 1 that preceded the overlong record", len(got))
	}
}

func TestReaderSourceStopsWhenTheContextIsCancelled(t *testing.T) {
	// A replay of stdin can block forever on a pipe nobody writes to. Quitting
	// has to end it, not wait for the writer.
	many := make([]export.Event, 0, 5000)
	for i := 0; i < 5000; i++ {
		many = append(many, ev(export.EventTypeFile, false, fmt.Sprintf("p%d", i), "prod", "Deployment", "api"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	src := &ReaderSource{R: strings.NewReader(jsonLines(many...)), Name: "capture.jsonl"}

	out := make(chan export.Event)
	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, out) }()

	for i := 0; i < 3; i++ {
		<-out
	}
	cancel()

	drained := make(chan struct{})
	go func() {
		for range out {
		}
		close(drained)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancellation is an orderly end, not a failure: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the reader did not return after its context was cancelled")
	}
	close(out)
	<-drained
}

func TestReaderSourceStopsBeforeReadingWhenAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := &ReaderSource{R: strings.NewReader(jsonLines(
		ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")))}

	out := make(chan export.Event, 4)
	if err := src.Run(ctx, out); err != nil {
		t.Fatalf("an already cancelled run returned %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf("delivered %d events under a cancelled context", len(out))
	}
}

func TestReaderSourceDescribesItself(t *testing.T) {
	named := &ReaderSource{R: strings.NewReader(""), Name: "capture.jsonl"}
	if got := named.Describe(); got != "capture.jsonl" {
		t.Errorf("Describe is %q, want the file it is replaying", got)
	}
	// An unnamed reader is the `--replay -` case, and "stdin" is what an
	// operator needs to see to know why nothing is arriving.
	unnamed := &ReaderSource{R: strings.NewReader("")}
	if got := unnamed.Describe(); got != "stdin" {
		t.Errorf("Describe is %q, want stdin", got)
	}
}

// BenchmarkReaderSourceDecode measures a realistic replay: a mixed capture of
// the shape the file sink writes, decoded end to end through the channel the
// UI reads from.
func BenchmarkReaderSourceDecode(b *testing.B) {
	types := []export.EventType{
		export.EventTypeFile, export.EventTypeNetwork, export.EventTypeProcess,
		export.EventTypeCapability, export.EventTypeSyscall,
	}
	evs := make([]export.Event, 0, 500)
	for i := 0; i < 500; i++ {
		evs = append(evs, ev(types[i%len(types)], i%7 == 0, "nginx", "prod", "Deployment", "api"))
	}
	blob := jsonLines(evs...)

	out := make(chan export.Event, 1024)
	drained := make(chan struct{})
	go func() {
		for range out {
		}
		close(drained)
	}()

	b.SetBytes(int64(len(blob)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := &ReaderSource{R: strings.NewReader(blob), Name: "bench"}
		if err := src.Run(context.Background(), out); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	close(out)
	<-drained
}
