/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/export"
)

func eventLine(t *testing.T, ev *export.Event) string {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw) + "\n"
}

func sampleEvents(t *testing.T) []*export.Event {
	t.Helper()
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	return []*export.Event{
		{
			Version: export.SchemaVersion, Timestamp: export.Timestamp(now),
			Type: export.EventTypeFile, Action: export.ActionDeny,
			Process: export.ProcessInfo{PID: 1, Comm: "curl"},
			File:    &export.FileInfo{Path: "/etc/shadow"},
			Kubernetes: &export.KubernetesRef{
				Namespace: "prod", Pod: "api-0", Container: "api",
				PodUID: "uid-1", ContainerID: "abcdef0123456789",
			},
		},
		{
			Version: export.SchemaVersion, Timestamp: export.Timestamp(now.Add(time.Second)),
			Type: export.EventTypeNetwork, Action: export.ActionObserve,
			Process: export.ProcessInfo{PID: 2, Comm: "nc"},
			Network: &export.NetworkInfo{DestinationIP: "8.8.8.8", DestinationPort: 53, Protocol: "udp"},
			Kubernetes: &export.KubernetesRef{
				Namespace: "dev", Pod: "worker-1", Container: "worker", PodUID: "uid-2",
			},
		},
		{
			Version: export.SchemaVersion, Timestamp: export.Timestamp(now.Add(2 * time.Second)),
			Type: export.EventTypeProcess, Action: export.ActionDeny,
			Process: export.ProcessInfo{PID: 3, Comm: "sh"},
			Exec:    &export.ExecInfo{Binary: "/bin/nc"},
		},
	}
}

// writeLog writes the sample events, plus a blank line and a corrupt line that
// the reader must skip.
func writeLog(t *testing.T, events []*export.Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.json")
	var b strings.Builder
	for i, ev := range events {
		b.WriteString(eventLine(t, ev))
		if i == 0 {
			b.WriteString("\n")
			b.WriteString("{not json}\n")
			b.WriteString("{\"version\":\"x\"}\n") // no type, skipped
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func decodeOutput(t *testing.T, out string) []*export.Event {
	t.Helper()
	var events []*export.Event
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var ev export.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("output line %q is not JSON: %v", line, err)
		}
		events = append(events, &ev)
	}
	return events
}

func runEventsForTest(t *testing.T, opts *eventsOptions) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := runEvents(context.Background(), opts, &buf)
	return buf.String(), err
}

func TestEventsMissingFileIsActionable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	_, err := runEventsForTest(t, &eventsOptions{file: missing})
	if err == nil {
		t.Fatal("expected an error for a missing log")
	}
	msg := err.Error()
	for _, want := range []string{missing, "file exporter", "--file"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q, got: %s", want, msg)
		}
	}
}

func TestEventsEmptyPath(t *testing.T) {
	if _, err := runEventsForTest(t, &eventsOptions{}); err == nil {
		t.Fatal("expected an error without a path")
	}
}

func TestEventsPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, permission bits do not apply")
	}
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := runEventsForTest(t, &eventsOptions{file: path})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v", err)
	}
}

func TestEventsPrintsAllAndSkipsGarbage(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	out, err := runEventsForTest(t, &eventsOptions{file: path})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := decodeOutput(t, out)
	if len(got) != 3 {
		t.Fatalf("printed %d events, want 3: %s", len(got), out)
	}
	if got[0].File == nil || got[0].File.Path != "/etc/shadow" {
		t.Errorf("first event = %+v", got[0])
	}
}

func TestEventsTypeFilter(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	out, err := runEventsForTest(t, &eventsOptions{file: path, types: []string{"network"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := decodeOutput(t, out)
	if len(got) != 1 || got[0].Type != export.EventTypeNetwork {
		t.Fatalf("output = %s", out)
	}

	out, err = runEventsForTest(t, &eventsOptions{file: path, types: []string{"file", "process"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := decodeOutput(t, out); len(got) != 2 {
		t.Fatalf("printed %d events, want 2", len(got))
	}
}

func TestEventsUnknownTypeIsRejected(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	_, err := runEventsForTest(t, &eventsOptions{file: path, types: []string{"dns"}})
	if err == nil || !strings.Contains(err.Error(), "unknown event type") {
		t.Fatalf("err = %v", err)
	}
}

func TestEventsDenialsOnly(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	out, err := runEventsForTest(t, &eventsOptions{file: path, denialsOnly: true})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := decodeOutput(t, out)
	if len(got) != 2 {
		t.Fatalf("printed %d events, want the 2 denials: %s", len(got), out)
	}
	for _, ev := range got {
		if ev.Action != export.ActionDeny {
			t.Errorf("event %q is not a denial", ev.Type)
		}
	}
}

func TestEventsPodFilter(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	cases := map[string]int{
		"api-0":          1,
		"prod/api-0":     1,
		"dev/api-0":      0,
		"uid-2":          1,
		"worker":         1,
		"abcdef01":       1,
		"does-not-exist": 0,
	}
	for selector, want := range cases {
		out, err := runEventsForTest(t, &eventsOptions{file: path, pod: selector})
		if err != nil {
			t.Fatalf("run %q: %v", selector, err)
		}
		if got := len(decodeOutput(t, out)); got != want {
			t.Errorf("pod=%q printed %d events, want %d", selector, got, want)
		}
	}
}

func TestEventsPodAndDenialFiltersCombine(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	out, err := runEventsForTest(t, &eventsOptions{file: path, pod: "dev/worker-1", denialsOnly: true})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := decodeOutput(t, out); len(got) != 0 {
		t.Fatalf("printed %d events, want none", len(got))
	}
}

func TestEventsTail(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	out, err := runEventsForTest(t, &eventsOptions{file: path, tail: 2})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := decodeOutput(t, out)
	if len(got) != 2 {
		t.Fatalf("printed %d events, want 2: %s", len(got), out)
	}
	if got[0].Type != export.EventTypeNetwork || got[1].Type != export.EventTypeProcess {
		t.Errorf("tail printed the wrong events: %s", out)
	}
}

func TestEventsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := runEventsForTest(t, &eventsOptions{file: path})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("output = %q", out)
	}
}

// syncBuffer is a bytes.Buffer safe for the follow goroutine to write while the
// test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestEventsFollow(t *testing.T) {
	events := sampleEvents(t)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, []byte(eventLine(t, events[0])), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runEvents(ctx, &eventsOptions{
			file:         path,
			follow:       true,
			pollInterval: 5 * time.Millisecond,
		}, out)
	}()

	waitForLines(t, out, 1)

	// Append the rest, one of them in two writes so the reader sees a partial
	// line first.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	line := eventLine(t, events[1])
	if _, err := f.WriteString(line[:len(line)/2]); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := f.WriteString(line[len(line)/2:]); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := f.WriteString(eventLine(t, events[2])); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitForLines(t, out, 3)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follow did not stop when the context was canceled")
	}

	got := decodeOutput(t, out.String())
	if len(got) != 3 {
		t.Fatalf("printed %d events, want 3", len(got))
	}
	if got[1].Network == nil || got[1].Network.DestinationIP != "8.8.8.8" {
		t.Errorf("the split line was not reassembled: %+v", got[1])
	}
}

func TestEventsFollowHandlesTruncation(t *testing.T) {
	events := sampleEvents(t)
	path := filepath.Join(t.TempDir(), "events.json")
	if err := os.WriteFile(path, []byte(eventLine(t, events[0])+eventLine(t, events[1])), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runEvents(ctx, &eventsOptions{
			file:         path,
			follow:       true,
			pollInterval: 5 * time.Millisecond,
		}, out)
	}()

	waitForLines(t, out, 2)

	// Rotation replaces the file with a shorter one; the reader must rewind.
	if err := os.WriteFile(path, []byte(eventLine(t, events[2])), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	waitForLines(t, out, 3)
	cancel()
	<-done

	got := decodeOutput(t, out.String())
	if got[len(got)-1].Type != export.EventTypeProcess {
		t.Errorf("last event = %q, want the one written after truncation", got[len(got)-1].Type)
	}
}

func waitForLines(t *testing.T, out *syncBuffer, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(out.String(), "\n") >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d lines, have %q", want, out.String())
}

func TestEventsSkipsOverlongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	huge := strings.Repeat("x", maxEventLine+10)
	content := "{\"garbage\":\"" + huge + "\"}\n" + eventLine(t, sampleEvents(t)[0])
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := runEventsForTest(t, &eventsOptions{file: path})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	got := decodeOutput(t, out)
	if len(got) != 1 || got[0].Type != export.EventTypeFile {
		t.Fatalf("printed %d events: %s", len(got), out)
	}
}

func TestNewEventsCommandFlags(t *testing.T) {
	cmd := NewEventsCommand()
	if cmd.Use != "events" {
		t.Errorf("use = %q", cmd.Use)
	}
	for _, name := range []string{"file", "follow", "type", "denials-only", "pod", "tail"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
	if got := cmd.Flags().Lookup("file").DefValue; got != export.DefaultEventLogPath {
		t.Errorf("default --file = %q", got)
	}
	if cmd.PersistentPreRunE == nil {
		t.Fatal("the command must override the Kubernetes client bootstrap")
	}
	if err := cmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Errorf("PersistentPreRunE = %v", err)
	}
}

func TestEventsCommandRunsEndToEnd(t *testing.T) {
	path := writeLog(t, sampleEvents(t))
	cmd := NewEventsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--file", path, "--denials-only", "--type", "file"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := decodeOutput(t, buf.String())
	if len(got) != 1 || got[0].Type != export.EventTypeFile {
		t.Fatalf("output = %s", buf.String())
	}
}

func TestEventsCommandReportsMissingFile(t *testing.T) {
	cmd := NewEventsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--file", filepath.Join(t.TempDir(), "missing.json")})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error, not a panic or success")
	}
	if !strings.Contains(err.Error(), "no event log at") {
		t.Errorf("err = %v", err)
	}
}
