package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func decodeLines(t *testing.T, data string) []*Event {
	t.Helper()
	var out []*Event
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %q is not valid JSON: %v", line, err)
		}
		out = append(out, &ev)
	}
	return out
}

func TestWriterExporterWritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	e := NewWriterExporter(&buf, "")
	if e.Name() != "writer" {
		t.Errorf("default name = %q", e.Name())
	}

	if err := e.Export(context.Background(), nil); err != nil {
		t.Fatalf("empty export: %v", err)
	}
	events := []*Event{testEvent(EventTypeSyscall), nil, testEvent(EventTypeFile)}
	if err := e.Export(context.Background(), events); err != nil {
		t.Fatalf("export: %v", err)
	}

	got := decodeLines(t, buf.String())
	if len(got) != 2 {
		t.Fatalf("wrote %d lines, want 2 (the nil event is skipped)", len(got))
	}
	if got[0].Type != EventTypeSyscall || got[1].Type != EventTypeFile {
		t.Errorf("types = %q %q", got[0].Type, got[1].Type)
	}
	if strings.Count(buf.String(), "\n") != 2 {
		t.Errorf("expected exactly one newline per event, got %q", buf.String())
	}

	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close is not idempotent: %v", err)
	}
	if err := e.Export(context.Background(), events); !errors.Is(err, ErrClosed) {
		t.Errorf("export after close = %v", err)
	}
}

func TestNewStdoutExporterDoesNotCloseStdout(t *testing.T) {
	e := NewStdoutExporter()
	if e.Name() != "stdout" {
		t.Errorf("name = %q", e.Name())
	}
	if e.closer != nil {
		t.Fatal("stdout must not be registered as a closer")
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stdout.Stat(); err != nil {
		t.Fatalf("stdout was closed: %v", err)
	}
}

func TestWriterExporterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	e := NewWriterExporter(&buf, "concurrent")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if err := e.Export(context.Background(), []*Event{testEvent(EventTypeNetwork)}); err != nil {
					t.Errorf("export: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := len(decodeLines(t, buf.String())); got != 200 {
		t.Fatalf("wrote %d lines, want 200", got)
	}
}

func TestFileExporterAppendsAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "events.json")

	e, err := NewFileExporter(FileOptions{Path: path})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if e.Name() != "file" || e.Path() != path {
		t.Errorf("name/path = %q/%q", e.Name(), e.Path())
	}
	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if e.Size() == 0 {
		t.Error("size should track the bytes written")
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopening appends rather than truncating.
	e2, err := NewFileExporter(FileOptions{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = e2.Close() }()
	if err := e2.Export(context.Background(), []*Event{testEvent(EventTypeProcess)}); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := decodeLines(t, string(data))
	if len(got) != 2 || got[0].Type != EventTypeFile || got[1].Type != EventTypeProcess {
		t.Fatalf("file holds %d events: %s", len(got), data)
	}
}

func TestFileExporterRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.json")

	e, err := NewFileExporter(FileOptions{Path: path, MaxSizeBytes: 400, MaxBackups: 2})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = e.Close() }()

	for i := 0; i < 40; i++ {
		if err := e.Export(context.Background(), []*Event{testEvent(EventTypeSyscall)}); err != nil {
			t.Fatalf("export %d: %v", i, err)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > 400 {
		t.Errorf("active file grew to %d bytes past the 400 byte threshold", info.Size())
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected a rotated file: %v", err)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("MaxBackups=2 must not keep a third backup (err = %v)", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) > 3 {
		t.Errorf("kept %d files, want at most the active file plus 2 backups", len(entries))
	}
}

func TestFileExporterRotationDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	e, err := NewFileExporter(FileOptions{Path: path, MaxSizeBytes: -1})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = e.Close() }()

	for i := 0; i < 20; i++ {
		if err := e.Export(context.Background(), []*Event{testEvent(EventTypeSyscall)}); err != nil {
			t.Fatalf("export: %v", err)
		}
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("rotation should be off, but %s.1 exists", path)
	}
}

func TestFileExporterExplicitRotateAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	e, err := NewFileExporter(FileOptions{Path: path})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := e.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotate did not move the file: %v", err)
	}
	if e.Size() != 0 {
		t.Errorf("size after rotation = %d", e.Size())
	}

	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close is not idempotent: %v", err)
	}
	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); !errors.Is(err, ErrClosed) {
		t.Errorf("export after close = %v", err)
	}
	if err := e.Rotate(); !errors.Is(err, ErrClosed) {
		t.Errorf("rotate after close = %v", err)
	}
	if err := e.Export(context.Background(), nil); err != nil {
		t.Errorf("empty export after close should be a no-op, got %v", err)
	}
}

func TestNewFileExporterErrors(t *testing.T) {
	if _, err := NewFileExporter(FileOptions{}); err == nil {
		t.Error("expected an error without a path")
	}
	// A path whose parent is an existing file cannot be created.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewFileExporter(FileOptions{Path: filepath.Join(blocker, "events.json")}); err == nil {
		t.Error("expected an error when the parent directory cannot be created")
	}
}

func TestFileExporterConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	e, err := NewFileExporter(FileOptions{Path: path, MaxSizeBytes: 2048, MaxBackups: 5})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = e.Close() }()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err != nil {
					t.Errorf("export: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
