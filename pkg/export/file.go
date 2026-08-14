package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// DefaultEventLogPath is where the agent writes the JSON-lines event log and
// where `pahlevan events` looks for it by default.
const DefaultEventLogPath = "/var/log/pahlevan/events.json"

// File sink defaults.
const (
	// DefaultMaxFileSizeBytes is the rotation threshold, 64 MiB.
	DefaultMaxFileSizeBytes int64 = 64 << 20
	// DefaultMaxBackups is how many rotated files are kept.
	DefaultMaxBackups = 3
)

// FileOptions configures the file sink.
type FileOptions struct {
	// Path is the JSON-lines file to append to. Required.
	Path string
	// MaxSizeBytes is the size at which the file is rotated. Zero uses
	// DefaultMaxFileSizeBytes; a negative value disables rotation.
	MaxSizeBytes int64
	// MaxBackups is how many rotated files (path.1 ... path.N) are kept. Zero
	// uses DefaultMaxBackups.
	MaxBackups int
	// FileMode is the mode for a newly created log file. Zero uses 0o640.
	FileMode os.FileMode
	// DirMode is the mode for the parent directory when it has to be created.
	// Zero uses 0o750.
	DirMode os.FileMode
}

func (o FileOptions) withDefaults() FileOptions {
	if o.MaxSizeBytes == 0 {
		o.MaxSizeBytes = DefaultMaxFileSizeBytes
	}
	if o.MaxBackups <= 0 {
		o.MaxBackups = DefaultMaxBackups
	}
	if o.FileMode == 0 {
		o.FileMode = 0o640
	}
	if o.DirMode == 0 {
		o.DirMode = 0o750
	}
	return o
}

// FileExporter appends JSON lines to a file, rotating it once it grows past
// the configured size. It is safe for concurrent use.
type FileExporter struct {
	opts FileOptions

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool
}

// NewFileExporter opens (creating it and its parent directory if needed) and
// appends to opts.Path.
func NewFileExporter(opts FileOptions) (*FileExporter, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("export: file sink needs a path")
	}
	RegisterMetrics()
	e := &FileExporter{opts: opts.withDefaults()}
	if err := e.open(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *FileExporter) open() error {
	dir := filepath.Dir(e.opts.Path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, e.opts.DirMode); err != nil {
			return fmt.Errorf("export: create %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(e.opts.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, e.opts.FileMode)
	if err != nil {
		return fmt.Errorf("export: open %s: %w", e.opts.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("export: stat %s: %w", e.opts.Path, err)
	}
	e.f = f
	e.size = info.Size()
	return nil
}

func (e *FileExporter) Name() string { return "file" }

// Path returns the file currently being written.
func (e *FileExporter) Path() string { return e.opts.Path }

func (e *FileExporter) Export(_ context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("export: encode event: %w", err)
		}
	}
	if buf.Len() == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	if err := e.rotateIfNeeded(int64(buf.Len())); err != nil {
		return err
	}
	n, err := e.f.Write(buf.Bytes())
	e.size += int64(n)
	if err != nil {
		return fmt.Errorf("export: write %s: %w", e.opts.Path, err)
	}
	return nil
}

// rotateIfNeeded rolls the file over when appending incoming bytes would push
// it past the threshold. The caller holds e.mu.
func (e *FileExporter) rotateIfNeeded(incoming int64) error {
	if e.opts.MaxSizeBytes < 0 {
		return nil
	}
	if e.size == 0 || e.size+incoming <= e.opts.MaxSizeBytes {
		return nil
	}
	return e.rotateLocked()
}

func (e *FileExporter) rotateLocked() error {
	if err := e.f.Close(); err != nil {
		return fmt.Errorf("export: close %s before rotation: %w", e.opts.Path, err)
	}
	// Shift path.N-1 -> path.N, dropping anything beyond MaxBackups.
	oldest := fmt.Sprintf("%s.%d", e.opts.Path, e.opts.MaxBackups)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("export: remove %s: %w", oldest, err)
	}
	for i := e.opts.MaxBackups - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", e.opts.Path, i)
		to := fmt.Sprintf("%s.%d", e.opts.Path, i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("export: rotate %s: %w", from, err)
		}
	}
	if err := os.Rename(e.opts.Path, e.opts.Path+".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("export: rotate %s: %w", e.opts.Path, err)
	}
	return e.open()
}

// Rotate forces a rotation. It is exported mainly so an operator triggered
// logrotate style signal handler can call it.
func (e *FileExporter) Rotate() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	return e.rotateLocked()
}

// Size returns the current size of the active file in bytes.
func (e *FileExporter) Size() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.size
}

func (e *FileExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	return e.f.Close()
}
