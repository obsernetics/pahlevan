package export

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// WriterExporter writes one JSON document per line to an io.Writer. It is the
// implementation behind the stdout sink and is exported so callers can point a
// sink at any writer (a test buffer, a pipe, a log shipper).
type WriterExporter struct {
	name string

	mu     sync.Mutex
	w      *bufio.Writer
	closer io.Closer
	enc    *json.Encoder
	closed bool
}

// NewStdoutExporter returns a JSON-lines sink on os.Stdout.
func NewStdoutExporter() *WriterExporter {
	return NewWriterExporter(os.Stdout, "stdout")
}

// NewWriterExporter returns a JSON-lines sink on w. If w is also an io.Closer
// it is closed by Close, except for os.Stdout and os.Stderr.
func NewWriterExporter(w io.Writer, name string) *WriterExporter {
	RegisterMetrics()
	if name == "" {
		name = "writer"
	}
	e := &WriterExporter{
		name: name,
		w:    bufio.NewWriter(w),
	}
	if c, ok := w.(io.Closer); ok && w != os.Stdout && w != os.Stderr {
		e.closer = c
	}
	e.enc = json.NewEncoder(e.w)
	return e
}

func (e *WriterExporter) Name() string { return e.name }

func (e *WriterExporter) Export(_ context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	for _, ev := range events {
		if ev == nil {
			continue
		}
		// json.Encoder already terminates each document with a newline, which
		// is exactly the JSON-lines framing consumers expect.
		if err := e.enc.Encode(ev); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
	}
	return e.w.Flush()
}

func (e *WriterExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	err := e.w.Flush()
	if e.closer != nil {
		if cerr := e.closer.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
