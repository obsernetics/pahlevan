package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// Source yields events until its context is cancelled.
//
// The interface exists so the model can be driven from a slice in a test. A
// terminal UI wired directly to a gRPC dial is a UI that can only be tested by
// standing up an agent, which in practice means it is not tested at all.
type Source interface {
	// Run delivers events to out until ctx is done or the stream ends. It
	// returns nil for an orderly end, including cancellation, and an error
	// only for a genuine failure.
	Run(ctx context.Context, out chan<- export.Event) error
	// Describe names the source for the status line: an address, a file, or
	// something a person can act on when nothing is arriving.
	Describe() string
}

// SliceSource replays a fixed set of events and stops. Used by tests and by
// `--replay`, which is how someone reproduces a UI problem from a captured
// JSON-lines file without a cluster.
type SliceSource struct {
	Events []export.Event
	Name   string
}

func (s *SliceSource) Run(ctx context.Context, out chan<- export.Event) error {
	for _, e := range s.Events {
		select {
		case <-ctx.Done():
			return nil
		case out <- e:
		}
	}
	return nil
}

func (s *SliceSource) Describe() string {
	if s.Name != "" {
		return s.Name
	}
	return fmt.Sprintf("%d replayed events", len(s.Events))
}

// ReaderSource decodes JSON-lines events from a reader: the format the file
// sink writes and `pahlevan events` prints, so a capture can be replayed into
// the UI unchanged.
type ReaderSource struct {
	R    io.Reader
	Name string

	mu   sync.Mutex
	bad  int
	seen int
}

func (s *ReaderSource) Run(ctx context.Context, out chan<- export.Event) error {
	dec := json.NewDecoder(s.R)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		var e export.Event
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// One malformed line should not end the session: a capture
			// truncated mid-write is the normal way these files end, and
			// discarding everything before it would be the wrong answer.
			s.mu.Lock()
			s.bad++
			bad := s.bad
			s.mu.Unlock()
			if bad > maxMalformedLines {
				return fmt.Errorf("%s: %d malformed records, giving up: %w", s.Describe(), bad, err)
			}
			continue
		}
		s.mu.Lock()
		s.seen++
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case out <- e:
		}
	}
}

// maxMalformedLines bounds how much garbage a replay tolerates before it is
// reported as a broken file rather than a truncated one.
const maxMalformedLines = 32

func (s *ReaderSource) Describe() string {
	if s.Name != "" {
		return s.Name
	}
	return "stdin"
}

// Malformed reports how many records failed to decode, so the status line can
// say so rather than quietly showing fewer events than the file contains.
func (s *ReaderSource) Malformed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bad
}
