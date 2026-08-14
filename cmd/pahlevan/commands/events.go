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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// defaultEventsPollInterval is how often --follow checks the log for new lines.
const defaultEventsPollInterval = 250 * time.Millisecond

// maxEventLine bounds a single JSON line, so a corrupt file cannot make the
// CLI allocate without limit.
const maxEventLine = 1 << 20

// eventsOptions holds the parsed flags of `pahlevan events`.
type eventsOptions struct {
	file        string
	follow      bool
	types       []string
	denialsOnly bool
	pod         string
	tail        int

	// pollInterval is overridden in tests to keep --follow fast.
	pollInterval time.Duration
}

// NewEventsCommand creates the events command, which streams the JSON-lines
// event log written by the agent's file exporter.
func NewEventsCommand() *cobra.Command {
	opts := &eventsOptions{
		file:         export.DefaultEventLogPath,
		pollInterval: defaultEventsPollInterval,
	}

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Stream security events as JSON lines",
		Long: fmt.Sprintf(`Stream the security events exported by the Pahlevan agent.

The agent's file sink writes one JSON document per line to %s. This command
reads that file, applies the requested filters and prints the matching events
as JSON lines, so it composes with jq and friends:

  pahlevan events --denials-only | jq -r '.process.comm'
  pahlevan events --follow --type=network --pod=frontend

The command reads a local file and does not talk to the API server, so it must
run where the log lives (on the node, or against a copy of the file).`,
			export.DefaultEventLogPath),
		Example: `  # Print every event recorded so far
  pahlevan events

  # Follow enforcement decisions for one pod
  pahlevan events --follow --denials-only --pod=payments-7d9

  # Only file and process events, last 20 of them
  pahlevan events --type=file --type=process --tail=20`,
		// The events command reads a local file; skip the parent's Kubernetes
		// client bootstrap so it works off-cluster too.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if opts.follow {
				var stop context.CancelFunc
				ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
				defer stop()
			}
			return runEvents(ctx, opts, cmd.OutOrStdout())
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.file, "file", opts.file, "Path to the JSON-lines event log written by the agent's file sink")
	flags.BoolVarP(&opts.follow, "follow", "f", false, "Keep the file open and print events as they are appended")
	flags.StringSliceVar(&opts.types, "type", nil, fmt.Sprintf("Only show these event types (%s); repeatable", export.EventTypeNames()))
	flags.BoolVar(&opts.denialsOnly, "denials-only", false, "Only show events the kernel denied")
	flags.StringVar(&opts.pod, "pod", "", "Only show events attributed to this pod (name, namespace/name, or pod UID)")
	flags.IntVar(&opts.tail, "tail", 0, "Print only the last N matching events before following (0 means all)")

	return cmd
}

// runEvents is the testable body of the events command.
func runEvents(ctx context.Context, opts *eventsOptions, out io.Writer) error {
	if opts.file == "" {
		return fmt.Errorf("no event log path: pass --file")
	}
	filter, err := export.NewFilter(opts.types, opts.denialsOnly)
	if err != nil {
		return err
	}

	f, err := os.Open(opts.file)
	if err != nil {
		return eventLogOpenError(opts.file, err)
	}
	defer func() { _ = f.Close() }()

	pollInterval := opts.pollInterval
	if pollInterval <= 0 {
		pollInterval = defaultEventsPollInterval
	}

	lines := newLineReader(f)
	printer := &eventPrinter{out: out, tail: opts.tail}

	for {
		line, ok, readErr := lines.next()
		if ok {
			if ev, ok := decodeEvent(line); ok && filter.Allow(ev) && matchesPod(ev, opts.pod) {
				if err := printer.add(ev); err != nil {
					return err
				}
			}
		}
		if readErr == nil {
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read %s: %w", opts.file, readErr)
		}

		// End of the file. Flush whatever the tail buffer holds, then either
		// stop or wait for the writer to append more.
		if err := printer.flush(); err != nil {
			return err
		}
		if !opts.follow {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollInterval):
		}
		if err := lines.rewindIfTruncated(opts.file); err != nil {
			return err
		}
	}
}

// eventPrinter writes matching events, honouring --tail by buffering until the
// first end of file is reached.
type eventPrinter struct {
	out      io.Writer
	tail     int
	buffered []*export.Event
	flushed  bool
}

func (p *eventPrinter) add(ev *export.Event) error {
	if p.tail > 0 && !p.flushed {
		p.buffered = append(p.buffered, ev)
		if len(p.buffered) > p.tail {
			p.buffered = p.buffered[len(p.buffered)-p.tail:]
		}
		return nil
	}
	return p.write(ev)
}

func (p *eventPrinter) flush() error {
	if p.flushed {
		return nil
	}
	p.flushed = true
	for _, ev := range p.buffered {
		if err := p.write(ev); err != nil {
			return err
		}
	}
	p.buffered = nil
	return nil
}

func (p *eventPrinter) write(ev *export.Event) error {
	encoded, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	if _, err := fmt.Fprintf(p.out, "%s\n", encoded); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	if flusher, ok := p.out.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// lineReader reads newline terminated records from a growing file. A partial
// line (the writer is mid-append) is held in pending until the newline lands,
// so following a live log never loses the head of a record.
type lineReader struct {
	f        *os.File
	r        *bufio.Reader
	pending  []byte
	overflow bool
}

func newLineReader(f *os.File) *lineReader {
	return &lineReader{f: f, r: bufio.NewReaderSize(f, 64*1024)}
}

// next returns the next complete line without its terminator. ok is false when
// no complete line was available; err is io.EOF once the file is exhausted.
func (l *lineReader) next() ([]byte, bool, error) {
	chunk, err := l.r.ReadBytes('\n')
	if len(chunk) > 0 {
		if len(l.pending)+len(chunk) > maxEventLine {
			// Refuse to buffer an unbounded line; skip it up to its newline.
			l.pending = nil
			l.overflow = true
		} else {
			l.pending = append(l.pending, chunk...)
		}
	}
	if err != nil {
		return nil, false, err
	}
	if l.overflow {
		l.overflow = false
		l.pending = nil
		return nil, false, nil
	}
	line := l.pending[:len(l.pending)-1]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	out := make([]byte, len(line))
	copy(out, line)
	l.pending = nil
	return out, true, nil
}

// rewindIfTruncated notices that the log was truncated or replaced (the file
// sink rotates by renaming) and restarts from the beginning so nothing is
// silently skipped.
func (l *lineReader) rewindIfTruncated(path string) error {
	info, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	offset, err := l.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("seek %s: %w", path, err)
	}
	// The buffered reader has read ahead of the records handed out, so compare
	// the file size against the position the reader actually reached.
	consumed := offset - int64(l.r.Buffered())
	if info.Size() >= consumed {
		return nil
	}
	if _, err := l.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind %s: %w", path, err)
	}
	l.r.Reset(l.f)
	l.pending = nil
	l.overflow = false
	return nil
}

func decodeEvent(line []byte) (*export.Event, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return nil, false
	}
	var ev export.Event
	if err := json.Unmarshal([]byte(trimmed), &ev); err != nil {
		// A truncated or corrupt line is skipped rather than fatal: the log is
		// append only and the writer may have been killed mid-line.
		return nil, false
	}
	if ev.Type == "" {
		return nil, false
	}
	return &ev, true
}

// matchesPod reports whether the event is attributed to the requested pod. The
// selector matches the pod name, namespace/name, the pod UID or the container
// ID prefix.
func matchesPod(ev *export.Event, selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return true
	}
	k := ev.Kubernetes
	if k == nil {
		return false
	}
	if ns, name, ok := strings.Cut(selector, "/"); ok {
		return k.Namespace == ns && k.Pod == name
	}
	switch {
	case k.Pod == selector, k.PodUID == selector, k.Container == selector:
		return true
	case k.ContainerID != "" && strings.HasPrefix(k.ContainerID, selector):
		return true
	}
	return false
}

// eventLogOpenError turns a failure to open the log into something an operator
// can act on instead of a bare "no such file".
func eventLogOpenError(path string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("no event log at %s.\n"+
			"The agent writes this file only when its file exporter is enabled; enable the export sink on the "+
			"pahlevan-agent DaemonSet (or copy the log off the node) and pass --file if it lives elsewhere", path)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("cannot read the event log at %s: permission denied.\n"+
			"The log is written with mode 0640 by the agent; run as root or adjust the file permissions", path)
	default:
		return fmt.Errorf("cannot read the event log at %s: %w", path, err)
	}
}
