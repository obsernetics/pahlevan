package tui

import "github.com/obsernetics/pahlevan/pkg/export"

// ring is a fixed-capacity buffer of the most recent events.
//
// The capacity is the whole point. A busy node produces events faster than a
// person reads them, and a slice that only ever appends turns a terminal UI
// into a memory leak that grows with the workload's syscall rate - on the one
// machine where an operator is already watching something go wrong. Past
// capacity the oldest event is dropped, because the newest is the one being
// looked at.
//
// Dropped events are counted rather than forgotten. A view that silently
// discards is a view that lies about what happened, and "12,481 earlier events
// not shown" is a materially different thing to read than a list that starts
// where the buffer happens to begin.
type ring struct {
	buf     []export.Event
	start   int // index of the oldest element
	size    int // number of elements held
	dropped uint64
}

func newRing(capacity int) *ring {
	if capacity < 1 {
		capacity = 1
	}
	return &ring{buf: make([]export.Event, capacity)}
}

// push appends an event, evicting the oldest if the buffer is full.
func (r *ring) push(e export.Event) {
	if r.size < len(r.buf) {
		r.buf[(r.start+r.size)%len(r.buf)] = e
		r.size++
		return
	}
	// Full: overwrite the oldest and advance the window.
	r.buf[r.start] = e
	r.start = (r.start + 1) % len(r.buf)
	r.dropped++
}

// len reports how many events are held.
func (r *ring) len() int { return r.size }

// cap reports the capacity.
func (r *ring) capacity() int { return len(r.buf) }

// at returns the i'th event, oldest first. Out-of-range indexes return the
// zero event and false rather than panicking, because the caller is a view
// doing arithmetic against a viewport height that can change under it.
func (r *ring) at(i int) (export.Event, bool) {
	if i < 0 || i >= r.size {
		return export.Event{}, false
	}
	return r.buf[(r.start+i)%len(r.buf)], true
}

// slice copies the held events, oldest first.
//
// It allocates, so views that only need a window should use last instead. It
// exists for tests and for export, where a stable snapshot matters more than
// an allocation.
func (r *ring) slice() []export.Event {
	out := make([]export.Event, 0, r.size)
	for i := 0; i < r.size; i++ {
		e, _ := r.at(i)
		out = append(out, e)
	}
	return out
}

// last copies the newest n events, oldest first among them. Asking for more
// than are held yields everything.
func (r *ring) last(n int) []export.Event {
	if n > r.size {
		n = r.size
	}
	if n < 0 {
		n = 0
	}
	out := make([]export.Event, 0, n)
	for i := r.size - n; i < r.size; i++ {
		e, _ := r.at(i)
		out = append(out, e)
	}
	return out
}

// reset empties the buffer, keeping its capacity and the dropped count. The
// count survives because it describes the session, not the current contents.
func (r *ring) reset() {
	r.start = 0
	r.size = 0
}
