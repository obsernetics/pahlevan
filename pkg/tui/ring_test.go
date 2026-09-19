package tui

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/obsernetics/pahlevan/pkg/export"
)

// marked builds an event whose comm is a sequence number. Eviction order is
// the whole contract of a ring, and a test that only counts elements cannot
// tell a buffer that dropped the oldest from one that dropped the newest.
func marked(i int) export.Event {
	return ev(export.EventTypeFile, false, fmt.Sprintf("p%d", i), "prod", "Deployment", "api")
}

func comms(evs []export.Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Process.Comm)
	}
	return out
}

func fill(r *ring, n int) {
	for i := 0; i < n; i++ {
		r.push(marked(i))
	}
}

func TestTheRingHoldsTheNewestEventsBelowAtAndAboveCapacity(t *testing.T) {
	// The capacity is what stops a terminal UI becoming a memory leak that
	// grows with the node's syscall rate, so the boundary it is enforced at
	// gets driven from both sides rather than from one comfortable middle.
	const capacity = 4
	for _, tc := range []struct {
		name    string
		pushed  int
		wantLen int
		wantAll []string
		dropped uint64
	}{
		{"empty", 0, 0, nil, 0},
		{"below capacity", 3, 3, []string{"p0", "p1", "p2"}, 0},
		{"exactly at capacity", 4, 4, []string{"p0", "p1", "p2", "p3"}, 0},
		{"one past capacity", 5, 4, []string{"p1", "p2", "p3", "p4"}, 1},
		{"many times capacity", 13, 4, []string{"p9", "p10", "p11", "p12"}, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRing(capacity)
			fill(r, tc.pushed)

			if got := r.len(); got != tc.wantLen {
				t.Errorf("len is %d, want %d", got, tc.wantLen)
			}
			if got := r.capacity(); got != capacity {
				t.Errorf("capacity is %d, want %d: pushing must never grow the buffer", got, capacity)
			}
			if got := comms(r.slice()); !reflect.DeepEqual(got, tc.wantAll) && !(len(got) == 0 && tc.wantAll == nil) {
				t.Errorf("slice is %v, want %v", got, tc.wantAll)
			}
			if r.dropped != tc.dropped {
				t.Errorf("dropped is %d, want %d: the count is what the status line says rolled off", r.dropped, tc.dropped)
			}
			// at must agree with slice element for element, because the views
			// read through at and the export path reads through slice.
			for i, want := range tc.wantAll {
				e, ok := r.at(i)
				if !ok {
					t.Fatalf("at(%d) reported no element while %d are held", i, r.len())
				}
				if e.Process.Comm != want {
					t.Errorf("at(%d) is %q, want %q", i, e.Process.Comm, want)
				}
			}
		})
	}
}

func TestEvictionIsFIFOAndEveryEvictionIsCountedExactlyOnce(t *testing.T) {
	// A view that silently discards is a view that lies about what happened.
	// "12,481 earlier events not shown" only means something if the counter
	// tracks evictions one for one, including across many wraps.
	const capacity = 8
	r := newRing(capacity)
	const pushes = capacity*5 + 3

	for i := 0; i < pushes; i++ {
		r.push(marked(i))
		wantDropped := 0
		if i+1 > capacity {
			wantDropped = i + 1 - capacity
		}
		if r.dropped != uint64(wantDropped) {
			t.Fatalf("after %d pushes dropped is %d, want %d", i+1, r.dropped, wantDropped)
		}
	}

	got := comms(r.slice())
	want := make([]string, 0, capacity)
	for i := pushes - capacity; i < pushes; i++ {
		want = append(want, fmt.Sprintf("p%d", i))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("contents are %v, want %v: the oldest event must be the one evicted", got, want)
	}
}

func TestAtOutOfRangeReturnsFalseRatherThanPanicking(t *testing.T) {
	// The caller is a view doing arithmetic against a viewport height that
	// changes under it on a resize. An index panic there takes the whole
	// program down and leaves the terminal in the alternate screen.
	for _, tc := range []struct {
		name   string
		held   int
		index  int
		wantOK bool
	}{
		{"negative index on an empty ring", 0, -1, false},
		{"zero index on an empty ring", 0, 0, false},
		{"negative index on a full ring", 4, -1, false},
		{"first held element", 4, 0, true},
		{"last held element", 4, 3, true},
		{"one past the end", 4, 4, false},
		{"far past the end", 4, 4096, false},
		{"inside the capacity but not yet written", 4, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRing(4)
			fill(r, tc.held)
			e, ok := r.at(tc.index)
			if ok != tc.wantOK {
				t.Fatalf("at(%d) ok is %v, want %v", tc.index, ok, tc.wantOK)
			}
			if !ok && e.Process.Comm != "" {
				t.Errorf("a rejected index still returned an event: %+v", e)
			}
		})
	}
}

func TestLastClampsEveryNToWhatIsActuallyHeld(t *testing.T) {
	// last feeds the visible window, and the window height comes from the
	// terminal. A negative or oversized n is the normal consequence of a
	// small window, not a programming error worth panicking over.
	r := newRing(8)
	fill(r, 5) // p0..p4

	for _, tc := range []struct {
		name string
		n    int
		want []string
	}{
		{"negative n yields nothing", -3, []string{}},
		{"zero n yields nothing", 0, []string{}},
		{"one yields only the newest", 1, []string{"p4"}},
		{"a window smaller than the contents", 3, []string{"p2", "p3", "p4"}},
		{"n equal to the size", 5, []string{"p0", "p1", "p2", "p3", "p4"}},
		{"n larger than the size yields everything", 500, []string{"p0", "p1", "p2", "p3", "p4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := comms(r.last(tc.n))
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("last(%d) is %v, want %v", tc.n, got, tc.want)
			}
		})
	}
}

func TestLastReadsThroughTheWrapPoint(t *testing.T) {
	// Once the buffer has wrapped, the newest events straddle the end of the
	// backing slice. Reading them without the modulo yields the oldest
	// events in the newest positions, which reads as a UI that has frozen.
	r := newRing(4)
	fill(r, 10) // p6..p9 remain
	if got, want := comms(r.last(3)), []string{"p7", "p8", "p9"}; !reflect.DeepEqual(got, want) {
		t.Errorf("last(3) after a wrap is %v, want %v", got, want)
	}
}

func TestResetEmptiesTheRingButKeepsCapacityAndTheDropCount(t *testing.T) {
	// The drop count describes the session, not the current contents: the "c"
	// key clears the list a person is reading, it does not make the events
	// that rolled off earlier un-happen.
	r := newRing(4)
	fill(r, 10)
	if r.dropped == 0 {
		t.Fatal("the fixture did not drop anything, so reset is not being tested")
	}
	droppedBefore := r.dropped

	r.reset()

	if r.len() != 0 {
		t.Errorf("len after reset is %d, want 0", r.len())
	}
	if r.capacity() != 4 {
		t.Errorf("capacity after reset is %d, want 4", r.capacity())
	}
	if r.dropped != droppedBefore {
		t.Errorf("reset changed the drop count to %d, want %d", r.dropped, droppedBefore)
	}
	if _, ok := r.at(0); ok {
		t.Error("at(0) still reports an element after reset")
	}
	if got := r.slice(); len(got) != 0 {
		t.Errorf("slice after reset is %v, want empty", comms(got))
	}

	// The emptied ring must still work, not just look empty.
	fill(r, 2)
	if got, want := comms(r.slice()), []string{"p0", "p1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after reusing the ring the contents are %v, want %v", got, want)
	}
}

func TestAZeroCapacityRingStillHoldsOneEvent(t *testing.T) {
	// The capacity divides in every index calculation. A zero from a
	// misconfigured --capacity would be a division by zero on the first
	// event rather than a bad-looking screen.
	for _, capacity := range []int{-7, 0, 1} {
		r := newRing(capacity)
		if r.capacity() != 1 {
			t.Errorf("newRing(%d) has capacity %d, want 1", capacity, r.capacity())
		}
		r.push(marked(0))
		r.push(marked(1))
		if got, want := comms(r.slice()), []string{"p1"}; !reflect.DeepEqual(got, want) {
			t.Errorf("newRing(%d) holds %v, want %v", capacity, got, want)
		}
	}
}

// BenchmarkRingPushSteadyState measures the state the UI actually lives in:
// full, evicting on every event. A push that allocates there allocates once
// per event on a node producing thousands a second.
func BenchmarkRingPushSteadyState(b *testing.B) {
	r := newRing(DefaultCapacity)
	e := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	for i := 0; i < DefaultCapacity; i++ {
		r.push(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.push(e)
	}
}

// BenchmarkRingLast50 measures one frame's worth of reading: the events view
// asks for a window on every redraw, and a redraw happens on every event.
func BenchmarkRingLast50(b *testing.B) {
	r := newRing(DefaultCapacity)
	e := ev(export.EventTypeFile, false, "nginx", "prod", "Deployment", "api")
	for i := 0; i < DefaultCapacity; i++ {
		r.push(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.last(50)
	}
}
