package ebpf

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The whole point of a cache is that it returns the same answer the slow path
// would. A cache that returns a different string for a different input is a
// decoder that mislabels events.
func TestInternReturnsTheSameStringTheSlowPathWould(t *testing.T) {
	cases := [][]byte{
		[]byte("nginx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("python3\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		[]byte("a\x00"),
		[]byte("sixteencharname"),
		[]byte("\x00"),
		{},
	}
	for _, b := range cases {
		want := b
		if i := indexZero(want); i >= 0 {
			want = want[:i]
		}
		got := internComm(b)
		if got != string(want) {
			t.Errorf("internComm(%q) = %q, want %q", b, got, want)
		}
		// Twice, so the cached path is checked too rather than only the miss.
		if got := internComm(b); got != string(want) {
			t.Errorf("internComm(%q) second call = %q, want %q", b, got, want)
		}
	}
}

// Two different inputs must never collide onto one cached string.
func TestInternDoesNotConflateDistinctValues(t *testing.T) {
	a := internComm([]byte("nginx\x00"))
	b := internComm([]byte("nginy\x00"))
	if a == b {
		t.Fatalf("two distinct names both interned to %q", a)
	}
	// A prefix must not match its longer form.
	short := internComm([]byte("ngin\x00"))
	if short == a {
		t.Errorf("%q and %q collided", short, a)
	}
}

// A NUL in the middle terminates, exactly as the kernel's fixed-width buffer
// means it to - the bytes after it are whatever was in the buffer before.
func TestInternStopsAtTheFirstNUL(t *testing.T) {
	got := internComm([]byte("sh\x00stale-garbage"))
	if got != "sh" {
		t.Errorf("internComm did not stop at the NUL: got %q", got)
	}
}

func TestContainerIDMatchesTheFormatItReplaced(t *testing.T) {
	for _, id := range []uint64{0, 1, 99, 4294967296, 18446744073709551615} {
		want := fmt.Sprintf("cgroup:%d", id)
		if got := containerIDFor(id); got != want {
			t.Errorf("containerIDFor(%d) = %q, want %q", id, got, want)
		}
		if got := containerIDFor(id); got != want {
			t.Errorf("containerIDFor(%d) cached = %q, want %q", id, got, want)
		}
	}
}

// Past the cap the tables must stop growing and fall back to allocating. A
// cache that grows without bound on attacker-influenced input is a leak, and an
// attacker who can exec arbitrary names controls this input.
func TestInternTablesAreBounded(t *testing.T) {
	tbl := &internTable{m: make(map[string]string, 8)}
	for i := 0; i < internCap+500; i++ {
		name := fmt.Sprintf("proc-%d", i)
		if got := tbl.lookup([]byte(name)); got != name {
			t.Fatalf("lookup(%q) = %q", name, got)
		}
	}
	tbl.mu.RLock()
	n := len(tbl.m)
	tbl.mu.RUnlock()
	if n > internCap {
		t.Errorf("the table grew to %d entries, past the %d cap", n, internCap)
	}
	// And it still returns correct answers once full, just without caching.
	if got := tbl.lookup([]byte("after-the-cap")); got != "after-the-cap" {
		t.Errorf("a lookup past the cap returned %q", got)
	}
}

func TestContainerIDTableIsBounded(t *testing.T) {
	// Uses the package-level table deliberately: the cap has to hold for the
	// one the decoders actually call.
	for i := uint64(0); i < internCap+500; i++ {
		_ = containerIDFor(i + 1_000_000)
	}
	containerIDs.mu.RLock()
	n := len(containerIDs.m)
	containerIDs.mu.RUnlock()
	if n > internCap {
		t.Errorf("the container id table grew to %d entries, past the %d cap", n, internCap)
	}
	if got := containerIDFor(999_999_999); got != "cgroup:999999999" {
		t.Errorf("a lookup past the cap returned %q", got)
	}
}

// The ring-buffer readers are separate goroutines, so every decoder - and
// therefore every intern table - is reached concurrently. Run with -race.
func TestInternIsSafeUnderConcurrentDecoders(t *testing.T) {
	tbl := &internTable{m: make(map[string]string, 8)}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				// Overlapping sets, so readers and writers contend on the same
				// keys rather than each having their own.
				name := fmt.Sprintf("proc-%d", i%50)
				if got := tbl.lookup([]byte(name)); got != name {
					t.Errorf("lookup(%q) = %q", name, got)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestContainerIDIsSafeUnderConcurrentDecoders(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := uint64(0); i < 500; i++ {
				id := i % 50
				want := fmt.Sprintf("cgroup:%d", id)
				if got := containerIDFor(id); got != want {
					t.Errorf("containerIDFor(%d) = %q, want %q", id, got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// splitArgs replaced bytes.Split, which allocated a slice of subslices per
// event and threw it away. It must split identically.
func TestSplitArgsMatchesBytesSplit(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"python3\x00-c\x00print(1)\x00", []string{"python3", "-c", "print(1)"}},
		{"ls", []string{"ls"}},
		{"", nil},
		{"\x00\x00\x00", nil},
		{"a\x00\x00b\x00", []string{"a", "b"}},
		{"trailing-no-nul\x00x", []string{"trailing-no-nul", "x"}},
	}
	for _, tc := range cases {
		got := splitArgs(nil, []byte(tc.raw))
		if len(got) != len(tc.want) {
			t.Errorf("splitArgs(%q) = %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitArgs(%q)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
			}
		}
	}
}

// argv is arbitrary attacker-influenced input. Interning it would be a cache an
// attacker fills, so splitArgs must not touch the intern tables.
func TestArgumentsAreNotInterned(t *testing.T) {
	pathTable.mu.RLock()
	before := len(pathTable.m)
	pathTable.mu.RUnlock()

	unique := "arg-" + strings.Repeat("z", 40)
	_ = splitArgs(nil, []byte(unique+"\x00"+unique+"2\x00"))

	pathTable.mu.RLock()
	after := len(pathTable.m)
	pathTable.mu.RUnlock()
	if after != before {
		t.Errorf("splitArgs added %d entries to the path table; argv must not be interned",
			after-before)
	}
}

func BenchmarkInternCommHit(b *testing.B) {
	buf := []byte("nginx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	_ = internComm(buf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = internComm(buf)
	}
}

func BenchmarkContainerIDForHit(b *testing.B) {
	_ = containerIDFor(4242)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = containerIDFor(4242)
	}
}

func BenchmarkSplitArgs(b *testing.B) {
	raw := []byte("python3\x00-c\x00import socket;socket.create_connection((1,2))\x00")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = splitArgs(make([]string, 0, 8), raw)
	}
}
