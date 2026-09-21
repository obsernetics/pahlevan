package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestSanitizePinComponent(t *testing.T) {
	// The installation name reaches a recursive remove, so the interesting
	// cases are the ones that would escape the pahlevan subtree.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain namespace", "pahlevan-system", "pahlevan-system"},
		{"keeps dots and underscores", "team_a.prod-1", "team_a.prod-1"},
		{"empty falls back", "", defaultInstallation},
		{"whitespace falls back", "   ", defaultInstallation},
		{"parent traversal cannot escape", "..", defaultInstallation},
		{"deep traversal cannot escape", "../../etc", "..-..-etc"},
		{"slash is not a separator", "a/b", "a-b"},
		{"nul and control chars", "a\x00b\nc", "a-b-c"},
		{"single dot falls back", ".", defaultInstallation},
		{"dots and dashes only falls back", ".-.-.", defaultInstallation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizePinComponent(tc.in); got != tc.want {
				t.Fatalf("sanitizePinComponent(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizePinComponentNeverEscapesTheNamespace(t *testing.T) {
	// The property that matters, stated directly: whatever comes in, the
	// joined root stays under /sys/fs/bpf/pahlevan.
	base := filepath.Join(DefaultBPFFSRoot, pinNamespace)
	for _, in := range []string{"..", "../..", "../../../", "a/../../b", "/etc", ".", "...."} {
		root := PinRootFor(DefaultBPFFSRoot, in)
		if !strings.HasPrefix(filepath.Clean(root), base+string(filepath.Separator)) {
			t.Fatalf("installation %q produced pin root %q, which is outside %q", in, root, base)
		}
	}
}

func TestSanitizePinComponentTruncates(t *testing.T) {
	got := sanitizePinComponent(strings.Repeat("n", 400))
	if len(got) != 200 {
		t.Fatalf("length = %d, want 200 (bpffs inherits NAME_MAX)", len(got))
	}
}

func TestPinRootFor(t *testing.T) {
	if got, want := PinRootFor("", "ns"), "/sys/fs/bpf/pahlevan/ns"; got != want {
		t.Fatalf("empty bpffs: got %q, want %q", got, want)
	}
	if got, want := PinRootFor("/mnt/bpf", "ns"), "/mnt/bpf/pahlevan/ns"; got != want {
		t.Fatalf("custom bpffs: got %q, want %q", got, want)
	}
}

func TestDefaultPinRoot(t *testing.T) {
	t.Run("explicit override wins", func(t *testing.T) {
		t.Setenv("PAHLEVAN_PIN_ROOT", "/mnt/bpf/custom")
		t.Setenv("PAHLEVAN_POD_NAMESPACE", "ignored")
		if got := DefaultPinRoot(); got != "/mnt/bpf/custom" {
			t.Fatalf("got %q, want the override", got)
		}
	})
	t.Run("namespace separates installations", func(t *testing.T) {
		t.Setenv("PAHLEVAN_PIN_ROOT", "")
		t.Setenv("PAHLEVAN_POD_NAMESPACE", "security")
		if got, want := DefaultPinRoot(), "/sys/fs/bpf/pahlevan/security"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("two namespaces do not collide", func(t *testing.T) {
		if PinRootFor("", "a") == PinRootFor("", "b") {
			t.Fatal("two installations share a pin root; each would adopt the other's state")
		}
	})
	t.Run("no namespace still yields a named directory", func(t *testing.T) {
		t.Setenv("PAHLEVAN_PIN_ROOT", "")
		t.Setenv("PAHLEVAN_POD_NAMESPACE", "")
		if got, want := DefaultPinRoot(), "/sys/fs/bpf/pahlevan/"+defaultInstallation; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

func TestDecidePin(t *testing.T) {
	good := pinMeta{Magic: pinMagic, Schema: pinSchemaVersion, Digest: 0xABCD, Collections: uint64(collSyscall)}

	cases := []struct {
		name       string
		found      bool
		readErr    error
		got        pinMeta
		want       pinDecision
		reasonHas  string
		wantDigest uint64
	}{
		{
			name: "nothing pinned is a first start", found: false,
			want: pinFresh, reasonHas: "no pinned state", wantDigest: 0xABCD,
		},
		{
			name: "same programs are adopted", found: true, got: good,
			want: pinAdopt, reasonHas: "matches", wantDigest: 0xABCD,
		},
		{
			// The upgrade case. Adopting here would leave the OLD programs
			// attached while the new agent decoded their events with new
			// structs.
			name: "different programs force a rebuild", found: true, got: good,
			want: pinRebuild, reasonHas: "pinned programs differ", wantDigest: 0x1234,
		},
		{
			name: "schema bump forces a rebuild", found: true,
			got:  pinMeta{Magic: pinMagic, Schema: pinSchemaVersion + 1, Digest: 0xABCD, Collections: 1},
			want: pinRebuild, reasonHas: "schema", wantDigest: 0xABCD,
		},
		{
			name: "someone else's pin is not adopted", found: true,
			got:  pinMeta{Magic: 0xDEADBEEF, Schema: pinSchemaVersion, Digest: 0xABCD, Collections: 1},
			want: pinRebuild, reasonHas: "not Pahlevan", wantDigest: 0xABCD,
		},
		{
			name: "an unreadable stamp is cleared, not trusted", found: true,
			readErr: errors.New("value size 8"),
			want:    pinRebuild, reasonHas: "unreadable", wantDigest: 0xABCD,
		},
		{
			// A stamp claiming nothing was pinned describes an empty tree;
			// adopting it would report "no gap" while adopting no objects.
			name: "a stamp with no collections is a fresh start", found: true,
			got:  pinMeta{Magic: pinMagic, Schema: pinSchemaVersion, Digest: 0xABCD},
			want: pinFresh, reasonHas: "no collections", wantDigest: 0xABCD,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := decidePin(tc.found, tc.readErr, tc.got, tc.wantDigest)
			if got != tc.want {
				t.Fatalf("decision = %v (%s), want %v", got, reason, tc.want)
			}
			if !strings.Contains(reason, tc.reasonHas) {
				t.Fatalf("reason %q does not mention %q; an operator has to be able to act on this line", reason, tc.reasonHas)
			}
		})
	}
}

func TestPinDecisionString(t *testing.T) {
	for d, want := range map[pinDecision]string{pinAdopt: "adopt", pinRebuild: "rebuild", pinFresh: "fresh"} {
		if got := d.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", d, got, want)
		}
	}
}

func TestObjectDigestIsStableAndNonZero(t *testing.T) {
	a := objectDigest()
	b := objectDigest()
	if a != b {
		t.Fatalf("digest is not stable within a process: %#x then %#x", a, b)
	}
	if a == 0 {
		t.Fatal("digest is zero; every pin tree would look like it matched an uninitialised stamp")
	}
}

func TestPinnableSkipsCompilerInternalMaps(t *testing.T) {
	for _, name := range []string{".rodata", ".bss", ".data", ""} {
		if pinnable(name) {
			t.Errorf("pinnable(%q) = true; internal maps have no valid pin filename", name)
		}
	}
	for _, name := range []string{"file_allowed", "exec_mode", "events"} {
		if !pinnable(name) {
			t.Errorf("pinnable(%q) = false; userspace addresses this map by name", name)
		}
	}
}

func TestPinStorePaths(t *testing.T) {
	p := newPinStore("/sys/fs/bpf/pahlevan/ns")
	if !p.enabled {
		t.Fatal("a non-empty root should enable pinning")
	}
	if got, want := p.mapsDir(collFile), "/sys/fs/bpf/pahlevan/ns/file/maps"; got != want {
		t.Errorf("mapsDir = %q, want %q", got, want)
	}
	if got, want := p.progsDir(collExec), "/sys/fs/bpf/pahlevan/ns/exec/progs"; got != want {
		t.Errorf("progsDir = %q, want %q", got, want)
	}
	if got, want := p.linksDir(collNetwork), "/sys/fs/bpf/pahlevan/ns/network/links"; got != want {
		t.Errorf("linksDir = %q, want %q", got, want)
	}
	if got, want := p.metaPath(), "/sys/fs/bpf/pahlevan/ns/meta"; got != want {
		t.Errorf("metaPath = %q, want %q", got, want)
	}
	// Every collection needs a directory name: one missing would silently
	// place its pins at the root and collide with another collection's.
	seen := map[string]bool{}
	for _, id := range allCollections {
		d := collectionDir[id]
		if d == "" {
			t.Fatalf("collection %d has no directory name", id)
		}
		if seen[d] {
			t.Fatalf("collection directory %q is used twice", d)
		}
		seen[d] = true
	}
}

func TestPinStoreDisabledWithoutRoot(t *testing.T) {
	p := newPinStore("")
	if p.enabled {
		t.Fatal("an empty root must disable pinning, not pin at the filesystem root")
	}
	if p.disabledReason == "" {
		t.Error("a disabled store must say why; otherwise the log line is silent")
	}
	// Disabled is a working state, not a broken one.
	if err := p.pin(collFile, nil); err != nil {
		t.Errorf("pin on a disabled store: %v", err)
	}
	if _, ok := p.adoptLink(collFile, linkFileOpen); ok {
		t.Error("a disabled store must not claim to have adopted a link")
	}
}

func TestNilPinStoreIsSafe(t *testing.T) {
	// A Manager built by hand - as several tests do - has no store. A panic
	// here would take the data plane down over an optional feature.
	var p *pinStore
	p.disable("because")
	if err := p.pin(collFile, nil); err != nil {
		t.Errorf("pin: %v", err)
	}
	if err := p.pinLink(collFile, linkFileOpen, nil); err != nil {
		t.Errorf("pinLink: %v", err)
	}
	if _, ok := p.adoptLink(collFile, linkFileOpen); ok {
		t.Error("adoptLink on a nil store returned a link")
	}
	if err := p.purge(); err != nil {
		t.Errorf("purge: %v", err)
	}
}

func TestPurgePinnedStateRefusesForeignPaths(t *testing.T) {
	// PurgePinnedState deletes recursively and takes an operator-supplied
	// path, so the guard is the only thing between a typo and a wiped
	// directory.
	for _, bad := range []string{"", "   ", "/", "/sys/fs/bpf", "/etc", "/sys/fs/bpf/cilium/x"} {
		if err := PurgePinnedState(bad); err == nil {
			t.Errorf("PurgePinnedState(%q) was accepted; it must refuse anything outside a %s pin root", bad, pinNamespace)
		}
	}
}

func TestPurgePinnedStateRemovesThePinRoot(t *testing.T) {
	// On an ordinary filesystem this only exercises the path handling and the
	// removal; that the unlink actually detaches a program is a kernel
	// property and is proved by the VM suite.
	base := t.TempDir()
	root := filepath.Join(base, pinNamespace, "ns")
	if err := os.MkdirAll(filepath.Join(root, "file", "links"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file", "links", linkFileOpen), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PurgePinnedState(root); err != nil {
		t.Fatalf("PurgePinnedState: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("pin root still present after purge: %v", err)
	}
	// Idempotent: uninstall may well be run twice.
	if err := PurgePinnedState(root); err != nil {
		t.Fatalf("second PurgePinnedState: %v", err)
	}
}

func TestCollectionNames(t *testing.T) {
	got := (collSyscall | collFile | collKprobe).names()
	want := []string{"syscall", "file", "kprobe"}
	if len(got) != len(want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v (fixed order, so log lines are comparable)", got, want)
		}
	}
	if n := collectionID(0).names(); len(n) != 0 {
		t.Errorf("empty set names = %v, want none", n)
	}
}

func TestManagerPinRootAndAdoptionDefaults(t *testing.T) {
	m := &Manager{}
	if m.AdoptedPinnedState() {
		t.Error("a fresh Manager must not claim to have adopted state")
	}
	if got := m.PinRoot(); got != "" {
		t.Errorf("PinRoot on a Manager with no store = %q, want empty", got)
	}
	m.SetPinRoot("/sys/fs/bpf/pahlevan/ns")
	if got := m.PinRoot(); got != "/sys/fs/bpf/pahlevan/ns" {
		t.Errorf("PinRoot = %q after SetPinRoot", got)
	}
	m.SetPinRoot("")
	if got := m.PinRoot(); got != "" {
		t.Errorf("SetPinRoot(\"\") must disable pinning, got %q", got)
	}
	// Teardown with no store is the uninstall of an agent that never pinned.
	if err := m.Teardown(); err != nil {
		t.Errorf("Teardown with no pin root: %v", err)
	}
}

func TestMapSizesForCoverEveryCollection(t *testing.T) {
	// A collection whose sizing table is missing would be adopted with the
	// compiled-in max_entries while its configuration said otherwise - the
	// exact silent mismatch checkMapCompatible exists to catch.
	m := &Manager{mapSizing: MapSizing{
		SyscallSeen: 11, FileAllowed: 22, NetworkAllowed: 33, ExecAllowed: 44, RingBufBytes: 55,
	}}
	for _, id := range allCollections {
		sizes := m.mapSizesFor(id)
		if len(sizes) == 0 {
			t.Errorf("collection %q has no map sizing entry", collectionDir[id])
		}
		for name, n := range sizes {
			if n == 0 {
				t.Errorf("collection %q map %q sized 0", collectionDir[id], name)
			}
		}
	}
	if got := m.mapSizesFor(collectionID(1 << 40)); got != nil {
		t.Errorf("unknown collection returned %v, want nil", got)
	}
}

func TestCollectionSlotIsDistinctPerCollection(t *testing.T) {
	// Adoption writes each adopted collection through its slot. Two
	// collections sharing one field would mean the second silently replaced
	// the first, and the Manager would believe it had adopted both.
	m := &Manager{}
	seen := map[**ebpf.Collection]collectionID{}
	for _, id := range allCollections {
		slot := m.collectionSlot(id)
		if slot == nil {
			t.Fatalf("collection %q has no Manager field; adoption would drop it", collectionDir[id])
		}
		if other, dup := seen[slot]; dup {
			t.Fatalf("collections %q and %q share a Manager field", collectionDir[other], collectionDir[id])
		}
		seen[slot] = id
	}
	if m.collectionSlot(collectionID(1<<40)) != nil {
		t.Error("an unknown collection returned a slot")
	}
}

func TestSpecLoadersCoverEveryCollection(t *testing.T) {
	for _, id := range allCollections {
		if specLoaders[id] == nil {
			t.Errorf("collection %q has no spec loader; it could be recorded as pinned and never adopted", collectionDir[id])
		}
	}
	m := &Manager{}
	if _, err := m.specFor(collectionID(1 << 40)); err == nil {
		t.Error("specFor accepted an unknown collection")
	}
}

func TestSpecForAppliesMapSizing(t *testing.T) {
	// The adopt path compares a pinned map against this spec, so the sizing
	// must already be applied by the time the comparison happens.
	m := &Manager{mapSizing: MapSizing{FileAllowed: 4096, RingBufBytes: 1 << 16}}
	spec, err := m.specFor(collFile)
	if err != nil {
		t.Skipf("file monitor spec unavailable on this build: %v", err)
	}
	if got := spec.Maps["file_allowed"].MaxEntries; got != 4096 {
		t.Errorf("file_allowed max_entries = %d, want 4096", got)
	}
	if got := spec.Maps["file_events"].MaxEntries; got != 1<<16 {
		t.Errorf("file_events size = %d, want %d", got, 1<<16)
	}
}

func BenchmarkObjectDigest(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = objectDigest()
	}
}

func BenchmarkDecidePin(b *testing.B) {
	b.ReportAllocs()
	got := pinMeta{Magic: pinMagic, Schema: pinSchemaVersion, Digest: 1, Collections: 1}
	for i := 0; i < b.N; i++ {
		_, _ = decidePin(true, nil, got, 1)
	}
}

func BenchmarkDefaultPinRoot(b *testing.B) {
	b.ReportAllocs()
	b.Setenv("PAHLEVAN_PIN_ROOT", "")
	b.Setenv("PAHLEVAN_POD_NAMESPACE", "pahlevan-system")
	for i := 0; i < b.N; i++ {
		_ = DefaultPinRoot()
	}
}

func BenchmarkSanitizePinComponent(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = sanitizePinComponent("pahlevan-system")
	}
}

func BenchmarkManagerSpecFor(b *testing.B) {
	// The startup path: parsing a collection's ELF and applying map sizing is
	// done once per collection on every start, and twice over on the adopt
	// path if it is ever allowed to load a spec it has already loaded.
	b.ReportAllocs()
	m := &Manager{mapSizing: MapSizing{FileAllowed: 4096, RingBufBytes: 1 << 16}}
	if _, err := m.specFor(collFile); err != nil {
		b.Skipf("file monitor spec unavailable: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.specFor(collFile); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAttachedReportsTheDataPlaneNotThePort(t *testing.T) {
	// A readiness probe wired to this must not go green before the required
	// hook is in the kernel; each of these three is a way the data plane can
	// be absent while the pod is otherwise healthy.
	m := &Manager{}
	if m.Attached() {
		t.Error("a Manager that has never started reported attached")
	}
	m.running = true
	if m.Attached() {
		t.Error("running with no syscall link reported attached")
	}
	m.syscallLinks = make([]link.Link, 1)
	if m.Attached() {
		t.Error("a link with no ring-buffer reader reported attached; events would go nowhere")
	}
}

func BenchmarkAttached(b *testing.B) {
	// On the readiness probe path, polled every few seconds per node.
	b.ReportAllocs()
	m := &Manager{}
	for i := 0; i < b.N; i++ {
		_ = m.Attached()
	}
}
