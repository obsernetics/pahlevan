package ebpf

import (
	"errors"
	"fmt"
	hashfnv "hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Surviving an agent restart.
//
// Everything this file exists for comes down to one sentence: a BPF object
// lives exactly as long as something holds a reference to it, and until now the
// only thing holding a reference was the agent process. When the agent exited -
// a DaemonSet rolling update, an OOM kill, a node-pressure eviction, an image
// upgrade - every link's file descriptor was closed, every LSM program detached,
// and the node went completely unenforced. The replacement pod then came up with
// freshly created, EMPTY allow-set maps. Two outcomes, both unacceptable:
//
//   - the new agent has not re-learned anything yet, so the workload runs
//     unprotected until learning and enforcement happen all over again; or
//   - something flips a cgroup to enforcing against an empty allow-set, and
//     every file open, exec, connect and capability check the container makes is
//     denied - the agent kills the workload it is supposed to protect.
//
// A rolling upgrade hits every node in the cluster, by design. So this is not an
// edge case; it is what happens every time Pahlevan is upgraded.
//
// The fix is bpffs. A pin is a second reference to the object, held by a
// filesystem rather than by a process, so the object outlives the process that
// made it. A pinned LSM link stays attached. A pinned map keeps its contents.
// The new agent opens the pins instead of creating new objects, and enforcement
// never stops - there is no window at all, because nothing was ever detached.
//
// # What is pinned
//
// Maps, programs and links, under a per-installation root:
//
//	/sys/fs/bpf/pahlevan/<installation>/<collection>/maps/<map name>
//	/sys/fs/bpf/pahlevan/<installation>/<collection>/progs/<program name>
//	/sys/fs/bpf/pahlevan/<installation>/<collection>/links/<hook name>
//	/sys/fs/bpf/pahlevan/<installation>/meta
//
// The installation component is what stops two Pahlevan installations on one
// node - a migration running old and new side by side, a second install in
// another namespace - from adopting each other's state. Sharing that state would
// be worse than either colliding or starting fresh: two agents would each be
// managing enforcement the other also believes it owns.
//
// # Why adoption is all-or-nothing per collection
//
// Adopting some objects and creating others is how silent corruption happens. If
// the maps were adopted but the programs reloaded, the pinned links would still
// point at the OLD programs and the new ones would attach alongside them: two
// copies of every hook, double denials, duplicated events. If a map were adopted
// whose value layout had changed but whose name and size had not, the kernel
// would read old bytes through a new struct and the allow-set would be quietly
// wrong. So either every recorded object for a collection loads and matches, or
// the whole pin root is purged and everything is rebuilt from scratch.
//
// Rebuilding is a real gap in enforcement, so it is never silent: it is logged
// with the reason, and the reason is always one of "these are not the same
// programs" or "this state is not ours".
//
// # Why a pin failure is never fatal
//
// A node with no bpffs, a read-only /sys/fs/bpf, a kernel too old for
// BPF_OBJ_PIN - on all of those, an agent that refuses to start protects nothing
// at all, which is strictly worse than an agent that protects until it restarts.
// Every failure here degrades to the old, unpinned behavior and says so.

const (
	// DefaultBPFFSRoot is where bpffs is mounted on every distribution that
	// mounts it at all, and what the agent DaemonSet mounts into the pod.
	DefaultBPFFSRoot = "/sys/fs/bpf"

	// pinNamespace keeps Pahlevan's pins in one subtree, so a teardown can
	// remove exactly this tool's state and nothing else that may be pinned on
	// the node (cilium, a CNI, a hand-loaded probe).
	pinNamespace = "pahlevan"

	// defaultInstallation is used when nothing identifies the installation.
	// It is a name, not an empty path component, so the pin root is always a
	// directory below pinNamespace and a purge can never be handed
	// "/sys/fs/bpf/pahlevan/" plus a trailing slash's worth of ambiguity.
	defaultInstallation = "pahlevan-system"

	// pinMetaName is the pinned array map that stamps the rest of the tree.
	// bpffs holds BPF objects and nothing else, so the only way to leave a
	// note next to the pins is to leave it IN a pin.
	pinMetaName = "meta"

	// pinMetaMapName is the kernel-visible name of that map, kept under the
	// kernel's 15-character limit so `bpftool map` shows it in full.
	pinMetaMapName = "pahlevan_meta"

	// pinMagic marks the meta map as ours: "PAHV". Without it, any array map
	// of the right size that happened to be pinned at that path would be read
	// as Pahlevan state.
	pinMagic uint32 = 0x50414856

	// pinSchemaVersion is the manual lever for incompatibility that nothing
	// else can see.
	//
	// The digest below catches a changed program or a changed map geometry. It
	// cannot catch a change in what the BYTES IN A MAP VALUE MEAN when the
	// program is unchanged - for instance a userspace-side reinterpretation of
	// an enforcement-mode word. Bump this whenever the meaning of anything
	// stored in a pinned map changes, and every agent will rebuild rather than
	// read old bytes through new eyes.
	pinSchemaVersion uint32 = 1
)

// collectionID identifies one BPF collection. The bit values are recorded in
// the meta map, so the set of collections that were pinned survives with the
// pins - which is how adoption tells "this node never had a file monitor,
// because the kernel has no BPF LSM" apart from "the file monitor's pins are
// gone, so something is wrong and we must rebuild".
type collectionID uint64

const (
	collSyscall collectionID = 1 << iota
	collFile
	collNetwork
	collExec
	collCapability
	collCred
	collShell
	collKprobe
)

// collectionDir is the directory name for each collection. Spelled out rather
// than derived, because these names are on-disk state: renaming a Go constant
// must not silently orphan a node's pins.
var collectionDir = map[collectionID]string{
	collSyscall:    "syscall",
	collFile:       "file",
	collNetwork:    "network",
	collExec:       "exec",
	collCapability: "capability",
	collCred:       "cred",
	collShell:      "shell",
	collKprobe:     "kprobe",
}

// allCollections is iteration order for the adopt and pin passes. Fixed, so a
// log line listing what was adopted reads the same on every node.
var allCollections = []collectionID{
	collSyscall, collFile, collNetwork, collExec,
	collCapability, collCred, collShell, collKprobe,
}

// Link names. These are on-disk state too: one file per attachment, named for
// the hook rather than for the program, because what must not be attached twice
// is the hook.
const (
	linkSyscallTracepoint = "tp_raw_syscalls_sys_enter"
	linkFileOpen          = "lsm_file_open"
	linkSocketConnect     = "lsm_socket_connect"
	linkBprmCheck         = "lsm_bprm_check_security"
	linkCapable           = "lsm_capable"
	linkCommitCreds       = "kprobe_commit_creds"
)

// pinMeta stamps a pin tree with what produced it.
//
// Fixed-width fields in a fixed order because this is read back out of a kernel
// map by a future binary: anything variable-length would need a decoder that is
// itself a compatibility surface.
type pinMeta struct {
	Magic       uint32
	Schema      uint32
	Digest      uint64
	Collections uint64
}

// pinMetaSize is the meta map's value size. A pinned map whose value size is not
// this is not a meta map we can read, whatever it is called.
const pinMetaSize = 24

// objectDigest is the identity of the BPF programs this binary would load.
//
// It hashes the compiled ELF objects themselves. That is deliberately strict:
// any change to the C - a new field in an event struct, a changed allow-set key
// derivation, a different enforcement decision - produces different bytes, so an
// upgraded agent refuses to adopt the previous version's programs and rebuilds
// instead. Adopting across a program change is precisely the silent mismatch
// this whole file exists to prevent: the old program is still the one attached,
// so the new agent would be decoding the old program's events with the new
// program's structs.
//
// The cost is that an upgrade which changes the BPF objects has an enforcement
// gap on each node as it rolls. That is the honest trade: a brief, logged,
// deliberate gap beats indefinitely enforcing a policy nobody can read correctly.
var objectDigest = sync.OnceValue(func() uint64 {
	h := hashfnv.New64a()
	// Sorted by name so the digest does not depend on map iteration or on the
	// order someone happens to list the blobs in.
	blobs := []struct {
		name string
		data []byte
	}{
		{"capability", _CapabilityMonitorBytes},
		{"cred", _CredMonitorBytes},
		{"exec", _ExecMonitorBytes},
		{"file", _FileMonitorBytes},
		{"kprobe", _GenericKprobeBytes},
		{"network", _NetworkMonitorBytes},
		{"shell", _ShellMonitorBytes},
		{"syscall", _SyscallMonitorBytes},
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].name < blobs[j].name })
	for _, b := range blobs {
		_, _ = h.Write([]byte(b.name))
		_, _ = h.Write(b.data)
	}
	// The schema is folded in as well, so bumping it invalidates every pin
	// tree without needing a second comparison anywhere.
	_, _ = h.Write([]byte{
		byte(pinSchemaVersion), byte(pinSchemaVersion >> 8),
		byte(pinSchemaVersion >> 16), byte(pinSchemaVersion >> 24),
	})
	return h.Sum64()
})

// sanitizePinComponent makes one path component safe to join into the pin root.
//
// The installation name comes from a namespace or an operator-supplied flag, so
// it is untrusted input being turned into a filesystem path. "../.." must not
// escape the pahlevan subtree, because the teardown path removes whatever the
// pin root points at.
func sanitizePinComponent(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	// A component of dots is "." or ".." after joining, which would point the
	// pin root at a parent directory - the one place a recursive remove must
	// never be aimed.
	if strings.Trim(out, ".-") == "" {
		return defaultInstallation
	}
	// bpffs inherits the kernel's NAME_MAX. Truncating here rather than
	// failing keeps a long namespace usable; collisions between two names
	// sharing a 200-character prefix are not a real configuration.
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// PinRootFor builds the pin root for one installation under a bpffs mount.
func PinRootFor(bpffs, installation string) string {
	if bpffs == "" {
		bpffs = DefaultBPFFSRoot
	}
	return filepath.Join(bpffs, pinNamespace, sanitizePinComponent(installation))
}

// DefaultPinRoot is where the agent pins its state unless told otherwise.
//
// PAHLEVAN_PIN_ROOT overrides the whole path, for an operator whose bpffs is
// mounted somewhere else. Otherwise the installation is the agent's own
// namespace, which the DaemonSet already exposes as PAHLEVAN_POD_NAMESPACE and
// which is exactly the granularity at which two installations are separate.
func DefaultPinRoot() string {
	if r := strings.TrimSpace(os.Getenv("PAHLEVAN_PIN_ROOT")); r != "" {
		return r
	}
	return PinRootFor(DefaultBPFFSRoot, os.Getenv("PAHLEVAN_POD_NAMESPACE"))
}

// pinStore is the on-bpffs state for one installation.
//
// Every method tolerates a nil receiver, and that is deliberate rather than
// defensive: a Manager built by hand in a test, or one constructed before
// SetPinRoot is called, has no store, and a nil-pointer panic in the attach
// path would take down the data plane over a feature whose entire contract is
// "degrade quietly when it is not available".
type pinStore struct {
	root string
	// enabled is false when pinning was switched off or has failed. Every
	// method is a no-op then, so the caller never has to branch: the agent
	// simply runs the way it did before pins existed.
	enabled bool
	// disabledReason is what to tell the operator once, at startup, about why
	// this node will not survive an agent restart.
	disabledReason string
}

func newPinStore(root string) *pinStore {
	if strings.TrimSpace(root) == "" {
		return &pinStore{disabledReason: "no pin root configured"}
	}
	return &pinStore{root: root, enabled: true}
}

func (p *pinStore) mapsDir(id collectionID) string {
	return filepath.Join(p.root, collectionDir[id], "maps")
}

func (p *pinStore) progsDir(id collectionID) string {
	return filepath.Join(p.root, collectionDir[id], "progs")
}

func (p *pinStore) linksDir(id collectionID) string {
	return filepath.Join(p.root, collectionDir[id], "links")
}

func (p *pinStore) metaPath() string { return filepath.Join(p.root, pinMetaName) }

// disable turns pinning off for the rest of this process's life and records why.
//
// Called from every failure path. The agent keeps running unpinned: an agent
// that enforces until it restarts is worth far more than one that refuses to
// start because a node has no bpffs.
func (p *pinStore) disable(reason string) {
	if p == nil {
		return
	}
	p.enabled = false
	if p.disabledReason == "" {
		p.disabledReason = reason
	}
}

// readMeta loads the stamp from a pin tree. The bool reports whether a readable
// meta map was found at all, which is different from finding one that does not
// match.
func (p *pinStore) readMeta() (pinMeta, bool, error) {
	m, err := ebpf.LoadPinnedMap(p.metaPath(), &ebpf.LoadPinOptions{})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pinMeta{}, false, nil
		}
		return pinMeta{}, false, err
	}
	defer m.Close()

	if m.Type() != ebpf.Array || m.ValueSize() != pinMetaSize {
		// Something else is pinned here. Report it as "found, and wrong", so
		// the caller purges rather than adopting whatever is underneath.
		return pinMeta{}, true, fmt.Errorf("pinned %s is a %s with a %d-byte value, not a %d-byte array",
			pinMetaName, m.Type(), m.ValueSize(), pinMetaSize)
	}
	var got pinMeta
	if err := m.Lookup(uint32(0), &got); err != nil {
		return pinMeta{}, true, fmt.Errorf("reading %s: %w", pinMetaName, err)
	}
	return got, true, nil
}

// writeMeta stamps the tree. It replaces any existing stamp, because the set of
// pinned collections grows as best-effort programs load on a node that could
// not load them before.
func (p *pinStore) writeMeta(meta pinMeta) error {
	if err := os.MkdirAll(p.root, 0o700); err != nil {
		return fmt.Errorf("creating pin root %s: %w", p.root, err)
	}
	// Remove any previous stamp first: a map pin cannot be replaced in place,
	// and a stale stamp describing a tree we have just rebuilt is the one
	// thing that must never be left behind.
	_ = os.Remove(p.metaPath())

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       pinMetaMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  pinMetaSize,
		MaxEntries: 1,
	})
	if err != nil {
		return fmt.Errorf("creating %s map: %w", pinMetaName, err)
	}
	defer m.Close()

	if err := m.Put(uint32(0), meta); err != nil {
		return fmt.Errorf("writing %s: %w", pinMetaName, err)
	}
	if err := m.Pin(p.metaPath()); err != nil {
		return fmt.Errorf("pinning %s at %s: %w", pinMetaName, p.metaPath(), err)
	}
	return nil
}

// pinDecision is what to do with the state found on bpffs.
type pinDecision int

const (
	// pinAdopt: the pinned state was produced by these exact programs. Take it
	// over and keep enforcing without ever detaching anything.
	pinAdopt pinDecision = iota
	// pinRebuild: there is state, and it is not ours to adopt. Purge it and
	// load fresh, accepting a logged gap.
	pinRebuild
	// pinFresh: nothing is pinned. Load and pin, so the NEXT restart adopts.
	pinFresh
)

func (d pinDecision) String() string {
	switch d {
	case pinAdopt:
		return "adopt"
	case pinRebuild:
		return "rebuild"
	default:
		return "fresh"
	}
}

// decidePin is the whole adopt-or-rebuild rule, kept pure so it can be tested
// without a kernel.
//
// readErr is non-nil when a stamp was present but unreadable; found is false
// when there is no stamp at all. The two are different outcomes: no stamp means
// a first start, an unreadable stamp means someone else's state is sitting at
// our path and must be cleared before we pin over it.
func decidePin(found bool, readErr error, got pinMeta, wantDigest uint64) (pinDecision, string) {
	switch {
	case readErr != nil:
		return pinRebuild, "pinned state is unreadable: " + readErr.Error()
	case !found:
		return pinFresh, "no pinned state on this node"
	case got.Magic != pinMagic:
		return pinRebuild, fmt.Sprintf("pinned state is not Pahlevan's (magic %#x)", got.Magic)
	case got.Schema != pinSchemaVersion:
		return pinRebuild, fmt.Sprintf("pinned state uses schema %d, this agent uses %d", got.Schema, pinSchemaVersion)
	case got.Digest != wantDigest:
		return pinRebuild, fmt.Sprintf("pinned programs differ from this agent's (digest %#x, want %#x)", got.Digest, wantDigest)
	case got.Collections == 0:
		// A stamp claiming nothing was pinned describes an empty tree. Treat
		// it as a fresh start rather than adopting zero objects and believing
		// enforcement carried over.
		return pinFresh, "pinned state records no collections"
	default:
		return pinAdopt, "pinned state matches this agent's programs"
	}
}

// checkMapCompatible refuses a pinned map whose shape does not match the spec
// this binary would have created.
//
// The digest already establishes that the programs are the same, so this should
// never fire in practice - except for the one case it exists for: map sizing is
// a runtime setting, so an agent restarted with a larger file_allowed would
// otherwise adopt the smaller map and quietly run with the old capacity while
// its own configuration says otherwise.
func checkMapCompatible(name string, m *ebpf.Map, spec *ebpf.MapSpec) error {
	if m.Type() != spec.Type {
		return fmt.Errorf("pinned map %q is a %s, spec says %s", name, m.Type(), spec.Type)
	}
	if m.KeySize() != spec.KeySize {
		return fmt.Errorf("pinned map %q has a %d-byte key, spec says %d", name, m.KeySize(), spec.KeySize)
	}
	if m.ValueSize() != spec.ValueSize {
		return fmt.Errorf("pinned map %q has a %d-byte value, spec says %d", name, m.ValueSize(), spec.ValueSize)
	}
	if m.MaxEntries() != spec.MaxEntries {
		return fmt.Errorf("pinned map %q holds %d entries, spec says %d", name, m.MaxEntries(), spec.MaxEntries)
	}
	return nil
}

// pinnable reports whether a map in a CollectionSpec is one userspace addresses
// by name.
//
// Compiler-internal maps (.rodata, .bss and friends) are skipped: they are
// reached only by the program that owns them, the program keeps them alive on
// its own, and their names are not valid pin filenames. Their CONTENTS are still
// covered, because they are compiled into the ELF the digest hashes.
func pinnable(name string) bool {
	return name != "" && !strings.HasPrefix(name, ".")
}

// adopt takes over one collection's pinned maps and programs.
//
// All or nothing: a collection that is half adopted is a collection where some
// objects are the ones the kernel is using and some are not.
func (p *pinStore) adopt(id collectionID, spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	coll := &ebpf.Collection{
		Maps:     make(map[string]*ebpf.Map, len(spec.Maps)),
		Programs: make(map[string]*ebpf.Program, len(spec.Programs)),
	}
	fail := func(err error) (*ebpf.Collection, error) {
		coll.Close()
		return nil, err
	}

	for name, ms := range spec.Maps {
		if !pinnable(name) {
			continue
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(p.mapsDir(id), name), &ebpf.LoadPinOptions{})
		if err != nil {
			return fail(fmt.Errorf("map %q: %w", name, err))
		}
		if cerr := checkMapCompatible(name, m, ms); cerr != nil {
			m.Close()
			return fail(cerr)
		}
		coll.Maps[name] = m
	}

	for name := range spec.Programs {
		prog, err := ebpf.LoadPinnedProgram(filepath.Join(p.progsDir(id), name), &ebpf.LoadPinOptions{})
		if err != nil {
			return fail(fmt.Errorf("program %q: %w", name, err))
		}
		coll.Programs[name] = prog
	}

	return coll, nil
}

// pin writes one collection's maps and programs to bpffs.
//
// Failure is reported but leaves the collection usable: the objects are loaded
// and attached either way, they just will not outlive this process.
func (p *pinStore) pin(id collectionID, coll *ebpf.Collection) error {
	if p == nil || !p.enabled || coll == nil {
		return nil
	}
	if err := os.MkdirAll(p.mapsDir(id), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", p.mapsDir(id), err)
	}
	if err := os.MkdirAll(p.progsDir(id), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", p.progsDir(id), err)
	}
	if err := os.MkdirAll(p.linksDir(id), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", p.linksDir(id), err)
	}

	for name, m := range coll.Maps {
		if !pinnable(name) {
			continue
		}
		path := filepath.Join(p.mapsDir(id), name)
		// A leftover pin at this path belongs to a tree we have already
		// decided not to adopt, so it is stale by construction: the purge that
		// preceded this should have removed it, and if it did not, pinning
		// would fail with EEXIST and cost us the restart we are trying to fix.
		_ = os.Remove(path)
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pinning map %q: %w", name, err)
		}
	}
	for name, prog := range coll.Programs {
		path := filepath.Join(p.progsDir(id), name)
		_ = os.Remove(path)
		if err := prog.Pin(path); err != nil {
			return fmt.Errorf("pinning program %q: %w", name, err)
		}
	}
	return nil
}

// adoptLink opens a pinned link, or reports that there is none.
//
// A missing link pin is normal, not an error: the hook may never have attached
// on this node - no BPF LSM, no such kernel symbol - and the caller will simply
// attach it now, with the program it has just adopted.
func (p *pinStore) adoptLink(id collectionID, name string) (link.Link, bool) {
	if p == nil || !p.enabled {
		return nil, false
	}
	l, err := link.LoadPinnedLink(filepath.Join(p.linksDir(id), name), &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, false
	}
	return l, true
}

// pinLink makes an attachment outlive this process. This is the single most
// important call in the file: a pinned link is what keeps the LSM hook in place
// while no Pahlevan process is running at all.
func (p *pinStore) pinLink(id collectionID, name string, l link.Link) error {
	if p == nil || !p.enabled || l == nil {
		return nil
	}
	if err := os.MkdirAll(p.linksDir(id), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", p.linksDir(id), err)
	}
	path := filepath.Join(p.linksDir(id), name)
	_ = os.Remove(path)
	if err := l.Pin(path); err != nil {
		return fmt.Errorf("pinning link %q: %w", name, err)
	}
	return nil
}

// purge removes the whole pin tree.
//
// Unlinking a pin drops the reference the filesystem holds. When no process
// holds the object either - which is the case for state left behind by an agent
// that has already exited - that is the last reference, so the link is destroyed
// and the program detaches. This is both the rebuild path and the uninstall
// path, and it is the ONLY thing that turns enforcement off for good.
func (p *pinStore) purge() error {
	if p == nil || p.root == "" {
		return nil
	}
	if err := os.RemoveAll(p.root); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing pin root %s: %w", p.root, err)
	}
	return nil
}

// PurgePinnedState detaches and removes everything Pahlevan has pinned under
// root, leaving the node with no Pahlevan programs attached.
//
// This is the UNINSTALL path, and it must never be reached by an agent shutting
// down normally. A DaemonSet pod terminating during a rolling update is expected
// to leave its pins exactly where they are - that is what makes the upgrade
// gapless. Calling this on SIGTERM would reintroduce the entire bug: every
// rolling update would detach every program on every node.
//
// An operator removing Pahlevan runs it explicitly, via `pahlevan-agent
// --teardown-pinned-state`, and gets a node with nothing attached and nothing
// enforcing rather than orphaned programs that nothing manages and nothing can
// switch off short of a reboot.
func PurgePinnedState(root string) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("no pin root given")
	}
	// Refuse to aim a recursive remove anywhere outside our own subtree. The
	// root is built from operator-supplied input, and this function deletes.
	if !strings.Contains(filepath.Clean(root), string(filepath.Separator)+pinNamespace+string(filepath.Separator)) {
		return fmt.Errorf("refusing to purge %q: not a %s pin root", root, pinNamespace)
	}
	return (&pinStore{root: root, enabled: true}).purge()
}

// ---------------------------------------------------------------------------
// Manager glue.
//
// Kept here rather than in manager.go so the whole restart story - decide,
// adopt, pin, tear down - reads top to bottom in one file.
// ---------------------------------------------------------------------------

// mapSizesFor is the runtime map-size override table for one collection.
//
// Single source of truth for both the fresh-load path and the compatibility
// check on the adopt path: if these two disagreed, an agent could adopt a map
// sized differently from the one it believes it configured.
func (m *Manager) mapSizesFor(id collectionID) map[string]uint32 {
	switch id {
	case collSyscall:
		return map[string]uint32{"syscall_seen": m.mapSizing.SyscallSeen, "events": m.mapSizing.RingBufBytes}
	case collFile:
		return map[string]uint32{"file_allowed": m.mapSizing.FileAllowed, "file_events": m.mapSizing.RingBufBytes}
	case collNetwork:
		return map[string]uint32{"network_allowed": m.mapSizing.NetworkAllowed, "network_events": m.mapSizing.RingBufBytes}
	case collExec:
		return map[string]uint32{"exec_allowed": m.mapSizing.ExecAllowed, "exec_events": m.mapSizing.RingBufBytes}
	case collCapability:
		return map[string]uint32{"cap_events": m.mapSizing.RingBufBytes}
	case collCred:
		return map[string]uint32{"cred_events": m.mapSizing.RingBufBytes}
	case collShell:
		return map[string]uint32{"shell_events": m.mapSizing.RingBufBytes}
	case collKprobe:
		return map[string]uint32{"kp_events": m.mapSizing.RingBufBytes}
	default:
		return nil
	}
}

// specLoaders maps a collection to its generated loader.
var specLoaders = map[collectionID]func() (*ebpf.CollectionSpec, error){
	collSyscall:    LoadSyscallMonitor,
	collFile:       LoadFileMonitor,
	collNetwork:    LoadNetworkMonitor,
	collExec:       LoadExecMonitor,
	collCapability: LoadCapabilityMonitor,
	collCred:       LoadCredMonitor,
	collShell:      LoadShellMonitor,
	collKprobe:     LoadGenericKprobe,
}

// specFor parses one collection's ELF and applies the configured map sizing.
func (m *Manager) specFor(id collectionID) (*ebpf.CollectionSpec, error) {
	load := specLoaders[id]
	if load == nil {
		return nil, fmt.Errorf("unknown collection %d", id)
	}
	spec, err := load()
	if err != nil {
		return nil, err
	}
	applyMapSizing(spec, m.mapSizesFor(id))
	return spec, nil
}

// collectionSlot returns the Manager field one collection lives in, so the
// adopt pass can fill exactly the same fields the fresh-load path does.
func (m *Manager) collectionSlot(id collectionID) **ebpf.Collection {
	switch id {
	case collSyscall:
		return &m.syscallCollection
	case collFile:
		return &m.fileCollection
	case collNetwork:
		return &m.networkCollection
	case collExec:
		return &m.execCollection
	case collCapability:
		return &m.capCollection
	case collCred:
		return &m.credCollection
	case collShell:
		return &m.shellCollection
	case collKprobe:
		return &m.kprobeCollection
	}
	return nil
}

// adoptPinnedState is the first thing LoadPrograms does.
//
// It decides, once, whether the state already on bpffs was produced by these
// exact programs, and if so takes the whole of it over. Anything less than
// complete success leaves the tree purged and the Manager untouched, so the
// caller's ordinary load path runs as if nothing had been pinned - which is the
// only way to be sure the kernel is not left running a mixture of two versions.
//
// Called with m.mu held.
func (m *Manager) adoptPinnedState() {
	if m.pins == nil || !m.pins.enabled {
		return
	}

	got, found, rerr := m.pins.readMeta()
	want := objectDigest()
	decision, reason := decidePin(found, rerr, got, want)

	switch decision {
	case pinFresh:
		log.Log.V(1).Info("no pinned eBPF state to adopt", "root", m.pins.root, "reason", reason)
		return
	case pinRebuild:
		// Loud on purpose. This is a real, if brief, enforcement gap on this
		// node, and an operator seeing a denial storm or a quiet window right
		// after an upgrade needs this line to explain it.
		log.Log.V(0).Info("rebuilding eBPF state; enforcement restarts on this node",
			"root", m.pins.root, "reason", reason)
		if err := m.pins.purge(); err != nil {
			m.pins.disable("could not purge incompatible pinned state: " + err.Error())
			log.Log.V(0).Info("could not purge incompatible pinned state; continuing without pinning",
				"root", m.pins.root, "error", err.Error())
		}
		return
	}

	// pinAdopt. Take over every collection the stamp says was pinned.
	adopted := make(map[collectionID]*ebpf.Collection, len(allCollections))
	rollback := func(err error, id collectionID) {
		for _, c := range adopted {
			c.Close()
		}
		log.Log.V(0).Info("pinned eBPF state could not be adopted; rebuilding",
			"root", m.pins.root, "collection", collectionDir[id], "error", err.Error())
		if perr := m.pins.purge(); perr != nil {
			m.pins.disable("could not purge unusable pinned state: " + perr.Error())
		}
	}

	for _, id := range allCollections {
		if got.Collections&uint64(id) == 0 {
			continue
		}
		spec, err := m.specFor(id)
		if err != nil {
			rollback(err, id)
			return
		}
		coll, err := m.pins.adopt(id, spec)
		if err != nil {
			rollback(err, id)
			return
		}
		adopted[id] = coll
	}
	if len(adopted) == 0 {
		return
	}

	for id, coll := range adopted {
		*m.collectionSlot(id) = coll
		m.adoptedCollections |= id
		m.pinnedCollections |= id
	}
	log.Log.V(0).Info("adopted pinned eBPF state; enforcement was never interrupted",
		"root", m.pins.root, "collections", m.adoptedCollections.names())
}

// names renders a collection set for a log line.
func (c collectionID) names() []string {
	var out []string
	for _, id := range allCollections {
		if c&id != 0 {
			out = append(out, collectionDir[id])
		}
	}
	return out
}

// adoptedLoaded reports whether a collection came from bpffs rather than from a
// fresh load. The attach path uses it to know a pinned link may already exist.
func (m *Manager) adoptedLoaded(id collectionID) bool {
	return m.adoptedCollections&id != 0
}

// pinCollection records one freshly created collection on bpffs. Best-effort:
// a node that cannot pin still runs, it just will not survive a restart.
func (m *Manager) pinCollection(id collectionID, coll *ebpf.Collection) {
	if m.pins == nil || !m.pins.enabled || coll == nil {
		return
	}
	if err := m.pins.pin(id, coll); err != nil {
		m.pins.disable("pinning " + collectionDir[id] + " failed: " + err.Error())
		log.Log.V(0).Info("could not pin eBPF objects; enforcement will NOT survive an agent restart on this node",
			"collection", collectionDir[id], "root", m.pins.root, "error", err.Error())
		return
	}
	m.pinnedCollections |= id
}

// stampPins writes the meta map that a future agent reads to decide whether it
// may adopt this state. Written last, after everything it describes exists: a
// stamp that promised objects which are not there would send the next agent
// down the adopt path and straight into a rollback.
//
// Called with m.mu held.
func (m *Manager) stampPins() {
	if m.pins == nil || !m.pins.enabled || m.pinnedCollections == 0 {
		return
	}
	err := m.pins.writeMeta(pinMeta{
		Magic:       pinMagic,
		Schema:      pinSchemaVersion,
		Digest:      objectDigest(),
		Collections: uint64(m.pinnedCollections),
	})
	if err != nil {
		// Without a stamp the next agent cannot adopt, so it would rebuild
		// from pins it has no way to validate. Purge instead: a clean restart
		// is recoverable, an unvalidatable one is not.
		log.Log.V(0).Info("could not stamp pinned eBPF state; discarding it",
			"root", m.pins.root, "error", err.Error())
		_ = m.pins.purge()
		m.pins.disable("could not write pin metadata: " + err.Error())
	}
}

// attachOrAdoptLink is the attach path's single entry point for a hook that may
// already be attached from a previous agent.
//
// When a pinned link exists, the hook is ALREADY in the kernel and has been the
// whole time - there is nothing to attach and nothing to wait for. When it does
// not, attach now and pin, so the next restart finds one.
//
// Adopted hooks are recorded so the attach path can report, in one line, how
// much of this node's enforcement carried over untouched.
func (m *Manager) attachOrAdoptLink(id collectionID, name string, attach func() (link.Link, error)) (link.Link, error) {
	if m.adoptedLoaded(id) {
		if l, ok := m.pins.adoptLink(id, name); ok {
			m.adoptedLinkNames = append(m.adoptedLinkNames, name)
			return l, nil
		}
	}
	l, err := attach()
	if err != nil {
		return nil, err
	}
	if perr := m.pins.pinLink(id, name, l); perr != nil {
		// The hook is attached and working; it just will not outlive this
		// process. Degrade rather than unwind a working attachment.
		m.pins.disable("pinning link " + name + " failed: " + perr.Error())
		log.Log.V(0).Info("could not pin an attached link; this hook will detach if the agent restarts",
			"link", name, "error", perr.Error())
	}
	return l, nil
}

// SetPinRoot points this Manager's pinned state at root, or disables pinning
// when root is empty. It must be called before LoadPrograms.
//
// The empty case is what a test or a bpffs-less node uses: the Manager then
// behaves exactly as it did before pinning existed.
func (m *Manager) SetPinRoot(root string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pins = newPinStore(root)
}

// PinRoot reports where this Manager pins its state, or "" when pinning is off.
func (m *Manager) PinRoot() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.pins == nil || !m.pins.enabled {
		return ""
	}
	return m.pins.root
}

// AdoptedPinnedState reports whether this agent took over eBPF state that a
// previous agent left attached, rather than loading its own.
//
// The agent uses it to decide whether the learned allow-sets need rebuilding
// from the ContainerProfile resources: adopted maps already hold them.
func (m *Manager) AdoptedPinnedState() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.adoptedCollections != 0
}

// Attached reports whether this node's data plane is actually in the kernel:
// the required syscall tracepoint is linked, its ring-buffer reader exists, and
// the event loops are running.
//
// It exists so the agent's readiness probe can answer the question an operator
// is actually asking. A probe wired to a plain ping reports ready as soon as the
// HTTP port binds, which on a node whose program load failed means a green pod
// with nothing attached - and, during a rolling update, means the next node's
// agent is torn down while this one protects nothing.
//
// Deliberately narrow. Only the REQUIRED hook is checked: the LSM programs are
// best-effort by design, and a kernel without the BPF LSM must not report a
// permanently unready pod that the DaemonSet rollout then waits on forever.
func (m *Manager) Attached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running && len(m.syscallLinks) > 0 && m.eventReader != nil
}

// Teardown detaches everything and removes the pinned state, leaving the node
// with no Pahlevan programs in the kernel.
//
// This is the uninstall path. Stop() and Close() deliberately do NOT do this:
// they release this process's handles and leave the pins - and therefore the
// enforcement - in place, which is what makes a rolling update gapless. Wiring
// Teardown into the pod's normal termination would restore the original bug in
// full, detaching every program on every node on every update.
func (m *Manager) Teardown() error {
	m.Stop()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pins == nil || m.pins.root == "" {
		return nil
	}
	err := m.pins.purge()
	m.adoptedCollections = 0
	m.pinnedCollections = 0
	return err
}
