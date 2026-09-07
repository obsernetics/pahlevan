package ebpf

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestSetActionDoesNotRaceWithReload guards against SetAction reading the
// collection fields without m.mu held. Load (and any future hot reload) only
// ever mutates them under m.mu.Lock, so a reader that skips the lock is a
// data race the moment a policy transition lands while the agent is
// (re)loading its eBPF objects - exactly the situation SetAction exists to
// serve, since it is how a cgroup's enforcement mode gets applied. Run with
// -race; this test passes without it regardless of whether the lock is held.
func TestSetActionDoesNotRaceWithReload(t *testing.T) {
	m := &Manager{}
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Loading and unloading are both plain writes to the same fields
			// SetAction reads; either direction races with an unguarded
			// reader, so toggling both ways covers Load and a future Close.
			m.mu.Lock()
			m.fileCollection = nil
			m.networkCollection = nil
			m.execCollection = nil
			m.capCollection = nil
			m.mu.Unlock()
		}
	}()

	spec := EnforcementSpec{Action: ActionDeny}
	for i := 0; i < 2000; i++ {
		if err := m.SetAction(uint64(i), spec); err != nil {
			t.Fatalf("SetAction with every hook unloaded should skip rather than fail: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestSetXActionNotLoaded exercises the one path in each per-hook setter that
// is reachable without a kernel: the collection for that hook was never
// installed, which is the normal state on a kernel without the BPF LSM and
// the only state a zero-value Manager can be put in on this host.
func TestSetXActionNotLoaded(t *testing.T) {
	spec := EnforcementSpec{Action: ActionDeny}
	cases := []struct {
		name string
		call func(*Manager) error
	}{
		{"file", func(m *Manager) error { return m.SetFileAction(1, spec) }},
		{"network", func(m *Manager) error { return m.SetNetworkAction(1, spec) }},
		{"exec", func(m *Manager) error { return m.SetExecAction(1, spec) }},
		{"capability", func(m *Manager) error { return m.SetCapabilityAction(1, spec) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(&Manager{})
			if err == nil {
				t.Fatal("expected an error for an unloaded hook, got nil")
			}
			if !errors.Is(err, errHookNotLoaded) {
				t.Errorf("error %q does not wrap errHookNotLoaded", err)
			}
			if !strings.Contains(err.Error(), tc.name) {
				t.Errorf("error %q does not name the %s hook", err, tc.name)
			}
		})
	}
}

// TestSetActionSkipsEveryUnloadedHook is SetAction's degraded-mode contract:
// on a kernel without the BPF LSM none of the four hooks load, and that must
// read as "nothing to do" rather than as four failures.
func TestSetActionSkipsEveryUnloadedHook(t *testing.T) {
	m := &Manager{}
	if err := m.SetAction(1, EnforcementSpec{Action: ActionDeny}); err != nil {
		t.Errorf("every hook unloaded should be a silent no-op, got %v", err)
	}
}

// TestSetActionRejectsAnInvalidSpecBeforeTouchingAnyHook checks that
// validation happens once, up front, rather than once per hook with the
// first hook's error winning arbitrarily.
func TestSetActionRejectsAnInvalidSpecBeforeTouchingAnyHook(t *testing.T) {
	m := &Manager{}
	err := m.SetAction(1, EnforcementSpec{Action: Action(200)})
	if err == nil {
		t.Fatal("an unimplemented action was accepted")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error %q does not explain the invalid action", err)
	}
}

// BenchmarkSetAction measures SetAction on a kernel without the BPF LSM: the
// four hooks are absent, so every call takes the skip path. This is the
// steady-state cost on the degraded-mode deployments the near-term roadmap
// still tracks (see ROADMAP.md "enforcement without the BPF LSM").
func BenchmarkSetAction(b *testing.B) {
	m := &Manager{}
	spec := EnforcementSpec{Action: ActionDeny}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.SetAction(1, spec)
	}
}
