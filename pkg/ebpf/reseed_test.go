package ebpf

import (
	"net"
	"strings"
	"testing"
)

func TestParseLearnedDestination(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantIP   string
		wantPort uint16
		wantErr  string
	}{
		// The spelling the learner actually publishes: the raw 32-bit word the
		// kernel reported, in decimal. Getting the byte order wrong here would
		// produce a key for an address nobody dials, and the restored entry
		// would silently permit nothing.
		{name: "raw ipv4 word", in: "16777343:443", wantIP: "127.0.0.1", wantPort: 443},
		{name: "raw zero address", in: "0:53", wantIP: "0.0.0.0", wantPort: 53},
		{name: "dotted quad", in: "10.0.0.1:8080", wantIP: "10.0.0.1", wantPort: 8080},
		{name: "bracketed ipv6", in: "[2001:db8::1]:443", wantIP: "2001:db8::1", wantPort: 443},
		{name: "bare ipv6 loopback", in: "[::1]:80", wantIP: "::1", wantPort: 80},
		{name: "max port", in: "10.0.0.1:65535", wantIP: "10.0.0.1", wantPort: 65535},

		{name: "empty", in: "", wantErr: "empty"},
		{name: "no port", in: "10.0.0.1", wantErr: "no port"},
		{name: "port out of range", in: "10.0.0.1:70000", wantErr: "port"},
		{name: "non-numeric port", in: "10.0.0.1:http", wantErr: "port"},
		{name: "no host", in: ":443", wantErr: "no host"},
		{name: "hostname is not an address", in: "example.com:443", wantErr: "not an IP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port, err := ParseLearnedDestination(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseLearnedDestination(%q) = %v:%d, want an error", tc.in, ip, port)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLearnedDestination(%q): %v", tc.in, err)
			}
			if got := ip.String(); got != tc.wantIP {
				t.Errorf("ip = %q, want %q", got, tc.wantIP)
			}
			if port != tc.wantPort {
				t.Errorf("port = %d, want %d", port, tc.wantPort)
			}
		})
	}
}

func TestParseLearnedDestinationRoundTripsTheAllowKey(t *testing.T) {
	// The whole point of the raw-word branch: a destination restored from a
	// profile has to derive the SAME allow-set key the kernel computed when it
	// learned the flow. A restored entry under a different key is an entry
	// that permits nothing while looking like it worked.
	const cgroup = uint64(0x1234)
	raw := uint32(16777343) // 127.0.0.1 as the kernel reports it
	want, err := NetworkAllowKeyProto(cgroup, net.ParseIP(IPv4String(raw)), 443, ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}

	ip, port, err := ParseLearnedDestination("16777343:443")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NetworkAllowKeyProto(cgroup, ip, port, ProtocolTCP)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("restored key %#x, kernel key %#x", got, want)
	}
}

func TestRestoreAllowSetsSkipsEntriesWithNoCgroup(t *testing.T) {
	// A profile written before the container was attributed has no cgroup id,
	// so there is no key to write under. Counting it as restored would report
	// a baseline that is not in the kernel.
	m := &Manager{}
	rep := m.RestoreAllowSets([]RestoreEntry{
		{Name: "ns/a", CgroupID: 0, Files: []string{"/etc/passwd"}},
		{Name: "ns/b", CgroupID: 0},
	})
	if rep.Containers != 0 {
		t.Errorf("Containers = %d, want 0", rep.Containers)
	}
	if rep.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", rep.Skipped)
	}
	if rep.Total() != 0 {
		t.Errorf("Total = %d, want 0", rep.Total())
	}
}

func TestRestoreAllowSetsReportsRatherThanFailing(t *testing.T) {
	// No collections are loaded, so every write fails. The restore must still
	// return - giving up halfway would leave a container with a partial
	// allow-set, which is the worst state to then enforce against.
	m := &Manager{}
	rep := m.RestoreAllowSets([]RestoreEntry{{
		Name:                "ns/pod/app",
		CgroupID:            42,
		Files:               []string{"/etc/passwd", ""},
		Executables:         []string{"/bin/sh"},
		Capabilities:        []string{"NET_BIND_SERVICE", "NOT_A_CAPABILITY"},
		NetworkDestinations: []string{"10.0.0.1:443", "garbage"},
	}})
	if rep.Containers != 1 {
		t.Fatalf("Containers = %d, want 1", rep.Containers)
	}
	if rep.Total() != 0 {
		t.Fatalf("Total = %d, want 0 with no collections loaded", rep.Total())
	}
	if len(rep.Errors) == 0 {
		t.Fatal("no problems reported; a silent failure here looks exactly like a successful restore")
	}
	joined := strings.Join(rep.Errors, "\n")
	for _, want := range []string{"NOT_A_CAPABILITY", "garbage", "/bin/sh"} {
		if !strings.Contains(joined, want) {
			t.Errorf("report does not name %q:\n%s", want, joined)
		}
	}
}

func TestRestoreReportCapsItsErrors(t *testing.T) {
	// A profile with ten thousand unparseable entries must produce a log line,
	// not a log flood.
	var rep RestoreReport
	for i := 0; i < maxRestoreErrors*10; i++ {
		rep.note("problem %d", i)
	}
	if len(rep.Errors) != maxRestoreErrors {
		t.Fatalf("Errors = %d, want at most %d", len(rep.Errors), maxRestoreErrors)
	}
	if rep.Errors[0] != "problem 0" {
		t.Errorf("first error = %q; the earliest problems are the ones worth keeping", rep.Errors[0])
	}
}

func TestRestoreReportTotal(t *testing.T) {
	rep := RestoreReport{Files: 1, Executables: 2, Capabilities: 3, Destinations: 4}
	if got := rep.Total(); got != 10 {
		t.Fatalf("Total = %d, want 10", got)
	}
}

func TestRestoreAllowSetsWithNoEntries(t *testing.T) {
	m := &Manager{}
	rep := m.RestoreAllowSets(nil)
	if rep.Containers != 0 || rep.Skipped != 0 || rep.Total() != 0 || len(rep.Errors) != 0 {
		t.Fatalf("empty restore reported %+v", rep)
	}
}

func BenchmarkParseLearnedDestination(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := ParseLearnedDestination("16777343:443"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRestoreAllowSets(b *testing.B) {
	// The fallback startup path: a node with a few hundred containers, each
	// with a few hundred learned paths, runs this once before the controllers
	// start.
	b.ReportAllocs()
	entries := make([]RestoreEntry, 0, 64)
	for i := 0; i < 64; i++ {
		entries = append(entries, RestoreEntry{
			Name:                "ns/pod/app",
			CgroupID:            uint64(i + 1),
			Files:               []string{"/etc/passwd", "/etc/hosts", "/lib/libc.so.6"},
			Executables:         []string{"/bin/sh", "/usr/bin/env"},
			Capabilities:        []string{"NET_BIND_SERVICE"},
			NetworkDestinations: []string{"16777343:443", "10.0.0.1:53"},
		})
	}
	m := &Manager{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.RestoreAllowSets(entries)
	}
}
