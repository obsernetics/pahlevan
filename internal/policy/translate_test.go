package policy

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

var now = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func dur(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }
func boolPtr(b bool) *bool                 { return &b }
func i32(v int32) *int32                   { return &v }

// hasWarning reports whether any warning contains the substring, so tests
// assert on the substance rather than exact phrasing.
func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestModeResolution(t *testing.T) {
	tests := []struct {
		name string
		cfg  policyv1alpha1.EnforcementConfig
		want adaptive.Mode
	}{
		{"empty defaults to monitoring, never blocking",
			policyv1alpha1.EnforcementConfig{}, adaptive.ModeMonitoring},
		{"off",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeOff}, adaptive.ModeOff},
		{"monitoring",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeMonitoring}, adaptive.ModeMonitoring},
		{"blocking",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking}, adaptive.ModeBlocking},
		{"alertOnly downgrades blocking",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking, AlertOnly: true},
			adaptive.ModeMonitoring},
		{"blockUnknown unset keeps blocking",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
			adaptive.ModeBlocking},
		{"blockUnknown true keeps blocking",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking, BlockUnknown: boolPtr(true)},
			adaptive.ModeBlocking},
		{"blockUnknown false downgrades: default-deny is the only enforcement there is",
			policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking, BlockUnknown: boolPtr(false)},
			adaptive.ModeMonitoring},
		{"unrecognized mode is treated as monitoring, not blocking",
			policyv1alpha1.EnforcementConfig{Mode: "Paranoid"}, adaptive.ModeMonitoring},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := Translate("p", policyv1alpha1.PahlevanPolicySpec{EnforcementConfig: tc.cfg}, now)
			assert.Equal(t, tc.want, d.Mode)
		})
	}
}

// The grace period was accepted by the CRD and dropped on the floor.
func TestGracePeriodIsHonoured(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		LearningConfig:    policyv1alpha1.LearningConfig{Duration: dur(5 * time.Minute)},
		EnforcementConfig: policyv1alpha1.EnforcementConfig{GracePeriod: dur(90 * time.Second)},
	}, now)
	assert.Empty(t, warnings)
	assert.Equal(t, 5*time.Minute, d.Window)
	assert.Equal(t, 90*time.Second, d.GracePeriod)
	assert.Equal(t, 5*time.Minute+90*time.Second, d.EnforceAfter())
}

func TestNegativeDurationsAreClamped(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		LearningConfig:    policyv1alpha1.LearningConfig{Duration: dur(-time.Minute)},
		EnforcementConfig: policyv1alpha1.EnforcementConfig{GracePeriod: dur(-time.Second)},
	}, now)
	assert.Equal(t, time.Duration(0), d.Window)
	assert.Equal(t, time.Duration(0), d.GracePeriod)
	assert.True(t, hasWarning(warnings, "duration is negative"))
	assert.True(t, hasWarning(warnings, "gracePeriod is negative"))
}

// An Off policy governs nothing, so nothing else is worth translating or
// warning about.
func TestOffModeSkipsTranslation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeOff,
		},
		FilePolicy:    &policyv1alpha1.FilePolicy{AllowedPaths: []string{"/etc/passwd"}},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{IngressRules: []policyv1alpha1.NetworkRule{{}}},
	}, now)
	assert.Equal(t, adaptive.ModeOff, d.Mode)
	assert.False(t, d.Tracked())
	assert.True(t, d.Overrides.Empty())
	assert.Empty(t, warnings)
}

func TestFilePolicyTranslation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		FilePolicy: &policyv1alpha1.FilePolicy{
			AllowedPaths:      []string{"/etc/ssl/cert.pem", " /var/run/secrets/token ", "", "/etc/ssl/cert.pem"},
			DeniedPaths:       []string{"/etc/shadow"},
			ReadOnlyPaths:     []string{"/etc/config"},
			WriteAllowedPaths: []string{"/var/log/app.log"},
			ExecutableFilter: &policyv1alpha1.ExecutableFilter{
				AllowedExecutables: []string{"/usr/bin/curl"},
				DeniedExecutables:  []string{"/usr/bin/nc"},
			},
		},
	}, now)

	assert.Empty(t, warnings)

	// Whitespace trimmed, blanks dropped, duplicates collapsed. Reads cover
	// allowedPaths, readOnlyPaths and writeAllowedPaths, since a path you may
	// write is a path you may open.
	assert.Equal(t, []string{
		"/etc/ssl/cert.pem", "/var/run/secrets/token", "/etc/config", "/var/log/app.log",
	}, d.Overrides.AllowedFiles)

	// Writes are a separate grant: allowedPaths and writeAllowedPaths only.
	assert.Equal(t, []string{
		"/etc/ssl/cert.pem", "/var/run/secrets/token", "/var/log/app.log",
	}, d.Overrides.AllowedWriteFiles)

	// readOnlyPaths means read-only, so the write is actively revoked rather
	// than merely not granted; that also survives a learned write.
	assert.Contains(t, d.Overrides.DeniedWriteFiles, "/etc/config")

	// deniedPaths revokes both modes, so a denial cannot be sidestepped by
	// opening the path the other way.
	assert.Equal(t, []string{"/etc/shadow"}, d.Overrides.DeniedFiles)
	assert.Contains(t, d.Overrides.DeniedWriteFiles, "/etc/shadow")

	assert.Equal(t, []string{"/usr/bin/curl"}, d.Overrides.AllowedExecs)
	assert.Equal(t, []string{"/usr/bin/nc"}, d.Overrides.DeniedExecs)
}

// readOnlyPaths used to be a lie: the allow-set keyed on the path alone, so a
// path granted for reading was equally writable.
func TestReadOnlyPathIsNotWritable(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		FilePolicy:        &policyv1alpha1.FilePolicy{ReadOnlyPaths: []string{"/etc/passwd"}},
	}, now)
	assert.Empty(t, warnings)
	assert.Equal(t, []string{"/etc/passwd"}, d.Overrides.AllowedFiles)
	assert.Equal(t, []string{"/etc/passwd"}, d.Overrides.DeniedWriteFiles)
	assert.Empty(t, d.Overrides.AllowedWriteFiles)
}

func TestWriteAllowedPathGrantsBothModes(t *testing.T) {
	d, _ := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		FilePolicy:        &policyv1alpha1.FilePolicy{WriteAllowedPaths: []string{"/var/log/app.log"}},
	}, now)
	assert.Equal(t, []string{"/var/log/app.log"}, d.Overrides.AllowedFiles)
	assert.Equal(t, []string{"/var/log/app.log"}, d.Overrides.AllowedWriteFiles)
	assert.Empty(t, d.Overrides.DeniedWriteFiles)
}

// A glob would be hashed literally and match nothing, which looks exactly like
// a rule that is applied but never fires.
func TestGlobPatternsAreCalledOut(t *testing.T) {
	_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		FilePolicy:        &policyv1alpha1.FilePolicy{AllowedPaths: []string{"/var/log/*.log"}},
	}, now)
	assert.True(t, hasWarning(warnings, "wildcard"))
}

func TestSyscallPolicyTranslation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy: &policyv1alpha1.SyscallPolicy{
			AllowedSyscalls:  []string{"openat", "read"},
			DeniedSyscalls:   []string{"ptrace"},
			CapabilityFilter: []string{"CAP_NET_ADMIN", "sys_admin", "CAP_NOT_A_THING"},
		},
	}, now)

	assert.Equal(t, []string{"openat", "read"}, d.Overrides.AllowedSyscalls)
	assert.Equal(t, []string{"ptrace"}, d.Overrides.DeniedSyscalls)
	// CAP_NET_ADMIN is 12, CAP_SYS_ADMIN is 21; the prefix is optional.
	assert.Equal(t, []uint32{12, 21}, d.Overrides.AllowedCapabilities)
	assert.True(t, hasWarning(warnings, "unknown capability"))
}

func TestProcessFilterIsReportedUnenforced(t *testing.T) {
	_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy:     &policyv1alpha1.SyscallPolicy{ProcessFilter: &policyv1alpha1.ProcessFilter{}},
	}, now)
	assert.True(t, hasWarning(warnings, "processFilter is not enforced"))
}

func egress(cidr string, ports ...int32) policyv1alpha1.NetworkRule {
	rule := policyv1alpha1.NetworkRule{
		Peers: []policyv1alpha1.NetworkPeer{{IPBlock: &policyv1alpha1.IPBlock{CIDR: cidr}}},
	}
	for _, p := range ports {
		rule.Ports = append(rule.Ports, policyv1alpha1.NetworkPort{Port: i32(p)})
	}
	return rule
}

func TestNetworkEgressTranslation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{
				egress("10.0.0.53/32", 53, 853),
				egress("2001:db8::1/128", 443),
			},
		},
	}, now)
	assert.Empty(t, warnings)

	require.Len(t, d.Overrides.AllowedDestinations, 3)
	assert.True(t, d.Overrides.AllowedDestinations[0].IP.Equal(net.ParseIP("10.0.0.53")))
	assert.Equal(t, uint16(53), d.Overrides.AllowedDestinations[0].Port)
	assert.Equal(t, uint16(853), d.Overrides.AllowedDestinations[1].Port)
	assert.True(t, d.Overrides.AllowedDestinations[2].IP.Equal(net.ParseIP("2001:db8::1")))
}

func TestNetworkEgressDenyAction(t *testing.T) {
	rule := egress("10.0.0.9/32", 4444)
	rule.Action = "Deny"
	d, _ := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy:     &policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{rule}},
	}, now)
	assert.Empty(t, d.Overrides.AllowedDestinations)
	require.Len(t, d.Overrides.DeniedDestinations, 1)
	assert.Equal(t, uint16(4444), d.Overrides.DeniedDestinations[0].Port)
}

// A prefix wider than a single host cannot be represented in a hash allow-set.
// Saying so is the whole point: a silently dropped rule looks enforced.
func TestWideCIDRIsRejectedWithAnExplanation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{egress("10.0.0.0/8", 443)},
		},
	}, now)
	assert.Empty(t, d.Overrides.AllowedDestinations)
	assert.True(t, hasWarning(warnings, "cannot express a prefix"))
}

func TestBareAddressIsAccepted(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{egress("10.0.0.53", 53)},
		},
	}, now)
	assert.Empty(t, warnings)
	require.Len(t, d.Overrides.AllowedDestinations, 1)
}

func TestPortRangesAndTheirLimits(t *testing.T) {
	small := policyv1alpha1.NetworkRule{
		Peers: []policyv1alpha1.NetworkPeer{{IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.1/32"}}},
		Ports: []policyv1alpha1.NetworkPort{{StartPort: i32(8000), EndPort: i32(8002)}},
	}
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy:     &policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{small}},
	}, now)
	assert.Empty(t, warnings)
	require.Len(t, d.Overrides.AllowedDestinations, 3)

	// A range wide enough to evict the learned baseline from the LRU is refused.
	wide := policyv1alpha1.NetworkRule{
		Peers: []policyv1alpha1.NetworkPeer{{IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.1/32"}}},
		Ports: []policyv1alpha1.NetworkPort{{StartPort: i32(1), EndPort: i32(65535)}},
	}
	d, warnings = Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy:     &policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{wide}},
	}, now)
	assert.Empty(t, d.Overrides.AllowedDestinations)
	assert.True(t, hasWarning(warnings, "over the 1024 limit"))

	// Inverted range.
	inverted := policyv1alpha1.NetworkRule{
		Peers: []policyv1alpha1.NetworkPeer{{IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.1/32"}}},
		Ports: []policyv1alpha1.NetworkPort{{StartPort: i32(90), EndPort: i32(80)}},
	}
	_, warnings = Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy:     &policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{inverted}},
	}, now)
	assert.True(t, hasWarning(warnings, "inverted"))
}

func TestUnrepresentableNetworkInputs(t *testing.T) {
	tests := []struct {
		name    string
		np      policyv1alpha1.NetworkPolicy
		warning string
	}{
		{"ingress is out of scope",
			policyv1alpha1.NetworkPolicy{IngressRules: []policyv1alpha1.NetworkRule{{}}},
			"egress only"},
		{"allowDNS needs an address",
			policyv1alpha1.NetworkPolicy{AllowDNS: true}, "need a concrete address"},
		{"allowLoopback needs an address",
			policyv1alpha1.NetworkPolicy{AllowLoopback: true}, "need a concrete address"},
		{"label-selected peers have no fixed address",
			policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{{
				Ports: []policyv1alpha1.NetworkPort{{Port: i32(80)}},
				Peers: []policyv1alpha1.NetworkPeer{{PodSelector: &policyv1alpha1.LabelSelector{}}},
			}}},
			"cannot be resolved to a fixed address"},
		{"a rule with no ports seeds nothing",
			policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{{
				Peers: []policyv1alpha1.NetworkPeer{{IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.1/32"}}},
			}}},
			"specifies no ports"},
		{"a port out of range",
			policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{{
				Ports: []policyv1alpha1.NetworkPort{{Port: i32(70000)}},
				Peers: []policyv1alpha1.NetworkPeer{{IPBlock: &policyv1alpha1.IPBlock{CIDR: "10.0.0.1/32"}}},
			}}},
			"out of range"},
		{"an invalid CIDR",
			policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{egress("not-an-ip", 80)}},
			"not an IP address"},
		{"an empty CIDR",
			policyv1alpha1.NetworkPolicy{EgressRules: []policyv1alpha1.NetworkRule{egress("", 80)}},
			"is empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			np := tc.np
			_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
				EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
				NetworkPolicy:     &np,
			}, now)
			assert.True(t, hasWarning(warnings, tc.warning), "warnings were %v", warnings)
		})
	}
}

func TestExceptionsTranslation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking,
			Exceptions: []policyv1alpha1.EnforcementException{
				{Type: policyv1alpha1.ExceptionTypeFile, Patterns: []string{"/etc/resolv.conf"}},
				{Type: policyv1alpha1.ExceptionTypeSyscall, Patterns: []string{"ptrace"}},
				{Type: policyv1alpha1.ExceptionTypeNetwork, Patterns: []string{"10.96.0.10:53"}},
			},
		},
	}, now)
	assert.Empty(t, warnings)
	assert.Equal(t, []string{"/etc/resolv.conf"}, d.Overrides.AllowedFiles)
	assert.Equal(t, []string{"ptrace"}, d.Overrides.AllowedSyscalls)
	require.Len(t, d.Overrides.AllowedDestinations, 1)
	assert.Equal(t, uint16(53), d.Overrides.AllowedDestinations[0].Port)
}

// An expired temporary exception that still widened the allow-set would be a
// permanent hole opened by a decision that was meant to be temporary.
func TestExpiredExceptionIsNotApplied(t *testing.T) {
	expired := metav1.NewTime(now.Add(-time.Hour))
	future := metav1.NewTime(now.Add(time.Hour))
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking,
			Exceptions: []policyv1alpha1.EnforcementException{
				{Type: policyv1alpha1.ExceptionTypeFile, Patterns: []string{"/tmp/expired"},
					Temporary: true, ExpiresAt: &expired},
				{Type: policyv1alpha1.ExceptionTypeFile, Patterns: []string{"/tmp/live"},
					Temporary: true, ExpiresAt: &future},
			},
		},
	}, now)
	assert.Equal(t, []string{"/tmp/live"}, d.Overrides.AllowedFiles)
	assert.True(t, hasWarning(warnings, "expired"))
}

func TestTemporaryExceptionWithoutExpiryIsFlagged(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode: policyv1alpha1.EnforcementModeBlocking,
			Exceptions: []policyv1alpha1.EnforcementException{
				{Type: policyv1alpha1.ExceptionTypeFile, Patterns: []string{"/tmp/x"}, Temporary: true},
			},
		},
	}, now)
	assert.Equal(t, []string{"/tmp/x"}, d.Overrides.AllowedFiles, "still applied")
	assert.True(t, hasWarning(warnings, "never expires"))
}

func TestMalformedExceptions(t *testing.T) {
	tests := []struct {
		name    string
		ex      policyv1alpha1.EnforcementException
		warning string
	}{
		{"no patterns",
			policyv1alpha1.EnforcementException{Type: policyv1alpha1.ExceptionTypeFile},
			"has no patterns"},
		{"unknown type",
			policyv1alpha1.EnforcementException{Type: "Wormhole", Patterns: []string{"x"}},
			"unknown type"},
		{"network pattern without a port",
			policyv1alpha1.EnforcementException{Type: policyv1alpha1.ExceptionTypeNetwork, Patterns: []string{"10.0.0.1"}},
			"not host:port"},
		{"network pattern naming a host",
			policyv1alpha1.EnforcementException{Type: policyv1alpha1.ExceptionTypeNetwork, Patterns: []string{"dns.example.com:53"}},
			"DNS names"},
		{"network pattern with a bad port",
			policyv1alpha1.EnforcementException{Type: policyv1alpha1.ExceptionTypeNetwork, Patterns: []string{"10.0.0.1:0"}},
			"invalid port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
				EnforcementConfig: policyv1alpha1.EnforcementConfig{
					Mode:       policyv1alpha1.EnforcementModeBlocking,
					Exceptions: []policyv1alpha1.EnforcementException{tc.ex},
				},
			}, now)
			assert.True(t, hasWarning(warnings, tc.warning), "warnings were %v", warnings)
		})
	}
}

// Overrides in a non-blocking policy are recorded but never reach the kernel,
// which is worth saying out loud.
func TestOverridesInMonitoringModeAreFlagged(t *testing.T) {
	_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeMonitoring},
		FilePolicy:        &policyv1alpha1.FilePolicy{AllowedPaths: []string{"/etc/x"}},
	}, now)
	assert.True(t, hasWarning(warnings, "no effect in Monitoring mode"))
}

func TestEmptySpecProducesNoWarnings(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{}, now)
	assert.Empty(t, warnings)
	assert.True(t, d.Overrides.Empty())
	assert.True(t, d.Tracked())
	assert.False(t, d.Blocking())
	assert.Equal(t, "p", d.PolicyName)
}

func TestOverridesEmpty(t *testing.T) {
	assert.True(t, adaptive.Overrides{}.Empty())
	assert.False(t, adaptive.Overrides{AllowedFiles: []string{"/x"}}.Empty())
	assert.False(t, adaptive.Overrides{DeniedSyscalls: []string{"ptrace"}}.Empty())
	assert.False(t, adaptive.Overrides{
		AllowedDestinations: []adaptive.Destination{{IP: net.IPv4(1, 2, 3, 4), Port: 80}},
	}.Empty())
}

// A realistic policy exercising every section at once.
func benchSpec() policyv1alpha1.PahlevanPolicySpec {
	future := metav1.NewTime(now.Add(time.Hour))
	return policyv1alpha1.PahlevanPolicySpec{
		LearningConfig: policyv1alpha1.LearningConfig{Duration: dur(5 * time.Minute)},
		EnforcementConfig: policyv1alpha1.EnforcementConfig{
			Mode:        policyv1alpha1.EnforcementModeBlocking,
			GracePeriod: dur(time.Minute),
			Exceptions: []policyv1alpha1.EnforcementException{
				{Type: policyv1alpha1.ExceptionTypeFile, Patterns: []string{"/etc/resolv.conf"}},
				{Type: policyv1alpha1.ExceptionTypeNetwork, Patterns: []string{"10.96.0.10:53"},
					Temporary: true, ExpiresAt: &future},
			},
		},
		FilePolicy: &policyv1alpha1.FilePolicy{
			AllowedPaths: []string{"/etc/ssl/cert.pem", "/var/run/secrets/token"},
			DeniedPaths:  []string{"/etc/shadow"},
		},
		SyscallPolicy: &policyv1alpha1.SyscallPolicy{
			AllowedSyscalls:  []string{"openat", "read", "write"},
			CapabilityFilter: []string{"CAP_NET_BIND_SERVICE"},
		},
		NetworkPolicy: &policyv1alpha1.NetworkPolicy{
			EgressRules: []policyv1alpha1.NetworkRule{egress("10.0.0.53/32", 53, 853)},
		},
	}
}

func TestFullSpecTranslatesCleanly(t *testing.T) {
	d, warnings := Translate("full", benchSpec(), now)
	assert.Empty(t, warnings)
	assert.Equal(t, adaptive.ModeBlocking, d.Mode)
	assert.Equal(t, 6*time.Minute, d.EnforceAfter())
	assert.Len(t, d.Overrides.AllowedFiles, 3)
	assert.Len(t, d.Overrides.DeniedFiles, 1)
	assert.Len(t, d.Overrides.AllowedSyscalls, 3)
	assert.Equal(t, []uint32{10}, d.Overrides.AllowedCapabilities)
	assert.Len(t, d.Overrides.AllowedDestinations, 3)
}

func BenchmarkTranslate(b *testing.B) {
	spec := benchSpec()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Translate("bench", spec, now)
	}
}

func BenchmarkTranslateEmptySpec(b *testing.B) {
	spec := policyv1alpha1.PahlevanPolicySpec{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Translate("bench", spec, now)
	}
}
