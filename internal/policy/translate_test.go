package policy

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
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

// An empty process filter must constrain nothing. Reading "no dimensions
// specified" as "an empty allow-list for every dimension" would deny every
// exec in the container.
func TestEmptyProcessFilterConstrainsNothing(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy:     &policyv1alpha1.SyscallPolicy{ProcessFilter: &policyv1alpha1.ProcessFilter{}},
	}, now)
	assert.Nil(t, d.Overrides.ProcFilter)
	assert.Empty(t, warnings)
}

// The three dimensions the kernel can enforce become the filter; commands
// become exec allow-set entries, because that is the mechanism that already
// governs which binary may run.
func TestProcessFilterIsTranslatedToTheKernelFilter(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy: &policyv1alpha1.SyscallPolicy{ProcessFilter: &policyv1alpha1.ProcessFilter{
			Commands:        []string{"/usr/bin/psql", "/bin/sh"},
			Users:           []string{"1000", "0"},
			Groups:          []string{"1000"},
			ParentProcesses: []string{"supervisord", " entrypoint.sh "},
		}},
	}, now)

	require.NotNil(t, d.Overrides.ProcFilter)
	assert.Equal(t, []string{"supervisord", "entrypoint.sh"}, d.Overrides.ProcFilter.ParentProcesses)
	assert.Equal(t, []uint32{1000, 0}, d.Overrides.ProcFilter.UIDs)
	assert.Equal(t, []uint32{1000}, d.Overrides.ProcFilter.GIDs)
	assert.Equal(t, []string{"/usr/bin/psql", "/bin/sh"}, d.Overrides.AllowedExecs)
	assert.Empty(t, warnings)
}

// A username cannot be resolved from the node: the kernel matches uids and the
// container has its own passwd file. Guessing would produce a filter that
// silently matches the wrong user.
func TestProcessFilterRejectsNonNumericUsers(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy: &policyv1alpha1.SyscallPolicy{ProcessFilter: &policyv1alpha1.ProcessFilter{
			Users:  []string{"postgres", "1000"},
			Groups: []string{"wheel"},
		}},
	}, now)

	require.NotNil(t, d.Overrides.ProcFilter)
	assert.Equal(t, []uint32{1000}, d.Overrides.ProcFilter.UIDs, "the numeric one is kept")
	assert.Empty(t, d.Overrides.ProcFilter.GIDs)
	assert.True(t, hasWarning(warnings, `users["postgres"]`))
	assert.True(t, hasWarning(warnings, `groups["wheel"]`))
}

// The kernel matches the resolved binary path, so a bare name would be written
// into the allow-set under a key nothing can ever match.
func TestProcessFilterRejectsRelativeCommands(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy: &policyv1alpha1.SyscallPolicy{ProcessFilter: &policyv1alpha1.ProcessFilter{
			Commands: []string{"curl", "/usr/bin/curl"},
		}},
	}, now)

	assert.Equal(t, []string{"/usr/bin/curl"}, d.Overrides.AllowedExecs)
	assert.True(t, hasWarning(warnings, "must be absolute"))
}

// comm is TASK_COMM_LEN, so a longer parent name matches on its truncation.
// Saying so is the difference between a filter that works and one that appears
// to and does not.
func TestProcessFilterWarnsAboutLongParentNames(t *testing.T) {
	_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		SyscallPolicy: &policyv1alpha1.SyscallPolicy{ProcessFilter: &policyv1alpha1.ProcessFilter{
			ParentProcesses: []string{"a-very-long-process-name"},
		}},
	}, now)
	assert.True(t, hasWarning(warnings, "first 15 characters"))
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

// allowDNS and allowLoopback name a class of destination rather than an
// address, so they cannot be allow-set entries - the allow-set is a hash of the
// exact destination. They used to be accepted by the API and do nothing but
// produce a warning; they are a per-cgroup flag checked in socket_connect now.
func TestBlanketEgressPermissionsAreEnforced(t *testing.T) {
	for name, tc := range map[string]struct {
		np   policyv1alpha1.NetworkPolicy
		want uint8
	}{
		"neither":  {policyv1alpha1.NetworkPolicy{}, 0},
		"dns":      {policyv1alpha1.NetworkPolicy{AllowDNS: true}, ebpf.RelaxDNS},
		"loopback": {policyv1alpha1.NetworkPolicy{AllowLoopback: true}, ebpf.RelaxLoopback},
		"both": {
			policyv1alpha1.NetworkPolicy{AllowDNS: true, AllowLoopback: true},
			ebpf.RelaxDNS | ebpf.RelaxLoopback,
		},
	} {
		t.Run(name, func(t *testing.T) {
			np := tc.np
			d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
				EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
				NetworkPolicy:     &np,
			}, now)
			assert.Equal(t, tc.want, d.Overrides.NetworkRelax)
			assert.False(t, hasWarning(warnings, "need a concrete address"),
				"these are enforced now, not reported as unrepresentable")
		})
	}
}

// A policy that sets only a blanket permission still has something to apply, so
// Empty() must not report it as nothing to do - the controller skips
// applyOverrides entirely on an empty override set.
func TestBlanketPermissionAloneIsNotAnEmptyOverride(t *testing.T) {
	np := policyv1alpha1.NetworkPolicy{AllowDNS: true}
	d, _ := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: policyv1alpha1.EnforcementModeBlocking},
		NetworkPolicy:     &np,
	}, now)
	assert.False(t, d.Overrides.Empty())
}

// A mode the controller does not recognize is mapped onto Monitoring, which is
// the safe default and an invisible one: the policy looks applied and enforces
// nothing. It must be reported.
func TestUnknownModeIsReported(t *testing.T) {
	for mode, want := range map[string]string{
		"Enforce":  "not one of Off, Monitoring or Blocking",
		"blocking": "not one of Off, Monitoring or Blocking",
		"":         "",
		"Off":      "",
		"Blocking": "",
	} {
		t.Run(mode, func(t *testing.T) {
			_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
				EnforcementConfig: policyv1alpha1.EnforcementConfig{
					Mode: policyv1alpha1.EnforcementMode(mode),
				},
			}, now)
			if want == "" {
				assert.False(t, hasWarning(warnings, "enforcementConfig.mode"),
					"warnings were %v", warnings)
				return
			}
			assert.True(t, hasWarning(warnings, want), "warnings were %v", warnings)
		})
	}
}

// `mode: Off` unquoted is a YAML 1.1 boolean, so it arrives as "false" and a
// policy the author meant to switch off keeps running. That is not a typo and
// deserves its own message.
func TestYAMLBooleanModeIsExplained(t *testing.T) {
	for _, mode := range []string{"false", "true"} {
		_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
			EnforcementConfig: policyv1alpha1.EnforcementConfig{
				Mode: policyv1alpha1.EnforcementMode(mode),
			},
		}, now)
		assert.True(t, hasWarning(warnings, "unquoted Off or On"),
			"mode %q: warnings were %v", mode, warnings)
	}
}

// An Off policy returns early, so the mode warning has to be emitted before
// that or the one mode most worth reporting would be the one that is not.
func TestUnknownModeIsReportedEvenThoughItBecomesMonitoring(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		EnforcementConfig: policyv1alpha1.EnforcementConfig{Mode: "Enforce"},
	}, now)
	assert.Equal(t, adaptive.ModeMonitoring, d.Mode)
	assert.True(t, hasWarning(warnings, "enforces nothing"), "warnings were %v", warnings)
}

// ---------------------------------------------------------------------------
// Declared expected behavior
//
// A declaration is the operator saying "the workload does this, you just did
// not see it". Learning is a window of wall-clock time, so a nightly batch or a
// weekly certificate renewal is absent from the baseline for exactly the same
// reason an attack is - nobody has ever seen the workload do it - and these
// tests pin the three properties that make it safe to say so in advance: the
// entry reaches the allow-set, it can only ever add, and it stays visibly an
// assertion rather than evidence.
// ---------------------------------------------------------------------------

// betaSpec builds a Blocking v1beta1 spec carrying a declaration, which is the
// only mode in which a declaration reaches the kernel.
func betaSpec(eb *policyv1beta1.ExpectedBehavior) policyv1beta1.PahlevanPolicySpec {
	return policyv1beta1.PahlevanPolicySpec{
		LearningConfig: policyv1beta1.LearningConfig{
			Duration:         dur(5 * time.Minute),
			ExpectedBehavior: eb,
		},
		EnforcementConfig: policyv1beta1.EnforcementConfig{
			Mode: policyv1beta1.EnforcementModeBlocking,
		},
	}
}

// destStrings renders the seeded destinations for comparison. net.IP is
// compared by its bytes, and ParseCIDR and ParseIP disagree about whether an
// IPv4 address is four bytes or sixteen, so comparing the rendered form is what
// makes these assertions about addresses rather than about representations.
func destStrings(dests []adaptive.Destination) []string {
	out := make([]string, 0, len(dests))
	for _, d := range dests {
		out = append(out, net.JoinHostPort(d.IP.String(), strconv.Itoa(int(d.Port))))
	}
	return out
}

func TestDeclaredBehaviorReachesTheAllowSet(t *testing.T) {
	tests := []struct {
		name    string
		declare policyv1beta1.ExpectedBehavior
		check   func(t *testing.T, o adaptive.Overrides, d Declaration)
	}{
		{
			name: "a read-only file",
			declare: policyv1beta1.ExpectedBehavior{
				Files: []policyv1beta1.ExpectedFile{{Path: "/etc/ssl/renewed.pem"}},
			},
			check: func(t *testing.T, o adaptive.Overrides, d Declaration) {
				assert.Equal(t, []string{"/etc/ssl/renewed.pem"}, o.AllowedFiles)
				// A read is not a write: the kernel allow-set keys on the
				// access mode, so declaring an open must not permit a rewrite.
				assert.Empty(t, o.AllowedWriteFiles)
				assert.Equal(t, []DeclaredFile{{Path: "/etc/ssl/renewed.pem"}}, d.Files)
			},
		},
		{
			name: "a written file grants the read it needs too",
			declare: policyv1beta1.ExpectedBehavior{
				Files: []policyv1beta1.ExpectedFile{{Path: "/var/lib/app/nightly.db", Write: true}},
			},
			check: func(t *testing.T, o adaptive.Overrides, _ Declaration) {
				assert.Equal(t, []string{"/var/lib/app/nightly.db"}, o.AllowedFiles)
				assert.Equal(t, []string{"/var/lib/app/nightly.db"}, o.AllowedWriteFiles)
			},
		},
		{
			name: "a network destination",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.43.12.7/32", Port: 5432},
				},
			},
			check: func(t *testing.T, o adaptive.Overrides, d Declaration) {
				assert.Equal(t, []string{"10.43.12.7:5432"}, destStrings(o.AllowedDestinations))
				assert.Equal(t, []string{"10.43.12.7:5432"}, destStrings(d.Destinations))
			},
		},
		{
			name: "a bare address, like an egress rule accepts",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.43.12.7", Port: 443, Protocol: policyv1beta1.TransportProtocolTCP},
				},
			},
			check: func(t *testing.T, o adaptive.Overrides, _ Declaration) {
				assert.Equal(t, []string{"10.43.12.7:443"}, destStrings(o.AllowedDestinations))
			},
		},
		{
			name: "an IPv6 destination",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "2001:db8::1/128", Port: 443},
				},
			},
			check: func(t *testing.T, o adaptive.Overrides, _ Declaration) {
				assert.Equal(t, []string{"[2001:db8::1]:443"}, destStrings(o.AllowedDestinations))
			},
		},
		{
			name: "an executable",
			declare: policyv1beta1.ExpectedBehavior{
				Executables: []string{"/usr/bin/pg_dump"},
			},
			check: func(t *testing.T, o adaptive.Overrides, d Declaration) {
				assert.Equal(t, []string{"/usr/bin/pg_dump"}, o.AllowedExecs)
				assert.Equal(t, []string{"/usr/bin/pg_dump"}, d.Executables)
			},
		},
		{
			name: "a capability, spelled either way",
			declare: policyv1beta1.ExpectedBehavior{
				Capabilities: []string{"CAP_DAC_OVERRIDE"},
			},
			check: func(t *testing.T, o adaptive.Overrides, d Declaration) {
				assert.Equal(t, []uint32{1}, o.AllowedCapabilities)
				assert.Equal(t, []uint32{1}, d.Capabilities)
			},
		},
		{
			name: "a capability without the CAP_ prefix is the same capability",
			declare: policyv1beta1.ExpectedBehavior{
				Capabilities: []string{"dac_override"},
			},
			check: func(t *testing.T, o adaptive.Overrides, _ Declaration) {
				assert.Equal(t, []uint32{1}, o.AllowedCapabilities)
			},
		},
		{
			name: "every kind at once",
			declare: policyv1beta1.ExpectedBehavior{
				Files:        []policyv1beta1.ExpectedFile{{Path: "/var/log/app.log", Write: true}},
				Executables:  []string{"/usr/sbin/logrotate"},
				Capabilities: []string{"CHOWN"},
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.0.0.53/32", Port: 853},
				},
			},
			check: func(t *testing.T, o adaptive.Overrides, d Declaration) {
				assert.Equal(t, []string{"/var/log/app.log"}, o.AllowedFiles)
				assert.Equal(t, []string{"/var/log/app.log"}, o.AllowedWriteFiles)
				assert.Equal(t, []string{"/usr/sbin/logrotate"}, o.AllowedExecs)
				assert.Equal(t, []uint32{0}, o.AllowedCapabilities)
				assert.Equal(t, []string{"10.0.0.53:853"}, destStrings(o.AllowedDestinations))
				assert.False(t, d.Empty())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, decl, warnings := TranslateSpec("p", betaSpec(&tc.declare), now)
			assert.Empty(t, warnings, "a representable declaration must translate silently")
			tc.check(t, d.Overrides, decl)
		})
	}
}

// The property the whole feature rests on. A declaration is an operator's
// assertion about behavior nobody observed, so it is allowed to add to the
// baseline and never to subtract from it: an assertion that could remove a
// learned entry would be a way to disable enforcement by writing YAML, and
// worse, a silent one.
func TestADeclarationNeverRemovesAnythingLearned(t *testing.T) {
	spec := betaSpec(&policyv1beta1.ExpectedBehavior{
		Files:        []policyv1beta1.ExpectedFile{{Path: "/var/lib/app/nightly.db", Write: true}},
		Executables:  []string{"/usr/bin/pg_dump"},
		Capabilities: []string{"DAC_OVERRIDE"},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{
			{CIDR: "10.43.12.7/32", Port: 5432},
		},
	})
	// Deny lists the policy itself set, which must survive the merge unchanged:
	// a declaration adding to the allow-set must not reopen something the
	// operator deliberately closed.
	spec.FilePolicy = &policyv1beta1.FilePolicy{
		DeniedPaths: []string{"/etc/shadow"},
	}
	spec.SyscallPolicy = &policyv1beta1.SyscallPolicy{DeniedSyscalls: []string{"ptrace"}}

	d, decl, warnings := TranslateSpec("p", spec, now)
	assert.Empty(t, warnings)
	require.False(t, decl.Empty())

	assert.Equal(t, []string{"/etc/shadow"}, d.Overrides.DeniedFiles)
	assert.Equal(t, []string{"/etc/shadow"}, d.Overrides.DeniedWriteFiles)
	assert.Equal(t, []string{"ptrace"}, d.Overrides.DeniedSyscalls)
	assert.Empty(t, d.Overrides.DeniedExecs)
	assert.Empty(t, d.Overrides.DeniedCapabilities)
	assert.Empty(t, d.Overrides.DeniedDestinations)
}

// The same claim at the level of the merge itself: whatever a declaration
// contains, mergeInto touches only the Allowed lists. Asserted separately
// because it is a property of the code rather than of one spec, and because a
// future field added to Overrides should fail this rather than pass it by
// accident.
func TestDeclarationMergeOnlyAdds(t *testing.T) {
	before := adaptive.Overrides{
		AllowedFiles:     []string{"/learned/path"},
		DeniedFiles:      []string{"/etc/shadow"},
		DeniedWriteFiles: []string{"/etc/shadow"},
		DeniedExecs:      []string{"/bin/busybox"},
		DeniedSyscalls:   []string{"ptrace"},
		DeniedDestinations: []adaptive.Destination{
			{IP: net.IPv4(10, 0, 0, 1), Port: 25},
		},
		DeniedCapabilities: []uint32{21},
	}
	after := before
	decl := Declaration{
		Files:        []DeclaredFile{{Path: "/declared/path", Write: true}},
		Executables:  []string{"/usr/bin/pg_dump"},
		Capabilities: []uint32{1},
		Destinations: []adaptive.Destination{{IP: net.IPv4(10, 43, 12, 7), Port: 5432}},
	}
	decl.mergeInto(&after)

	assert.Equal(t, []string{"/learned/path", "/declared/path"}, after.AllowedFiles,
		"the learned entry is still there and the declared one was appended")
	assert.Equal(t, before.DeniedFiles, after.DeniedFiles)
	assert.Equal(t, before.DeniedWriteFiles, after.DeniedWriteFiles)
	assert.Equal(t, before.DeniedExecs, after.DeniedExecs)
	assert.Equal(t, before.DeniedSyscalls, after.DeniedSyscalls)
	assert.Equal(t, before.DeniedDestinations, after.DeniedDestinations)
	assert.Equal(t, before.DeniedCapabilities, after.DeniedCapabilities)
}

// Every refusal below names the field that was refused, because a warning that
// says a declaration was dropped without saying which one leaves the operator
// no better off than the silent drop it replaced. The entry must also be
// genuinely absent: a warning plus a widened entry would be the worst of both.
func TestUnrepresentableDeclarationsAreRefused(t *testing.T) {
	tests := []struct {
		name    string
		declare policyv1beta1.ExpectedBehavior
		field   string
		because string
	}{
		{
			name: "a relative path",
			declare: policyv1beta1.ExpectedBehavior{
				Files: []policyv1beta1.ExpectedFile{{Path: "etc/passwd"}},
			},
			field:   "learningConfig.expectedBehavior.files[0].path",
			because: "is not absolute",
		},
		{
			name: "an empty path",
			declare: policyv1beta1.ExpectedBehavior{
				Files: []policyv1beta1.ExpectedFile{{Path: "   "}},
			},
			field:   "learningConfig.expectedBehavior.files[0].path",
			because: "is empty",
		},
		{
			name: "a wildcard path, which would be seeded literally and never match",
			declare: policyv1beta1.ExpectedBehavior{
				Files: []policyv1beta1.ExpectedFile{{Path: "/var/log/*.log"}},
			},
			field:   "learningConfig.expectedBehavior.files[0].path",
			because: "wildcard",
		},
		{
			name: "a relative executable",
			declare: policyv1beta1.ExpectedBehavior{
				Executables: []string{"pg_dump"},
			},
			field:   "learningConfig.expectedBehavior.executables[0]",
			because: "is not absolute",
		},
		{
			name: "a wildcard executable",
			declare: policyv1beta1.ExpectedBehavior{
				Executables: []string{"/usr/bin/pg_dump?"},
			},
			field:   "learningConfig.expectedBehavior.executables[0]",
			because: "wildcard",
		},
		{
			name: "a capability the kernel does not have",
			declare: policyv1beta1.ExpectedBehavior{
				Capabilities: []string{"CAP_MAKE_COFFEE"},
			},
			field:   "learningConfig.expectedBehavior.capabilities[0]",
			because: "is not a Linux capability",
		},
		{
			name: "an empty capability",
			declare: policyv1beta1.ExpectedBehavior{
				Capabilities: []string{" "},
			},
			field:   "learningConfig.expectedBehavior.capabilities[0]",
			because: "is empty",
		},
		{
			name: "a CIDR covering more than one host",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.43.12.0/24", Port: 5432},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].cidr",
			because: "covers 256 addresses",
		},
		{
			name: "an IPv6 prefix covering more than one host",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "2001:db8::/64", Port: 443},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].cidr",
			because: "cannot express a prefix",
		},
		{
			name: "a CIDR that is not an address at all",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "db.internal", Port: 5432},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].cidr",
			because: "is not an IP address",
		},
		{
			name: "an empty CIDR",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "  ", Port: 5432},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].cidr",
			because: "is empty",
		},
		{
			name: "port zero",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.43.12.7/32", Port: 0},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].port",
			because: "outside 1-65535",
		},
		{
			name: "a port past the end of the port space",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.43.12.7/32", Port: 70000},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].port",
			because: "outside 1-65535",
		},
		{
			name: "a negative port",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.43.12.7/32", Port: -1},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].port",
			because: "outside 1-65535",
		},
		{
			name: "UDP, which would be seeded as TCP",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.96.0.10/32", Port: 53, Protocol: policyv1beta1.TransportProtocolUDP},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].protocol",
			because: "is UDP, which cannot be declared",
		},
		{
			name: "a protocol that is neither",
			declare: policyv1beta1.ExpectedBehavior{
				NetworkDestinations: []policyv1beta1.ExpectedDestination{
					{CIDR: "10.96.0.10/32", Port: 53, Protocol: "SCTP"},
				},
			},
			field:   "learningConfig.expectedBehavior.networkDestinations[0].protocol",
			because: "is not TCP or UDP",
		},
		{
			name:    "a declaration that declares nothing",
			declare: policyv1beta1.ExpectedBehavior{},
			field:   "learningConfig.expectedBehavior",
			because: "declares nothing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, decl, warnings := TranslateSpec("p", betaSpec(&tc.declare), now)
			assert.True(t, hasWarning(warnings, tc.field),
				"the warning has to name %s so the author can find it; got %v", tc.field, warnings)
			assert.True(t, hasWarning(warnings, tc.because),
				"the warning has to say why; got %v", warnings)
			assert.True(t, decl.Empty(), "a refused declaration must seed nothing")
			assert.True(t, d.Overrides.Empty(),
				"a refused declaration must not reach the allow-set in any form")
		})
	}
}

// One bad entry must not take the good ones with it. An operator who mistypes
// one of six paths should get five seeded entries and one warning, not a policy
// that quietly declares nothing.
func TestOneRefusedEntryDoesNotDiscardTheRest(t *testing.T) {
	_, decl, warnings := TranslateSpec("p", betaSpec(&policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{
			{Path: "/var/lib/app/nightly.db", Write: true},
			{Path: "relative/path"},
			{Path: "/etc/ssl/renewed.pem"},
		},
	}), now)

	assert.True(t, hasWarning(warnings, "files[1].path"))
	assert.Len(t, warnings, 1)
	assert.Equal(t, []DeclaredFile{
		{Path: "/var/lib/app/nightly.db", Write: true},
		{Path: "/etc/ssl/renewed.pem"},
	}, decl.Files)
}

// The same operation named twice is one allow-set entry, not two. Duplicates
// are harmless in the kernel - the key is the same - but they double the
// declared list a human reads, and a path declared read and write is two
// different operations rather than a duplicate.
func TestDeclarationsAreDeduplicated(t *testing.T) {
	_, decl, warnings := TranslateSpec("p", betaSpec(&policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{
			{Path: "/var/lib/app/nightly.db"},
			{Path: " /var/lib/app/nightly.db "},
			{Path: "/var/lib/app/nightly.db", Write: true},
		},
		Executables:  []string{"/usr/bin/pg_dump", "/usr/bin/pg_dump"},
		Capabilities: []string{"CAP_DAC_OVERRIDE", "dac_override"},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{
			{CIDR: "10.43.12.7/32", Port: 5432},
			{CIDR: "10.43.12.7", Port: 5432, Protocol: policyv1beta1.TransportProtocolTCP},
		},
	}), now)

	assert.Empty(t, warnings)
	assert.Equal(t, []DeclaredFile{
		{Path: "/var/lib/app/nightly.db"},
		{Path: "/var/lib/app/nightly.db", Write: true},
	}, decl.Files)
	assert.Equal(t, []string{"/usr/bin/pg_dump"}, decl.Executables)
	assert.Equal(t, []uint32{1}, decl.Capabilities)
	assert.Equal(t, []string{"10.43.12.7:5432"}, destStrings(decl.Destinations))
}

// Requirement three: a profile has to say which entries were observed and which
// were asserted. Once an entry is in the kernel allow-set the two are
// indistinguishable - the map holds a hash, not a provenance - so the
// distinction has to be carried in what gets reported.
func TestDeclaredEntriesAreDistinguishableFromLearnedOnes(t *testing.T) {
	_, decl, warnings := TranslateSpec("p", betaSpec(&policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{
			{Path: "/var/lib/app/nightly.db", Write: true},
			{Path: "/etc/ssl/renewed.pem"},
		},
		Executables:  []string{"/usr/bin/pg_dump"},
		Capabilities: []string{"CAP_DAC_OVERRIDE"},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{
			{CIDR: "10.43.12.7/32", Port: 5432},
		},
	}), now)
	require.Empty(t, warnings)

	// A profile as the agent would report it: learned entries already present,
	// including one path that was both learned and declared.
	status := &policyv1beta1.ContainerProfileStatus{
		LearnedFiles:               []string{"/etc/nginx/nginx.conf", "/etc/ssl/renewed.pem"},
		LearnedExecutables:         []string{"/usr/sbin/nginx"},
		LearnedCapabilities:        []string{"NET_BIND_SERVICE"},
		LearnedNetworkDestinations: []string{"10.0.0.1:443"},
	}
	learnedBefore := append([]string(nil), status.LearnedFiles...)
	decl.ReportInto(status)

	// The learned lists are untouched, so what the container actually did is
	// still readable as exactly that.
	assert.Equal(t, learnedBefore, status.LearnedFiles)
	assert.Equal(t, []string{"/usr/sbin/nginx"}, status.LearnedExecutables)
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, status.LearnedCapabilities)
	assert.Equal(t, []string{"10.0.0.1:443"}, status.LearnedNetworkDestinations)

	// And the declared ones are reported separately, with the write marked.
	assert.Equal(t, []string{
		"/etc/ssl/renewed.pem",
		"/var/lib/app/nightly.db (write)",
	}, status.DeclaredFiles)
	assert.Equal(t, []string{"10.43.12.7:5432"}, status.DeclaredNetworkDestinations)
	assert.Equal(t, []string{"/usr/bin/pg_dump"}, status.DeclaredExecutables)
	assert.Equal(t, []string{"DAC_OVERRIDE"}, status.DeclaredCapabilities)

	// A path that was both learned and declared appears in both lists, which is
	// the honest answer: the workload did open it, and somebody also asserted
	// it would. Erasing either half would lose a fact.
	assert.Contains(t, status.LearnedFiles, "/etc/ssl/renewed.pem")
	assert.Contains(t, status.DeclaredFiles, "/etc/ssl/renewed.pem")
}

// Re-reporting an unchanged declaration writes an unchanged status. Otherwise
// every sync would be an API write, and a profile's resourceVersion would climb
// forever on a policy nobody touched.
func TestReportIntoIsIdempotentAndClearsWhatItOwns(t *testing.T) {
	_, decl, _ := TranslateSpec("p", betaSpec(&policyv1beta1.ExpectedBehavior{
		Executables: []string{"/usr/bin/pg_dump", "/usr/bin/aws"},
	}), now)

	first := &policyv1beta1.ContainerProfileStatus{}
	decl.ReportInto(first)
	second := &policyv1beta1.ContainerProfileStatus{}
	decl.ReportInto(second)
	assert.Equal(t, first, second)

	// An emptied declaration clears the lists rather than leaving the last
	// declaration standing: a profile must not report entries the policy no
	// longer declares and the kernel no longer has seeded.
	stale := &policyv1beta1.ContainerProfileStatus{
		DeclaredFiles:               []string{"/gone"},
		DeclaredNetworkDestinations: []string{"10.0.0.1:1"},
		DeclaredExecutables:         []string{"/gone"},
		DeclaredCapabilities:        []string{"CHOWN"},
		LearnedFiles:                []string{"/etc/nginx/nginx.conf"},
	}
	Declaration{}.ReportInto(stale)
	assert.Nil(t, stale.DeclaredFiles)
	assert.Nil(t, stale.DeclaredNetworkDestinations)
	assert.Nil(t, stale.DeclaredExecutables)
	assert.Nil(t, stale.DeclaredCapabilities)
	assert.Equal(t, []string{"/etc/nginx/nginx.conf"}, stale.LearnedFiles,
		"clearing declarations must not touch what was learned")
}

func TestReportIntoToleratesANilStatus(t *testing.T) {
	assert.NotPanics(t, func() { Declaration{}.ReportInto(nil) })
}

// A declaration only reaches the kernel when the container is enforcing, which
// is the same thing the allow and deny lists already warn about. Said once per
// policy rather than twice, because two warnings for one cause is how a warning
// list becomes something people skim.
func TestDeclarationsAreReportedAsInertWhenNothingEnforces(t *testing.T) {
	spec := betaSpec(&policyv1beta1.ExpectedBehavior{
		Executables: []string{"/usr/bin/pg_dump"},
	})
	spec.EnforcementConfig.Mode = policyv1beta1.EnforcementModeMonitoring

	d, decl, warnings := TranslateSpec("p", spec, now)
	assert.True(t, hasWarning(warnings, "learningConfig.expectedBehavior is recorded but has no effect"))
	assert.False(t, decl.Empty(), "the declaration is still translated, just not enforced yet")
	assert.Equal(t, []string{"/usr/bin/pg_dump"}, d.Overrides.AllowedExecs)

	// With an allow list of its own present, the existing warning already says
	// it, and the declaration does not repeat the point.
	spec.FilePolicy = &policyv1beta1.FilePolicy{AllowedPaths: []string{"/etc/x"}}
	_, _, warnings = TranslateSpec("p", spec, now)
	assert.True(t, hasWarning(warnings, "no effect in Monitoring mode"))
	assert.False(t, hasWarning(warnings, "learningConfig.expectedBehavior is recorded"))
}

// An Off policy governs nothing, so there is nothing to declare into and
// nothing worth warning about. Translate stops for the same reason.
func TestOffPolicyIgnoresDeclarations(t *testing.T) {
	spec := betaSpec(&policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{{Path: "not-even-valid"}},
	})
	spec.EnforcementConfig.Mode = policyv1beta1.EnforcementModeOff

	d, decl, warnings := TranslateSpec("p", spec, now)
	assert.Equal(t, adaptive.ModeOff, d.Mode)
	assert.True(t, decl.Empty())
	assert.True(t, d.Overrides.Empty())
	assert.Empty(t, warnings)
}

// Everything but the declaration is translated by the one code path both
// versions share, so a hub spec with no declaration must produce exactly what
// the equivalent v1alpha1 spec produces. Two translators for one spec would
// drift, and a rule honored in one version and dropped in the other is the bug
// this package exists to make testable.
func TestTranslateSpecMatchesTranslateWhenNothingIsDeclared(t *testing.T) {
	alpha := benchSpec()
	var hub policyv1beta1.PahlevanPolicy
	require.NoError(t, (&policyv1alpha1.PahlevanPolicy{Spec: alpha}).ConvertTo(&hub))

	want, wantWarnings := Translate("p", alpha, now)
	got, decl, gotWarnings := TranslateSpec("p", hub.Spec, now)

	assert.Equal(t, want, got)
	assert.Equal(t, wantWarnings, gotWarnings)
	assert.True(t, decl.Empty())
}

// A nil declaration block is the common case and must cost nothing and say
// nothing.
func TestNoDeclarationIsSilent(t *testing.T) {
	d, decl, warnings := TranslateSpec("p", betaSpec(nil), now)
	assert.Empty(t, warnings)
	assert.True(t, decl.Empty())
	assert.True(t, d.Overrides.Empty())
}

// Translation runs per policy per container resolution, and a declaration adds
// a pass over four lists plus a down-conversion of the spec. ReportAllocs
// because allocation count is what a translator regresses on first.
func BenchmarkTranslateSpec(b *testing.B) {
	var hub policyv1beta1.PahlevanPolicy
	if err := (&policyv1alpha1.PahlevanPolicy{Spec: benchSpec()}).ConvertTo(&hub); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = TranslateSpec("bench", hub.Spec, now)
	}
}

func BenchmarkTranslateSpecWithDeclarations(b *testing.B) {
	var hub policyv1beta1.PahlevanPolicy
	if err := (&policyv1alpha1.PahlevanPolicy{Spec: benchSpec()}).ConvertTo(&hub); err != nil {
		b.Fatal(err)
	}
	hub.Spec.LearningConfig.ExpectedBehavior = &policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{
			{Path: "/var/lib/app/nightly.db", Write: true},
			{Path: "/etc/ssl/renewed.pem"},
		},
		Executables:  []string{"/usr/bin/pg_dump", "/usr/sbin/logrotate"},
		Capabilities: []string{"CAP_DAC_OVERRIDE", "CHOWN"},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{
			{CIDR: "10.43.12.7/32", Port: 5432},
			{CIDR: "10.0.0.53/32", Port: 853, Protocol: policyv1beta1.TransportProtocolTCP},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = TranslateSpec("bench", hub.Spec, now)
	}
}

// Reporting is on the agent's status-sync path, which runs per container per
// interval, so it is worth knowing what it costs.
func BenchmarkDeclarationReportInto(b *testing.B) {
	_, decl, _ := TranslateSpec("bench", betaSpec(&policyv1beta1.ExpectedBehavior{
		Files: []policyv1beta1.ExpectedFile{
			{Path: "/var/lib/app/nightly.db", Write: true},
			{Path: "/etc/ssl/renewed.pem"},
		},
		Executables:  []string{"/usr/bin/pg_dump"},
		Capabilities: []string{"CAP_DAC_OVERRIDE"},
		NetworkDestinations: []policyv1beta1.ExpectedDestination{
			{CIDR: "10.43.12.7/32", Port: 5432},
		},
	}), now)
	status := &policyv1beta1.ContainerProfileStatus{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decl.ReportInto(status)
	}
}
