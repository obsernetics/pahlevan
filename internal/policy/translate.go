// Package policy translates a PahlevanPolicy spec into the decision the
// adaptive controller acts on.
//
// It exists as its own package because the translation is where the CRD's
// promises are either kept or quietly dropped, and that deserves direct tests.
// Previously this logic lived inline in the agent's resolver and covered three
// of the spec's fields; everything else - grace periods, the Off/Monitoring
// distinction, every exception and allow/deny list - was parsed into the Go
// type and then ignored.
package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

// maxPortsPerRule bounds how many ports a single egress rule may contribute.
// The kernel allow-set is keyed on the exact (address, port) pair, so a port
// range has to be enumerated entry by entry. A rule spanning the whole port
// space would insert 65535 entries per address and evict everything else from
// an LRU map, so a range this wide is reported as unrepresentable instead.
const maxPortsPerRule = 1024

// Translate converts a policy spec into a Decision, together with the
// human-readable warnings for anything in the spec that cannot be represented.
//
// Warnings are returned rather than logged so the caller can surface them on
// the policy's status, where the author will actually see them. Silently
// dropping an unrepresentable rule is how a policy comes to look enforced when
// it is not.
func Translate(name string, spec policyv1alpha1.PahlevanPolicySpec, now time.Time) (adaptive.Decision, []string) {
	var warnings []string

	d := adaptive.Decision{
		PolicyName: name,
		Mode:       resolveMode(spec.EnforcementConfig),
	}
	if spec.LearningConfig.Duration != nil {
		d.Window = spec.LearningConfig.Duration.Duration
	}
	if spec.EnforcementConfig.GracePeriod != nil {
		d.GracePeriod = spec.EnforcementConfig.GracePeriod.Duration
	}
	if d.Window < 0 {
		warnings = append(warnings, "learningConfig.duration is negative; treated as zero")
		d.Window = 0
	}
	if d.GracePeriod < 0 {
		warnings = append(warnings, "enforcementConfig.gracePeriod is negative; treated as zero")
		d.GracePeriod = 0
	}

	// An Off policy governs nothing, so there is no point translating the rest
	// and no point warning about it.
	if d.Mode == adaptive.ModeOff {
		return d, warnings
	}

	o := &d.Overrides
	warnings = append(warnings, applyFilePolicy(o, spec.FilePolicy)...)
	warnings = append(warnings, applySyscallPolicy(o, spec.SyscallPolicy)...)
	warnings = append(warnings, applyNetworkPolicy(o, spec.NetworkPolicy)...)
	warnings = append(warnings, applyExceptions(o, spec.EnforcementConfig.Exceptions, now)...)

	if !o.Empty() && d.Mode != adaptive.ModeBlocking {
		warnings = append(warnings,
			"allow and deny lists are recorded but have no effect in "+string(d.Mode)+
				" mode; they apply when the container is enforcing")
	}
	return d, warnings
}

// resolveMode folds AlertOnly and BlockUnknown into the declared mode so the
// controller never has to re-derive it.
//
// An empty mode means Monitoring, not Blocking: a policy that forgot to say
// must not start denying traffic. AlertOnly downgrades Blocking, which is what
// the field is for. BlockUnknown being explicitly false under Blocking is a
// contradiction - default-deny of unlearned behaviour is the only enforcement
// this kernel data plane performs - so it downgrades too, rather than
// enforcing something the author asked not to.
func resolveMode(c policyv1alpha1.EnforcementConfig) adaptive.Mode {
	switch c.Mode {
	case policyv1alpha1.EnforcementModeOff:
		return adaptive.ModeOff
	case policyv1alpha1.EnforcementModeBlocking:
		if c.AlertOnly {
			return adaptive.ModeMonitoring
		}
		if c.BlockUnknown != nil && !*c.BlockUnknown {
			return adaptive.ModeMonitoring
		}
		return adaptive.ModeBlocking
	default:
		return adaptive.ModeMonitoring
	}
}

func applyFilePolicy(o *adaptive.Overrides, fp *policyv1alpha1.FilePolicy) []string {
	if fp == nil {
		return nil
	}
	var warnings []string
	o.AllowedFiles = append(o.AllowedFiles, cleanPaths(fp.AllowedPaths)...)
	o.DeniedFiles = append(o.DeniedFiles, cleanPaths(fp.DeniedPaths)...)

	// ReadOnlyPaths and WriteAllowedPaths are both "this path may be opened".
	// The LSM hook governs file_open without splitting read from write, so
	// honouring them as allow entries is accurate for what the kernel does and
	// the distinction is called out rather than pretended.
	if len(fp.ReadOnlyPaths) > 0 || len(fp.WriteAllowedPaths) > 0 {
		o.AllowedFiles = append(o.AllowedFiles, cleanPaths(fp.ReadOnlyPaths)...)
		o.AllowedFiles = append(o.AllowedFiles, cleanPaths(fp.WriteAllowedPaths)...)
		warnings = append(warnings,
			"readOnlyPaths and writeAllowedPaths are allowed as opens; the file_open "+
				"LSM hook does not distinguish read from write, so read-only is not enforced")
	}
	if ef := fp.ExecutableFilter; ef != nil {
		o.AllowedExecs = append(o.AllowedExecs, cleanPaths(ef.AllowedExecutables)...)
		o.DeniedExecs = append(o.DeniedExecs, cleanPaths(ef.DeniedExecutables)...)
	}
	if warn := warnGlobs("filePolicy", append(append([]string{}, fp.AllowedPaths...), fp.DeniedPaths...)); warn != "" {
		warnings = append(warnings, warn)
	}
	return warnings
}

func applySyscallPolicy(o *adaptive.Overrides, sp *policyv1alpha1.SyscallPolicy) []string {
	if sp == nil {
		return nil
	}
	var warnings []string
	o.AllowedSyscalls = append(o.AllowedSyscalls, cleanNames(sp.AllowedSyscalls)...)
	o.DeniedSyscalls = append(o.DeniedSyscalls, cleanNames(sp.DeniedSyscalls)...)

	for _, c := range sp.CapabilityFilter {
		num, ok := ebpf.CapabilityNumber(c)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("unknown capability %q in syscallPolicy.capabilityFilter", c))
			continue
		}
		o.AllowedCapabilities = append(o.AllowedCapabilities, num)
	}
	if sp.ProcessFilter != nil {
		warnings = append(warnings,
			"syscallPolicy.processFilter is not enforced: the data plane keys on cgroup, "+
				"not on process attributes")
	}
	return warnings
}

func applyNetworkPolicy(o *adaptive.Overrides, np *policyv1alpha1.NetworkPolicy) []string {
	if np == nil {
		return nil
	}
	var warnings []string
	if len(np.IngressRules) > 0 {
		warnings = append(warnings,
			"networkPolicy.ingressRules are ignored: the socket_connect LSM hook governs "+
				"egress only")
	}
	if np.AllowDNS || np.AllowLoopback {
		warnings = append(warnings,
			"networkPolicy.allowDNS and allowLoopback need a concrete address and port to "+
				"seed; express them as egressRules with an ipBlock and port")
	}
	for i, rule := range np.EgressRules {
		dests, warns := translateEgressRule(i, rule)
		warnings = append(warnings, warns...)
		if isDeny(rule.Action) {
			o.DeniedDestinations = append(o.DeniedDestinations, dests...)
		} else {
			o.AllowedDestinations = append(o.AllowedDestinations, dests...)
		}
	}
	return warnings
}

// translateEgressRule expands one rule into concrete destinations. Only exact
// host addresses survive: the allow-set is a hash of (address, port), so a
// prefix shorter than /32 or /128 has no representation in it.
func translateEgressRule(idx int, rule policyv1alpha1.NetworkRule) ([]adaptive.Destination, []string) {
	var warnings []string
	ports, portWarn := rulePorts(idx, rule.Ports)
	warnings = append(warnings, portWarn...)
	if len(ports) == 0 {
		return nil, warnings
	}

	var ips []net.IP
	for _, peer := range rule.Peers {
		switch {
		case peer.IPBlock != nil:
			ip, warn := hostIPFromCIDR(idx, peer.IPBlock.CIDR)
			if warn != "" {
				warnings = append(warnings, warn)
				continue
			}
			if len(peer.IPBlock.Except) > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"egressRules[%d].ipBlock.except is ignored: a single-host block has nothing to except", idx))
			}
			ips = append(ips, ip)
		case peer.PodSelector != nil || peer.NamespaceSelector != nil:
			warnings = append(warnings, fmt.Sprintf(
				"egressRules[%d] selects peers by label, which cannot be resolved to a fixed "+
					"address at policy translation time; use an ipBlock", idx))
		}
	}
	if len(ips) == 0 {
		return nil, warnings
	}

	dests := make([]adaptive.Destination, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, p := range ports {
			dests = append(dests, adaptive.Destination{IP: ip, Port: p})
		}
	}
	return dests, warnings
}

func rulePorts(idx int, ports []policyv1alpha1.NetworkPort) ([]uint16, []string) {
	var warnings []string
	var out []uint16
	seen := map[uint16]struct{}{}
	add := func(p int32) {
		if p < 1 || p > 65535 {
			warnings = append(warnings, fmt.Sprintf("egressRules[%d] port %d is out of range", idx, p))
			return
		}
		v := uint16(p)
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, p := range ports {
		switch {
		case p.Port != nil:
			add(*p.Port)
		case p.StartPort != nil && p.EndPort != nil:
			start, end := *p.StartPort, *p.EndPort
			if end < start {
				warnings = append(warnings, fmt.Sprintf(
					"egressRules[%d] port range %d-%d is inverted", idx, start, end))
				continue
			}
			if end-start+1 > maxPortsPerRule {
				warnings = append(warnings, fmt.Sprintf(
					"egressRules[%d] port range %d-%d spans %d ports, over the %d limit; "+
						"the kernel allow-set holds one entry per port and a range this wide "+
						"would evict the learned baseline", idx, start, end, end-start+1, maxPortsPerRule))
				continue
			}
			for p := start; p <= end; p++ {
				add(p)
			}
		default:
			warnings = append(warnings, fmt.Sprintf(
				"egressRules[%d] has a port entry with neither port nor a start/end range", idx))
		}
	}
	if len(ports) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"egressRules[%d] specifies no ports; the allow-set is keyed on (address, port) "+
				"so there is nothing to seed", idx))
	}
	return out, warnings
}

// hostIPFromCIDR accepts a bare address or a single-host prefix and rejects
// anything wider.
func hostIPFromCIDR(idx int, cidr string) (net.IP, string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, fmt.Sprintf("egressRules[%d].ipBlock.cidr is empty", idx)
	}
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil {
			return ip, ""
		}
		return nil, fmt.Sprintf("egressRules[%d].ipBlock.cidr %q is not an IP address", idx, cidr)
	}
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Sprintf("egressRules[%d].ipBlock.cidr %q is invalid: %v", idx, cidr, err)
	}
	ones, bits := network.Mask.Size()
	if ones != bits {
		return nil, fmt.Sprintf(
			"egressRules[%d].ipBlock.cidr %q covers %d addresses; the kernel allow-set is a "+
				"hash of the exact destination and cannot express a prefix, so only /%d hosts "+
				"are seeded", idx, cidr, 1<<(bits-ones), bits)
	}
	return ip, ""
}

// applyExceptions turns enforcement exceptions into allow entries, skipping any
// that have expired. An expired exception that still widened the allow-set
// would be a permanent hole opened by a temporary decision.
func applyExceptions(o *adaptive.Overrides, exceptions []policyv1alpha1.EnforcementException, now time.Time) []string {
	var warnings []string
	for i, ex := range exceptions {
		if ex.Temporary && ex.ExpiresAt != nil && !now.Before(ex.ExpiresAt.Time) {
			warnings = append(warnings, fmt.Sprintf(
				"exceptions[%d] expired at %s and is not applied", i, ex.ExpiresAt.Time.Format(time.RFC3339)))
			continue
		}
		if ex.Temporary && ex.ExpiresAt == nil {
			warnings = append(warnings, fmt.Sprintf(
				"exceptions[%d] is marked temporary but has no expiresAt, so it never expires", i))
		}
		patterns := cleanNames(ex.Patterns)
		if len(patterns) == 0 {
			warnings = append(warnings, fmt.Sprintf("exceptions[%d] has no patterns", i))
			continue
		}
		switch ex.Type {
		case policyv1alpha1.ExceptionTypeFile:
			o.AllowedFiles = append(o.AllowedFiles, patterns...)
			if warn := warnGlobs(fmt.Sprintf("exceptions[%d]", i), patterns); warn != "" {
				warnings = append(warnings, warn)
			}
		case policyv1alpha1.ExceptionTypeSyscall:
			o.AllowedSyscalls = append(o.AllowedSyscalls, patterns...)
		case policyv1alpha1.ExceptionTypeNetwork:
			dests, warns := parseDestinations(i, patterns)
			warnings = append(warnings, warns...)
			o.AllowedDestinations = append(o.AllowedDestinations, dests...)
		default:
			warnings = append(warnings, fmt.Sprintf(
				"exceptions[%d] has unknown type %q; expected Syscall, Network or File", i, ex.Type))
		}
	}
	return warnings
}

// parseDestinations reads "ip:port" exception patterns.
func parseDestinations(idx int, patterns []string) ([]adaptive.Destination, []string) {
	var warnings []string
	var out []adaptive.Destination
	for _, p := range patterns {
		host, portStr, err := net.SplitHostPort(p)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"exceptions[%d] network pattern %q is not host:port", idx, p))
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			warnings = append(warnings, fmt.Sprintf(
				"exceptions[%d] network pattern %q does not name an IP address; DNS names "+
					"cannot be resolved to a stable allow-set key", idx, p))
			continue
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"exceptions[%d] network pattern %q has an invalid port", idx, p))
			continue
		}
		out = append(out, adaptive.Destination{IP: ip, Port: uint16(port)})
	}
	return out, warnings
}

// warnGlobs reports patterns that look like globs. The allow-set is keyed on an
// exact path hash, so a wildcard matches nothing and would look like an applied
// rule that never fires.
func warnGlobs(field string, patterns []string) string {
	var globs []string
	for _, p := range patterns {
		if strings.ContainsAny(p, "*?[") {
			globs = append(globs, p)
		}
	}
	if len(globs) == 0 {
		return ""
	}
	return fmt.Sprintf("%s contains wildcard patterns (%s) which are matched literally: "+
		"the kernel allow-set is keyed on an exact path hash", field, strings.Join(globs, ", "))
}

func cleanPaths(in []string) []string { return cleanNames(in) }
func isDeny(a policyv1alpha1.PolicyAction) bool {
	return strings.EqualFold(string(a), "Deny") || strings.EqualFold(string(a), "Block")
}

func cleanNames(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
