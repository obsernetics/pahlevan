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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	policyv1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
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
	return TranslateIn(name, spec, now, Context{})
}

// TranslateIn is Translate with the cluster state a selector peer needs to be
// expanded into addresses. Translate is TranslateIn with none, which is what
// the operator and the unit tests use.
func TranslateIn(
	name string,
	spec policyv1alpha1.PahlevanPolicySpec,
	now time.Time,
	ctx Context,
) (adaptive.Decision, []string) {
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

	d.SelfHealing = adaptive.SelfHealingDecision{
		Enabled:   spec.SelfHealing.Enabled,
		Threshold: int(spec.SelfHealing.RollbackThreshold),
	}
	if spec.SelfHealing.RollbackWindow != nil {
		d.SelfHealing.Window = spec.SelfHealing.RollbackWindow.Duration
	}
	if d.SelfHealing.Threshold < 0 {
		warnings = append(warnings, "selfHealing.rollbackThreshold is negative; the default is used")
		d.SelfHealing.Threshold = 0
	}
	if d.SelfHealing.Window < 0 {
		warnings = append(warnings, "selfHealing.rollbackWindow is negative; the default is used")
		d.SelfHealing.Window = 0
	}
	if spec.SelfHealing.RecoveryStrategy != "" &&
		spec.SelfHealing.RecoveryStrategy != policyv1alpha1.RecoveryStrategyRollback {
		warnings = append(warnings, fmt.Sprintf(
			"selfHealing.recoveryStrategy %q is not implemented; the only recovery is Rollback, "+
				"which returns the container to learning", spec.SelfHealing.RecoveryStrategy))
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

	if warn := warnUnknownMode(spec.EnforcementConfig.Mode); warn != "" {
		warnings = append(warnings, warn)
	}
	warnings = append(warnings, warnInertFields(spec)...)

	o := &d.Overrides
	warnings = append(warnings, applyFilePolicy(o, spec.FilePolicy)...)
	warnings = append(warnings, applySyscallPolicy(o, spec.SyscallPolicy)...)
	warnings = append(warnings, applyNetworkPolicy(o, spec.NetworkPolicy, ctx)...)
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
// contradiction - default-deny of unlearned behavior is the only enforcement
// this kernel data plane performs - so it downgrades too, rather than
// enforcing something the author asked not to.
// warnInertFields reports the parts of the spec that are accepted by the API
// and acted on by nothing.
//
// These are not unimplementable, and several are not even unreasonable. What
// makes them worth a warning is that they are indistinguishable, from the
// author's side, from the fields that work: the policy applies, the status goes
// green, and the setting does nothing. That is strictly worse than a field that
// does not exist, because a field that does not exist produces an error.
//
// Each was found by asking which code reads it. The two engines that read
// several of them - pkg/policies.EnforcementEngine and
// internal/learner.SyscallLearner - are constructed only by the integration
// test framework, never by the agent or the operator, so a field only they
// consume is inert in every deployment.
func warnInertFields(spec policyv1alpha1.PahlevanPolicySpec) []string {
	var out []string

	if spec.LearningConfig.WindowSize != nil {
		out = append(out,
			"learningConfig.windowSize has no effect: the adaptive controller observes "+
				"continuously rather than in sampling windows, and the only code that reads "+
				"this field is not built into the agent")
	}
	if spec.LearningConfig.LifecycleAware {
		out = append(out,
			"learningConfig.lifecycleAware has no effect: it is displayed and stored but "+
				"nothing acts on it. A restarted container gets a new cgroup id and therefore "+
				"a new baseline regardless")
	}
	if fp := spec.FilePolicy; fp != nil {
		if fp.DefaultAction != "" {
			out = append(out, defaultActionWarning("filePolicy"))
		}
		if fp.ExecutableFilter != nil && fp.ExecutableFilter.RequireSignature {
			out = append(out,
				"filePolicy.executableFilter.requireSignature has no effect: nothing verifies "+
					"executable signatures, and the kernel hook has no way to")
		}
	}
	if sp := spec.SyscallPolicy; sp != nil && sp.DefaultAction != "" {
		out = append(out, defaultActionWarning("syscallPolicy"))
	}
	if np := spec.NetworkPolicy; np != nil && np.DefaultAction != "" {
		out = append(out, defaultActionWarning("networkPolicy"))
	}
	if inertObservability(spec.ObservabilityConfig) {
		out = append(out,
			"observabilityConfig has no effect: the agent's metrics, tracing and logging are "+
				"configured by its flags (--observability-exports, --otlp-endpoint, "+
				"--metrics-detail) and apply to the whole node, not per policy")
	}
	return out
}

// defaultActionWarning explains why a default action is redundant rather than
// merely unimplemented, which is a different thing and worth saying.
func defaultActionWarning(field string) string {
	return field + ".defaultAction has no effect. Default-deny of unlearned behavior is " +
		"what enforcement is, so Deny is already the behavior under Blocking and Allow is " +
		"what Monitoring mode means; the field cannot express a third thing"
}

// inertObservability reports whether anything was set in the block. Comparing
// against the zero value rather than listing sub-fields keeps this correct when
// the block grows.
func inertObservability(c policyv1alpha1.ObservabilityConfig) bool {
	return c.Metrics.Enabled || len(c.Metrics.Exporters) > 0 || c.Metrics.Interval != nil ||
		c.Tracing.Enabled || c.Tracing.Exporter.Type != "" || c.Tracing.SamplingRate != nil ||
		c.Logging.Level != "" || c.Logging.Format != "" || len(c.Logging.Outputs) > 0 ||
		c.Visualization.Enabled || len(c.Visualization.Exporters) > 0
}

// warnUnknownMode reports a mode the controller does not recognize.
//
// resolveMode maps anything unknown onto Monitoring, which is the safe default
// but an invisible one: a typo produces a policy that looks applied and
// enforces nothing. The CRD now rejects an unknown mode at admission, so this
// covers objects stored before that validation existed, and clusters where the
// CRD has not been upgraded.
//
// The "false" and "true" cases get their own message because they are not
// typos. `mode: Off` unquoted is a YAML 1.1 boolean, so it arrives as false -
// and a policy the author meant to switch off keeps running.
func warnUnknownMode(m policyv1alpha1.EnforcementMode) string {
	switch m {
	case "", policyv1alpha1.EnforcementModeOff,
		policyv1alpha1.EnforcementModeMonitoring,
		policyv1alpha1.EnforcementModeBlocking:
		return ""
	case "false", "true":
		return fmt.Sprintf(
			"enforcementConfig.mode is %q, which is what YAML turns an unquoted Off or On "+
				"into; write mode: \"Off\" in quotes. Treated as Monitoring", string(m))
	default:
		return fmt.Sprintf(
			"enforcementConfig.mode %q is not one of Off, Monitoring or Blocking; "+
				"treated as Monitoring, so this policy enforces nothing", string(m))
	}
}

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

	// allowedPaths grants both modes: an operator naming a path without
	// qualification means the workload may use it.
	allowed := cleanPaths(fp.AllowedPaths)
	o.AllowedFiles = append(o.AllowedFiles, allowed...)
	o.AllowedWriteFiles = append(o.AllowedWriteFiles, allowed...)

	// deniedPaths revokes both, so a denial cannot be sidestepped by opening
	// the path the other way.
	denied := cleanPaths(fp.DeniedPaths)
	o.DeniedFiles = append(o.DeniedFiles, denied...)
	o.DeniedWriteFiles = append(o.DeniedWriteFiles, denied...)

	// readOnlyPaths and writeAllowedPaths are now real rather than aspirational:
	// the allow-set keys on the access mode, so granting a read genuinely does
	// not grant a write.
	for _, p := range cleanPaths(fp.ReadOnlyPaths) {
		o.AllowedFiles = append(o.AllowedFiles, p)
		o.DeniedWriteFiles = append(o.DeniedWriteFiles, p)
	}
	for _, p := range cleanPaths(fp.WriteAllowedPaths) {
		o.AllowedFiles = append(o.AllowedFiles, p)
		o.AllowedWriteFiles = append(o.AllowedWriteFiles, p)
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
	warnings = append(warnings, applyProcessFilter(o, sp.ProcessFilter)...)
	return warnings
}

// applyProcessFilter turns the CRD's process filter into the kernel-enforced
// one.
//
// The mapping is not one field per dimension. Commands names the binaries that
// may be executed, which is exactly what the exec allow-set already keys on, so
// it becomes AllowedExecs rather than a fourth filter dimension - one mechanism
// instead of two that would have to agree. Users, Groups and ParentProcesses
// have no allow-set equivalent and become the filter proper.
//
// Users and Groups are numeric here. The kernel sees uids, not names: it has no
// view of the container's /etc/passwd, and resolving a name on the node would
// resolve it against the wrong passwd file. A non-numeric entry is reported
// rather than guessed at.
func applyProcessFilter(o *adaptive.Overrides, pf *policyv1alpha1.ProcessFilter) []string {
	if pf == nil {
		return nil
	}
	var warnings []string

	// Commands are binaries, which the exec allow-set already governs.
	for _, c := range cleanPaths(pf.Commands) {
		if !strings.HasPrefix(c, "/") {
			warnings = append(warnings, fmt.Sprintf(
				"syscallPolicy.processFilter.commands[%q] is ignored: the kernel matches the "+
					"resolved binary path, so this must be absolute", c))
			continue
		}
		o.AllowedExecs = append(o.AllowedExecs, c)
	}
	if warn := warnGlobs("syscallPolicy.processFilter.commands", pf.Commands); warn != "" {
		warnings = append(warnings, warn)
	}

	f := &ebpf.ProcFilter{}
	f.ParentProcesses = cleanNames(pf.ParentProcesses)
	for _, p := range f.ParentProcesses {
		if len(p) > 15 {
			warnings = append(warnings, fmt.Sprintf(
				"syscallPolicy.processFilter.parentProcesses[%q] is matched on its first 15 "+
					"characters: the kernel's comm field is TASK_COMM_LEN", p))
		}
	}

	f.UIDs, warnings = parseIDs("users", pf.Users, warnings)
	f.GIDs, warnings = parseIDs("groups", pf.Groups, warnings)

	if !f.Empty() {
		o.ProcFilter = f
	}
	return warnings
}

// parseIDs converts the numeric uid/gid strings the CRD accepts, reporting the
// ones it cannot.
func parseIDs(field string, values []string, warnings []string) ([]uint32, []string) {
	var out []uint32
	for _, v := range cleanNames(values) {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"syscallPolicy.processFilter.%s[%q] is ignored: the kernel matches numeric ids, "+
					"and a name cannot be resolved against the container's passwd file from the node",
				field, v))
			continue
		}
		out = append(out, uint32(n))
	}
	return out, warnings
}

func applyNetworkPolicy(o *adaptive.Overrides, np *policyv1alpha1.NetworkPolicy, ctx Context) []string {
	if np == nil {
		return nil
	}
	var warnings []string
	if len(np.IngressRules) > 0 {
		warnings = append(warnings,
			"networkPolicy.ingressRules are ignored: the socket_connect LSM hook governs "+
				"egress only")
	}
	// Blanket permissions. These name a class of destination rather than an
	// address, so they are a per-cgroup flag checked in socket_connect ahead of
	// the allow-set rather than allow-set entries. Seeding a guessed set of
	// loopback addresses and ports instead would be both incomplete and
	// impossible to withdraw.
	if np.AllowLoopback {
		o.NetworkRelax |= ebpf.RelaxLoopback
	}
	if np.AllowDNS {
		o.NetworkRelax |= ebpf.RelaxDNS
	}
	for i, rule := range np.EgressRules {
		dests, selected, warns := translateEgressRule(i, rule, ctx)
		warnings = append(warnings, warns...)
		if isDeny(rule.Action) {
			o.DeniedDestinations = append(o.DeniedDestinations, dests...)
			// A deny rule written with a selector is not tracked as a
			// selector destination: withdrawing a denial when a pod stops
			// matching would re-permit the address, and a rule whose removal
			// grants access is not a thing a deny rule should ever do. The
			// set is simply re-derived on the next reconcile.
			continue
		}
		o.AllowedDestinations = append(o.AllowedDestinations, dests...)
		o.SelectorDestinations = append(o.SelectorDestinations, selected...)
	}
	return warnings
}

// translateEgressRule expands one rule into concrete destinations. Only exact
// host addresses survive: the allow-set is a hash of (address, port), so a
// prefix shorter than /32 or /128 has no representation in it.
//
// The second return is the subset that came from a selector peer, which the
// controller re-derives on every reconcile; see adaptive.Overrides.
func translateEgressRule(
	idx int,
	rule policyv1alpha1.NetworkRule,
	ctx Context,
) (dests []adaptive.Destination, selected []adaptive.Destination, warnings []string) {
	ports, portWarn := rulePorts(idx, rule.Ports)
	warnings = append(warnings, portWarn...)
	if len(ports) == 0 {
		return nil, nil, warnings
	}

	var ips []net.IP
	for _, peer := range rule.Peers {
		switch {
		case peer.IPBlock != nil:
			ip, warn := hostIPFromCIDR(
				fmt.Sprintf("egressRules[%d].ipBlock.cidr", idx), peer.IPBlock.CIDR)
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
			// A selector peer is expanded against the identity index into the
			// addresses matching it right now. Programmed exactly like an
			// ipBlock, and recorded as selector derived so the set can be
			// corrected as pods come and go.
			sel, warns := ctx.resolveSelectorPeer(
				fmt.Sprintf("egressRules[%d] peer", idx), peer, ports)
			warnings = append(warnings, warns...)
			selected = append(selected, sel...)
		}
	}

	dests = make([]adaptive.Destination, 0, len(ips)*len(ports)+len(selected))
	for _, ip := range ips {
		for _, p := range ports {
			dests = append(dests, adaptive.Destination{IP: ip, Port: p})
		}
	}
	dests = append(dests, selected...)
	if len(dests) == 0 {
		return nil, nil, warnings
	}
	return dests, selected, warnings
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
//
// field is the spec path being translated, so the warning names the thing the
// author wrote. An egress rule and a declared destination reach the same
// allow-set through the same key derivation and therefore have to obey the same
// rule; only the field name differs, and it is the field name that makes a
// warning actionable.
func hostIPFromCIDR(field, cidr string) (net.IP, string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, fmt.Sprintf("%s is empty", field)
	}
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil {
			return ip, ""
		}
		return nil, fmt.Sprintf("%s %q is not an IP address", field, cidr)
	}
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Sprintf("%s %q is invalid: %v", field, cidr, err)
	}
	ones, bits := network.Mask.Size()
	if ones != bits {
		return nil, fmt.Sprintf(
			"%s %q covers %d addresses; the kernel allow-set is a "+
				"hash of the exact destination and cannot express a prefix, so only /%d hosts "+
				"are seeded", field, cidr, 1<<(bits-ones), bits)
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
				"exceptions[%d] expired at %s and is not applied", i, ex.ExpiresAt.Format(time.RFC3339)))
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
			o.AllowedWriteFiles = append(o.AllowedWriteFiles, patterns...)
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

// ---------------------------------------------------------------------------
// Declared expected behavior
// ---------------------------------------------------------------------------

// declField is the spec path every declaration warning is rooted at. Warnings
// are read by somebody holding the YAML they wrote, so they have to name the
// field rather than describe it.
const declField = "learningConfig.expectedBehavior"

// DeclaredFile is one path a policy declared, with the access mode it declared
// it for. Reads and writes are separate entries in the kernel allow-set, so
// this is not a detail: a declaration of a read does not permit a write.
type DeclaredFile struct {
	Path  string
	Write bool
}

// Declaration is the exact set of operations a policy asserted its workload
// performs, after everything unrepresentable has been refused.
//
// It is returned alongside the Decision rather than folded into it because the
// two answer different questions. The Decision says what the kernel should
// permit; the Declaration says which of those entries are there because
// somebody asserted them rather than because the workload was observed doing
// them. An operator reading a profile has to be able to tell the difference,
// and once the entries are in the allow-set they are indistinguishable - the
// kernel stores a hash, not a provenance.
type Declaration struct {
	Files        []DeclaredFile
	Destinations []adaptive.Destination
	Executables  []string

	// Capabilities are numbers rather than the names the policy wrote, so the
	// spelling reported back is always ebpf.CapabilityName's and therefore
	// always the spelling the learned list uses. A policy may write
	// "CAP_SYS_TIME" or "sys_time"; a profile must not show both.
	Capabilities []uint32
}

// Empty reports whether nothing was declared.
func (d Declaration) Empty() bool {
	return len(d.Files) == 0 && len(d.Destinations) == 0 &&
		len(d.Executables) == 0 && len(d.Capabilities) == 0
}

// mergeInto adds the declared entries to the overrides the learned baseline is
// corrected with.
//
// Only the Allowed lists are touched, and that is the guarantee the whole
// feature rests on: a declaration is additive, so it can add a rare operation
// to the allow-set but can never remove something the workload was actually
// observed doing. An operator who wants to take something away has
// filePolicy.deniedPaths and the deny lists, where removal is what they asked
// for and is visible as such.
//
// A declared write grants the read too, which is what
// filePolicy.writeAllowedPaths already does: a workload that writes a file
// opens it, and granting the write alone would deny the open that precedes it.
func (d Declaration) mergeInto(o *adaptive.Overrides) {
	for _, f := range d.Files {
		o.AllowedFiles = append(o.AllowedFiles, f.Path)
		if f.Write {
			o.AllowedWriteFiles = append(o.AllowedWriteFiles, f.Path)
		}
	}
	o.AllowedExecs = append(o.AllowedExecs, d.Executables...)
	o.AllowedCapabilities = append(o.AllowedCapabilities, d.Capabilities...)
	o.AllowedDestinations = append(o.AllowedDestinations, d.Destinations...)
}

// ReportInto writes the declaration into the profile status fields that report
// it, replacing whatever was there so a re-sync of an unchanged policy writes
// an unchanged status.
//
// This exists so the entries the agent seeds into the kernel and the entries it
// reports as declared come from one place. Two renderings of the same
// declaration would eventually disagree, and the failure mode of that is a
// profile that says a path was declared when the allow-set entry was actually
// refused, which is worse than reporting nothing.
//
// Every list is sorted, matching how the learned lists are written, so a status
// update is driven by the declaration changing rather than by map iteration
// order.
func (d Declaration) ReportInto(status *policyv1beta1.ContainerProfileStatus) {
	if status == nil {
		return
	}
	status.DeclaredFiles = nil
	status.DeclaredNetworkDestinations = nil
	status.DeclaredExecutables = nil
	status.DeclaredCapabilities = nil

	if len(d.Files) > 0 {
		files := make([]string, 0, len(d.Files))
		for _, f := range d.Files {
			// The write marker is not decoration. A declared write is a much
			// larger assertion than a declared read, and a status that renders
			// them identically hides that from the person auditing it.
			if f.Write {
				files = append(files, f.Path+" (write)")
				continue
			}
			files = append(files, f.Path)
		}
		sort.Strings(files)
		status.DeclaredFiles = files
	}
	if len(d.Destinations) > 0 {
		dests := make([]string, 0, len(d.Destinations))
		for _, dest := range d.Destinations {
			// net.JoinHostPort, so an IPv6 destination reads as [::1]:443 the
			// way the learned list writes it rather than as an ambiguous
			// ::1:443.
			dests = append(dests, net.JoinHostPort(dest.IP.String(), strconv.Itoa(int(dest.Port))))
		}
		sort.Strings(dests)
		status.DeclaredNetworkDestinations = dests
	}
	if len(d.Executables) > 0 {
		execs := append([]string(nil), d.Executables...)
		sort.Strings(execs)
		status.DeclaredExecutables = execs
	}
	if len(d.Capabilities) > 0 {
		caps := make([]string, 0, len(d.Capabilities))
		for _, c := range d.Capabilities {
			// Without the CAP_ prefix, which is the spelling a pod spec uses in
			// securityContext.capabilities and the one learnedCapabilities
			// reports, so the two lists can be compared without translating.
			caps = append(caps, strings.TrimPrefix(ebpf.CapabilityName(c), "CAP_"))
		}
		sort.Strings(caps)
		status.DeclaredCapabilities = caps
	}
}

// TranslateSpec translates a v1beta1 spec, which is the hub version and the one
// that can carry declared expected behavior.
//
// The spec is converted down to v1alpha1 and handed to Translate rather than
// translated by a second copy of the same logic. Everything but the declaration
// has an exact v1alpha1 counterpart, and two translators for one spec would
// drift - a rule honored in one version and dropped in the other is precisely
// the class of bug this package was extracted to make testable.
//
// The declaration is read from the v1beta1 spec directly, because it is the one
// thing the down-conversion cannot carry.
func TranslateSpec(name string, spec policyv1beta1.PahlevanPolicySpec, now time.Time) (adaptive.Decision, Declaration, []string) {
	return TranslateSpecIn(name, spec, now, Context{})
}

// TranslateSpecIn is TranslateSpec with the cluster state a selector peer
// needs to be expanded into addresses.
func TranslateSpecIn(
	name string,
	spec policyv1beta1.PahlevanPolicySpec,
	now time.Time,
	ctx Context,
) (adaptive.Decision, Declaration, []string) {
	var spoke policyv1alpha1.PahlevanPolicy
	if err := spoke.ConvertFrom(&policyv1beta1.PahlevanPolicy{Spec: spec}); err != nil {
		// Unreachable today: the conversion is field-by-field assignment and
		// returns nil. Reported rather than ignored because a policy that
		// silently translated to an empty decision would look like a policy
		// governing nothing, which is indistinguishable from mode: "Off".
		return adaptive.Decision{PolicyName: name}, Declaration{},
			[]string{fmt.Sprintf("policy could not be translated: %v", err)}
	}
	d, warnings := TranslateIn(name, spoke.Spec, now, ctx)

	// An Off policy governs nothing, so there is nothing to declare into. This
	// mirrors Translate, which stops for the same reason.
	if d.Mode == adaptive.ModeOff {
		return d, Declaration{}, warnings
	}

	decl, declWarnings := declare(spec.LearningConfig.ExpectedBehavior)
	warnings = append(warnings, declWarnings...)

	// Recorded before the merge: Translate has already warned if the spec's own
	// allow and deny lists are inert in this mode, and saying it twice for one
	// policy trains the reader to skim the warnings.
	quiet := d.Overrides.Empty()
	decl.mergeInto(&d.Overrides)
	if quiet && !decl.Empty() && d.Mode != adaptive.ModeBlocking {
		warnings = append(warnings,
			declField+" is recorded but has no effect in "+string(d.Mode)+
				" mode; declarations are seeded into the allow-set when the container "+
				"starts enforcing")
	}
	return d, decl, warnings
}

// declare turns a declaration into the entries that can be seeded exactly,
// refusing everything else.
//
// The refusals are the point. A declaration exists because the learning window
// did not observe an operation, so nothing will ever prove the entry wrong: if
// a declared path is silently widened, or written in a form the kernel can
// never match, the operator finds out the same way they would have without the
// declaration at all - when the nightly job is denied. Refusing loudly at
// translation is the only moment where the mistake is still cheap.
func declare(eb *policyv1beta1.ExpectedBehavior) (Declaration, []string) {
	if eb == nil {
		return Declaration{}, nil
	}
	if len(eb.Files) == 0 && len(eb.NetworkDestinations) == 0 &&
		len(eb.Executables) == 0 && len(eb.Capabilities) == 0 {
		// The CRD refuses this with minProperties, so reaching here means an
		// object stored before that validation existed, or a cluster whose CRD
		// has not been upgraded. Silence would let an operator believe a rare
		// operation was covered by a block that says nothing.
		return Declaration{}, []string{declField +
			" declares nothing; remove it or name the operations the workload performs"}
	}

	var d Declaration
	var warnings []string

	seenFiles := map[DeclaredFile]struct{}{}
	for i, f := range eb.Files {
		path, warn := declaredPath(fmt.Sprintf("%s.files[%d].path", declField, i), f.Path)
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		entry := DeclaredFile{Path: path, Write: f.Write}
		if _, dup := seenFiles[entry]; dup {
			continue
		}
		seenFiles[entry] = struct{}{}
		d.Files = append(d.Files, entry)
	}

	seenExecs := map[string]struct{}{}
	for i, e := range eb.Executables {
		path, warn := declaredPath(fmt.Sprintf("%s.executables[%d]", declField, i), e)
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		if _, dup := seenExecs[path]; dup {
			continue
		}
		seenExecs[path] = struct{}{}
		d.Executables = append(d.Executables, path)
	}

	seenCaps := map[uint32]struct{}{}
	for i, c := range eb.Capabilities {
		field := fmt.Sprintf("%s.capabilities[%d]", declField, i)
		name := strings.TrimSpace(c)
		if name == "" {
			warnings = append(warnings, field+" is empty")
			continue
		}
		num, ok := ebpf.CapabilityNumber(name)
		if !ok {
			// The API server cannot check this: the set of capability names is
			// the kernel's, not the schema's. A typo would otherwise be a
			// declaration that seeds an allow-set entry for nothing.
			warnings = append(warnings, fmt.Sprintf(
				"%s %q is not a Linux capability; write the name with or without the "+
					"CAP_ prefix, as in CAP_NET_BIND_SERVICE or net_bind_service", field, name))
			continue
		}
		if _, dup := seenCaps[num]; dup {
			continue
		}
		seenCaps[num] = struct{}{}
		d.Capabilities = append(d.Capabilities, num)
	}

	seenDests := map[string]struct{}{}
	for i, dest := range eb.NetworkDestinations {
		field := fmt.Sprintf("%s.networkDestinations[%d]", declField, i)
		if warn := declaredProtocol(field, dest.Protocol); warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		if dest.Port < 1 || dest.Port > 65535 {
			warnings = append(warnings, fmt.Sprintf(
				"%s.port %d is outside 1-65535; a port is 16 bits on the wire and the "+
					"allow-set key holds exactly those bits", field, dest.Port))
			continue
		}
		ip, warn := hostIPFromCIDR(field+".cidr", dest.CIDR)
		if warn != "" {
			warnings = append(warnings, warn)
			continue
		}
		key := ip.String() + "/" + strconv.Itoa(int(dest.Port))
		if _, dup := seenDests[key]; dup {
			continue
		}
		seenDests[key] = struct{}{}
		d.Destinations = append(d.Destinations, adaptive.Destination{IP: ip, Port: uint16(dest.Port)})
	}

	return d, warnings
}

// declaredPath validates one declared path against what the kernel can match.
//
// The CRD already enforces absoluteness and non-emptiness, so the first two
// checks cover objects stored before those markers existed. The wildcard check
// has no CRD equivalent and is the one that matters most: filePolicy warns
// about a glob and applies it literally, which is tolerable for a rule that
// also names real paths, but a declaration that matches nothing is the entire
// statement. It is refused instead.
func declaredPath(field, raw string) (string, string) {
	path := strings.TrimSpace(raw)
	switch {
	case path == "":
		return "", field + " is empty; a declaration has to name the operation it declares"
	case !strings.HasPrefix(path, "/"):
		return "", fmt.Sprintf(
			"%s %q is not absolute: enforcement keys on the path the kernel resolves, "+
				"so a relative path can never match", field, path)
	case strings.ContainsAny(path, "*?["):
		return "", fmt.Sprintf(
			"%s %q is a wildcard, which the allow-set cannot express: it is keyed on an "+
				"exact path hash, so this would be seeded literally and never match. "+
				"Name each path the workload uses", field, path)
	}
	return path, ""
}

// declaredProtocol refuses the transports an allow-set entry cannot be written
// for.
//
// UDP is the honest failure here. The kernel key folds the protocol in, but the
// Decision a declaration is merged into carries only (address, port) and is
// seeded over TCP, so a declared UDP destination would be written as a TCP
// entry: granting a protocol nobody declared, and not granting the one that
// was. Widening it that way would be the exact bargain this field exists to
// avoid.
func declaredProtocol(field string, p policyv1beta1.TransportProtocol) string {
	switch p {
	case "", policyv1beta1.TransportProtocolTCP:
		return ""
	case policyv1beta1.TransportProtocolUDP:
		return field + ".protocol is UDP, which cannot be declared: the allow-set entry a " +
			"declaration is seeded as carries only the address and port and is written for " +
			"TCP, so this would permit TCP to a destination nobody declared and still deny " +
			"the UDP that was"
	default:
		return fmt.Sprintf("%s.protocol %q is not TCP or UDP", field, p)
	}
}
