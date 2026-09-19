package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	v1beta1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1beta1"
)

// This file is the spoke half of the hub-and-spoke conversion between
// v1alpha1 and v1beta1. v1beta1 is the hub, so it knows nothing about this
// version; everything that has to remember what v1alpha1 got wrong lives here.
//
// The conversions are written out field by field rather than reflected or
// JSON-round-tripped. That is deliberate and it is the whole point: a
// reflective converter matches fields by name and silently ignores the ones
// that do not match, which is exactly the failure an API graduation must not
// have. Written out, a field that is not converted is a field that is visibly
// not mentioned, and TestEveryV1Alpha1FieldIsCarriedOrDocumented fails on it.

// IntentionallyDropped names every v1alpha1 field that v1beta1 does not carry,
// with the reason. Anything not listed here must round-trip unchanged.
//
// The key is the field's JSON path in v1alpha1, with "[]" marking a list, and
// an entry covers the field and everything underneath it. The value is why the
// field is gone, in terms of what it did rather than what it was called. A test
// walks the v1alpha1 types and fails if a field is absent from v1beta1 and
// absent from this map, so this cannot fall out of date by being forgotten.
var IntentionallyDropped = map[string]string{
	"spec.enforcementConfig.exceptions[].temporary": "" +
		"an exception is temporary exactly when it has an expiresAt. Carrying " +
		"both let them disagree, and enforcement applied an expiry only when " +
		"both were set - so an expiresAt written on its own was accepted, " +
		"displayed, and never acted on. Converting back sets temporary from " +
		"whether expiresAt is present, which is what the pair meant whenever " +
		"it was consistent.",

	"spec.networkPolicy.egressRules[].peers[].namespaceSelector.namespaceSelector": "" +
		"a namespace selector nested inside a namespace selector. v1alpha1 used " +
		"one selector type everywhere, so this was legal to write and read by " +
		"nothing.",
	"spec.networkPolicy.egressRules[].peers[].podSelector.namespaceSelector": "" +
		"a peer's pod selector is already scoped by the peer's own " +
		"namespaceSelector. This second one was legal to write and read by " +
		"nothing.",
	"spec.networkPolicy.ingressRules[].peers[].namespaceSelector.namespaceSelector": "" +
		"same as the egress case: a namespace selector inside a namespace " +
		"selector, read by nothing.",
	"spec.networkPolicy.ingressRules[].peers[].podSelector.namespaceSelector": "" +
		"same as the egress case: a second namespace selector on a pod " +
		"selector, read by nothing.",

	"status.enforcementStatus.blockedSyscalls": "" +
		"always zero by construction. Syscalls are confined by the generated " +
		"seccomp profile, whose denials the kernel does not report back to the " +
		"agent, and the BPF syscall program is observation only. Converting " +
		"back leaves it at zero, which is the only value it has ever held.",
}

// IntentionallyAdded names every v1beta1 field with no v1alpha1 counterpart.
//
// A test keeps it short unless somebody writes down a reason. A graduation is
// not the place to introduce a field nothing sets: docs/api-reference.md
// already has to carry a list of fields the API accepts and nothing acts on,
// and the way that list stays short is by refusing to add to it here.
//
// An entry covers the field and everything underneath it, the way
// IntentionallyDropped does, so declaring a block once does not mean listing
// every leaf inside it.
//
// Every entry below is one-way lossy and has to be, because v1alpha1 has
// nowhere to put it: a v1beta1 object read as v1alpha1 loses these fields, and
// a client that reads v1alpha1 and writes it back erases them from the stored
// object. That is the price of the field existing in one version only. It is
// bounded by v1beta1 being the storage version and v1alpha1 being deprecated,
// and it is why docs/policy-reference.md tells operators to write declarations
// against v1beta1.
var IntentionallyAdded = map[string]string{
	"spec.learningConfig.expectedBehavior": "" +
		"declared expected behavior, and the only field in the graduation that " +
		"is an addition rather than a correction. Learning is a window of " +
		"wall-clock time, so an operation the workload performs once a day - a " +
		"nightly batch, a weekly certificate renewal, a log rotation - is " +
		"absent from the learned baseline and is refused under Blocking. From " +
		"the kernel's side it is indistinguishable from an attack: the only " +
		"evidence against it is that the workload has never done it before. " +
		"v1alpha1 had no way to state the difference in advance, and the " +
		"mitigations were guessing a longer duration or letting self-healing " +
		"roll enforcement back after the job had already been denied.",

	"status.declaredFiles": "" +
		"the file paths permitted because a policy declared them rather than " +
		"because this container was observed opening them. Folding them into " +
		"learnedFiles would make an assertion indistinguishable from evidence, " +
		"which is the one thing a learned baseline is for.",
	"status.declaredNetworkDestinations": "" +
		"the egress destinations permitted by declaration rather than by " +
		"observation. Kept out of learnedNetworkDestinations so an incident " +
		"responder asking how a destination came to be permitted gets an answer.",
	"status.declaredExecutables": "" +
		"the binaries permitted by declaration rather than by observation. " +
		"Kept out of learnedExecutables for the same reason: a declared exec is " +
		"the highest-value entry in a profile to be able to audit.",
	"status.declaredCapabilities": "" +
		"the capabilities permitted by declaration rather than by observation. " +
		"Kept out of learnedCapabilities so admission comparing a pod's " +
		"requested privilege against what the workload has actually needed is " +
		"not comparing it against what somebody asserted it would need.",
}

// ---------------------------------------------------------------------------
// PahlevanPolicy
// ---------------------------------------------------------------------------

var (
	_ conversion.Convertible = &PahlevanPolicy{}
	_ conversion.Convertible = &ContainerProfile{}
	_ conversion.Convertible = &AttackSurface{}
)

// ConvertTo converts this PahlevanPolicy to the hub version.
func (src *PahlevanPolicy) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.PahlevanPolicy)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec = toBetaPolicySpec(src.Spec)
	dst.Status = toBetaPolicyStatus(src.Status)
	return nil
}

// ConvertFrom converts the hub version into this PahlevanPolicy.
func (dst *PahlevanPolicy) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.PahlevanPolicy)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec = fromBetaPolicySpec(src.Spec)
	dst.Status = fromBetaPolicyStatus(src.Status)
	return nil
}

func toBetaPolicySpec(in PahlevanPolicySpec) v1beta1.PahlevanPolicySpec {
	return v1beta1.PahlevanPolicySpec{
		Selector:            toBetaWorkloadSelector(in.Selector),
		LearningConfig:      toBetaLearningConfig(in.LearningConfig),
		EnforcementConfig:   toBetaEnforcementConfig(in.EnforcementConfig),
		SyscallPolicy:       toBetaSyscallPolicy(in.SyscallPolicy),
		NetworkPolicy:       toBetaNetworkPolicy(in.NetworkPolicy),
		FilePolicy:          toBetaFilePolicy(in.FilePolicy),
		SelfHealing:         toBetaSelfHealing(in.SelfHealing),
		ObservabilityConfig: toBetaObservability(in.ObservabilityConfig),
	}
}

func fromBetaPolicySpec(in v1beta1.PahlevanPolicySpec) PahlevanPolicySpec {
	return PahlevanPolicySpec{
		Selector:            fromBetaWorkloadSelector(in.Selector),
		LearningConfig:      fromBetaLearningConfig(in.LearningConfig),
		EnforcementConfig:   fromBetaEnforcementConfig(in.EnforcementConfig),
		SyscallPolicy:       fromBetaSyscallPolicy(in.SyscallPolicy),
		NetworkPolicy:       fromBetaNetworkPolicy(in.NetworkPolicy),
		FilePolicy:          fromBetaFilePolicy(in.FilePolicy),
		SelfHealing:         fromBetaSelfHealing(in.SelfHealing),
		ObservabilityConfig: fromBetaObservability(in.ObservabilityConfig),
	}
}

// ---------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------

func toBetaWorkloadSelector(in LabelSelector) v1beta1.WorkloadSelector {
	return v1beta1.WorkloadSelector{
		MatchLabels:       copyStringMap(in.MatchLabels),
		MatchExpressions:  toBetaRequirements(in.MatchExpressions),
		NamespaceSelector: toBetaNamespaceSelector(in.NamespaceSelector),
	}
}

func fromBetaWorkloadSelector(in v1beta1.WorkloadSelector) LabelSelector {
	return LabelSelector{
		MatchLabels:       copyStringMap(in.MatchLabels),
		MatchExpressions:  fromBetaRequirements(in.MatchExpressions),
		NamespaceSelector: fromBetaNamespaceSelector(in.NamespaceSelector),
	}
}

// toBetaLabelSelector converts a selector used in a network peer position.
//
// in.NamespaceSelector is dropped here, and that is the only lossy step in the
// spec conversion: see IntentionallyDropped for the two paths it covers.
func toBetaLabelSelector(in *LabelSelector) *v1beta1.LabelSelector {
	if in == nil {
		return nil
	}
	return &v1beta1.LabelSelector{
		MatchLabels:      copyStringMap(in.MatchLabels),
		MatchExpressions: toBetaRequirements(in.MatchExpressions),
	}
}

func fromBetaLabelSelector(in *v1beta1.LabelSelector) *LabelSelector {
	if in == nil {
		return nil
	}
	return &LabelSelector{
		MatchLabels:      copyStringMap(in.MatchLabels),
		MatchExpressions: fromBetaRequirements(in.MatchExpressions),
	}
}

func toBetaNamespaceSelector(in *NamespaceSelector) *v1beta1.NamespaceSelector {
	if in == nil {
		return nil
	}
	return &v1beta1.NamespaceSelector{
		MatchLabels:      copyStringMap(in.MatchLabels),
		MatchExpressions: toBetaRequirements(in.MatchExpressions),
	}
}

func fromBetaNamespaceSelector(in *v1beta1.NamespaceSelector) *NamespaceSelector {
	if in == nil {
		return nil
	}
	return &NamespaceSelector{
		MatchLabels:      copyStringMap(in.MatchLabels),
		MatchExpressions: fromBetaRequirements(in.MatchExpressions),
	}
}

func toBetaRequirements(in []LabelSelectorRequirement) []v1beta1.LabelSelectorRequirement {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.LabelSelectorRequirement, len(in))
	for i, r := range in {
		out[i] = v1beta1.LabelSelectorRequirement{
			Key:      r.Key,
			Operator: v1beta1.LabelSelectorOperator(r.Operator),
			Values:   copyStrings(r.Values),
		}
	}
	return out
}

func fromBetaRequirements(in []v1beta1.LabelSelectorRequirement) []LabelSelectorRequirement {
	if in == nil {
		return nil
	}
	out := make([]LabelSelectorRequirement, len(in))
	for i, r := range in {
		out[i] = LabelSelectorRequirement{
			Key:      r.Key,
			Operator: LabelSelectorOperator(r.Operator),
			Values:   copyStrings(r.Values),
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Learning and enforcement
// ---------------------------------------------------------------------------

// toBetaLearningConfig leaves ExpectedBehavior nil: v1alpha1 has no way to
// declare behavior, so there is nothing to carry up. An operator who wants
// declarations writes the policy as v1beta1.
func toBetaLearningConfig(in LearningConfig) v1beta1.LearningConfig {
	return v1beta1.LearningConfig{
		Duration:       copyDuration(in.Duration),
		WindowSize:     copyDuration(in.WindowSize),
		MinSamples:     copyInt32(in.MinSamples),
		AutoTransition: in.AutoTransition,
		LifecycleAware: in.LifecycleAware,
	}
}

// fromBetaLearningConfig drops ExpectedBehavior, which is the one place in the
// spec conversion where reading a stored object as v1alpha1 loses something a
// user wrote. There is no v1alpha1 field that means it and no honest place to
// put it, so it is listed in IntentionallyAdded rather than approximated into
// an exception, which would be a permanent hole where a declaration was meant.
func fromBetaLearningConfig(in v1beta1.LearningConfig) LearningConfig {
	return LearningConfig{
		Duration:       copyDuration(in.Duration),
		WindowSize:     copyDuration(in.WindowSize),
		MinSamples:     copyInt32(in.MinSamples),
		AutoTransition: in.AutoTransition,
		LifecycleAware: in.LifecycleAware,
	}
}

func toBetaEnforcementConfig(in EnforcementConfig) v1beta1.EnforcementConfig {
	return v1beta1.EnforcementConfig{
		Mode:         v1beta1.EnforcementMode(in.Mode),
		GracePeriod:  copyDuration(in.GracePeriod),
		AlertOnly:    in.AlertOnly,
		BlockUnknown: copyBool(in.BlockUnknown),
		Exceptions:   toBetaExceptions(in.Exceptions),
	}
}

func fromBetaEnforcementConfig(in v1beta1.EnforcementConfig) EnforcementConfig {
	return EnforcementConfig{
		Mode:         EnforcementMode(in.Mode),
		GracePeriod:  copyDuration(in.GracePeriod),
		AlertOnly:    in.AlertOnly,
		BlockUnknown: copyBool(in.BlockUnknown),
		Exceptions:   fromBetaExceptions(in.Exceptions),
	}
}

func toBetaExceptions(in []EnforcementException) []v1beta1.EnforcementException {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.EnforcementException, len(in))
	for i, e := range in {
		// Temporary is not carried: see IntentionallyDropped. An exception
		// marked temporary with no expiry never expired anyway, so nothing
		// that was being enforced is lost by forgetting the flag.
		out[i] = v1beta1.EnforcementException{
			Type:      v1beta1.ExceptionType(e.Type),
			Patterns:  copyStrings(e.Patterns),
			Reason:    e.Reason,
			ExpiresAt: copyTime(e.ExpiresAt),
		}
	}
	return out
}

func fromBetaExceptions(in []v1beta1.EnforcementException) []EnforcementException {
	if in == nil {
		return nil
	}
	out := make([]EnforcementException, len(in))
	for i, e := range in {
		out[i] = EnforcementException{
			Type:     ExceptionType(e.Type),
			Patterns: copyStrings(e.Patterns),
			Reason:   e.Reason,
			// Reconstructed rather than remembered: in v1beta1 an expiry is
			// what makes an exception temporary, so this is the pair's meaning
			// whenever the two agreed.
			Temporary: e.ExpiresAt != nil,
			ExpiresAt: copyTime(e.ExpiresAt),
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Syscall, network and file policy
// ---------------------------------------------------------------------------

func toBetaSyscallPolicy(in *SyscallPolicy) *v1beta1.SyscallPolicy {
	if in == nil {
		return nil
	}
	return &v1beta1.SyscallPolicy{
		AllowedSyscalls:  copyStrings(in.AllowedSyscalls),
		DeniedSyscalls:   copyStrings(in.DeniedSyscalls),
		DefaultAction:    v1beta1.PolicyAction(in.DefaultAction),
		CapabilityFilter: copyStrings(in.CapabilityFilter),
		ProcessFilter:    toBetaProcessFilter(in.ProcessFilter),
	}
}

func fromBetaSyscallPolicy(in *v1beta1.SyscallPolicy) *SyscallPolicy {
	if in == nil {
		return nil
	}
	return &SyscallPolicy{
		AllowedSyscalls:  copyStrings(in.AllowedSyscalls),
		DeniedSyscalls:   copyStrings(in.DeniedSyscalls),
		DefaultAction:    PolicyAction(in.DefaultAction),
		CapabilityFilter: copyStrings(in.CapabilityFilter),
		ProcessFilter:    fromBetaProcessFilter(in.ProcessFilter),
	}
}

func toBetaProcessFilter(in *ProcessFilter) *v1beta1.ProcessFilter {
	if in == nil {
		return nil
	}
	return &v1beta1.ProcessFilter{
		Commands:        copyStrings(in.Commands),
		Users:           copyStrings(in.Users),
		Groups:          copyStrings(in.Groups),
		ParentProcesses: copyStrings(in.ParentProcesses),
	}
}

func fromBetaProcessFilter(in *v1beta1.ProcessFilter) *ProcessFilter {
	if in == nil {
		return nil
	}
	return &ProcessFilter{
		Commands:        copyStrings(in.Commands),
		Users:           copyStrings(in.Users),
		Groups:          copyStrings(in.Groups),
		ParentProcesses: copyStrings(in.ParentProcesses),
	}
}

func toBetaNetworkPolicy(in *NetworkPolicy) *v1beta1.NetworkPolicy {
	if in == nil {
		return nil
	}
	return &v1beta1.NetworkPolicy{
		EgressRules:   toBetaNetworkRules(in.EgressRules),
		IngressRules:  toBetaNetworkRules(in.IngressRules),
		DefaultAction: v1beta1.PolicyAction(in.DefaultAction),
		AllowLoopback: in.AllowLoopback,
		AllowDNS:      in.AllowDNS,
	}
}

func fromBetaNetworkPolicy(in *v1beta1.NetworkPolicy) *NetworkPolicy {
	if in == nil {
		return nil
	}
	return &NetworkPolicy{
		EgressRules:   fromBetaNetworkRules(in.EgressRules),
		IngressRules:  fromBetaNetworkRules(in.IngressRules),
		DefaultAction: PolicyAction(in.DefaultAction),
		AllowLoopback: in.AllowLoopback,
		AllowDNS:      in.AllowDNS,
	}
}

func toBetaNetworkRules(in []NetworkRule) []v1beta1.NetworkRule {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.NetworkRule, len(in))
	for i, r := range in {
		out[i] = v1beta1.NetworkRule{
			Protocols: copyStrings(r.Protocols),
			Ports:     toBetaNetworkPorts(r.Ports),
			Peers:     toBetaNetworkPeers(r.Peers),
			Action:    v1beta1.PolicyAction(r.Action),
		}
	}
	return out
}

func fromBetaNetworkRules(in []v1beta1.NetworkRule) []NetworkRule {
	if in == nil {
		return nil
	}
	out := make([]NetworkRule, len(in))
	for i, r := range in {
		out[i] = NetworkRule{
			Protocols: copyStrings(r.Protocols),
			Ports:     fromBetaNetworkPorts(r.Ports),
			Peers:     fromBetaNetworkPeers(r.Peers),
			Action:    PolicyAction(r.Action),
		}
	}
	return out
}

func toBetaNetworkPorts(in []NetworkPort) []v1beta1.NetworkPort {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.NetworkPort, len(in))
	for i, p := range in {
		out[i] = v1beta1.NetworkPort{
			Port:      copyInt32(p.Port),
			StartPort: copyInt32(p.StartPort),
			EndPort:   copyInt32(p.EndPort),
			Protocol:  p.Protocol,
		}
	}
	return out
}

func fromBetaNetworkPorts(in []v1beta1.NetworkPort) []NetworkPort {
	if in == nil {
		return nil
	}
	out := make([]NetworkPort, len(in))
	for i, p := range in {
		out[i] = NetworkPort{
			Port:      copyInt32(p.Port),
			StartPort: copyInt32(p.StartPort),
			EndPort:   copyInt32(p.EndPort),
			Protocol:  p.Protocol,
		}
	}
	return out
}

func toBetaNetworkPeers(in []NetworkPeer) []v1beta1.NetworkPeer {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.NetworkPeer, len(in))
	for i, p := range in {
		out[i] = v1beta1.NetworkPeer{
			IPBlock:           toBetaIPBlock(p.IPBlock),
			NamespaceSelector: toBetaLabelSelector(p.NamespaceSelector),
			PodSelector:       toBetaLabelSelector(p.PodSelector),
		}
	}
	return out
}

func fromBetaNetworkPeers(in []v1beta1.NetworkPeer) []NetworkPeer {
	if in == nil {
		return nil
	}
	out := make([]NetworkPeer, len(in))
	for i, p := range in {
		out[i] = NetworkPeer{
			IPBlock:           fromBetaIPBlock(p.IPBlock),
			NamespaceSelector: fromBetaLabelSelector(p.NamespaceSelector),
			PodSelector:       fromBetaLabelSelector(p.PodSelector),
		}
	}
	return out
}

func toBetaIPBlock(in *IPBlock) *v1beta1.IPBlock {
	if in == nil {
		return nil
	}
	return &v1beta1.IPBlock{CIDR: in.CIDR, Except: copyStrings(in.Except)}
}

func fromBetaIPBlock(in *v1beta1.IPBlock) *IPBlock {
	if in == nil {
		return nil
	}
	return &IPBlock{CIDR: in.CIDR, Except: copyStrings(in.Except)}
}

func toBetaFilePolicy(in *FilePolicy) *v1beta1.FilePolicy {
	if in == nil {
		return nil
	}
	return &v1beta1.FilePolicy{
		AllowedPaths:      copyStrings(in.AllowedPaths),
		DeniedPaths:       copyStrings(in.DeniedPaths),
		DefaultAction:     v1beta1.PolicyAction(in.DefaultAction),
		ReadOnlyPaths:     copyStrings(in.ReadOnlyPaths),
		WriteAllowedPaths: copyStrings(in.WriteAllowedPaths),
		ExecutableFilter:  toBetaExecutableFilter(in.ExecutableFilter),
	}
}

func fromBetaFilePolicy(in *v1beta1.FilePolicy) *FilePolicy {
	if in == nil {
		return nil
	}
	return &FilePolicy{
		AllowedPaths:      copyStrings(in.AllowedPaths),
		DeniedPaths:       copyStrings(in.DeniedPaths),
		DefaultAction:     PolicyAction(in.DefaultAction),
		ReadOnlyPaths:     copyStrings(in.ReadOnlyPaths),
		WriteAllowedPaths: copyStrings(in.WriteAllowedPaths),
		ExecutableFilter:  fromBetaExecutableFilter(in.ExecutableFilter),
	}
}

func toBetaExecutableFilter(in *ExecutableFilter) *v1beta1.ExecutableFilter {
	if in == nil {
		return nil
	}
	return &v1beta1.ExecutableFilter{
		AllowedExecutables: copyStrings(in.AllowedExecutables),
		DeniedExecutables:  copyStrings(in.DeniedExecutables),
		RequireSignature:   in.RequireSignature,
	}
}

func fromBetaExecutableFilter(in *v1beta1.ExecutableFilter) *ExecutableFilter {
	if in == nil {
		return nil
	}
	return &ExecutableFilter{
		AllowedExecutables: copyStrings(in.AllowedExecutables),
		DeniedExecutables:  copyStrings(in.DeniedExecutables),
		RequireSignature:   in.RequireSignature,
	}
}

// ---------------------------------------------------------------------------
// Self-healing and observability
// ---------------------------------------------------------------------------

func toBetaSelfHealing(in SelfHealingConfig) v1beta1.SelfHealingConfig {
	return v1beta1.SelfHealingConfig{
		Enabled:           in.Enabled,
		RollbackThreshold: in.RollbackThreshold,
		RollbackWindow:    copyDuration(in.RollbackWindow),
		RecoveryStrategy:  v1beta1.RecoveryStrategy(in.RecoveryStrategy),
	}
}

func fromBetaSelfHealing(in v1beta1.SelfHealingConfig) SelfHealingConfig {
	return SelfHealingConfig{
		Enabled:           in.Enabled,
		RollbackThreshold: in.RollbackThreshold,
		RollbackWindow:    copyDuration(in.RollbackWindow),
		RecoveryStrategy:  RecoveryStrategy(in.RecoveryStrategy),
	}
}

func toBetaObservability(in ObservabilityConfig) v1beta1.ObservabilityConfig {
	out := v1beta1.ObservabilityConfig{
		Metrics: v1beta1.MetricsConfig{
			Enabled:  in.Metrics.Enabled,
			Interval: copyDuration(in.Metrics.Interval),
		},
		Tracing: v1beta1.TracingConfig{
			Enabled:      in.Tracing.Enabled,
			SamplingRate: copyString(in.Tracing.SamplingRate),
			Exporter: v1beta1.TracingExporter{
				Type:     in.Tracing.Exporter.Type,
				Endpoint: in.Tracing.Exporter.Endpoint,
				Config:   *in.Tracing.Exporter.Config.DeepCopy(),
			},
		},
		Logging: v1beta1.LoggingConfig{
			Level:  in.Logging.Level,
			Format: in.Logging.Format,
		},
		Visualization: v1beta1.VisualizationConfig{
			Enabled:        in.Visualization.Enabled,
			UpdateInterval: copyDuration(in.Visualization.UpdateInterval),
		},
	}
	if in.Metrics.Exporters != nil {
		out.Metrics.Exporters = make([]v1beta1.MetricsExporter, len(in.Metrics.Exporters))
		for i, e := range in.Metrics.Exporters {
			out.Metrics.Exporters[i] = v1beta1.MetricsExporter{
				Type: e.Type, Endpoint: e.Endpoint, Config: *e.Config.DeepCopy(),
			}
		}
	}
	if in.Logging.Outputs != nil {
		out.Logging.Outputs = make([]v1beta1.LogOutput, len(in.Logging.Outputs))
		for i, o := range in.Logging.Outputs {
			out.Logging.Outputs[i] = v1beta1.LogOutput{Type: o.Type, Config: *o.Config.DeepCopy()}
		}
	}
	if in.Visualization.Exporters != nil {
		out.Visualization.Exporters = make([]v1beta1.VisualizationExporter, len(in.Visualization.Exporters))
		for i, e := range in.Visualization.Exporters {
			out.Visualization.Exporters[i] = v1beta1.VisualizationExporter{
				Type: e.Type, Endpoint: e.Endpoint, Config: *e.Config.DeepCopy(),
			}
		}
	}
	return out
}

func fromBetaObservability(in v1beta1.ObservabilityConfig) ObservabilityConfig {
	out := ObservabilityConfig{
		Metrics: MetricsConfig{
			Enabled:  in.Metrics.Enabled,
			Interval: copyDuration(in.Metrics.Interval),
		},
		Tracing: TracingConfig{
			Enabled:      in.Tracing.Enabled,
			SamplingRate: copyString(in.Tracing.SamplingRate),
			Exporter: TracingExporter{
				Type:     in.Tracing.Exporter.Type,
				Endpoint: in.Tracing.Exporter.Endpoint,
				Config:   *in.Tracing.Exporter.Config.DeepCopy(),
			},
		},
		Logging: LoggingConfig{
			Level:  in.Logging.Level,
			Format: in.Logging.Format,
		},
		Visualization: VisualizationConfig{
			Enabled:        in.Visualization.Enabled,
			UpdateInterval: copyDuration(in.Visualization.UpdateInterval),
		},
	}
	if in.Metrics.Exporters != nil {
		out.Metrics.Exporters = make([]MetricsExporter, len(in.Metrics.Exporters))
		for i, e := range in.Metrics.Exporters {
			out.Metrics.Exporters[i] = MetricsExporter{
				Type: e.Type, Endpoint: e.Endpoint, Config: *e.Config.DeepCopy(),
			}
		}
	}
	if in.Logging.Outputs != nil {
		out.Logging.Outputs = make([]LogOutput, len(in.Logging.Outputs))
		for i, o := range in.Logging.Outputs {
			out.Logging.Outputs[i] = LogOutput{Type: o.Type, Config: *o.Config.DeepCopy()}
		}
	}
	if in.Visualization.Exporters != nil {
		out.Visualization.Exporters = make([]VisualizationExporter, len(in.Visualization.Exporters))
		for i, e := range in.Visualization.Exporters {
			out.Visualization.Exporters[i] = VisualizationExporter{
				Type: e.Type, Endpoint: e.Endpoint, Config: *e.Config.DeepCopy(),
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Policy status
// ---------------------------------------------------------------------------

func toBetaPolicyStatus(in PahlevanPolicyStatus) v1beta1.PahlevanPolicyStatus {
	return v1beta1.PahlevanPolicyStatus{
		Phase:             v1beta1.PolicyPhase(in.Phase),
		Conditions:        toBetaConditions(in.Conditions),
		LearningStatus:    toBetaLearningStatus(in.LearningStatus),
		EnforcementStatus: toBetaEnforcementStatus(in.EnforcementStatus),
		AttackSurface:     toBetaAttackSurfaceStatusPtr(in.AttackSurface),
		TargetWorkloads:   toBetaWorkloadRefs(in.TargetWorkloads),
		LastUpdated:       copyTime(in.LastUpdated),
	}
}

func fromBetaPolicyStatus(in v1beta1.PahlevanPolicyStatus) PahlevanPolicyStatus {
	return PahlevanPolicyStatus{
		Phase:             PolicyPhase(in.Phase),
		Conditions:        fromBetaConditions(in.Conditions),
		LearningStatus:    fromBetaLearningStatus(in.LearningStatus),
		EnforcementStatus: fromBetaEnforcementStatus(in.EnforcementStatus),
		AttackSurface:     fromBetaAttackSurfaceStatusPtr(in.AttackSurface),
		TargetWorkloads:   fromBetaWorkloadRefs(in.TargetWorkloads),
		LastUpdated:       copyTime(in.LastUpdated),
	}
}

func toBetaConditions(in []PolicyCondition) []v1beta1.PolicyCondition {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.PolicyCondition, len(in))
	for i, c := range in {
		out[i] = v1beta1.PolicyCondition{
			Type:               v1beta1.PolicyConditionType(c.Type),
			Status:             v1beta1.ConditionStatus(c.Status),
			LastTransitionTime: *c.LastTransitionTime.DeepCopy(),
			Reason:             c.Reason,
			Message:            c.Message,
		}
	}
	return out
}

func fromBetaConditions(in []v1beta1.PolicyCondition) []PolicyCondition {
	if in == nil {
		return nil
	}
	out := make([]PolicyCondition, len(in))
	for i, c := range in {
		out[i] = PolicyCondition{
			Type:               PolicyConditionType(c.Type),
			Status:             ConditionStatus(c.Status),
			LastTransitionTime: *c.LastTransitionTime.DeepCopy(),
			Reason:             c.Reason,
			Message:            c.Message,
		}
	}
	return out
}

func toBetaLearningStatus(in *LearningStatus) *v1beta1.LearningStatus {
	if in == nil {
		return nil
	}
	return &v1beta1.LearningStatus{
		StartTime:           copyTime(in.StartTime),
		EndTime:             copyTime(in.EndTime),
		SamplesCollected:    in.SamplesCollected,
		SyscallsLearned:     in.SyscallsLearned,
		NetworkFlowsLearned: in.NetworkFlowsLearned,
		FilePathsLearned:    in.FilePathsLearned,
		Progress:            copyInt32(in.Progress),
	}
}

func fromBetaLearningStatus(in *v1beta1.LearningStatus) *LearningStatus {
	if in == nil {
		return nil
	}
	return &LearningStatus{
		StartTime:           copyTime(in.StartTime),
		EndTime:             copyTime(in.EndTime),
		SamplesCollected:    in.SamplesCollected,
		SyscallsLearned:     in.SyscallsLearned,
		NetworkFlowsLearned: in.NetworkFlowsLearned,
		FilePathsLearned:    in.FilePathsLearned,
		Progress:            copyInt32(in.Progress),
	}
}

func toBetaEnforcementStatus(in *EnforcementStatus) *v1beta1.EnforcementStatus {
	if in == nil {
		return nil
	}
	// BlockedSyscalls is not carried: see IntentionallyDropped. It is zero in
	// every object the agent has ever written, because nothing in the data
	// plane can increment it.
	return &v1beta1.EnforcementStatus{
		StartTime:                 copyTime(in.StartTime),
		BlockedNetworkConnections: in.BlockedNetworkConnections,
		BlockedFileAccess:         in.BlockedFileAccess,
		BlockedExecs:              in.BlockedExecs,
		BlockedCapabilities:       in.BlockedCapabilities,
		BlockedTotal:              in.BlockedTotal,
		EnforcingContainers:       in.EnforcingContainers,
		TotalContainers:           in.TotalContainers,
		AlertsGenerated:           in.AlertsGenerated,
		RollbackCount:             in.RollbackCount,
	}
}

func fromBetaEnforcementStatus(in *v1beta1.EnforcementStatus) *EnforcementStatus {
	if in == nil {
		return nil
	}
	return &EnforcementStatus{
		StartTime: copyTime(in.StartTime),
		// BlockedSyscalls stays at its zero value, which is the only value the
		// field has ever reported.
		BlockedNetworkConnections: in.BlockedNetworkConnections,
		BlockedFileAccess:         in.BlockedFileAccess,
		BlockedExecs:              in.BlockedExecs,
		BlockedCapabilities:       in.BlockedCapabilities,
		BlockedTotal:              in.BlockedTotal,
		EnforcingContainers:       in.EnforcingContainers,
		TotalContainers:           in.TotalContainers,
		AlertsGenerated:           in.AlertsGenerated,
		RollbackCount:             in.RollbackCount,
	}
}

func toBetaAttackSurfaceStatus(in AttackSurfaceStatus) v1beta1.AttackSurfaceStatus {
	return v1beta1.AttackSurfaceStatus{
		ExposedSyscalls: copyStrings(in.ExposedSyscalls),
		ExposedPorts:    copyInt32s(in.ExposedPorts),
		WritableFiles:   copyStrings(in.WritableFiles),
		Capabilities:    copyStrings(in.Capabilities),
		RiskScore:       copyInt32(in.RiskScore),
		LastAnalysis:    copyTime(in.LastAnalysis),
	}
}

func fromBetaAttackSurfaceStatus(in v1beta1.AttackSurfaceStatus) AttackSurfaceStatus {
	return AttackSurfaceStatus{
		ExposedSyscalls: copyStrings(in.ExposedSyscalls),
		ExposedPorts:    copyInt32s(in.ExposedPorts),
		WritableFiles:   copyStrings(in.WritableFiles),
		Capabilities:    copyStrings(in.Capabilities),
		RiskScore:       copyInt32(in.RiskScore),
		LastAnalysis:    copyTime(in.LastAnalysis),
	}
}

func toBetaAttackSurfaceStatusPtr(in *AttackSurfaceStatus) *v1beta1.AttackSurfaceStatus {
	if in == nil {
		return nil
	}
	out := toBetaAttackSurfaceStatus(*in)
	return &out
}

func fromBetaAttackSurfaceStatusPtr(in *v1beta1.AttackSurfaceStatus) *AttackSurfaceStatus {
	if in == nil {
		return nil
	}
	out := fromBetaAttackSurfaceStatus(*in)
	return &out
}

func toBetaWorkloadRefs(in []WorkloadReference) []v1beta1.WorkloadReference {
	if in == nil {
		return nil
	}
	out := make([]v1beta1.WorkloadReference, len(in))
	for i, w := range in {
		out[i] = v1beta1.WorkloadReference(w)
	}
	return out
}

func fromBetaWorkloadRefs(in []v1beta1.WorkloadReference) []WorkloadReference {
	if in == nil {
		return nil
	}
	out := make([]WorkloadReference, len(in))
	for i, w := range in {
		out[i] = WorkloadReference(w)
	}
	return out
}

func toBetaWorkloadRef(in *WorkloadReference) *v1beta1.WorkloadReference {
	if in == nil {
		return nil
	}
	out := v1beta1.WorkloadReference(*in)
	return &out
}

func fromBetaWorkloadRef(in *v1beta1.WorkloadReference) *WorkloadReference {
	if in == nil {
		return nil
	}
	out := WorkloadReference(*in)
	return &out
}

// ---------------------------------------------------------------------------
// ContainerProfile
// ---------------------------------------------------------------------------

// ConvertTo converts this ContainerProfile to the hub version.
func (src *ContainerProfile) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.ContainerProfile)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec = v1beta1.ContainerProfileSpec{
		PolicyRef:   src.Spec.PolicyRef,
		Workload:    toBetaWorkloadRef(src.Spec.Workload),
		PodName:     src.Spec.PodName,
		Namespace:   src.Spec.Namespace,
		ContainerID: src.Spec.ContainerID,
		CgroupID:    src.Spec.CgroupID,
		Node:        src.Spec.Node,
	}
	s := src.Status
	dst.Status = v1beta1.ContainerProfileStatus{
		// Phase gains a type and an enum in v1beta1. The conversion is a
		// straight cast because the only values the agent has ever written are
		// the two the enum permits; anything else was already a profile no
		// reader could interpret.
		Phase:                      v1beta1.ProfilePhase(s.Phase),
		LearnedSyscalls:            copyInt64s(s.LearnedSyscalls),
		LearnedFiles:               copyStrings(s.LearnedFiles),
		LearnedNetworkDestinations: copyStrings(s.LearnedNetworkDestinations),
		LearnedExecutables:         copyStrings(s.LearnedExecutables),
		LearnedCapabilities:        copyStrings(s.LearnedCapabilities),
		SyscallCount:               s.SyscallCount,
		FileCount:                  s.FileCount,
		NetworkCount:               s.NetworkCount,
		FirstSeen:                  copyTime(s.FirstSeen),
		EnforcingSince:             copyTime(s.EnforcingSince),
		LastUpdated:                copyTime(s.LastUpdated),
		EnforcementAttempts:        s.EnforcementAttempts,
		RollbackCount:              s.RollbackCount,
		LastRollbackTime:           copyTime(s.LastRollbackTime),
		LastRollbackReason:         s.LastRollbackReason,
		DenialCount:                s.DenialCount,
		Seccomp:                    toBetaSeccomp(s.Seccomp),
		DeniedFiles:                s.DeniedFiles,
		DeniedNetwork:              s.DeniedNetwork,
		DeniedExecs:                s.DeniedExecs,
		DeniedCapabilities:         s.DeniedCapabilities,
	}
	return nil
}

// ConvertFrom converts the hub version into this ContainerProfile.
func (dst *ContainerProfile) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.ContainerProfile)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec = ContainerProfileSpec{
		PolicyRef:   src.Spec.PolicyRef,
		Workload:    fromBetaWorkloadRef(src.Spec.Workload),
		PodName:     src.Spec.PodName,
		Namespace:   src.Spec.Namespace,
		ContainerID: src.Spec.ContainerID,
		CgroupID:    src.Spec.CgroupID,
		Node:        src.Spec.Node,
	}
	s := src.Status
	// The declared* lists are not carried: v1alpha1 has nowhere to put them,
	// and inventing somewhere would mean folding declarations into the learned
	// lists, which is exactly the confusion they exist to prevent. See
	// IntentionallyAdded.
	dst.Status = ContainerProfileStatus{
		Phase:                      string(s.Phase),
		LearnedSyscalls:            copyInt64s(s.LearnedSyscalls),
		LearnedFiles:               copyStrings(s.LearnedFiles),
		LearnedNetworkDestinations: copyStrings(s.LearnedNetworkDestinations),
		LearnedExecutables:         copyStrings(s.LearnedExecutables),
		LearnedCapabilities:        copyStrings(s.LearnedCapabilities),
		SyscallCount:               s.SyscallCount,
		FileCount:                  s.FileCount,
		NetworkCount:               s.NetworkCount,
		FirstSeen:                  copyTime(s.FirstSeen),
		EnforcingSince:             copyTime(s.EnforcingSince),
		LastUpdated:                copyTime(s.LastUpdated),
		EnforcementAttempts:        s.EnforcementAttempts,
		RollbackCount:              s.RollbackCount,
		LastRollbackTime:           copyTime(s.LastRollbackTime),
		LastRollbackReason:         s.LastRollbackReason,
		DenialCount:                s.DenialCount,
		Seccomp:                    fromBetaSeccomp(s.Seccomp),
		DeniedFiles:                s.DeniedFiles,
		DeniedNetwork:              s.DeniedNetwork,
		DeniedExecs:                s.DeniedExecs,
		DeniedCapabilities:         s.DeniedCapabilities,
	}
	return nil
}

func toBetaSeccomp(in *SeccompProfileRef) *v1beta1.SeccompProfileRef {
	if in == nil {
		return nil
	}
	return &v1beta1.SeccompProfileRef{
		LocalhostProfile: in.LocalhostProfile,
		Path:             in.Path,
		Node:             in.Node,
		AllowedSyscalls:  in.AllowedSyscalls,
		TotalSyscalls:    in.TotalSyscalls,
		SkippedUnknown:   in.SkippedUnknown,
		GeneratedAt:      copyTime(in.GeneratedAt),
	}
}

func fromBetaSeccomp(in *v1beta1.SeccompProfileRef) *SeccompProfileRef {
	if in == nil {
		return nil
	}
	return &SeccompProfileRef{
		LocalhostProfile: in.LocalhostProfile,
		Path:             in.Path,
		Node:             in.Node,
		AllowedSyscalls:  in.AllowedSyscalls,
		TotalSyscalls:    in.TotalSyscalls,
		SkippedUnknown:   in.SkippedUnknown,
		GeneratedAt:      copyTime(in.GeneratedAt),
	}
}

// ---------------------------------------------------------------------------
// AttackSurface
// ---------------------------------------------------------------------------

// ConvertTo converts this AttackSurface to the hub version.
func (src *AttackSurface) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.AttackSurface)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec = v1beta1.AttackSurfaceSpec{
		PolicyRef: src.Spec.PolicyRef,
		Workload:  toBetaWorkloadRef(src.Spec.Workload),
		Namespace: src.Spec.Namespace,
	}
	dst.Status = toBetaAttackSurfaceStatus(src.Status)
	return nil
}

// ConvertFrom converts the hub version into this AttackSurface.
func (dst *AttackSurface) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.AttackSurface)
	dst.ObjectMeta = *src.ObjectMeta.DeepCopy()
	dst.Spec = AttackSurfaceSpec{
		PolicyRef: src.Spec.PolicyRef,
		Workload:  fromBetaWorkloadRef(src.Spec.Workload),
		Namespace: src.Spec.Namespace,
	}
	dst.Status = fromBetaAttackSurfaceStatus(src.Status)
	return nil
}

// ---------------------------------------------------------------------------
// Copy helpers
//
// Each preserves nil, because a nil slice and an empty one are different
// objects to the API server: nil is omitted from the serialized form and an
// empty one is written as []. A converter that turned one into the other would
// make every conversion a spurious write, and the round-trip test would not
// catch it if the helpers themselves were sloppy.
// ---------------------------------------------------------------------------

func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func copyInt32s(in []int32) []int32 {
	if in == nil {
		return nil
	}
	out := make([]int32, len(in))
	copy(out, in)
	return out
}

func copyInt64s(in []int64) []int64 {
	if in == nil {
		return nil
	}
	out := make([]int64, len(in))
	copy(out, in)
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyDuration(in *metav1.Duration) *metav1.Duration {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyTime(in *metav1.Time) *metav1.Time {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}

func copyInt32(in *int32) *int32 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyBool(in *bool) *bool {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyString(in *string) *string {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
