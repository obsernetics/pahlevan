/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/cli"
)

// riskyCapabilities is the set of Linux capabilities that materially widen a
// container's attack surface: each one either grants kernel-level control or
// defeats the usual file/uid boundaries. The value is the weight the derived
// risk score adds when the capability is held.
var riskyCapabilities = map[string]int{
	"CAP_SYS_ADMIN":       12,
	"CAP_SYS_MODULE":      12,
	"CAP_SYS_RAWIO":       10,
	"CAP_SYS_PTRACE":      8,
	"CAP_BPF":             8,
	"CAP_SYS_BOOT":        6,
	"CAP_NET_ADMIN":       6,
	"CAP_NET_RAW":         4,
	"CAP_DAC_OVERRIDE":    6,
	"CAP_DAC_READ_SEARCH": 6,
	"CAP_SETUID":          5,
	"CAP_SETGID":          5,
	"CAP_SYS_CHROOT":      3,
	"CAP_MKNOD":           3,
	"CAP_PERFMON":         3,
}

// riskySyscalls is the set of syscalls that are the usual building blocks of
// container escape, kernel tampering and credential theft. A workload that
// still exposes them after learning is worth flagging even when its overall
// risk score is modest.
var riskySyscalls = map[string]struct{}{
	"ptrace":            {},
	"process_vm_readv":  {},
	"process_vm_writev": {},
	"mount":             {},
	"umount":            {},
	"umount2":           {},
	"pivot_root":        {},
	"chroot":            {},
	"unshare":           {},
	"setns":             {},
	"clone3":            {},
	"init_module":       {},
	"finit_module":      {},
	"delete_module":     {},
	"kexec_load":        {},
	"kexec_file_load":   {},
	"bpf":               {},
	"perf_event_open":   {},
	"userfaultfd":       {},
	"keyctl":            {},
	"add_key":           {},
	"request_key":       {},
	"open_by_handle_at": {},
	"name_to_handle_at": {},
	"iopl":              {},
	"ioperm":            {},
	"reboot":            {},
	"syslog":            {},
	"quotactl":          {},
	"personality":       {},
	"setuid":            {},
	"setgid":            {},
}

// highRiskThreshold is the score at or above which a workload is reported as
// needing attention in the report summary.
const highRiskThreshold = 60

// NewAttackSurfaceCommand creates the attack surface command
func NewAttackSurfaceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attack-surface",
		Short: "Analyze attack surface",
		Long: `Inspect the attack surface Pahlevan computed for your workloads.

The operator publishes one AttackSurface resource per analyzed workload,
recording the syscalls, ports, writable paths and capabilities that remain
reachable, together with a risk score. These commands read those resources
(and the ContainerProfile baselines that back them) and present them.`,
	}

	cmd.AddCommand(
		NewAttackSurfaceAnalyzeCommand(),
		NewAttackSurfaceReportCommand(),
	)

	return cmd
}

// surfaceExposure is the per-workload view rendered by analyze and embedded in
// the report.
type surfaceExposure struct {
	Namespace       string   `json:"namespace"`
	Name            string   `json:"name"`
	Workload        string   `json:"workload,omitempty"`
	PolicyRef       string   `json:"policyRef,omitempty"`
	RiskScore       int32    `json:"riskScore"`
	RiskLevel       string   `json:"riskLevel"`
	RiskDerived     bool     `json:"riskDerived"`
	ExposedPorts    []int32  `json:"exposedPorts,omitempty"`
	WritableFiles   []string `json:"writableFiles,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	RiskyCapability []string `json:"riskyCapabilities,omitempty"`
	ExposedSyscalls []string `json:"exposedSyscalls,omitempty"`
	RiskySyscalls   []string `json:"riskySyscalls,omitempty"`
	LastAnalysis    string   `json:"lastAnalysis,omitempty"`

	// Baseline is the learned ContainerProfile data behind this surface, when
	// profiles for the same workload/namespace could be correlated.
	Baseline *baselineSummary `json:"baseline,omitempty"`
}

// baselineSummary aggregates the ContainerProfile records that back a surface.
type baselineSummary struct {
	Containers     int32 `json:"containers"`
	Learning       int32 `json:"learning"`
	Enforcing      int32 `json:"enforcing"`
	LearnedSyscall int32 `json:"learnedSyscalls"`
	LearnedFiles   int32 `json:"learnedFiles"`
	LearnedNetwork int32 `json:"learnedNetworkDestinations"`
	Rollbacks      int32 `json:"rollbacks"`
	Denials        int32 `json:"denials"`
}

// Phase renders the dominant enforcement phase of the backing profiles.
func (b *baselineSummary) Phase() string {
	switch {
	case b == nil || b.Containers == 0:
		return "Unknown"
	case b.Enforcing > 0 && b.Learning == 0:
		return "Enforcing"
	case b.Learning > 0 && b.Enforcing == 0:
		return "Learning"
	case b.Enforcing > 0 && b.Learning > 0:
		return "Mixed"
	default:
		return "Unknown"
	}
}

// attackSurfaceAnalysis is the document analyze emits in json/yaml form.
type attackSurfaceAnalysis struct {
	Scope     string            `json:"scope"`
	MinRisk   int32             `json:"minRisk"`
	Total     int               `json:"totalAttackSurfaces"`
	Shown     int               `json:"shown"`
	Message   string            `json:"message,omitempty"`
	Exposures []surfaceExposure `json:"exposures"`
}

// NewAttackSurfaceAnalyzeCommand creates the attack surface analyze command
func NewAttackSurfaceAnalyzeCommand() *cobra.Command {
	var (
		namespace     string
		allNamespaces bool
		output        string
		minRisk       int32
	)

	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze the computed attack surface of your workloads",
		Long: `Read the AttackSurface resources the operator computed and rank the
workloads by risk.

For every workload the analysis prints the risk score, the ports still exposed,
the writable paths, the effective capabilities and the syscalls that remain
reachable, highlighting the capabilities and syscalls that are the usual
building blocks of container escape. Where a ContainerProfile exists for the
same workload its learned baseline (syscall/file/network counts, enforcement
phase, rollbacks and denials) is folded in.

The command reads what the operator already computed; it does not itself
inspect the kernel. If no AttackSurface resources exist yet, nothing has been
analyzed - see the message the command prints in that case.`,
		Example: `  # Rank every analyzed workload in the cluster
  pahlevan attack-surface analyze --all-namespaces

  # Only the workloads scoring 60 or above in one namespace
  pahlevan attack-surface analyze -n payments --min-risk 60

  # Machine readable
  pahlevan attack-surface analyze -A -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateOutputFormat(output, "table", "wide", "json", "yaml"); err != nil {
				return err
			}
			if minRisk < 0 || minRisk > 100 {
				return fmt.Errorf("invalid --min-risk %d: expected a value between 0 and 100", minRisk)
			}

			k8sClient, _, _, globalNs, ready := GetClients()
			if !ready || k8sClient == nil {
				return errClientsNotReady()
			}

			ns := namespace
			if ns == "" {
				ns = globalNs
			}
			if allNamespaces {
				ns = ""
			}

			writer := cli.NewOutputWriter(output)
			writer.Writer = cmd.OutOrStdout()

			analysis, err := buildAttackSurfaceAnalysis(cmd.Context(), k8sClient, ns, minRisk)
			if err != nil {
				return err
			}
			return renderAttackSurfaceAnalysis(writer, output, analysis)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&namespace, "namespace", "n", "", "Namespace to analyze (defaults to the kubeconfig context namespace)")
	flags.BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Analyze workloads across every namespace")
	flags.StringVarP(&output, "output", "o", "table", "Output format (table, wide, json, yaml)")
	flags.Int32Var(&minRisk, "min-risk", 0, "Only show workloads whose risk score is at least this value (0-100)")

	return cmd
}

// buildAttackSurfaceAnalysis lists the AttackSurface resources in scope,
// correlates them with the learned ContainerProfiles and returns the ranked
// analysis.
func buildAttackSurfaceAnalysis(ctx context.Context, k8sClient client.Client, namespace string, minRisk int32) (*attackSurfaceAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var listOpts []client.ListOption
	if namespace != "" {
		listOpts = append(listOpts, client.InNamespace(namespace))
	}

	surfaces := &policyv1alpha1.AttackSurfaceList{}
	if err := k8sClient.List(ctx, surfaces, listOpts...); err != nil {
		if isNoKindMatch(err) {
			return nil, fmt.Errorf("the AttackSurface CRD is not installed in this cluster.\n"+
				"Install the Pahlevan CRDs (kubectl apply -f install.yaml) so the operator can publish attack-surface analyses: %w", err)
		}
		return nil, fmt.Errorf("failed to list attack surfaces: %w", err)
	}

	// The learned baselines are best effort: an older install may not have the
	// ContainerProfile CRD, which must not fail the analysis.
	profiles := &policyv1alpha1.ContainerProfileList{}
	if err := k8sClient.List(ctx, profiles, listOpts...); err != nil {
		profiles.Items = nil
	}
	baselines := indexBaselines(profiles.Items)

	analysis := &attackSurfaceAnalysis{
		Scope:   scopeLabel(namespace),
		MinRisk: minRisk,
		Total:   len(surfaces.Items),
	}

	for i := range surfaces.Items {
		exposure := newSurfaceExposure(&surfaces.Items[i], baselines)
		if exposure.RiskScore < minRisk {
			continue
		}
		analysis.Exposures = append(analysis.Exposures, exposure)
	}
	sortExposures(analysis.Exposures)
	analysis.Shown = len(analysis.Exposures)

	switch {
	case analysis.Total == 0:
		analysis.Message = noAttackSurfaceMessage(namespace)
	case analysis.Shown == 0:
		analysis.Message = fmt.Sprintf(
			"%d attack surface(s) found in %s, but none scored at or above the --min-risk threshold of %d.",
			analysis.Total, analysis.Scope, minRisk)
	}
	if analysis.Exposures == nil {
		analysis.Exposures = []surfaceExposure{}
	}
	return analysis, nil
}

// noAttackSurfaceMessage explains an empty result: an empty table alone reads
// like "nothing is at risk" when it actually means "nothing has been analyzed".
func noAttackSurfaceMessage(namespace string) string {
	return fmt.Sprintf(
		"No AttackSurface resources exist in %s, so nothing has been analyzed yet.\n"+
			"The Pahlevan operator computes these from the ContainerProfile baselines the node agents learn: "+
			"a workload gets an AttackSurface only after a PahlevanPolicy selects it and its containers have been "+
			"observed for at least one learning window. Check 'pahlevan status' for the operator and 'pahlevan policy list' "+
			"for the policies in place.",
		scopeLabel(namespace))
}

// scopeLabel renders the analyzed namespace scope for messages.
func scopeLabel(namespace string) string {
	if namespace == "" {
		return "all namespaces"
	}
	return fmt.Sprintf("namespace %q", namespace)
}

// baselineKey identifies the workload a ContainerProfile belongs to so it can
// be matched against an AttackSurface for the same workload.
type baselineKey struct {
	namespace string
	workload  string
}

// indexBaselines folds the learned ContainerProfiles into per-workload
// summaries keyed by namespace and workload name.
func indexBaselines(profiles []policyv1alpha1.ContainerProfile) map[baselineKey]*baselineSummary {
	index := make(map[baselineKey]*baselineSummary, len(profiles))
	for i := range profiles {
		p := &profiles[i]
		for _, key := range profileKeys(p) {
			summary := index[key]
			if summary == nil {
				summary = &baselineSummary{}
				index[key] = summary
			}
			summary.Containers++
			switch strings.ToLower(p.Status.Phase) {
			case "learning":
				summary.Learning++
			case "enforcing":
				summary.Enforcing++
			}
			summary.LearnedSyscall += p.Status.SyscallCount
			summary.LearnedFiles += p.Status.FileCount
			summary.LearnedNetwork += p.Status.NetworkCount
			summary.Rollbacks += p.Status.RollbackCount
			summary.Denials += p.Status.DenialCount
		}
	}
	return index
}

// profileKeys returns every key a profile should be indexed under: its workload
// reference and its policy reference both identify the same surface depending
// on how the operator named the AttackSurface.
func profileKeys(p *policyv1alpha1.ContainerProfile) []baselineKey {
	ns := p.Spec.Namespace
	if ns == "" {
		ns = p.Namespace
	}
	seen := map[baselineKey]struct{}{}
	var keys []baselineKey
	add := func(name string) {
		if name == "" {
			return
		}
		k := baselineKey{namespace: ns, workload: name}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	if p.Spec.Workload != nil {
		add(p.Spec.Workload.Name)
	}
	add(p.Spec.PolicyRef)
	return keys
}

// newSurfaceExposure converts one AttackSurface into the rendered view,
// attaching the learned baseline when one can be correlated.
func newSurfaceExposure(as *policyv1alpha1.AttackSurface, baselines map[baselineKey]*baselineSummary) surfaceExposure {
	ns := as.Spec.Namespace
	if ns == "" {
		ns = as.Namespace
	}

	score, derived := surfaceRiskScore(&as.Status)
	exposure := surfaceExposure{
		Namespace:       ns,
		Name:            as.Name,
		Workload:        workloadLabel(as.Spec.Workload),
		PolicyRef:       as.Spec.PolicyRef,
		RiskScore:       score,
		RiskLevel:       riskLevel(score),
		RiskDerived:     derived,
		ExposedPorts:    sortedPorts(as.Status.ExposedPorts),
		WritableFiles:   sortedCopy(as.Status.WritableFiles),
		Capabilities:    sortedCopy(as.Status.Capabilities),
		RiskyCapability: filterRiskyCapabilities(as.Status.Capabilities),
		ExposedSyscalls: sortedCopy(as.Status.ExposedSyscalls),
		RiskySyscalls:   filterRiskySyscalls(as.Status.ExposedSyscalls),
	}
	if as.Status.LastAnalysis != nil {
		exposure.LastAnalysis = cli.FormatTimestamp(as.Status.LastAnalysis.Time)
	}

	for _, name := range []string{workloadName(as.Spec.Workload), as.Spec.PolicyRef, as.Name} {
		if name == "" {
			continue
		}
		if b, ok := baselines[baselineKey{namespace: ns, workload: name}]; ok {
			exposure.Baseline = b
			break
		}
	}
	return exposure
}

// workloadLabel renders a workload reference as "Kind/name".
func workloadLabel(ref *policyv1alpha1.WorkloadReference) string {
	if ref == nil || ref.Name == "" {
		return ""
	}
	if ref.Kind == "" {
		return ref.Name
	}
	return ref.Kind + "/" + ref.Name
}

func workloadName(ref *policyv1alpha1.WorkloadReference) string {
	if ref == nil {
		return ""
	}
	return ref.Name
}

// surfaceRiskScore returns the operator-computed risk score when present. When
// the operator has not scored the surface yet, a score is derived from the
// exposure itself so the ranking is still meaningful; the boolean reports which
// of the two happened.
func surfaceRiskScore(status *policyv1alpha1.AttackSurfaceStatus) (int32, bool) {
	if status.RiskScore != nil {
		return clampScore(*status.RiskScore), false
	}
	return deriveRiskScore(status), true
}

// deriveRiskScore approximates a risk score from the raw exposure. Capabilities
// dominate (they are the direct escape primitives), then risky syscalls, then
// the breadth of listening ports and writable paths.
func deriveRiskScore(status *policyv1alpha1.AttackSurfaceStatus) int32 {
	score := 0
	for _, capability := range status.Capabilities {
		score += riskyCapabilities[normalizeCapability(capability)]
	}
	score += 3 * len(filterRiskySyscalls(status.ExposedSyscalls))
	score += 2 * len(status.ExposedPorts)
	score += len(status.WritableFiles)
	if n := len(status.ExposedSyscalls); n > 0 {
		score += n / 25
	}
	return clampScore(int32(score))
}

func clampScore(score int32) int32 {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// riskLevel buckets a 0-100 score into a human label.
func riskLevel(score int32) string {
	switch {
	case score >= 80:
		return "Critical"
	case score >= highRiskThreshold:
		return "High"
	case score >= 30:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Minimal"
	}
}

// normalizeCapability upper-cases a capability and adds the CAP_ prefix so both
// "sys_admin" and "CAP_SYS_ADMIN" match the risky set.
func normalizeCapability(capability string) string {
	c := strings.ToUpper(strings.TrimSpace(capability))
	if c == "" {
		return ""
	}
	if !strings.HasPrefix(c, "CAP_") {
		c = "CAP_" + c
	}
	return c
}

// filterRiskyCapabilities returns the sorted subset of capabilities that widen
// the attack surface materially.
func filterRiskyCapabilities(capabilities []string) []string {
	var out []string
	for _, c := range capabilities {
		if _, ok := riskyCapabilities[normalizeCapability(c)]; ok {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// filterRiskySyscalls returns the sorted subset of syscalls associated with
// escape, kernel tampering or credential manipulation.
func filterRiskySyscalls(syscalls []string) []string {
	var out []string
	for _, s := range syscalls {
		if _, ok := riskySyscalls[strings.ToLower(strings.TrimSpace(s))]; ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

func sortedPorts(in []int32) []int32 {
	if len(in) == 0 {
		return nil
	}
	out := make([]int32, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sortExposures ranks by descending risk, then namespace and name so equal
// scores still render in a stable order.
func sortExposures(exposures []surfaceExposure) {
	sort.Slice(exposures, func(i, j int) bool {
		if exposures[i].RiskScore != exposures[j].RiskScore {
			return exposures[i].RiskScore > exposures[j].RiskScore
		}
		if exposures[i].Namespace != exposures[j].Namespace {
			return exposures[i].Namespace < exposures[j].Namespace
		}
		return exposures[i].Name < exposures[j].Name
	})
}

// renderAttackSurfaceAnalysis writes the analysis in the requested format.
func renderAttackSurfaceAnalysis(writer *cli.OutputWriter, output string, analysis *attackSurfaceAnalysis) error {
	if output == "json" || output == "yaml" {
		return writer.WriteObject(analysis)
	}

	if analysis.Message != "" {
		writer.PrintInfo(analysis.Message)
		if analysis.Shown == 0 {
			return nil
		}
	}

	table := cli.NewTableData("NAMESPACE", "NAME", "WORKLOAD", "RISK", "LEVEL", "PORTS", "WRITABLE", "CAPS", "SYSCALLS", "PHASE")
	for _, e := range analysis.Exposures {
		table.AddRow(
			e.Namespace,
			e.Name,
			orNone(e.Workload),
			riskCell(e),
			e.RiskLevel,
			formatPorts(e.ExposedPorts),
			fmt.Sprintf("%d", len(e.WritableFiles)),
			formatCapCell(e),
			formatSyscallCell(e),
			e.Baseline.Phase(),
		)
	}
	if err := table.Render(writer); err != nil {
		return err
	}

	if output == "wide" {
		fmt.Fprintln(writer.Writer)
		for _, e := range analysis.Exposures {
			writeExposureDetail(writer.Writer, e)
		}
		return nil
	}

	fmt.Fprintf(writer.Writer, "\n%d of %d attack surface(s) shown for %s.\n", analysis.Shown, analysis.Total, analysis.Scope)
	fmt.Fprintf(writer.Writer, "Use -o wide for the full port, path, capability and syscall lists.\n")
	return nil
}

// writeExposureDetail prints the full lists that the table only counts.
func writeExposureDetail(w io.Writer, e surfaceExposure) {
	fmt.Fprintf(w, "%s/%s  %s (risk %d, %s)\n", e.Namespace, e.Name, orNone(e.Workload), e.RiskScore, e.RiskLevel)
	if e.PolicyRef != "" {
		fmt.Fprintf(w, "  Policy:              %s\n", e.PolicyRef)
	}
	fmt.Fprintf(w, "  Exposed ports:       %s\n", formatPortsFull(e.ExposedPorts))
	fmt.Fprintf(w, "  Writable paths:      %s\n", cli.FormatList(e.WritableFiles))
	fmt.Fprintf(w, "  Capabilities:        %s\n", cli.FormatList(e.Capabilities))
	fmt.Fprintf(w, "  Risky capabilities:  %s\n", cli.FormatList(e.RiskyCapability))
	fmt.Fprintf(w, "  Exposed syscalls:    %d (%s)\n", len(e.ExposedSyscalls), cli.FormatList(e.ExposedSyscalls))
	fmt.Fprintf(w, "  Risky syscalls:      %s\n", cli.FormatList(e.RiskySyscalls))
	if e.LastAnalysis != "" {
		fmt.Fprintf(w, "  Last analysis:       %s\n", e.LastAnalysis)
	}
	if b := e.Baseline; b != nil {
		fmt.Fprintf(w, "  Learned baseline:    %d container(s), %s, %d syscalls / %d files / %d network destinations\n",
			b.Containers, b.Phase(), b.LearnedSyscall, b.LearnedFiles, b.LearnedNetwork)
		fmt.Fprintf(w, "  Self-healing:        %d rollback(s), %d denial(s)\n", b.Rollbacks, b.Denials)
	}
	fmt.Fprintln(w)
}

func riskCell(e surfaceExposure) string {
	if e.RiskDerived {
		return fmt.Sprintf("%d*", e.RiskScore)
	}
	return fmt.Sprintf("%d", e.RiskScore)
}

func formatCapCell(e surfaceExposure) string {
	if len(e.RiskyCapability) == 0 {
		return fmt.Sprintf("%d", len(e.Capabilities))
	}
	return fmt.Sprintf("%d (%d risky)", len(e.Capabilities), len(e.RiskyCapability))
}

func formatSyscallCell(e surfaceExposure) string {
	if len(e.RiskySyscalls) == 0 {
		return fmt.Sprintf("%d", len(e.ExposedSyscalls))
	}
	return fmt.Sprintf("%d (%d risky)", len(e.ExposedSyscalls), len(e.RiskySyscalls))
}

func formatPortsFull(ports []int32) string {
	if len(ports) == 0 {
		return "<none>"
	}
	strs := make([]string, 0, len(ports))
	for _, p := range ports {
		strs = append(strs, fmt.Sprintf("%d", p))
	}
	return strings.Join(strs, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}

// errClientsNotReady is the shared message for commands that need a cluster.
func errClientsNotReady() error {
	return fmt.Errorf("kubernetes clients are not initialized; check your kubeconfig and cluster connectivity")
}

// --- report ---------------------------------------------------------------

// nameCount is a name with the number of workloads exposing it.
type nameCount struct {
	Name      string `json:"name"`
	Workloads int    `json:"workloads"`
}

// portCount is a port with the number of workloads exposing it.
type portCount struct {
	Port      int32 `json:"port"`
	Workloads int   `json:"workloads"`
}

// reportTotals is the cluster-wide roll-up at the head of the report.
type reportTotals struct {
	AttackSurfaces    int     `json:"attackSurfaces"`
	Namespaces        int     `json:"namespaces"`
	Policies          int     `json:"policies"`
	ContainerProfiles int     `json:"containerProfiles"`
	AverageRisk       float64 `json:"averageRiskScore"`
	MaxRisk           int32   `json:"maxRiskScore"`
	HighRisk          int     `json:"highRiskWorkloads"`
	UniquePorts       int     `json:"uniqueExposedPorts"`
	UniqueCaps        int     `json:"uniqueCapabilities"`
	UniqueWritable    int     `json:"uniqueWritablePaths"`
}

// enforcementPosture summarizes how far the cluster has moved from learning to
// enforcing, and how much self-healing has been needed.
type enforcementPosture struct {
	ProfilesTotal     int            `json:"profilesTotal"`
	ProfilesLearning  int            `json:"profilesLearning"`
	ProfilesEnforcing int            `json:"profilesEnforcing"`
	ProfilesOther     int            `json:"profilesOther"`
	Rollbacks         int32          `json:"rollbacks"`
	Denials           int32          `json:"denials"`
	ProfilesRolledBk  int            `json:"profilesWithRollbacks"`
	LastRollback      string         `json:"lastRollback,omitempty"`
	LastRollbackWhy   string         `json:"lastRollbackReason,omitempty"`
	PoliciesByPhase   map[string]int `json:"policiesByPhase,omitempty"`
}

// EnforcingRatio is the fraction of profiles that reached enforcing.
func (e enforcementPosture) EnforcingRatio() float64 {
	if e.ProfilesTotal == 0 {
		return 0
	}
	return float64(e.ProfilesEnforcing) / float64(e.ProfilesTotal)
}

// attackSurfaceReport is the full document the report command emits.
type attackSurfaceReport struct {
	GeneratedAt   string             `json:"generatedAt"`
	Scope         string             `json:"scope"`
	Totals        reportTotals       `json:"totals"`
	TopWorkloads  []surfaceExposure  `json:"topWorkloads"`
	ExposedPorts  []portCount        `json:"exposedPorts,omitempty"`
	Capabilities  []nameCount        `json:"capabilities,omitempty"`
	WritablePaths []nameCount        `json:"writablePaths,omitempty"`
	RiskySyscalls []nameCount        `json:"riskySyscalls,omitempty"`
	Enforcement   enforcementPosture `json:"enforcement"`
	Message       string             `json:"message,omitempty"`
}

// NewAttackSurfaceReportCommand creates the attack surface report command
func NewAttackSurfaceReportCommand() *cobra.Command {
	var (
		namespace     string
		allNamespaces bool
		output        string
		file          string
		top           int
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a full attack surface report",
		Long: `Generate a saveable attack surface report for the cluster.

The report contains the cluster totals (analyzed workloads, namespaces,
policies and learned profiles, average and peak risk), the riskiest workloads,
the aggregate exposed ports, capabilities, writable paths and risky syscalls
ranked by how many workloads share them, and the enforcement posture: how many
ContainerProfiles are still learning versus enforcing, and how much self-healing
rollback has been needed.

Use --file to write the report to disk; markdown output is intended for
attaching to a review or an issue.`,
		Example: `  # Print the cluster report
  pahlevan attack-surface report --all-namespaces

  # Save a markdown report for review
  pahlevan attack-surface report -A -o markdown --file surface.md

  # Machine readable, one namespace
  pahlevan attack-surface report -n payments -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateOutputFormat(output, "table", "json", "yaml", "markdown"); err != nil {
				return err
			}
			if top <= 0 {
				return fmt.Errorf("invalid --top %d: expected a positive number of workloads", top)
			}

			k8sClient, _, _, globalNs, ready := GetClients()
			if !ready || k8sClient == nil {
				return errClientsNotReady()
			}

			ns := namespace
			if ns == "" {
				ns = globalNs
			}
			if allNamespaces {
				ns = ""
			}

			report, err := buildAttackSurfaceReport(cmd.Context(), k8sClient, ns, top)
			if err != nil {
				return err
			}

			var buf bytes.Buffer
			writer := cli.NewOutputWriter(output)
			writer.Writer = &buf
			if err := renderAttackSurfaceReport(writer, output, report); err != nil {
				return err
			}

			if file == "" {
				_, err := cmd.OutOrStdout().Write(buf.Bytes())
				return err
			}
			if err := writeReportFile(file, buf.Bytes()); err != nil {
				return err
			}
			out := cli.NewOutputWriter("table")
			out.Writer = cmd.OutOrStdout()
			out.PrintSuccess(fmt.Sprintf("Attack surface report written to %s (%s)", file, cli.FormatBytes(int64(buf.Len()))))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&namespace, "namespace", "n", "", "Namespace to report on (defaults to the kubeconfig context namespace)")
	flags.BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Report on every namespace")
	flags.StringVarP(&output, "output", "o", "table", "Output format (table, json, yaml, markdown)")
	flags.StringVar(&file, "file", "", "Write the report to this file instead of stdout")
	flags.IntVar(&top, "top", 10, "How many of the riskiest workloads to list")

	return cmd
}

// writeReportFile writes the rendered report, creating parent directories that
// already exist only (it does not create a whole tree implicitly).
func writeReportFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("cannot write report to %s: %w", path, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("cannot write report to %s: %w", path, err)
	}
	return nil
}

// buildAttackSurfaceReport aggregates every AttackSurface, ContainerProfile and
// PahlevanPolicy in scope into the report document.
func buildAttackSurfaceReport(ctx context.Context, k8sClient client.Client, namespace string, top int) (*attackSurfaceReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var listOpts []client.ListOption
	if namespace != "" {
		listOpts = append(listOpts, client.InNamespace(namespace))
	}

	surfaces := &policyv1alpha1.AttackSurfaceList{}
	if err := k8sClient.List(ctx, surfaces, listOpts...); err != nil {
		if isNoKindMatch(err) {
			return nil, fmt.Errorf("the AttackSurface CRD is not installed in this cluster.\n"+
				"Install the Pahlevan CRDs (kubectl apply -f install.yaml) so the operator can publish attack-surface analyses: %w", err)
		}
		return nil, fmt.Errorf("failed to list attack surfaces: %w", err)
	}

	profiles := &policyv1alpha1.ContainerProfileList{}
	if err := k8sClient.List(ctx, profiles, listOpts...); err != nil {
		profiles.Items = nil
	}
	policies := &policyv1alpha1.PahlevanPolicyList{}
	if err := k8sClient.List(ctx, policies, listOpts...); err != nil {
		policies.Items = nil
	}

	return aggregateAttackSurfaceReport(surfaces.Items, profiles.Items, policies.Items, namespace, top), nil
}

// aggregateAttackSurfaceReport is the pure aggregation the report renders. It
// is separated from the API calls so it can be tested and benchmarked directly.
func aggregateAttackSurfaceReport(
	surfaces []policyv1alpha1.AttackSurface,
	profiles []policyv1alpha1.ContainerProfile,
	policies []policyv1alpha1.PahlevanPolicy,
	namespace string,
	top int,
) *attackSurfaceReport {
	baselines := indexBaselines(profiles)

	exposures := make([]surfaceExposure, 0, len(surfaces))
	namespaces := make(map[string]struct{}, len(surfaces))
	portWorkloads := make(map[int32]int)
	capWorkloads := make(map[string]int)
	pathWorkloads := make(map[string]int)
	syscallWorkloads := make(map[string]int)

	var totalRisk int64
	var maxRisk int32
	highRisk := 0

	for i := range surfaces {
		e := newSurfaceExposure(&surfaces[i], baselines)
		exposures = append(exposures, e)
		namespaces[e.Namespace] = struct{}{}
		totalRisk += int64(e.RiskScore)
		if e.RiskScore > maxRisk {
			maxRisk = e.RiskScore
		}
		if e.RiskScore >= highRiskThreshold {
			highRisk++
		}
		for _, p := range dedupePorts(e.ExposedPorts) {
			portWorkloads[p]++
		}
		for _, c := range dedupeStrings(e.Capabilities) {
			capWorkloads[c]++
		}
		for _, p := range dedupeStrings(e.WritableFiles) {
			pathWorkloads[p]++
		}
		for _, s := range dedupeStrings(e.RiskySyscalls) {
			syscallWorkloads[s]++
		}
	}
	sortExposures(exposures)

	report := &attackSurfaceReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Scope:       scopeLabel(namespace),
		Totals: reportTotals{
			AttackSurfaces:    len(surfaces),
			Namespaces:        len(namespaces),
			Policies:          len(policies),
			ContainerProfiles: len(profiles),
			MaxRisk:           maxRisk,
			HighRisk:          highRisk,
			UniquePorts:       len(portWorkloads),
			UniqueCaps:        len(capWorkloads),
			UniqueWritable:    len(pathWorkloads),
		},
		ExposedPorts:  topPortCounts(portWorkloads, top),
		Capabilities:  topNameCounts(capWorkloads, top),
		WritablePaths: topNameCounts(pathWorkloads, top),
		RiskySyscalls: topNameCounts(syscallWorkloads, top),
		Enforcement:   summarizeEnforcement(profiles, policies),
	}
	if len(surfaces) > 0 {
		report.Totals.AverageRisk = roundTo(float64(totalRisk)/float64(len(surfaces)), 1)
	}
	if len(exposures) > top {
		exposures = exposures[:top]
	}
	report.TopWorkloads = exposures
	if len(surfaces) == 0 {
		report.Message = noAttackSurfaceMessage(namespace)
	}
	return report
}

// summarizeEnforcement rolls the learned profiles and the policies into the
// posture section of the report.
func summarizeEnforcement(profiles []policyv1alpha1.ContainerProfile, policies []policyv1alpha1.PahlevanPolicy) enforcementPosture {
	posture := enforcementPosture{
		ProfilesTotal:   len(profiles),
		PoliciesByPhase: map[string]int{},
	}
	var lastRollback *metav1.Time
	for i := range profiles {
		p := &profiles[i]
		switch strings.ToLower(p.Status.Phase) {
		case "learning":
			posture.ProfilesLearning++
		case "enforcing":
			posture.ProfilesEnforcing++
		default:
			posture.ProfilesOther++
		}
		posture.Rollbacks += p.Status.RollbackCount
		posture.Denials += p.Status.DenialCount
		if p.Status.RollbackCount > 0 {
			posture.ProfilesRolledBk++
		}
		if t := p.Status.LastRollbackTime; t != nil {
			if lastRollback == nil || t.After(lastRollback.Time) {
				lastRollback = t
				posture.LastRollbackWhy = p.Status.LastRollbackReason
			}
		}
	}
	if lastRollback != nil {
		posture.LastRollback = cli.FormatTimestamp(lastRollback.Time)
	}
	for i := range policies {
		phase := string(policies[i].Status.Phase)
		if phase == "" {
			phase = "Unknown"
		}
		posture.PoliciesByPhase[phase]++
	}
	if len(posture.PoliciesByPhase) == 0 {
		posture.PoliciesByPhase = nil
	}
	return posture
}

func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupePorts(in []int32) []int32 {
	if len(in) < 2 {
		return in
	}
	seen := make(map[int32]struct{}, len(in))
	out := in[:0:0]
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// topNameCounts returns the n most widely shared names, ties broken by name.
func topNameCounts(counts map[string]int, n int) []nameCount {
	if len(counts) == 0 {
		return nil
	}
	out := make([]nameCount, 0, len(counts))
	for name, c := range counts {
		out = append(out, nameCount{Name: name, Workloads: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workloads != out[j].Workloads {
			return out[i].Workloads > out[j].Workloads
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// topPortCounts returns the n most widely exposed ports, ties broken by port.
func topPortCounts(counts map[int32]int, n int) []portCount {
	if len(counts) == 0 {
		return nil
	}
	out := make([]portCount, 0, len(counts))
	for port, c := range counts {
		out = append(out, portCount{Port: port, Workloads: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workloads != out[j].Workloads {
			return out[i].Workloads > out[j].Workloads
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func roundTo(v float64, digits int) float64 {
	pow := 1.0
	for i := 0; i < digits; i++ {
		pow *= 10
	}
	return float64(int64(v*pow+0.5)) / pow
}

// renderAttackSurfaceReport writes the report in the requested format.
func renderAttackSurfaceReport(writer *cli.OutputWriter, output string, report *attackSurfaceReport) error {
	switch output {
	case "json", "yaml":
		return writer.WriteObject(report)
	case "markdown":
		return writeReportMarkdown(writer.Writer, report)
	default:
		return writeReportTable(writer, report)
	}
}

func writeReportTable(writer *cli.OutputWriter, report *attackSurfaceReport) error {
	w := writer.Writer
	fmt.Fprintf(w, "=== Pahlevan Attack Surface Report ===\n\n")
	fmt.Fprintf(w, "Generated:            %s\n", report.GeneratedAt)
	fmt.Fprintf(w, "Scope:                %s\n\n", report.Scope)

	if report.Message != "" {
		writer.PrintInfo(report.Message)
		fmt.Fprintln(w)
	}

	t := report.Totals
	fmt.Fprintf(w, "--- Cluster totals ---\n")
	fmt.Fprintf(w, "Analyzed workloads:   %d across %d namespace(s)\n", t.AttackSurfaces, t.Namespaces)
	fmt.Fprintf(w, "Policies:             %d\n", t.Policies)
	fmt.Fprintf(w, "Container profiles:   %d\n", t.ContainerProfiles)
	fmt.Fprintf(w, "Risk score:           avg %.1f, max %d, %d workload(s) at or above %d\n",
		t.AverageRisk, t.MaxRisk, t.HighRisk, highRiskThreshold)
	fmt.Fprintf(w, "Distinct exposure:    %d port(s), %d capability(ies), %d writable path(s)\n\n",
		t.UniquePorts, t.UniqueCaps, t.UniqueWritable)

	fmt.Fprintf(w, "--- Riskiest workloads ---\n")
	if len(report.TopWorkloads) == 0 {
		fmt.Fprintf(w, "<none>\n\n")
	} else {
		table := cli.NewTableData("NAMESPACE", "NAME", "WORKLOAD", "RISK", "LEVEL", "PORTS", "WRITABLE", "RISKY CAPS", "RISKY SYSCALLS")
		for _, e := range report.TopWorkloads {
			table.AddRow(
				e.Namespace, e.Name, orNone(e.Workload), riskCell(e), e.RiskLevel,
				fmt.Sprintf("%d", len(e.ExposedPorts)),
				fmt.Sprintf("%d", len(e.WritableFiles)),
				fmt.Sprintf("%d", len(e.RiskyCapability)),
				fmt.Sprintf("%d", len(e.RiskySyscalls)),
			)
		}
		if err := table.Render(writer); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}

	writeCountSection(w, "Most exposed ports", portCountRows(report.ExposedPorts))
	writeCountSection(w, "Most common capabilities", nameCountRows(report.Capabilities))
	writeCountSection(w, "Most common writable paths", nameCountRows(report.WritablePaths))
	writeCountSection(w, "Most common risky syscalls", nameCountRows(report.RiskySyscalls))

	e := report.Enforcement
	fmt.Fprintf(w, "--- Enforcement posture ---\n")
	fmt.Fprintf(w, "Container profiles:   %d total, %d learning, %d enforcing, %d other\n",
		e.ProfilesTotal, e.ProfilesLearning, e.ProfilesEnforcing, e.ProfilesOther)
	fmt.Fprintf(w, "Enforcing ratio:      %s\n", cli.FormatPercentage(e.EnforcingRatio()))
	fmt.Fprintf(w, "Self-healing:         %d rollback(s) across %d profile(s), %d denial(s)\n",
		e.Rollbacks, e.ProfilesRolledBk, e.Denials)
	if e.LastRollback != "" {
		fmt.Fprintf(w, "Last rollback:        %s (%s)\n", e.LastRollback, orNone(e.LastRollbackWhy))
	}
	if len(e.PoliciesByPhase) > 0 {
		fmt.Fprintf(w, "Policies by phase:\n")
		for _, phase := range sortedKeys(e.PoliciesByPhase) {
			fmt.Fprintf(w, "  %-14s %d\n", phase+":", e.PoliciesByPhase[phase])
		}
	}
	return nil
}

func writeCountSection(w io.Writer, title string, rows [][2]string) {
	fmt.Fprintf(w, "--- %s ---\n", title)
	if len(rows) == 0 {
		fmt.Fprintf(w, "<none>\n\n")
		return
	}
	for _, r := range rows {
		fmt.Fprintf(w, "  %-46s %s\n", cli.TruncateString(r[0], 46), r[1])
	}
	fmt.Fprintln(w)
}

func nameCountRows(counts []nameCount) [][2]string {
	rows := make([][2]string, 0, len(counts))
	for _, c := range counts {
		rows = append(rows, [2]string{c.Name, fmt.Sprintf("%d workload(s)", c.Workloads)})
	}
	return rows
}

func portCountRows(counts []portCount) [][2]string {
	rows := make([][2]string, 0, len(counts))
	for _, c := range counts {
		rows = append(rows, [2]string{fmt.Sprintf("%d", c.Port), fmt.Sprintf("%d workload(s)", c.Workloads)})
	}
	return rows
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func writeReportMarkdown(w io.Writer, report *attackSurfaceReport) error {
	fmt.Fprintf(w, "# Pahlevan attack surface report\n\n")
	fmt.Fprintf(w, "- **Generated:** %s\n", report.GeneratedAt)
	fmt.Fprintf(w, "- **Scope:** %s\n\n", report.Scope)

	if report.Message != "" {
		fmt.Fprintf(w, "> %s\n\n", strings.ReplaceAll(report.Message, "\n", "\n> "))
	}

	t := report.Totals
	fmt.Fprintf(w, "## Cluster totals\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Analyzed workloads | %d |\n", t.AttackSurfaces)
	fmt.Fprintf(w, "| Namespaces | %d |\n", t.Namespaces)
	fmt.Fprintf(w, "| Policies | %d |\n", t.Policies)
	fmt.Fprintf(w, "| Container profiles | %d |\n", t.ContainerProfiles)
	fmt.Fprintf(w, "| Average risk score | %.1f |\n", t.AverageRisk)
	fmt.Fprintf(w, "| Maximum risk score | %d |\n", t.MaxRisk)
	fmt.Fprintf(w, "| Workloads at risk >= %d | %d |\n", highRiskThreshold, t.HighRisk)
	fmt.Fprintf(w, "| Distinct exposed ports | %d |\n", t.UniquePorts)
	fmt.Fprintf(w, "| Distinct capabilities | %d |\n", t.UniqueCaps)
	fmt.Fprintf(w, "| Distinct writable paths | %d |\n\n", t.UniqueWritable)

	fmt.Fprintf(w, "## Riskiest workloads\n\n")
	if len(report.TopWorkloads) == 0 {
		fmt.Fprintf(w, "_No analyzed workloads._\n\n")
	} else {
		fmt.Fprintf(w, "| Namespace | Name | Workload | Risk | Level | Ports | Writable | Risky caps | Risky syscalls |\n")
		fmt.Fprintf(w, "|---|---|---|---|---|---|---|---|---|\n")
		for _, e := range report.TopWorkloads {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %d | %d | %s | %s |\n",
				e.Namespace, e.Name, orNone(e.Workload), riskCell(e), e.RiskLevel,
				len(e.ExposedPorts), len(e.WritableFiles),
				mdList(e.RiskyCapability), mdList(e.RiskySyscalls))
		}
		fmt.Fprintln(w)
	}

	writeMarkdownCounts(w, "Most exposed ports", "Port", portCountRows(report.ExposedPorts))
	writeMarkdownCounts(w, "Most common capabilities", "Capability", nameCountRows(report.Capabilities))
	writeMarkdownCounts(w, "Most common writable paths", "Path", nameCountRows(report.WritablePaths))
	writeMarkdownCounts(w, "Most common risky syscalls", "Syscall", nameCountRows(report.RiskySyscalls))

	e := report.Enforcement
	fmt.Fprintf(w, "## Enforcement posture\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Container profiles | %d |\n", e.ProfilesTotal)
	fmt.Fprintf(w, "| Learning | %d |\n", e.ProfilesLearning)
	fmt.Fprintf(w, "| Enforcing | %d |\n", e.ProfilesEnforcing)
	fmt.Fprintf(w, "| Other phase | %d |\n", e.ProfilesOther)
	fmt.Fprintf(w, "| Enforcing ratio | %s |\n", cli.FormatPercentage(e.EnforcingRatio()))
	fmt.Fprintf(w, "| Rollbacks | %d across %d profile(s) |\n", e.Rollbacks, e.ProfilesRolledBk)
	fmt.Fprintf(w, "| Denials | %d |\n", e.Denials)
	if e.LastRollback != "" {
		fmt.Fprintf(w, "| Last rollback | %s (%s) |\n", e.LastRollback, orNone(e.LastRollbackWhy))
	}
	fmt.Fprintln(w)

	if len(e.PoliciesByPhase) > 0 {
		fmt.Fprintf(w, "### Policies by phase\n\n| Phase | Policies |\n|---|---|\n")
		for _, phase := range sortedKeys(e.PoliciesByPhase) {
			fmt.Fprintf(w, "| %s | %d |\n", phase, e.PoliciesByPhase[phase])
		}
		fmt.Fprintln(w)
	}
	return nil
}

func writeMarkdownCounts(w io.Writer, title, column string, rows [][2]string) {
	fmt.Fprintf(w, "## %s\n\n", title)
	if len(rows) == 0 {
		fmt.Fprintf(w, "_None._\n\n")
		return
	}
	fmt.Fprintf(w, "| %s | Workloads |\n|---|---|\n", column)
	for _, r := range rows {
		fmt.Fprintf(w, "| %s | %s |\n", r[0], r[1])
	}
	fmt.Fprintln(w)
}

func mdList(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, "<br>")
}
