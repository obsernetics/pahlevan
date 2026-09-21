// Operational guards for everything Pahlevan ships to a cluster.
//
// The manifests in deploy/base, the all-in-one install.yaml built from them,
// and the Helm chart are three ways to install the same two components, and
// nothing compared them. They had drifted: the chart's ClusterRole was missing
// four grants the base had, its crds/ directory held one of the three CRDs the
// controllers watch (and a stale copy of that one), and neither installer gave
// the agent a startup probe - so on any node where loading and attaching the
// eBPF programs took longer than three liveness failures, the kubelet killed
// the agent while it was starting normally, forever.
//
// Every check below runs against the real files and against what `helm
// template` actually renders, with default values and with the values a real
// operator sets. None of them reads a fixture, because a fixture is a copy and
// a copy is what drifted in the first place.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
)

// ---------------------------------------------------------------------------
// Numbers these guards hold the manifests to, each with the thing it is read
// from rather than chosen against.
// ---------------------------------------------------------------------------

const (
	// controller-runtime's default manager shutdown budget
	// (defaultGracefulShutdownPeriod in pkg/manager/manager.go). Neither
	// binary overrides it, so SIGTERM can take this long to stop the runnables
	// before anything else in the shutdown path even begins.
	crGracefulShutdownSeconds = 30

	// The agent loads and attaches its eBPF programs before it constructs the
	// manager that serves the health port, so the port is closed for all of
	// BTF parse, CO-RE relocation and verification. Two minutes is the budget
	// a cold, busy node needs; less than this is the crash loop described at
	// the top of this file.
	agentStartupBudgetSeconds = 120

	// The operator only has to build its caches and bind, but on a cluster
	// whose CRDs were applied moments earlier, or whose API server is slow to
	// serve the initial list, that outlasts the three liveness failures the
	// manifests used to allow.
	operatorStartupBudgetSeconds = 45

	// A one-second probe timeout - the Kubernetes default - is shorter than a
	// stop-the-world pause on a node under the memory pressure the agent
	// exists to survive, and a timed-out liveness probe is a kill.
	minProbeTimeoutSeconds = 2

	// A single missed probe must never be fatal.
	minProbeFailureThreshold = 3
)

// ---------------------------------------------------------------------------
// Sources. Every property is checked against all of them.
// ---------------------------------------------------------------------------

// productionValues is what an operator running this on a real cluster changes:
// a pinned tag, a private registry, more operator replicas, an older cluster
// without user namespaces, and the generated-seccomp feature turned off. The
// point is that the guards below hold for a render nobody wrote them against.
const productionValues = `
image:
  repository: registry.example.internal/pahlevan
  tag: v9.9.9
  pullPolicy: Always
  pullSecrets:
    - name: registry-creds
operator:
  replicaCount: 3
  hostUsers: true
  podDisruptionBudget:
    enabled: true
    maxUnavailable: 1
  nodeSelector:
    node-role.kubernetes.io/control-plane: ""
  podAnnotations:
    example.com/injected: "false"
agent:
  seccomp:
    generate: false
  startupProbe:
    periodSeconds: 10
    failureThreshold: 30
  podAnnotations:
    example.com/injected: "false"
observability:
  exports: prometheus
`

// baseManifests is deploy/base as written, the kustomize base every overlay
// builds on.
func baseManifests(t *testing.T) []manifest {
	t.Helper()
	files, err := filepath.Glob(repoPath("deploy/base/*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("globbing deploy/base: %v", err)
	}
	sort.Strings(files)
	var out []manifest
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		rel, _ := filepath.Rel(repoRoot, f)
		out = append(out, splitManifests(t, rel, b)...)
	}
	return out
}

func installManifests(t *testing.T) []manifest {
	t.Helper()
	b, err := os.ReadFile(repoPath("install.yaml"))
	if err != nil {
		t.Fatalf("reading install.yaml: %v", err)
	}
	return splitManifests(t, "install.yaml", b)
}

// helmTemplateProduction renders the chart with productionValues. The file is
// written to a temp dir rather than committed so that it cannot be quietly
// edited into agreeing with a manifest that regressed.
func helmTemplateProduction(t *testing.T) []manifest {
	t.Helper()
	p := filepath.Join(t.TempDir(), "production.yaml")
	if err := os.WriteFile(p, []byte(productionValues), 0o644); err != nil {
		t.Fatalf("writing production values: %v", err)
	}
	return helmTemplate(t, "-f", p)
}

// eachSource runs fn over every shipped representation of the deployment.
// A property that holds in deploy/base and not in the chart is a property half
// the users do not get.
func eachSource(t *testing.T, fn func(t *testing.T, source string, ms []manifest)) {
	t.Helper()
	for _, s := range []struct {
		name string
		load func(*testing.T) []manifest
	}{
		{"deploy/base", baseManifests},
		{"install.yaml", installManifests},
		{"chart (default values)", func(t *testing.T) []manifest { return helmTemplate(t) }},
		{"chart (production values)", helmTemplateProduction},
	} {
		t.Run(s.name, func(t *testing.T) {
			ms := s.load(t)
			if len(ms) == 0 {
				t.Fatalf("%s produced no manifests, so every assertion below would pass vacuously", s.name)
			}
			fn(t, s.name, ms)
		})
	}
}

// ---------------------------------------------------------------------------
// Workloads.
// ---------------------------------------------------------------------------

type workload struct {
	manifest
	component string // "node-agent" or "control-plane"
	labels    map[string]string
	spec      corev1.PodSpec
	replicas  *int32
}

// workloads returns the agent and the operator from a manifest set, keyed by
// the component label both installers set. Matching on the label rather than
// on the object name is what lets the same assertions run against the chart,
// whose names carry the release prefix. The optional dashboard has its own
// guards in dashboard_test.go and is skipped here.
func workloads(t *testing.T, ms []manifest) map[string]workload {
	t.Helper()
	out := map[string]workload{}
	for _, m := range kinds(ms, "Deployment", "DaemonSet") {
		if strings.Contains(strings.ToLower(m.name), "dashboard") {
			continue
		}
		var d appsv1.Deployment // spec.template and spec.replicas decode the same for a DaemonSet
		if err := yaml.Unmarshal(m.raw, &d); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		c := d.Spec.Template.Labels["app.kubernetes.io/component"]
		if c == "" {
			t.Errorf("%s has no app.kubernetes.io/component label on its pod template; these guards key on it, and an unlabelled workload is one nothing here checks", m)
			continue
		}
		if prev, dup := out[c]; dup {
			t.Fatalf("two workloads claim component %q: %s and %s", c, prev, m)
		}
		out[c] = workload{manifest: m, component: c, labels: d.Spec.Template.Labels, spec: d.Spec.Template.Spec, replicas: d.Spec.Replicas}
	}
	for _, want := range []string{"node-agent", "control-plane"} {
		if _, ok := out[want]; !ok {
			t.Fatalf("no workload with component %q was found; the source changed shape and these guards stopped covering it", want)
		}
	}
	return out
}

func container(t *testing.T, w workload) corev1.Container {
	t.Helper()
	if len(w.spec.Containers) != 1 {
		t.Fatalf("%s has %d containers; these guards assume one and would silently skip the others", w, len(w.spec.Containers))
	}
	return w.spec.Containers[0]
}

// ---------------------------------------------------------------------------
// 1. Disruption: a drain or an upgrade must not take the control plane to zero.
// ---------------------------------------------------------------------------

func TestOperatorHasADisruptionBudget(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		op := workloads(t, ms)["control-plane"]

		var found []manifest
		for _, m := range kinds(ms, "PodDisruptionBudget") {
			var pdb policyv1.PodDisruptionBudget
			if err := yaml.Unmarshal(m.raw, &pdb); err != nil {
				t.Fatalf("parsing %s: %v", m, err)
			}
			sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
			if err != nil {
				t.Fatalf("%s has an unusable selector: %v", m, err)
			}
			if !sel.Matches(labels.Set(op.labels)) {
				continue
			}
			found = append(found, m)

			if pdb.Spec.MaxUnavailable == nil {
				t.Errorf("%s: %s uses minAvailable. At operator.replicaCount 1 that permits zero disruptions, so `kubectl drain` of that node blocks forever and scaling the operator down silently makes the cluster undrainable. maxUnavailable permits one eviction at a time at any replica count", source, m)
			} else if got := pdb.Spec.MaxUnavailable.IntValue(); got < 1 {
				t.Errorf("%s: %s sets maxUnavailable %v, which permits no disruption at all and wedges every drain", source, m, pdb.Spec.MaxUnavailable)
			}
		}

		if len(found) == 0 {
			t.Errorf("%s ships no PodDisruptionBudget covering the operator (pod labels %v). A cluster upgrade drains nodes back to back and the anti-affinity is only `preferred`, so both leader-elected replicas can go at once and no PahlevanPolicy is reconciled until one comes back and wins the lease", source, op.labels)
		}
		if len(found) > 1 {
			t.Errorf("%s: %d budgets match the operator's pods (%v). Overlapping budgets on one pod are evaluated together and the most restrictive wins, which is not what any of them says", source, len(found), found)
		}
	})
}

// A PodDisruptionBudget must NOT cover the agent. `kubectl drain` deletes
// DaemonSet pods rather than evicting them, so a budget would not protect the
// agent from a drain; what it would do is sit at zero allowed disruptions
// forever once a node is cordoned - a DaemonSet pod there can never become
// available again - and wedge the descheduler and the cluster autoscaler
// cluster-wide.
func TestNoDisruptionBudgetCoversTheAgent(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		agent := workloads(t, ms)["node-agent"]
		for _, m := range kinds(ms, "PodDisruptionBudget") {
			var pdb policyv1.PodDisruptionBudget
			if err := yaml.Unmarshal(m.raw, &pdb); err != nil {
				t.Fatalf("parsing %s: %v", m, err)
			}
			sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
			if err != nil {
				t.Fatalf("%s has an unusable selector: %v", m, err)
			}
			if sel.Matches(labels.Set(agent.labels)) {
				t.Errorf("%s: %s selects the agent DaemonSet's pods. A drain deletes DaemonSet pods instead of evicting them, so this protects nothing, and once a node is cordoned the budget can never be satisfied again and blocks every other eviction in the cluster", source, m)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 2. Scheduling: priority and taints.
// ---------------------------------------------------------------------------

func TestPriorityClassesSurviveNodePressure(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		w := workloads(t, ms)
		if got := w["node-agent"].spec.PriorityClassName; got != "system-node-critical" {
			t.Errorf("%s: the agent's priorityClassName is %q, want system-node-critical. The kubelet evicts by priority under node pressure, and an agent evicted before the pods it watches leaves those pods running with nothing enforcing against them - the node keeps its workloads and loses its monitor", source, got)
		}
		if got := w["control-plane"].spec.PriorityClassName; got == "" {
			t.Errorf("%s: the operator has no priorityClassName, so it is an ordinary Burstable pod and is evicted under node pressure ahead of every workload that declared one. While no replica holds the lease, no PahlevanPolicy is reconciled", source)
		}
	})
}

// The agent has to run on every node it is meant to protect, and the nodes
// most worth protecting are the ones carrying taints: control-plane, dedicated
// pools, nodes under a custom NoExecute. A toleration with no key and operator
// Exists is the only form that covers taints this repo has never heard of.
func TestAgentToleratesEveryTaint(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		w := workloads(t, ms)
		var universal bool
		for _, tol := range w["node-agent"].spec.Tolerations {
			if tol.Key == "" && tol.Operator == corev1.TolerationOpExists && tol.Effect == "" {
				universal = true
			}
		}
		if !universal {
			t.Errorf("%s: the agent's tolerations %v do not include an unqualified {operator: Exists}. It will not be scheduled on control-plane nodes or on any tainted pool, and those nodes then run with no enforcement and no record while the DaemonSet reports itself fully rolled out", source, w["node-agent"].spec.Tolerations)
		}

		var cp bool
		for _, tol := range w["control-plane"].spec.Tolerations {
			if tol.Key == "node-role.kubernetes.io/control-plane" || (tol.Key == "" && tol.Operator == corev1.TolerationOpExists) {
				cp = true
			}
		}
		if !cp {
			t.Errorf("%s: the operator tolerates no control-plane taint (%v); on a cluster whose only schedulable nodes are control-plane nodes it stays Pending", source, w["control-plane"].spec.Tolerations)
		}
	})
}

// Two replicas on one node is one node failure away from no control plane, and
// it is also the case the PodDisruptionBudget has to work hardest to cover.
// `preferred` rather than `required` on purpose: a single-node cluster must
// still be able to schedule both.
func TestOperatorReplicasPreferSeparateNodes(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		op := workloads(t, ms)["control-plane"]
		if op.replicas != nil && *op.replicas < 2 {
			t.Skipf("%s runs a single operator replica; spreading is meaningless", source)
		}
		replicas := int32(1)
		if op.replicas != nil {
			replicas = *op.replicas
		}
		aff := op.spec.Affinity
		if aff == nil || aff.PodAntiAffinity == nil {
			t.Fatalf("%s: the operator runs %d replicas with no podAntiAffinity, so the scheduler is free to put them all on one node and a single node failure takes the whole control plane", source, replicas)
		}
		var ok bool
		for _, term := range aff.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution {
			if term.PodAffinityTerm.TopologyKey == "kubernetes.io/hostname" {
				ok = true
			}
		}
		for _, term := range aff.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
			if term.TopologyKey == "kubernetes.io/hostname" {
				t.Errorf("%s: the operator's anti-affinity is `required` on hostname. On a single-node cluster - kind, a laptop, CI - every replica after the first stays Pending forever", source)
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: the operator's podAntiAffinity does not spread on kubernetes.io/hostname", source)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. Probes.
// ---------------------------------------------------------------------------

func TestProbesSurviveASlowStartup(t *testing.T) {
	budgets := map[string]int32{
		"node-agent":    agentStartupBudgetSeconds,
		"control-plane": operatorStartupBudgetSeconds,
	}
	why := map[string]string{
		"node-agent":    "the agent loads and attaches its eBPF programs before it builds the manager that serves the health port, so nothing listens there for the whole of BTF parse, CO-RE relocation and verification. A liveness probe firing in that window kills a container that is starting normally, and it does so again on every restart",
		"control-plane": "the probe server does not bind until mgr.Start, after the caches are built; on a cluster whose CRDs were applied moments earlier that outlasts three liveness failures",
	}

	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		for component, w := range workloads(t, ms) {
			c := container(t, w)

			if c.StartupProbe == nil {
				t.Errorf("%s: %s has no startupProbe. %s", source, w, why[component])
				continue
			}
			period := c.StartupProbe.PeriodSeconds
			if period == 0 {
				period = 10 // kubelet default
			}
			threshold := c.StartupProbe.FailureThreshold
			if threshold == 0 {
				threshold = 3 // kubelet default
			}
			if got := period * threshold; got < budgets[component] {
				t.Errorf("%s: %s allows %ds to start (periodSeconds %d x failureThreshold %d), want at least %ds. %s", source, w, got, period, threshold, budgets[component], why[component])
			}

			for name, p := range map[string]*corev1.Probe{"livenessProbe": c.LivenessProbe, "readinessProbe": c.ReadinessProbe} {
				if p == nil {
					t.Errorf("%s: %s has no %s. Without a liveness probe a wedged process is never restarted; without a readiness probe the Service keeps sending to a pod that cannot answer and the PodDisruptionBudget counts it as available", source, w, name)
					continue
				}
				if p.TimeoutSeconds < minProbeTimeoutSeconds {
					t.Errorf("%s: %s %s has timeoutSeconds %d (0 means the 1s default), want at least %d. One second is shorter than a stop-the-world pause on a loaded node, and a timed-out liveness probe is a kill", source, w, name, p.TimeoutSeconds, minProbeTimeoutSeconds)
				}
				if p.FailureThreshold < minProbeFailureThreshold {
					t.Errorf("%s: %s %s has failureThreshold %d (0 means the 3 default), want at least %d, so that one missed probe is never fatal", source, w, name, p.FailureThreshold, minProbeFailureThreshold)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 4. Resources. The agent's floor is read from the BPF map bound the project
//    measures on a live kernel, so the two cannot drift apart.
// ---------------------------------------------------------------------------

// bpfMapCeilingMiB is the map footprint pkg/ebpf/vmload_test.go loads all the
// programs and measures with bpftool, failing above its own bound. Since
// kernel 5.11 BPF map memory is charged to the memcg of the process that
// created the map, so that whole footprint comes out of the agent container's
// memory limit and a limit below it is an OOM kill during startup, before a
// single event is read.
func bpfMapCeilingMiB(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile(repoPath("pkg/ebpf/vmload_test.go"))
	if err != nil {
		t.Fatalf("reading the BPF map footprint guard: %v", err)
	}
	m := regexp.MustCompile(`if mib > (\d+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("pkg/ebpf/vmload_test.go no longer bounds the measured BPF map footprint, so the agent's memory request has nothing to be sized against")
	}
	n, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestResourcesAreSetAndFitTheBPFMaps(t *testing.T) {
	mapFloor := resource.MustParse(fmt.Sprintf("%dMi", bpfMapCeilingMiB(t)))

	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		for component, w := range workloads(t, ms) {
			c := container(t, w)
			for _, res := range []struct {
				kind string
				list corev1.ResourceList
			}{{"requests", c.Resources.Requests}, {"limits", c.Resources.Limits}} {
				for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
					if q, ok := res.list[name]; !ok || q.IsZero() {
						t.Errorf("%s: %s sets no %s.%s. Without a request the scheduler cannot reserve for it and the pod is BestEffort, first in line for the OOM killer; without a limit one bad node can starve everything else on it", source, w, res.kind, name)
					}
				}
			}

			req, lim := c.Resources.Requests.Memory(), c.Resources.Limits.Memory()
			if lim.Cmp(*req) < 0 {
				t.Errorf("%s: %s has a memory limit (%s) below its request (%s), which the API server rejects outright", source, w, lim, req)
			}

			if component != "node-agent" {
				continue
			}
			// The agent is the one that pays for the maps.
			if req.Cmp(mapFloor) < 0 {
				t.Errorf("%s: %s requests %s of memory, which is below the %s of BPF maps pkg/ebpf/vmload_test.go measures on a live kernel. Those maps are charged to this container's memcg on kernel 5.11+, so the pod can be scheduled onto a node that cannot hold it and is OOM-killed at map creation", source, w, req, &mapFloor)
			}
			if lim.Cmp(mapFloor) <= 0 {
				t.Errorf("%s: %s limits memory to %s, leaving nothing above the %s of BPF maps for the Go heap and the controller-runtime cache it holds over every pod, node and workload in the cluster", source, w, lim, &mapFloor)
			}
		}
	})
}

// GOMAXPROCS from the CPU limit. Without it the Go runtime sizes its scheduler
// from the node's core count - 128 on a big machine - while the cgroup allows
// a fraction of one core, and the result is permanent throttling plus a stack
// for every P that never runs.
func TestAgentPinsGOMAXPROCSToItsLimit(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		c := container(t, workloads(t, ms)["node-agent"])
		for _, e := range c.Env {
			if e.Name != "GOMAXPROCS" {
				continue
			}
			if e.ValueFrom == nil || e.ValueFrom.ResourceFieldRef == nil ||
				!strings.HasPrefix(e.ValueFrom.ResourceFieldRef.Resource, "limits.cpu") {
				t.Errorf("%s: %s sets GOMAXPROCS from something other than limits.cpu (%+v); a hardcoded value goes wrong the moment the limit is tuned", source, workloads(t, ms)["node-agent"], e)
			}
			return
		}
		t.Errorf("%s: the agent does not set GOMAXPROCS from its CPU limit, so the Go runtime sizes itself from the node's core count while the cgroup allows a fraction of a core", source)
	})
}

// ---------------------------------------------------------------------------
// 5. Termination.
// ---------------------------------------------------------------------------

// observabilityFlushSeconds is the deadline the agent's final metric and span
// flush gets, read from where it is declared so the two cannot drift.
func observabilityFlushSeconds(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile(repoPath("pkg/observability/manager.go"))
	if err != nil {
		t.Fatalf("reading the observability manager: %v", err)
	}
	m := regexp.MustCompile(`shutdownTimeout\s*=\s*(\d+)\s*\*\s*time\.Second`).FindSubmatch(b)
	if m == nil {
		t.Fatal("pkg/observability/manager.go no longer declares shutdownTimeout as a whole number of seconds, so the grace period has nothing to be sized against")
	}
	n, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// On SIGTERM both binaries unwind in stages: controller-runtime stops its
// runnables under its own 30s default, then the deferred closers run (for the
// agent, detaching the eBPF links), then observability flushes what it has
// buffered. A grace period shorter than the sum is a SIGKILL partway through:
// for the agent that leaves links attached behind a dead ring-buffer reader,
// and for the operator it skips the leader-election release, so the standby
// waits out the whole lease with nothing reconciling.
func TestTerminationGraceCoversTheShutdownPath(t *testing.T) {
	need := int64(crGracefulShutdownSeconds) + observabilityFlushSeconds(t)

	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		for _, w := range workloads(t, ms) {
			g := w.spec.TerminationGracePeriodSeconds
			if g == nil {
				t.Errorf("%s: %s leaves terminationGracePeriodSeconds unset, which is 30 - exactly the manager's own shutdown budget, with nothing left for the %ds flush that follows it", source, w, observabilityFlushSeconds(t))
				continue
			}
			if *g < need {
				t.Errorf("%s: %s allows %ds to stop, but the shutdown path is %ds of controller-runtime graceful shutdown plus %ds of observability flush = %ds. The kubelet SIGKILLs partway through", source, w, *g, crGracefulShutdownSeconds, observabilityFlushSeconds(t), need)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 6. Security context.
// ---------------------------------------------------------------------------

// agentCapabilities is the set the agent may hold. CAP_BPF + CAP_PERFMON is
// the modern least-privilege pair (kernel 5.8+); SYS_ADMIN and SYS_RESOURCE
// cover older kernels and map operations; NET_ADMIN covers the network hooks.
// Anything outside this list is privilege nobody reviewed.
var agentCapabilities = map[corev1.Capability]bool{
	"BPF": true, "PERFMON": true, "SYS_ADMIN": true, "SYS_RESOURCE": true, "NET_ADMIN": true,
}

func TestSecurityContextsAreAsTightAsEachComponentAllows(t *testing.T) {
	eachSource(t, func(t *testing.T, source string, ms []manifest) {
		w := workloads(t, ms)

		// --- The operator holds no privilege at all, and that is checkable. ---
		op := w["control-plane"]
		opc := container(t, op)
		if op.spec.HostPID || op.spec.HostNetwork || op.spec.HostIPC {
			t.Errorf("%s: %s shares a host namespace (hostPID=%v hostNetwork=%v hostIPC=%v). The operator talks to the API server and nothing else; a host namespace here is blast radius with no purpose", source, op, op.spec.HostPID, op.spec.HostNetwork, op.spec.HostIPC)
		}
		for _, v := range op.spec.Volumes {
			if v.HostPath != nil {
				t.Errorf("%s: %s mounts hostPath %q; the operator needs no path into the node's filesystem", source, op, v.HostPath.Path)
			}
		}
		if op.spec.SecurityContext == nil || op.spec.SecurityContext.RunAsNonRoot == nil || !*op.spec.SecurityContext.RunAsNonRoot {
			t.Errorf("%s: %s does not set runAsNonRoot on the pod, so a container escape starts as root on the node", source, op)
		}
		if op.spec.SecurityContext == nil || op.spec.SecurityContext.SeccompProfile == nil ||
			op.spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("%s: %s does not set seccompProfile RuntimeDefault. The operator needs no unusual syscall and there is nothing to trade away by confining it", source, op)
		}
		if sc := opc.SecurityContext; sc == nil {
			t.Errorf("%s: %s has no container securityContext", source, op)
		} else {
			if sc.Privileged != nil && *sc.Privileged {
				t.Errorf("%s: %s is privileged; it needs no privilege whatsoever", source, op)
			}
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				t.Errorf("%s: %s allows privilege escalation, so a setuid binary in the image undoes runAsNonRoot", source, op)
			}
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				t.Errorf("%s: %s has a writable root filesystem, which lets a code-execution bug persist across the restart that would otherwise clear it", source, op)
			}
			if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				t.Errorf("%s: %s does not set runAsNonRoot on the container", source, op)
			}
			if sc.Capabilities == nil || !containsCap(sc.Capabilities.Drop, "ALL") {
				t.Errorf("%s: %s does not drop ALL capabilities", source, op)
			}
			if sc.Capabilities != nil && len(sc.Capabilities.Add) > 0 {
				t.Errorf("%s: %s adds capabilities %v. The operator does not load eBPF, does not touch the kernel and does not need one of them", source, op, sc.Capabilities.Add)
			}
		}

		// --- The agent genuinely needs privilege. What it must NOT do is take
		// more than it needs, or lose the parts that are still tightenable. ---
		ag := w["node-agent"]
		agc := container(t, ag)
		if ag.spec.HostNetwork {
			t.Errorf("%s: %s sets hostNetwork. The agent reads the kernel; it does not need the node's network namespace, and taking it puts its metrics and health ports straight onto the node's address", source, ag)
		}
		if ag.spec.HostIPC {
			t.Errorf("%s: %s sets hostIPC, which it has no use for", source, ag)
		}
		sc := agc.SecurityContext
		if sc == nil {
			t.Fatalf("%s: %s has no securityContext, so it runs with whatever the runtime defaults to", source, ag)
		}
		if sc.Privileged != nil && *sc.Privileged {
			t.Errorf("%s: %s is privileged: true. That is every capability plus unrestricted device access, and it is not needed - the named capability set below is what eBPF load and attach actually require", source, ag)
		}
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Errorf("%s: %s has a writable root filesystem. This is the one component an attacker most wants to persist inside", source, ag)
		}
		if sc.Capabilities == nil || !containsCap(sc.Capabilities.Drop, "ALL") {
			t.Errorf("%s: %s does not drop ALL before adding back what it needs, so it keeps the runtime's default capability set as well", source, ag)
		}
		if sc.Capabilities != nil {
			for _, c := range sc.Capabilities.Add {
				if !agentCapabilities[c] {
					t.Errorf("%s: %s adds %s, which is outside the reviewed set %v. eBPF load and attach need BPF, PERFMON and the older-kernel fallbacks; anything else is privilege that arrived without a reason", source, ag, c, capNames())
				}
			}
		}
		// Pinned, not omitted. Omitted means Unconfined today, but a node
		// started with --seccomp-default turns it into RuntimeDefault, whose
		// profile gates bpf(2) and perf_event_open(2) on the capability set -
		// so the agent fails program load with EPERM on that cluster only,
		// for a reason nothing in the manifest would explain.
		effective := agc.SecurityContext.SeccompProfile
		if effective == nil && ag.spec.SecurityContext != nil {
			effective = ag.spec.SecurityContext.SeccompProfile
		}
		if effective == nil {
			t.Errorf("%s: %s pins no seccompProfile. Unset is Unconfined on most nodes and RuntimeDefault on a node started with --seccomp-default, and the agent behaves differently on the two", source, ag)
		}
	})
}

// ---------------------------------------------------------------------------
// 7. Chart correctness.
// ---------------------------------------------------------------------------

// Helm installs the files in crds/ and never templates them, so a CRD missing
// there is a CRD the chart simply does not create. The agent and the operator
// both run controllers over all three kinds; a manager whose informer cannot
// list its type never syncs and exits after the cache timeout, which is a
// crash loop with a message about caches rather than about a missing CRD.
//
// The chart shipped exactly one of the three, and that one was a hand-written
// copy generated by an older controller-gen than the real thing - so even the
// kind it did install had a schema the API server would prune fields against.
func TestChartShipsEveryCRDTheControllersWatch(t *testing.T) {
	generated, err := filepath.Glob(repoPath("config/crd/*.yaml"))
	if err != nil || len(generated) == 0 {
		t.Fatalf("globbing config/crd: %v", err)
	}
	for _, src := range generated {
		want, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		dst := repoPath(filepath.Join("charts/pahlevan-operator/crds", filepath.Base(src)))
		got, err := os.ReadFile(dst)
		if os.IsNotExist(err) {
			t.Errorf("the chart does not ship %s. Helm never templates crds/, so this kind is simply not created by `helm install`, and the controller that watches it exits when its informer cannot sync. Run: cp config/crd/*.yaml charts/pahlevan-operator/crds/", filepath.Base(src))
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("charts/pahlevan-operator/crds/%s differs from the generated config/crd copy. A hand-maintained CRD goes stale silently: the API server prunes any field the shipped schema does not describe, so a policy applies cleanly and does nothing. Run: cp config/crd/*.yaml charts/pahlevan-operator/crds/", filepath.Base(src))
		}
	}
	// And nothing extra, which is how the stale hand-written copy survived.
	extra, _ := filepath.Glob(repoPath("charts/pahlevan-operator/crds/*.yaml"))
	for _, f := range extra {
		if _, err := os.Stat(repoPath(filepath.Join("config/crd", filepath.Base(f)))); os.IsNotExist(err) {
			t.Errorf("charts/pahlevan-operator/crds/%s has no counterpart in config/crd, so it is a hand-maintained CRD nothing regenerates", filepath.Base(f))
		}
	}
}

// The chart's RBAC must grant at least what deploy/base grants. It did not:
// the agent's ClusterRole was missing namespaces, services, the apps workload
// kinds and networkpolicies, all of which its controllers list. The base
// carries a comment recording what that costs - four restarts in ten minutes,
// each wiping the learned baseline - and a Helm install hit it while a kubectl
// apply of the same release did not.
func TestChartRBACGrantsEverythingTheBaseDoes(t *testing.T) {
	baseRoles := clusterRoleRules(t, baseManifests(t))
	for _, src := range []struct {
		name string
		ms   []manifest
	}{
		{"chart (default values)", helmTemplate(t)},
		{"chart (production values)", helmTemplateProduction(t)},
	} {
		chartRoles := clusterRoleRules(t, src.ms)
		for component, want := range baseRoles {
			got, ok := chartRoles[component]
			if !ok {
				t.Errorf("%s renders no ClusterRole for %s", src.name, component)
				continue
			}
			for key, verbs := range want {
				for _, v := range verbs {
					if !contains(got[key], v) {
						t.Errorf("%s: the %s ClusterRole is missing %q on %s, which deploy/base grants. The controller that lists it cannot sync its informer, and the manager exits after the cache timeout - a crash loop that says nothing about RBAC", src.name, component, v, key)
					}
				}
			}
		}
	}
}

// clusterRoleRules flattens the agent's and operator's ClusterRoles into
// {component: {"apiGroup/resource": verbs}}. Keyed on the component the role
// name ends in, so the chart's release-prefixed names line up with the base's.
func clusterRoleRules(t *testing.T, ms []manifest) map[string]map[string][]string {
	t.Helper()
	out := map[string]map[string][]string{}
	for _, m := range kinds(ms, "ClusterRole") {
		var component string
		switch {
		case strings.HasSuffix(m.name, "-agent"):
			component = "agent"
		case strings.HasSuffix(m.name, "-operator"):
			component = "operator"
		default:
			continue
		}
		var role rbacv1.ClusterRole
		if err := yaml.Unmarshal(m.raw, &role); err != nil {
			t.Fatalf("parsing %s: %v", m, err)
		}
		if out[component] == nil {
			out[component] = map[string][]string{}
		}
		for _, r := range role.Rules {
			for _, g := range r.APIGroups {
				for _, res := range r.Resources {
					key := g + "/" + res
					out[component][key] = append(out[component][key], r.Verbs...)
				}
			}
		}
	}
	return out
}

// Whatever `helm template` prints has to be objects a cluster accepts. This
// catches the indentation mistakes a `{{- toYaml . | nindent }}` makes when a
// value's shape changes, which lint does not see because lint renders with the
// defaults only.
func TestChartRendersValidObjects(t *testing.T) {
	for _, src := range []struct {
		name string
		ms   []manifest
	}{
		{"default values", helmTemplate(t)},
		{"production values", helmTemplateProduction(t)},
		{"dashboard enabled", helmTemplate(t, "--set", "dashboard.enabled=true")},
		{"agent disabled", helmTemplate(t, "--set", "agent.enabled=false")},
		{"operator disabled", helmTemplate(t, "--set", "operator.enabled=false")},
	} {
		if len(src.ms) == 0 && src.name != "agent disabled" && src.name != "operator disabled" {
			t.Errorf("%s rendered nothing", src.name)
		}
		for _, m := range src.ms {
			var obj struct {
				APIVersion string            `json:"apiVersion"`
				Kind       string            `json:"kind"`
				Metadata   map[string]any    `json:"metadata"`
				Labels     map[string]string `json:"-"`
			}
			if err := yaml.Unmarshal(m.raw, &obj); err != nil {
				t.Errorf("%s: %s does not parse: %v", src.name, m, err)
				continue
			}
			if obj.APIVersion == "" || obj.Kind == "" {
				t.Errorf("%s: %s has no apiVersion/kind, so kubectl would reject the whole stream", src.name, m)
			}
			if obj.Metadata["name"] == nil || obj.Metadata["name"] == "" {
				t.Errorf("%s: %s has no metadata.name", src.name, m)
			}
		}
	}
	// Turning a component off has to remove its objects, not render an empty
	// husk: a ServiceAccount with a cluster-wide read binding and no pod is
	// still a credential sitting in the cluster.
	for _, tc := range []struct{ flag, forbid string }{
		{"agent.enabled=false", "node-agent"},
		{"operator.enabled=false", "control-plane"},
	} {
		for _, m := range helmTemplate(t, "--set", tc.flag) {
			if strings.Contains(string(m.raw), "app.kubernetes.io/component: "+tc.forbid) {
				t.Errorf("--set %s still renders %s", tc.flag, m)
			}
		}
	}
}

// The chart README shipped a values table for a chart that did not exist:
// enforcement.mode, learning.duration, webhooks.*, development.*, compliance.*
// and a podDisruptionBudget block, none of which any template read. Helm
// accepts --set for a key nothing uses without a word of complaint, so an
// operator following that table got a cluster configured exactly as it was
// before and no way to tell. Every dotted key the README names in backticks
// has to resolve in values.yaml.
func TestChartREADMEOnlyNamesRealValues(t *testing.T) {
	b, err := os.ReadFile(repoPath("charts/pahlevan-operator/README.md"))
	if err != nil {
		t.Fatalf("reading the chart README: %v", err)
	}
	// Fenced blocks hold kubectl and helm commands, not values keys.
	doc := regexp.MustCompile("(?s)```.*?```").ReplaceAllString(string(b), "")

	vb, err := os.ReadFile(repoPath("charts/pahlevan-operator/values.yaml"))
	if err != nil {
		t.Fatalf("reading values.yaml: %v", err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(vb, &values); err != nil {
		t.Fatalf("parsing values.yaml: %v", err)
	}

	dotted := regexp.MustCompile("`([a-z][A-Za-z0-9]*(?:\\.[A-Za-z0-9_*]+)+)`")
	var checked int
	for _, m := range dotted.FindAllStringSubmatch(doc, -1) {
		parts := strings.Split(m[1], ".")
		if _, top := values[parts[0]]; !top {
			continue // not a values path at all (a filename, a label, an image tag)
		}
		checked++
		cur := any(values)
		for i, part := range parts {
			if part == "*" {
				break // "dashboard.image.*" stands for the whole subtree
			}
			node, ok := cur.(map[string]any)
			if !ok {
				t.Errorf("the chart README documents `%s`, but %s in values.yaml is not a map, so that key cannot exist", m[1], strings.Join(parts[:i], "."))
				break
			}
			v, ok := node[part]
			if !ok {
				t.Errorf("the chart README documents `%s`, which is not in values.yaml. `--set %s=...` is accepted by Helm and read by nothing, so it looks exactly like a setting that had no effect", m[1], m[1])
				break
			}
			cur = v
		}
	}
	if checked < 20 {
		t.Errorf("only %d values keys were found in the chart README; either it stopped documenting the chart or this guard stopped recognising the table", checked)
	}
}

// ---------------------------------------------------------------------------

func containsCap(caps []corev1.Capability, want corev1.Capability) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func capNames() []string {
	out := make([]string, 0, len(agentCapabilities))
	for c := range agentCapabilities {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}

func BenchmarkWorkloadGuards(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "install.yaml"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := &testing.T{}
		ms := splitManifests(t, "install.yaml", raw)
		for _, m := range kinds(ms, "Deployment", "DaemonSet") {
			var d appsv1.Deployment
			if err := yaml.Unmarshal(m.raw, &d); err != nil {
				b.Fatal(err)
			}
		}
	}
}
