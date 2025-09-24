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

package controller

import (
	"context"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"
	"github.com/obsernetics/pahlevan/pkg/visualization"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// AttackSurfaceAnalyzerReconciler manages cluster-wide attack surface analysis
type AttackSurfaceAnalyzerReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	EBPFManager           *ebpf.Manager
	MetricsManager        *metrics.Manager
	ObservabilityManager  *observability.Manager
	AttackSurfaceAnalyzer *visualization.AttackSurfaceAnalyzer
	AnalysisInterval      time.Duration
	LastFullAnalysis      time.Time
}

//+kubebuilder:rbac:groups="",resources=pods;services;configmaps;secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=deployments;replicasets;daemonsets;statefulsets,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies;ingresses,verbs=get;list;watch
//+kubebuilder:rbac:groups=policy.pahlevan.io,resources=pahlevanpolicies,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;update;patch

func (r *AttackSurfaceAnalyzerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// This controller performs cluster-wide analysis, so we don't reconcile specific resources
	// Instead, we trigger analysis based on timing and significant cluster changes

	shouldAnalyze := false

	// Check if enough time has passed since last analysis
	if time.Since(r.LastFullAnalysis) >= r.AnalysisInterval {
		shouldAnalyze = true
		logger.Info("Triggering attack surface analysis due to time interval")
	}

	// Check if this is a significant resource change that warrants immediate analysis
	if r.isSignificantChange(ctx, req) {
		shouldAnalyze = true
		logger.Info("Triggering attack surface analysis due to significant change", "resource", req.NamespacedName)
	}

	if shouldAnalyze {
		if err := r.performClusterAnalysis(ctx); err != nil {
			logger.Error(err, "Failed to perform cluster attack surface analysis")
			return ctrl.Result{RequeueAfter: 5 * time.Minute}, err
		}
		r.LastFullAnalysis = time.Now()
	}

	// Requeue for next analysis interval
	return ctrl.Result{RequeueAfter: r.AnalysisInterval}, nil
}

func (r *AttackSurfaceAnalyzerReconciler) performClusterAnalysis(ctx context.Context) error {
	logger := log.FromContext(ctx)
	logger.Info("Starting cluster-wide attack surface analysis")

	startTime := time.Now()

	// Perform comprehensive cluster analysis
	clusterGraph, err := r.AttackSurfaceAnalyzer.AnalyzeClusterAttackSurface()
	if err != nil {
		return err
	}

	// Analyze individual workloads
	if err := r.analyzeWorkloads(ctx); err != nil {
		logger.Error(err, "Failed to analyze workloads")
	}

	// Update metrics
	analysisTime := time.Since(startTime)
	logger.Info("Completed cluster attack surface analysis",
		"duration", analysisTime,
		"riskScore", clusterGraph.RiskAggregation.TotalRiskScore,
		"nodes", len(clusterGraph.Nodes),
		"edges", len(clusterGraph.Edges))

	// Export analysis results
	if err := r.exportAnalysisResults(ctx, clusterGraph); err != nil {
		logger.Error(err, "Failed to export analysis results")
	}

	return nil
}

func (r *AttackSurfaceAnalyzerReconciler) analyzeWorkloads(ctx context.Context) error {
	logger := log.FromContext(ctx)

	// Get all PahlevanPolicies to determine which workloads to analyze
	policies := &policyv1alpha1.PahlevanPolicyList{}
	if err := r.List(ctx, policies, &client.ListOptions{}); err != nil {
		return err
	}

	for _, policy := range policies.Items {
		// Find workloads targeted by this policy
		workloads, err := r.getTargetWorkloads(ctx, &policy)
		if err != nil {
			logger.Error(err, "Failed to get target workloads", "policy", policy.Name)
			continue
		}

		for _, workload := range workloads {
			workloadRef := learner.WorkloadReference{
				APIVersion: workload.GetObjectKind().GroupVersionKind().GroupVersion().String(),
				Kind:       workload.GetObjectKind().GroupVersionKind().Kind,
				Name:       workload.GetName(),
				Namespace:  workload.GetNamespace(),
				UID:        string(workload.GetUID()),
			}

			// Analyze attack surface for this workload
			surface, err := r.AttackSurfaceAnalyzer.AnalyzeWorkloadAttackSurface(workloadRef)
			if err != nil {
				logger.Error(err, "Failed to analyze workload attack surface", "workload", workloadRef.Name)
				continue
			}

			// Update policy status with attack surface information
			r.updatePolicyWithAttackSurface(&policy, surface)
		}

		// Update policy status
		if err := r.Status().Update(ctx, &policy); err != nil {
			logger.Error(err, "Failed to update policy status", "policy", policy.Name)
		}
	}

	return nil
}

func (r *AttackSurfaceAnalyzerReconciler) getTargetWorkloads(ctx context.Context, policy *policyv1alpha1.PahlevanPolicy) ([]client.Object, error) {
	var workloads []client.Object

	// Get Deployments
	deployments := &appsv1.DeploymentList{}
	if err := r.List(ctx, deployments, &client.ListOptions{Namespace: policy.Namespace}); err != nil {
		return nil, err
	}

	for _, deployment := range deployments.Items {
		if r.matchesSelector(deployment.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &deployment)
		}
	}

	// Get StatefulSets
	statefulSets := &appsv1.StatefulSetList{}
	if err := r.List(ctx, statefulSets, &client.ListOptions{Namespace: policy.Namespace}); err != nil {
		return nil, err
	}

	for _, sts := range statefulSets.Items {
		if r.matchesSelector(sts.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &sts)
		}
	}

	// Get DaemonSets
	daemonSets := &appsv1.DaemonSetList{}
	if err := r.List(ctx, daemonSets, &client.ListOptions{Namespace: policy.Namespace}); err != nil {
		return nil, err
	}

	for _, ds := range daemonSets.Items {
		if r.matchesSelector(ds.Labels, policy.Spec.Selector) {
			workloads = append(workloads, &ds)
		}
	}

	return workloads, nil
}

func (r *AttackSurfaceAnalyzerReconciler) updatePolicyWithAttackSurface(policy *policyv1alpha1.PahlevanPolicy, surface *visualization.WorkloadAttackSurface) {
	if policy.Status.AttackSurface == nil {
		policy.Status.AttackSurface = &policyv1alpha1.AttackSurfaceStatus{}
	}

	// Update exposed syscalls
	var exposedSyscalls []string
	for _, container := range surface.Containers {
		if container.SyscallExposure != nil {
			// Use the available syscall data from SyscallExposureAnalysis
			exposedSyscalls = append(exposedSyscalls, container.SyscallExposure.RiskySyscalls...)
		}
	}
	policy.Status.AttackSurface.ExposedSyscalls = exposedSyscalls

	// Update exposed ports
	var exposedPorts []int32
	if surface.ServiceExposure != nil {
		for _, port := range surface.ServiceExposure.Ports {
			exposedPorts = append(exposedPorts, port.Port)
		}
	}
	policy.Status.AttackSurface.ExposedPorts = exposedPorts

	// Update writable files
	var writableFiles []string
	for _, container := range surface.Containers {
		if container.FileSystemExposure != nil {
			writableFiles = append(writableFiles, container.FileSystemExposure.WritablePaths...)
		}
	}
	policy.Status.AttackSurface.WritableFiles = writableFiles

	// Update capabilities
	var capabilities []string
	for _, container := range surface.Containers {
		if container.CapabilityAnalysis != nil {
			capabilities = append(capabilities, container.CapabilityAnalysis.Added...)
			capabilities = append(capabilities, container.CapabilityAnalysis.Risky...)
		}
	}
	policy.Status.AttackSurface.Capabilities = capabilities

	// Update risk score
	riskScore := int32(surface.OverallRiskScore)
	policy.Status.AttackSurface.RiskScore = &riskScore

	// Update last analysis time
	now := metav1.Now()
	policy.Status.AttackSurface.LastAnalysis = &now
}

func (r *AttackSurfaceAnalyzerReconciler) exportAnalysisResults(ctx context.Context, clusterGraph *visualization.ClusterAttackSurfaceGraph) error {
	// Export to various formats

	// Export to JSON for debugging/storage
	jsonData, err := r.AttackSurfaceAnalyzer.ExportToFormat(visualization.ExportFormatJSON)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to export to JSON")
	} else {
		// Store JSON data (could be saved to ConfigMap, sent to external system, etc.)
		_ = jsonData
	}

	// Export to Grafana format
	grafanaData, err := r.AttackSurfaceAnalyzer.ExportToFormat(visualization.ExportFormatGrafana)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to export to Grafana")
	} else {
		_ = grafanaData
	}

	// Export to Mermaid diagram
	mermaidData, err := r.AttackSurfaceAnalyzer.ExportToFormat(visualization.ExportFormatMermaid)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to export to Mermaid")
	} else {
		_ = mermaidData
	}

	// Update observability metrics
	if r.ObservabilityManager != nil {
		_, err := r.ObservabilityManager.ExportObservabilityData()
		if err != nil {
			log.FromContext(ctx).Error(err, "Failed to export observability data")
		}
	}

	return nil
}

func (r *AttackSurfaceAnalyzerReconciler) isSignificantChange(ctx context.Context, req ctrl.Request) bool {
	// Determine if this resource change is significant enough to trigger immediate analysis

	// Get the resource that changed
	var resource client.Object

	// Try different resource types
	pod := &corev1.Pod{}
	if r.Get(ctx, req.NamespacedName, pod) == nil {
		resource = pod
	} else {
		svc := &corev1.Service{}
		if r.Get(ctx, req.NamespacedName, svc) == nil {
			resource = svc
		} else {
			deployment := &appsv1.Deployment{}
			if r.Get(ctx, req.NamespacedName, deployment) == nil {
				resource = deployment
			} else {
				netpol := &networkingv1.NetworkPolicy{}
				if r.Get(ctx, req.NamespacedName, netpol) == nil {
					resource = netpol
				} else {
					policy := &policyv1alpha1.PahlevanPolicy{}
					if r.Get(ctx, req.NamespacedName, policy) == nil {
						resource = policy
					}
				}
			}
		}
	}

	if resource == nil {
		return false
	}

	// Check if this resource type warrants immediate analysis
	switch resource.(type) {
	case *corev1.Service:
		// Service changes can affect attack surface
		return true
	case *networkingv1.NetworkPolicy:
		// Network policy changes definitely affect attack surface
		return true
	case *policyv1alpha1.PahlevanPolicy:
		// Policy changes should trigger analysis
		return true
	case *appsv1.Deployment, *appsv1.StatefulSet, *appsv1.DaemonSet:
		// Workload changes might affect attack surface
		return true
	}

	return false
}

func (r *AttackSurfaceAnalyzerReconciler) matchesSelector(labels map[string]string, selector policyv1alpha1.LabelSelector) bool {
	// Check matchLabels
	for key, value := range selector.MatchLabels {
		if labels[key] != value {
			return false
		}
	}

	// Check matchExpressions
	for _, expr := range selector.MatchExpressions {
		labelValue, exists := labels[expr.Key]

		switch expr.Operator {
		case policyv1alpha1.LabelSelectorOpIn:
			if !exists {
				return false
			}
			found := false
			for _, value := range expr.Values {
				if labelValue == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case policyv1alpha1.LabelSelectorOpNotIn:
			if exists {
				for _, value := range expr.Values {
					if labelValue == value {
						return false
					}
				}
			}
		case policyv1alpha1.LabelSelectorOpExists:
			if !exists {
				return false
			}
		case policyv1alpha1.LabelSelectorOpDoesNotExist:
			if exists {
				return false
			}
		}
	}

	return true
}

func (r *AttackSurfaceAnalyzerReconciler) syscallNumberToName(nr uint64) string {
	// Comprehensive syscall number to name mapping (Linux x86_64)
	names := map[uint64]string{
		// File operations
		0:   "read",
		1:   "write",
		2:   "open",
		3:   "close",
		8:   "lseek",
		9:   "mmap",
		10:  "mprotect",
		11:  "munmap",
		16:  "ioctl",
		17:  "pread64",
		18:  "pwrite64",
		19:  "readv",
		20:  "writev",
		21:  "access",
		22:  "pipe",
		40:  "sendfile",
		257: "openat",
		258: "mkdirat",
		259: "mknodat",
		260: "fchownat",
		261: "futimesat",
		262: "newfstatat",
		263: "unlinkat",
		264: "renameat",
		265: "linkat",
		266: "symlinkat",
		267: "readlinkat",
		268: "fchmodat",
		269: "faccessat",

		// Network operations
		41:  "socket",
		42:  "connect",
		43:  "accept",
		44:  "sendto",
		45:  "recvfrom",
		46:  "sendmsg",
		47:  "recvmsg",
		48:  "shutdown",
		49:  "bind",
		50:  "listen",
		51:  "getsockname",
		52:  "getpeername",
		53:  "socketpair",
		54:  "setsockopt",
		55:  "getsockopt",
		288: "accept4",

		// Process operations
		56:  "clone",
		57:  "fork",
		58:  "vfork",
		59:  "execve",
		60:  "exit",
		61:  "wait4",
		62:  "kill",
		89:  "readlink",
		100: "getpriority",
		// Note: 101 is ptrace (moved to dangerous syscalls)
		102: "sched_setparam",
		103: "sched_getparam",
		104: "sched_setscheduler",
		105: "sched_getscheduler",
		106: "sched_get_priority_max",
		107: "sched_get_priority_min",
		108: "sched_rr_get_interval",
		// User/group operations
		121: "setgid",
		122: "getgid",
		123: "setuid",
		124: "getuid",
		125: "setreuid",

		// Memory management
		12:  "brk",
		25:  "mremap",
		26:  "msync",
		27:  "mincore",
		28:  "madvise",
		29:  "shmget",
		30:  "shmat",
		31:  "shmctl",

		// Security/capabilities
		92:  "chown",
		93:  "fchown",
		94:  "lchown",
		95:  "umask",
		96:  "gettimeofday",
		97:  "getrlimit",
		98:  "getrusage",
		99:  "sysinfo",
		// Note: IDs 104-108 used in Process operations section
		109: "setregid",
		110: "getgroups",
		111: "setgroups",
		112: "setresuid",
		113: "getresuid",
		114: "setresgid",
		115: "getresgid",
		116: "setpgid",
		117: "getpgid",
		118: "setpgrp",
		119: "setsid",
		120: "getpgrp",

		// Dangerous syscalls
		165: "mount",
		166: "umount2",
		134: "uselib",
		101: "ptrace",
		310: "process_vm_readv",
		311: "process_vm_writev",
		313: "finit_module",
		175: "init_module",
		176: "delete_module",
		154: "modify_ldt",
		159: "adjtimex",
		171: "setdomainname",
		170: "sethostname",
		164: "settimeofday",
		227: "clock_settime",

		// File system operations
		83:  "mkdir",
		84:  "rmdir",
		85:  "creat",
		86:  "link",
		87:  "unlink",
		88:  "symlink",
		90:  "chmod",
		91:  "fchmod",
		133: "mknod",
		137: "statfs",
		138: "fstatfs",
		161: "chroot",
		162: "sync",
		163: "acct",
	}

	if name, exists := names[nr]; exists {
		return name
	}

	return "unknown"
}

// SetupWithManager sets up the controller with the Manager.
func (r *AttackSurfaceAnalyzerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.AnalysisInterval == 0 {
		r.AnalysisInterval = 5 * time.Minute
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.PahlevanPolicy{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.Service{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&networkingv1.NetworkPolicy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
