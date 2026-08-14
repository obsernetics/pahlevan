// Command pahlevan-agent is the per-node data-plane component of Pahlevan.
//
// It is meant to run as a privileged DaemonSet (one pod per node). It owns the
// eBPF data plane: loading and attaching programs, consuming the kernel event
// stream, learning per-container behavioural baselines, and applying enforcement
// locally on the node it runs on. Unlike the operator it does NOT participate in
// leader election — every node's agent is independently active for its own node.
//
// The control-plane duties (CRD defaulting/validation, cluster-wide status
// aggregation, admission policy) live in the separate pahlevan-operator binary.
package main

import (
	"context"
	"flag"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/obsernetics/pahlevan/internal/adaptive"
	"github.com/obsernetics/pahlevan/internal/controller"
	"github.com/obsernetics/pahlevan/pkg/attribution"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("agent-setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		learningWindowDur    time.Duration
		enforcementDelay     time.Duration
		observabilityExports string
		nodeName             string
		seccompDir           string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.DurationVar(&learningWindowDur, "learning-window", 5*time.Minute,
		"Duration for learning phase before switching to enforcement.")
	flag.DurationVar(&enforcementDelay, "enforcement-delay", 30*time.Second,
		"Delay before starting enforcement after learning phase.")
	flag.StringVar(&observabilityExports, "observability-exports", "prometheus,otel",
		"Comma-separated list of observability exports (prometheus,otel,datadog).")
	flag.StringVar(&nodeName, "node-name", os.Getenv("PAHLEVAN_NODE_NAME"),
		"Name of the node this agent runs on (defaults to $PAHLEVAN_NODE_NAME).")
	flag.StringVar(&seccompDir, "seccomp-dir", os.Getenv("PAHLEVAN_SECCOMP_DIR"),
		"Directory to write learned seccomp profiles for use as pod localhostProfiles (empty disables).")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if nodeName == "" {
		setupLog.Info("warning: node name is empty; set --node-name or PAHLEVAN_NODE_NAME for correct node-scoped behaviour")
	}

	// Observability + metrics.
	observabilityManager, err := observability.NewManager(observabilityExports)
	if err != nil {
		setupLog.Error(err, "unable to setup observability")
		os.Exit(1)
	}
	defer observabilityManager.Shutdown()

	metricsManager := metrics.NewManager()

	// Data plane: initialize the eBPF manager. Program load/attach happens inside
	// the manager and requires a privileged, eBPF-capable kernel (the DaemonSet
	// runtime environment). Construction failing here means the node cannot run
	// the data plane at all, so we exit.
	ebpfManager, err := ebpf.NewManager()
	if err != nil {
		setupLog.Error(err, "unable to initialize eBPF manager")
		os.Exit(1)
	}
	defer ebpfManager.Close()

	if err := ebpfManager.LoadPrograms(); err != nil {
		setupLog.Error(err, "unable to load eBPF programs")
		os.Exit(1)
	}
	// Note: Start() attaches the programs; do NOT call AttachPrograms() here or
	// the links attach twice (EEXIST). Event handlers are registered below,
	// before Start(), so no events are missed.

	// The agent runs a controller-runtime manager WITHOUT leader election: each
	// node's agent is active for its own node. Cross-node status coordination is
	// handled via per-node status entries (see PahlevanPolicy status), not by
	// electing a single active agent.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Index pods by node so the policy resolver can list only this node's pods.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, "spec.nodeName",
		func(o client.Object) []string { return []string{o.(*corev1.Pod).Spec.NodeName} }); err != nil {
		setupLog.Error(err, "unable to index pods by node")
		os.Exit(1)
	}

	// The adaptive controller is the core learn->enforce loop: it consumes the
	// eBPF event stream, attributes events to pods, and flips each matched
	// container to in-kernel enforcement when its learning window closes.
	attrResolver := attribution.NewResolver(attribution.DefaultCgroupRoot)
	polResolver := newPolicyResolver(mgr.GetClient(), nodeName)
	adaptiveCtl := adaptive.NewController(ctrl.Log.WithName("adaptive"), ebpfManager, attrResolver, polResolver)
	adaptiveCtl.SeccompDir = seccompDir
	adaptiveCtl.Client = mgr.GetClient()
	adaptiveCtl.Node = nodeName

	// Register event handlers BEFORE starting readers so no events are missed.
	ebpfManager.AddEventHandler(&agentObserver{log: ctrl.Log.WithName("observer")})
	ebpfManager.AddEventHandler(adaptiveCtl)

	// dataCtx drives the eBPF ring-buffer readers; cancelled on shutdown signal.
	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	if err := ebpfManager.Start(dataCtx); err != nil {
		setupLog.Error(err, "unable to start eBPF event readers")
		os.Exit(1)
	}
	setupLog.Info("eBPF data plane attached and running")

	// Run the adaptive control loop once the cache is synced (mgr.Add starts it
	// after leader-election/cache readiness).
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		refresh := func() {
			if err := polResolver.Refresh(ctx); err != nil {
				setupLog.V(1).Info("policy refresh failed", "error", err.Error())
			}
			if err := attrResolver.Refresh(); err != nil {
				setupLog.V(1).Info("cgroup refresh failed", "error", err.Error())
			}
		}
		refresh()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				refresh()
				adaptiveCtl.Reconcile()
			}
		}
	})); err != nil {
		setupLog.Error(err, "unable to add adaptive controller runnable")
		os.Exit(1)
	}

	if err = (&controller.PahlevanPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		EBPFManager:          ebpfManager,
		MetricsManager:       metricsManager,
		ObservabilityManager: observabilityManager,
		LearningWindow:       learningWindowDur,
		EnforcementDelay:     enforcementDelay,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PahlevanPolicy")
		os.Exit(1)
	}

	if err = (&controller.ContainerLearnerReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		EBPFManager:          ebpfManager,
		MetricsManager:       metricsManager,
		ObservabilityManager: observabilityManager,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ContainerLearner")
		os.Exit(1)
	}

	if err = (&controller.AttackSurfaceAnalyzerReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		EBPFManager:          ebpfManager,
		MetricsManager:       metricsManager,
		ObservabilityManager: observabilityManager,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AttackSurfaceAnalyzer")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting pahlevan-agent", "node", nodeName)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running agent")
		os.Exit(1)
	}
}

// agentObserver is the default sink for the eBPF event pipeline. It counts events
// and logs a periodic sample; the learner is fed from here in a later step.
type agentObserver struct {
	log      logr.Logger
	syscalls atomic.Uint64
	networks atomic.Uint64
	files    atomic.Uint64
}

func (o *agentObserver) HandleSyscallEvent(e *ebpf.SyscallEvent) error {
	n := o.syscalls.Add(1)
	// Every observed (cgroup,syscall) pair is already deduped in-kernel, so each
	// event is a distinct signal worth a debug line; sample INFO occasionally.
	o.log.V(1).Info("syscall", "nr", e.SyscallNr, "comm", e.Comm, "cgroup", e.CgroupID, "pid", e.PID)
	if n%1000 == 0 {
		o.log.Info("syscall events observed", "count", n)
	}
	return nil
}

func (o *agentObserver) HandleNetworkEvent(e *ebpf.NetworkEvent) error {
	o.networks.Add(1)
	return nil
}

func (o *agentObserver) HandleFileEvent(e *ebpf.FileEvent) error {
	o.files.Add(1)
	return nil
}
