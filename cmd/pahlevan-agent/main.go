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
	"flag"
	"os"
	"time"

	"github.com/obsernetics/pahlevan/internal/controller"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	"github.com/obsernetics/pahlevan/pkg/observability"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
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
