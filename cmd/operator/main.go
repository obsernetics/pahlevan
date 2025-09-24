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
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		enableLeaderElection bool
		probeAddr            string
		enableWebhooks       bool
		learningWindowDur    time.Duration
		enforcementDelay     time.Duration
		observabilityExports string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", false, "Enable admission webhooks.")
	flag.DurationVar(&learningWindowDur, "learning-window", 5*time.Minute,
		"Duration for learning phase before switching to enforcement.")
	flag.DurationVar(&enforcementDelay, "enforcement-delay", 30*time.Second,
		"Delay before starting enforcement after learning phase.")
	flag.StringVar(&observabilityExports, "observability-exports", "prometheus,otel",
		"Comma-separated list of observability exports (prometheus,otel,datadog).")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Setup observability
	observabilityManager, err := observability.NewManager(observabilityExports)
	if err != nil {
		setupLog.Error(err, "unable to setup observability")
		os.Exit(1)
	}
	defer observabilityManager.Shutdown()

	// Setup metrics
	metricsManager := metrics.NewManager()

	// Initialize eBPF manager
	ebpfManager, err := ebpf.NewManager()
	if err != nil {
		setupLog.Error(err, "unable to initialize eBPF manager")
		os.Exit(1)
	}
	defer ebpfManager.Close()

	// Load eBPF programs
	if err := ebpfManager.LoadPrograms(); err != nil {
		setupLog.Error(err, "unable to load eBPF programs")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "pahlevan-operator-lock",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup controllers
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

	// Setup webhooks if enabled
	if enableWebhooks {
		setupLog.Info("Webhook support not yet implemented")
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
