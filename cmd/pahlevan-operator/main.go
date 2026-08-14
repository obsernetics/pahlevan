// Command pahlevan-operator is the cluster control-plane component of Pahlevan.
//
// It runs as a leader-elected Deployment (not per-node) and, unlike the agent,
// requires no host privileges or eBPF access - so it can run inside a user
// namespace (hostUsers: false). Its responsibilities are control-plane only:
//
//   - CRD defaulting/validation lifecycle
//   - cluster-wide aggregation of per-node status written by the agents
//   - CEL ValidatingAdmissionPolicy lifecycle (replaces the legacy webhook)
//
// The per-node eBPF data plane (load/attach/learn/enforce) lives entirely in the
// separate pahlevan-agent binary.
package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/obsernetics/pahlevan/internal/admission"
	"github.com/obsernetics/pahlevan/pkg/observability"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("operator-setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		observabilityExports string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election to ensure a single active operator.")
	flag.StringVar(&observabilityExports, "observability-exports", "prometheus,otel",
		"Comma-separated list of observability exports (prometheus,otel,datadog).")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	observabilityManager, err := observability.NewManager(observabilityExports)
	if err != nil {
		setupLog.Error(err, "unable to setup observability")
		os.Exit(1)
	}
	defer observabilityManager.Shutdown()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              "pahlevan-operator-lock",
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Control plane: ensure the CEL ValidatingAdmissionPolicy hardening baseline
	// exists (in-process admission, no webhook/certs). Runs after cache sync.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		if err := admission.Ensure(ctx, mgr.GetClient()); err != nil {
			if errors.Is(err, admission.ErrUnsupported) {
				setupLog.Info("CEL admission policy skipped", "reason", err.Error())
				return nil
			}
			setupLog.Error(err, "failed to ensure CEL admission policy")
			return nil // don't crash the operator over admission
		}
		setupLog.Info("CEL ValidatingAdmissionPolicy ensured (pahlevan-pod-hardening)")
		return nil
	})); err != nil {
		setupLog.Error(err, "unable to add admission runnable")
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

	setupLog.Info("starting pahlevan-operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running operator")
		os.Exit(1)
	}
}
