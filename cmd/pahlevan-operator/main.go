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
	"time"

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

	// derivedAdmissionInterval is how often admission rules are re-derived from
	// the learned baselines. Slow, because a baseline only changes when a
	// container finishes learning or a policy is deleted.
	derivedAdmissionInterval = 2 * time.Minute
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
	defer func() { _ = observabilityManager.Shutdown() }()

	// os.Exit skips deferred calls, so a fatal startup error would drop every
	// buffered span and metric - precisely the evidence needed to work out why
	// startup failed. Fatal errors after this point go through fatalf instead.
	fatalf := func(err error, msg string) {
		setupLog.Error(err, msg)
		_ = observabilityManager.Shutdown()
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              "pahlevan-operator-lock",
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		fatalf(err, "unable to start manager")
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
		fatalf(err, "unable to add admission runnable")
	}

	// Derived admission: rules generated from what each workload was observed
	// doing, rather than a baseline written by hand.
	//
	// Re-derived on a timer because a baseline changes when a container
	// finishes learning, and rolled back to nothing when a policy loses its
	// baseline: a rule outliving the evidence for it looks deliberate and is
	// the worst kind of stale.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ticker := time.NewTicker(derivedAdmissionInterval)
		defer ticker.Stop()
		reconcile := func() {
			n, err := admission.EnsureDerived(ctx, mgr.GetClient())
			if errors.Is(err, admission.ErrUnsupported) {
				return
			}
			if err != nil {
				setupLog.V(1).Info("derived admission reconcile failed", "error", err.Error())
				return
			}
			if n > 0 {
				setupLog.Info("derived admission policies reconciled", "policies", n)
			}
		}
		reconcile()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				reconcile()
			}
		}
	})); err != nil {
		fatalf(err, "unable to add derived admission runnable")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		fatalf(err, "unable to set up health check")
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		fatalf(err, "unable to set up ready check")
	}

	setupLog.Info("starting pahlevan-operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fatalf(err, "problem running operator")
	}
}
