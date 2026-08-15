// Command pahlevan-agent is the per-node data-plane component of Pahlevan.
//
// It is meant to run as a privileged DaemonSet (one pod per node). It owns the
// eBPF data plane: loading and attaching programs, consuming the kernel event
// stream, learning per-container behavioral baselines, and applying enforcement
// locally on the node it runs on. Unlike the operator it does NOT participate in
// leader election - every node's agent is independently active for its own node.
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
	"github.com/obsernetics/pahlevan/pkg/export"
	"github.com/obsernetics/pahlevan/pkg/grpcapi"
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
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("agent-setup")

	// version is stamped at build time by the Dockerfile's -ldflags
	// (-X main.version). It is reported over the gRPC status RPC so a client
	// can tell which agent it is talking to without reading the pod spec.
	version = "dev"
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
		exportFile           string
		exportWebhook        string
		exportDenialsOnly    bool
		metricsDetail        string
		seccompRoot          string
		grpcAddr             string
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
	flag.StringVar(&exportFile, "export-file", os.Getenv("PAHLEVAN_EXPORT_FILE"),
		"Write JSON-lines security events to this file for `pahlevan events` and log shippers (empty disables).")
	flag.StringVar(&exportWebhook, "export-webhook", os.Getenv("PAHLEVAN_EXPORT_WEBHOOK"),
		"POST batched JSON security events to this URL (empty disables).")
	flag.StringVar(&grpcAddr, "grpc-bind-address", "",
		"Address for the gRPC event stream (for example :9090). Empty disables it. "+
			"Clients subscribe with `pahlevan events --grpc <addr>`.")
	flag.StringVar(&seccompRoot, "seccomp-root", "/var/lib/kubelet/seccomp",
		"The kubelet's seccomp root. Only used to render the localhostProfile value "+
			"reported on ContainerProfile; the agent never reads this path.")
	flag.StringVar(&metricsDetail, "metrics-detail", "basic",
		"Metrics cardinality: basic (aggregate, default) or high (adds per-container, "+
			"per-syscall and per-path series - expensive across a fleet).")
	flag.BoolVar(&exportDenialsOnly, "export-denials-only", true,
		"Export only in-kernel denials rather than every observation.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if nodeName == "" {
		setupLog.Info("warning: node name is empty; set --node-name or PAHLEVAN_NODE_NAME for correct node-scoped behavior")
	}

	// Observability + metrics.
	observabilityManager, err := observability.NewManager(observabilityExports)
	if err != nil {
		setupLog.Error(err, "unable to setup observability")
		os.Exit(1)
	}
	defer observabilityManager.Shutdown()

	// os.Exit skips deferred calls, so a fatal startup error would drop every
	// buffered span and metric - precisely the evidence needed to work out why
	// startup failed. Fatal errors after this point go through fatalf instead.
	fatalf := func(err error, msg string) {
		setupLog.Error(err, msg)
		_ = observabilityManager.Shutdown()
		os.Exit(1)
	}

	// Register metrics with the controller-runtime registry, which is the one
	// actually served on the metrics endpoint. A private registry would mean the
	// metrics exist but are never scrapeable.
	metricsManager := metrics.NewManagerWithDetail(
		ctrlmetrics.Registry, ctrlmetrics.Registry, metrics.ParseDetailLevel(metricsDetail))
	setupLog.Info("metrics registered", "detail", metricsManager.Detail())

	// Data plane: initialize the eBPF manager. Program load/attach happens inside
	// the manager and requires a privileged, eBPF-capable kernel (the DaemonSet
	// runtime environment). Construction failing here means the node cannot run
	// the data plane at all, so we exit.
	ebpfManager, err := ebpf.NewManager()
	if err != nil {
		fatalf(err, "unable to initialize eBPF manager")
	}
	defer ebpfManager.Close()

	if err := ebpfManager.LoadPrograms(); err != nil {
		fatalf(err, "unable to load eBPF programs")
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
		fatalf(err, "unable to start manager")
	}

	// Index pods by node so the policy resolver can list only this node's pods.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, "spec.nodeName",
		func(o client.Object) []string { return []string{o.(*corev1.Pod).Spec.NodeName} }); err != nil {
		fatalf(err, "unable to index pods by node")
	}

	// The adaptive controller is the core learn->enforce loop: it consumes the
	// eBPF event stream, attributes events to pods, and flips each matched
	// container to in-kernel enforcement when its learning window closes.
	attrResolver := attribution.NewResolver(attribution.DefaultCgroupRoot)
	polResolver := newPolicyResolver(mgr.GetClient(), nodeName)
	adaptiveCtl := adaptive.NewController(ctrl.Log.WithName("adaptive"), ebpfManager, attrResolver, polResolver)
	adaptiveCtl.SeccompDir = seccompDir
	adaptiveCtl.SeccompRoot = seccompRoot
	adaptiveCtl.Client = mgr.GetClient()
	adaptiveCtl.Node = nodeName
	adaptiveCtl.Metrics = metricsManager

	// The gRPC event stream is a live consumer on the same pipeline as the file
	// and webhook sinks, so a subscriber sees exactly the events those sinks
	// see, filtered and attributed the same way.
	var grpcServer *grpcapi.Server
	var grpcTee []export.Enqueuer
	if grpcAddr != "" {
		grpcServer = grpcapi.New(grpcapi.Options{
			Status: func() grpcapi.Status {
				st := grpcapi.Status{Node: nodeName, Version: version}
				for _, p := range adaptiveCtl.Snapshot() {
					st.ContainersTracked++
					switch p.Phase {
					case adaptive.PhaseLearning:
						st.ContainersLearning++
					case adaptive.PhaseEnforcing:
						st.ContainersEnforcing++
					}
				}
				return st
			},
		})
		grpcTee = append(grpcTee, grpcServer)
	}

	// Event export: JSON-lines file and/or webhook, so events leave the process
	// for `pahlevan events`, log shippers, and SIEMs.
	exportPipeline, err := export.New(export.Config{
		Tee:           grpcTee,
		FilePath:      exportFile,
		WebhookURL:    exportWebhook,
		QueueCapacity: 8192,
		BatchSize:     256,
		FlushInterval: time.Second,
		DenialsOnly:   exportDenialsOnly,
		Source:        nodeName,
		Attribution: func(id uint64) (export.KubernetesRef, bool) {
			ref, ok := attrResolver.Lookup(id)
			if !ok {
				return export.KubernetesRef{}, false
			}
			ns, pod, _ := polResolver.PodMeta(ref.PodUID)
			detail, _ := polResolver.PodDetail(ref.PodUID)
			name, image, _ := polResolver.ContainerDetail(ref.PodUID, ref.ContainerID)
			return export.KubernetesRef{
				Namespace: ns, Pod: pod, PodUID: ref.PodUID,
				ContainerID: ref.ContainerID, Runtime: ref.Runtime, QoSClass: ref.QoSClass,
				Node:         nodeName,
				WorkloadKind: detail.WorkloadKind, WorkloadName: detail.WorkloadName,
				Labels:    detail.Labels,
				Container: name,
				Image:     image,
			}, true
		},
		OnError: func(err error) { setupLog.Error(err, "event export failed") },
	})
	if err != nil {
		fatalf(err, "unable to configure event export")
	}
	if exportPipeline != nil {
		defer exportPipeline.Close()
		ebpfManager.AddEventHandler(exportPipeline.Handler)
		setupLog.Info("event export enabled", "file", exportFile, "webhook", exportWebhook != "", "denialsOnly", exportDenialsOnly)
	}

	// Register event handlers BEFORE starting readers so no events are missed.
	ebpfManager.AddEventHandler(&agentObserver{log: ctrl.Log.WithName("observer")})
	ebpfManager.AddEventHandler(adaptiveCtl)

	// dataCtx drives the eBPF ring-buffer readers; canceled on shutdown signal.
	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	if err := ebpfManager.Start(dataCtx); err != nil {
		fatalf(err, "unable to start eBPF event readers")
	}
	setupLog.Info("eBPF data plane attached and running")

	if grpcServer != nil {
		go func() {
			setupLog.Info("gRPC event stream listening", "address", grpcAddr)
			if err := grpcServer.Serve(dataCtx, grpcAddr); err != nil {
				// A failed event stream must not take the data plane down with
				// it: enforcement keeps working, subscribers do not.
				setupLog.Error(err, "gRPC event stream stopped", "address", grpcAddr)
			}
		}()
	}

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
		fatalf(err, "unable to add adaptive controller runnable")
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
		fatalf(err, "unable to set up health check")
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		fatalf(err, "unable to set up ready check")
	}

	setupLog.Info("starting pahlevan-agent", "node", nodeName)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fatalf(err, "problem running agent")
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

func (o *agentObserver) HandleProcessEvent(event *ebpf.ProcessEvent) error {
	return nil
}

func (o *agentObserver) HandleCapabilityEvent(event *ebpf.CapabilityEvent) error {
	return nil
}
