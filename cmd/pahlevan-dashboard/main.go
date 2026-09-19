// Command pahlevan-dashboard serves Pahlevan's optional read-only web view.
//
// It is a separate binary and a separate Deployment on purpose. It is not in
// install.yaml and not in the default Helm values, so a cluster that never
// enables it runs exactly the bytes it ran before. Nothing in the agent or the
// operator imports pkg/dashboard.
//
// It is also the least privileged component in the project. It holds no eBPF
// capability, opens nothing in the kernel, and its service account needs
// exactly four grants: create on tokenreviews and subjectaccessreviews, and
// read on the three Pahlevan CRDs. Who may see what is decided per read by the
// API server, against the viewer's own token, not by anything in this process.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/dashboard"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("dashboard-setup")

	// version is stamped at build time by the Dockerfile's -ldflags
	// (-X main.version), matching the agent and the operator.
	version = "dev"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
}

// stringList collects a flag that may be repeated or comma separated, so
// --agent a:9090 --agent b:9090 and --agent a:9090,b:9090 both work. An
// operator listing agents should not have to remember which one this binary
// wanted.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pahlevan-dashboard: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr           string
		tlsCert        string
		tlsKey         string
		clientCA       string
		allowInsecure  bool
		audiences      stringList
		agents         stringList
		agentCA        string
		agentServer    string
		agentTokenFile string
		agentInsecure  bool
		showVersion    bool
	)

	flag.StringVar(&addr, "addr", dashboard.DefaultAddr, "Address to serve the dashboard on.")
	flag.StringVar(&tlsCert, "tls-cert", "", "PEM certificate for the dashboard listener.")
	flag.StringVar(&tlsKey, "tls-key", "", "PEM private key for the dashboard listener.")
	flag.StringVar(&clientCA, "tls-client-ca", "",
		"PEM CA bundle; when set, a client must also present a certificate signed by it.")
	flag.BoolVar(&allowInsecure, "insecure", false,
		"Serve plaintext. Every request carries a Kubernetes bearer token, so only set this "+
			"when the listener is genuinely unreachable, such as behind a sidecar that terminates TLS.")
	flag.Var(&audiences, "audience",
		"Audience a presented token must be valid for. Repeatable. Empty accepts the API server's default audience.")
	flag.Var(&agents, "agent",
		"host:port of an agent's gRPC event stream to subscribe to, for live denials and process trees. Repeatable.")
	flag.StringVar(&agentCA, "agent-ca", "", "PEM CA bundle verifying the agents' certificates.")
	flag.StringVar(&agentServer, "agent-server-name", "",
		"Name to verify in the agents' certificates, when dialing an address that is not that name.")
	flag.StringVar(&agentTokenFile, "agent-token-file", "",
		"File holding the bearer token the agents require. Refused without TLS to the agent.")
	flag.BoolVar(&agentInsecure, "agent-insecure", false, "Dial the agents in plaintext.")
	flag.BoolVar(&showVersion, "version", false, "Print the version and exit.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if showVersion {
		fmt.Printf("pahlevan-dashboard %s\n", version)
		return nil
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("loading the Kubernetes configuration: %w; the dashboard needs either an "+
			"in-cluster service account or a KUBECONFIG", err)
	}
	reader, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("building the Kubernetes client: %w", err)
	}
	kube, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("building the Kubernetes clientset: %w", err)
	}

	var store *dashboard.Store
	sources, err := buildSources(agents, agentCA, agentServer, agentTokenFile, agentInsecure)
	if err != nil {
		return err
	}
	if len(sources) > 0 {
		store = dashboard.NewStore(dashboard.StoreOptions{})
	}

	server, err := dashboard.New(dashboard.Options{
		Addr:          addr,
		TLS:           dashboard.TLSConfig{CertFile: tlsCert, KeyFile: tlsKey, ClientCAFile: clientCA},
		AllowInsecure: allowInsecure,
		Reader:        reader,
		Kube:          kube,
		Audiences:     audiences,
		Store:         store,
		Log:           ctrl.Log.WithName("dashboard"),
	})
	if err != nil {
		return err
	}

	ctx := ctrl.SetupSignalHandler()
	for i := range sources {
		source := sources[i]
		source.Log = ctrl.Log.WithName("dashboard-source")
		go func() {
			if err := source.Run(ctx, store); err != nil {
				setupLog.Error(err, "agent source stopped", "endpoint", source.Endpoint)
			}
		}()
	}

	setupLog.Info("starting the Pahlevan dashboard",
		"version", version, "addr", addr, "transport", server.Describe(),
		"agents", len(sources), "mode", "read-only")

	return server.ListenAndServe(ctx)
}

// buildSources turns the agent flags into subscribers, failing at startup
// rather than at the first connection: a token that would be sent in cleartext
// is a configuration error, and finding out at startup is the difference
// between fixing it and publishing it.
func buildSources(endpoints stringList, caFile, serverName, tokenFile string, plaintext bool) ([]dashboard.AgentSource, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}
	token := ""
	if tokenFile != "" {
		raw, err := os.ReadFile(tokenFile) // #nosec G304 -- the operator named this file
		if err != nil {
			return nil, fmt.Errorf("reading the agent token from %q: %w", tokenFile, err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return nil, fmt.Errorf("the agent token file %q is empty", tokenFile)
		}
	}
	out := make([]dashboard.AgentSource, 0, len(endpoints))
	for _, endpoint := range endpoints {
		source := dashboard.AgentSource{
			Endpoint:   endpoint,
			Token:      token,
			CAFile:     caFile,
			ServerName: serverName,
			Insecure:   plaintext,
		}
		if err := source.Validate(); err != nil {
			return nil, err
		}
		out = append(out, source)
	}
	return out, nil
}
