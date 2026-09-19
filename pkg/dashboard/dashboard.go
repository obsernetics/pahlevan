// Package dashboard serves Pahlevan's optional read-only web view.
//
// Everything Pahlevan learns is already reachable through `kubectl get -o
// yaml`, a Prometheus scrape or a log line, which means a learned profile is a
// YAML status block nobody reads until something is denied. This package is
// the answer to that: a browser view of what each workload does - the process
// tree, the learned file, network and syscall surface, the flow from learning
// to enforcement, and what was denied and why - drawn as diagrams rather than
// another table of rows.
//
// It is optional in the real sense. Nothing in the agent or the operator
// imports it, it is a separate binary and Deployment, and a cluster that never
// enables it runs exactly the bytes it ran before.
//
// The security posture is the part that matters, because a security tool that
// ships a dashboard with a cluster-admin service account and a bespoke login
// page has handed an attacker a better primitive than the one it defends
// against. So:
//
//   - Read-only. There is no write path in this package at all: the router
//     registers GET handlers and nothing else, and non-GET methods are refused
//     before any handler runs. Changing a policy or a mode from a browser is
//     not a capability that exists here.
//   - Authentication and authorisation are delegated to Kubernetes. The
//     browser presents a bearer token, the server calls TokenReview to
//     establish who that is, and a SubjectAccessReview for every read, so a
//     viewer sees exactly the namespaces their own RBAC allows. No user
//     database, no session secret, no separate permission model to get wrong.
//   - TLS unless an operator explicitly says the listener is unreachable,
//     mirroring pkg/grpcapi's AllowInsecure.
//   - A strict Content-Security-Policy with no inline script and no external
//     origin. Every asset is served from the binary through embed.
//
// The dashboard holds no privilege of its own beyond reading three CRDs and
// asking the API server who a token belongs to. It gets no path into the
// kernel; the agent stays the only privileged component.
package dashboard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DefaultAddr is the listen address. ClusterIP only is the deployment's job,
// not this binary's, but binding all interfaces on a fixed port is what a
// Service expects.
const DefaultAddr = ":8443"

// readHeaderTimeout bounds how long a client may take to send its headers. A
// listener without it can be held open indefinitely by a peer that connects
// and says nothing, which is the cheapest denial of service there is.
const readHeaderTimeout = 10 * time.Second

// Options configures a Server.
type Options struct {
	// Addr is the listen address. Empty uses DefaultAddr.
	Addr string

	// TLS is the server's transport security. Without it the server refuses to
	// start unless AllowInsecure is set.
	TLS TLSConfig

	// AllowInsecure permits a plaintext listener.
	//
	// It exists for the cases that are genuinely fine - a unit test, a
	// developer on a laptop, a listener behind a sidecar that terminates TLS -
	// and it has to be set on purpose, which is the whole difference.
	AllowInsecure bool

	// Reader reads the three Pahlevan CRDs with the dashboard's own service
	// account. What a viewer is allowed to see is decided separately, by a
	// SubjectAccessReview per read against the viewer's own identity.
	Reader client.Reader

	// Kube is used only for TokenReview and SubjectAccessReview. The service
	// account needs create on those two subresources and read on the three
	// CRDs. That is the whole list.
	Kube kubernetes.Interface

	// Audiences, when set, is the audience list a presented token must be
	// valid for. A token minted for a different audience is refused even
	// though the API server would happily tell us whose it is, because
	// accepting one turns the dashboard into a credential relay.
	Audiences []string

	// Store is the optional live event aggregate. Without it the dashboard
	// still renders everything the CRDs carry; with it, denials gain their
	// process ancestry and their reason.
	Store *Store

	// Log receives startup and request-failure messages. The zero value
	// discards them.
	Log logr.Logger
}

// Validate rejects a configuration that would not do what it appears to.
func (o *Options) Validate() error {
	if err := o.TLS.Validate(); err != nil {
		return err
	}
	// The dashboard serves, in one place, which workloads exist, which paths
	// they read, which destinations they dial and every denial against them.
	// That is a reconnaissance report, and it is served to whoever presents a
	// token - so the token itself travels on every request. In plaintext that
	// token is published to anything on the path, which is a worse outcome
	// than having no dashboard.
	if !o.TLS.Enabled() && !o.AllowInsecure {
		return errors.New(
			"the dashboard listener would be plaintext, and every request to it carries a " +
				"Kubernetes bearer token that anything on the path could read. Configure " +
				"--tls-cert and --tls-key, or pass --insecure if this listener is genuinely " +
				"unreachable (a unit test, or a sidecar that terminates TLS in front of it)")
	}
	if o.Reader == nil {
		return errors.New("the dashboard has no Kubernetes reader, so it could not load any " +
			"policy, profile or attack surface. Pass a client built from the in-cluster config")
	}
	if o.Kube == nil {
		return errors.New("the dashboard has no Kubernetes clientset, so it could not run " +
			"TokenReview or SubjectAccessReview and would have to decide access itself. " +
			"Pass a clientset built from the in-cluster config")
	}
	return nil
}

// Server is the dashboard's HTTP server.
type Server struct {
	opts   Options
	auth   *Authenticator
	access *Authorizer
	mux    *http.ServeMux
	log    logr.Logger
}

// New builds a Server. It returns an error rather than a half-configured
// server, so a missing certificate is a startup failure naming the flag to
// pass instead of a listener that is quietly plaintext.
func New(opts Options) (*Server, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	s := &Server{
		opts:   opts,
		auth:   NewAuthenticator(opts.Kube, opts.Audiences),
		access: NewAuthorizer(opts.Kube),
		log:    opts.Log,
	}
	s.mux = s.routes()
	return s, nil
}

// Handler returns the fully wrapped handler: security headers outside, the
// read-only method guard next, then the router. Tests exercise this rather
// than a live listener, so what they assert is what a browser receives.
func (s *Server) Handler() http.Handler {
	return SecurityHeaders(s.opts.TLS.Enabled(), readOnly(s.mux))
}

// Describe renders the transport posture for the startup log, so an operator
// can see from the logs whether the listener is protected rather than having
// to infer it from which flags they think they set.
func (s *Server) Describe() string {
	if s.opts.TLS.Enabled() {
		if s.opts.TLS.ClientCAFile != "" {
			return "TLS with client certificates"
		}
		return "TLS"
	}
	return "PLAINTEXT (--insecure) - every bearer token presented to this listener is readable on the wire"
}

// ListenAndServe runs the server until ctx is cancelled, then shuts it down
// gracefully. A cancelled context is a clean stop, not an error.
func (s *Server) ListenAndServe(ctx context.Context) error {
	tlsCfg, err := s.opts.TLS.ServerConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.opts.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig:         tlsCfg,
	}

	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("the dashboard could not listen on %s: %w", s.opts.Addr, err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	s.log.Info("dashboard listening", "addr", s.opts.Addr, "transport", s.Describe())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("the dashboard listener on %s stopped: %w", s.opts.Addr, err)
	case <-ctx.Done():
		// A bounded shutdown: an in-flight request should finish, but a client
		// holding a connection open must not keep the process alive past a
		// pod's termination grace period.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("the dashboard did not shut down cleanly: %w", err)
		}
		return nil
	}
}

// readOnly refuses anything that is not a read before the router sees it.
//
// The router registers GET patterns only, so a POST would already 405, but
// this is the control that survives someone adding a handler later: there is
// one place that says the dashboard does not mutate, and it is in front of
// everything.
func readOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed,
				"the dashboard is read-only; it serves GET and HEAD and has no endpoint that changes a policy, a mode or a profile")
		}
	})
}
