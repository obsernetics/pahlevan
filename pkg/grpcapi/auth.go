package grpcapi

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Transport security for the event stream.
//
// The stream carries every denial on the node: which pods exist, which paths
// they read, which destinations they dial, and the full command line of every
// exec. That is a reconnaissance report. Serving it in plaintext to anything
// that can reach the port is not a defensible default for a security tool, and
// "bind it to localhost" is advice rather than a control.
//
// So the server requires credentials. It used to start without them and merely
// say so in the log, on the reasoning that an agent refusing to run because
// nobody had issued a certificate is an agent nobody runs. That reasoning was
// wrong in one specific way: the person who forgets the certificate and the
// person who reads the startup log are rarely the same person, and a warning
// nobody reads is not a control. Serving a reconnaissance report in plaintext
// is now a startup error naming exactly what to do about it.
//
// AllowInsecure exists for the cases that are genuinely fine - a unit test, a
// developer on a laptop, a listener bound to loopback behind a sidecar that
// terminates TLS. It has to be set on purpose, which is the whole difference.
//
// Two mechanisms, deliberately separate:
//
//   - TLS, optionally with client certificates (mTLS). This is the one to use
//     in a cluster, where cert-manager or the built-in signer issues them.
//   - A bearer token, for the case TLS does not cover: a developer tunneling
//     the port, or a collector that cannot present a certificate. It is checked
//     in constant time and refused entirely over plaintext, because a token on
//     an unencrypted connection is a token you have published.

// TLSConfig describes the server's transport credentials.
type TLSConfig struct {
	// CertFile and KeyFile enable TLS. Both or neither.
	CertFile string
	KeyFile  string
	// ClientCAFile enables mTLS: a client must present a certificate signed by
	// this CA. Without it, TLS encrypts the stream but authenticates nobody.
	ClientCAFile string
}

// Enabled reports whether TLS is configured.
func (c TLSConfig) Enabled() bool { return c.CertFile != "" && c.KeyFile != "" }

// Validate catches a half-configured setup at startup rather than at the first
// connection. A cert without a key is a typo, and silently falling back to
// plaintext because of it is how a stream ends up unencrypted while its
// operator believes otherwise.
func (c TLSConfig) Validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf(
			"grpc TLS needs both a certificate and a key; got cert=%q key=%q", c.CertFile, c.KeyFile)
	}
	if c.ClientCAFile != "" && !c.Enabled() {
		return fmt.Errorf(
			"grpc client CA %q is set without a server certificate, so mTLS cannot be enforced",
			c.ClientCAFile)
	}
	return nil
}

// Credentials builds the server's transport credentials, or nil for plaintext.
func (c TLSConfig) Credentials() (credentials.TransportCredentials, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled() {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the grpc certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.2 is the floor rather than 1.3 because a collector in the
		// cluster may not speak 1.3 yet; anything below 1.2 is not negotiable.
		MinVersion: tls.VersionTLS12,
	}

	if c.ClientCAFile != "" {
		pem, err := os.ReadFile(c.ClientCAFile) // #nosec G304 -- the operator named this file
		if err != nil {
			return nil, fmt.Errorf("reading the grpc client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the grpc client CA %q contains no certificates", c.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(cfg), nil
}

// tokenAuth returns interceptors enforcing a bearer token.
//
// Both a unary and a stream interceptor, because Subscribe is a stream and
// GetStatus is not - protecting only one of them would leave the other open,
// and the one people forget is the stream.
func tokenAuth(token string) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	check := func(ctx context.Context) error {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "no metadata")
		}
		values := md.Get("authorization")
		if len(values) == 0 {
			return status.Error(codes.Unauthenticated, "no authorization header")
		}
		presented := strings.TrimPrefix(values[0], "Bearer ")
		// Constant time, so a caller cannot recover the token one byte at a
		// time from response latency.
		if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			return status.Error(codes.Unauthenticated, "invalid token")
		}
		return nil
	}

	unary := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if err := check(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}

	stream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := check(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}

	return unary, stream
}

// AuthConfig is the full authentication setup for the event stream.
type AuthConfig struct {
	TLS TLSConfig
	// Token, when set, requires a matching bearer token on every call.
	Token string
	// AllowInsecure permits a plaintext, unauthenticated listener.
	//
	// Without it a listener with neither TLS nor a token fails to start. The
	// failure is the point: an operator who meant to configure credentials
	// finds out at startup rather than after somebody else finds the port.
	AllowInsecure bool
}

// Secure reports whether the stream is encrypted and its peers authenticated.
func (a AuthConfig) Secure() bool {
	return a.TLS.Enabled() && (a.TLS.ClientCAFile != "" || a.Token != "")
}

// Validate rejects a configuration that would not do what it appears to.
func (a AuthConfig) Validate() error {
	if err := a.TLS.Validate(); err != nil {
		return err
	}
	// A bearer token on an unencrypted connection is a token you have
	// published: it is sent in cleartext on every call, to anyone on the path.
	// Refusing is better than accepting a control that provides no protection.
	if a.Token != "" && !a.TLS.Enabled() {
		return fmt.Errorf(
			"a grpc bearer token requires TLS: without it the token is sent in cleartext " +
				"on every call and protects nothing")
	}
	// The stream carries every denial on the node - which pods exist, which
	// paths they read, which destinations they dial, the full command line of
	// every exec. Serving that to anything that can reach the port is not a
	// defensible default, and "bind it to localhost" is advice rather than a
	// control.
	if !a.TLS.Enabled() && a.Token == "" && !a.AllowInsecure {
		return fmt.Errorf(
			"the grpc listener would be plaintext and unauthenticated, and it serves every " +
				"denial on this node. Configure --grpc-tls-cert and --grpc-tls-key, add " +
				"--grpc-client-ca for mTLS or --grpc-token for a bearer token, or pass " +
				"--grpc-insecure if this listener is genuinely unreachable")
	}
	return nil
}

// ServerOptions renders the configuration as grpc.ServerOptions.
func (a AuthConfig) ServerOptions() ([]grpc.ServerOption, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	var opts []grpc.ServerOption

	creds, err := a.TLS.Credentials()
	if err != nil {
		return nil, err
	}
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	if a.Token != "" {
		unary, stream := tokenAuth(a.Token)
		opts = append(opts, grpc.UnaryInterceptor(unary), grpc.StreamInterceptor(stream))
	}
	return opts, nil
}

// Describe renders the configuration for the agent's startup log, so an
// operator can see from the logs whether the stream is protected rather than
// having to infer it from which flags they think they set.
func (a AuthConfig) Describe() string {
	switch {
	case a.TLS.ClientCAFile != "" && a.Token != "":
		return "mTLS + bearer token"
	case a.TLS.ClientCAFile != "":
		return "mTLS"
	case a.TLS.Enabled() && a.Token != "":
		return "TLS + bearer token"
	case a.TLS.Enabled():
		return "TLS, no client authentication"
	default:
		return "PLAINTEXT AND UNAUTHENTICATED (--grpc-insecure) - reachable by anything that can reach the port"
	}
}
