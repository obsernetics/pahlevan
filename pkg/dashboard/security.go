package dashboard

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// TLSConfig describes the dashboard's transport security. It mirrors
// pkg/grpcapi's TLSConfig deliberately: an operator who has configured the
// agent's gRPC listener should not have to learn a second shape for the same
// question.
type TLSConfig struct {
	// CertFile and KeyFile enable TLS. Both or neither.
	CertFile string
	KeyFile  string
	// ClientCAFile requires a client certificate signed by this CA, in
	// addition to the bearer token. It is not a replacement for the token:
	// identity still comes from Kubernetes, the certificate only decides who
	// may open the connection at all.
	ClientCAFile string
}

// Enabled reports whether TLS is configured.
func (c TLSConfig) Enabled() bool { return c.CertFile != "" && c.KeyFile != "" }

// Validate catches a half-configured setup at startup rather than at the first
// connection. A certificate without a key is a typo, and falling back to
// plaintext because of it is how a listener ends up unencrypted while its
// operator believes otherwise.
func (c TLSConfig) Validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf(
			"dashboard TLS needs both a certificate and a key; got cert=%q key=%q", c.CertFile, c.KeyFile)
	}
	if c.ClientCAFile != "" && !c.Enabled() {
		return fmt.Errorf(
			"dashboard client CA %q is set without a server certificate, so client certificates "+
				"cannot be required", c.ClientCAFile)
	}
	return nil
}

// ServerConfig builds the tls.Config for the listener, or nil for plaintext.
func (c TLSConfig) ServerConfig() (*tls.Config, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Enabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the dashboard certificate from %q and %q: %w",
			c.CertFile, c.KeyFile, err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.2 is the floor because a corporate proxy in front of the
		// browser may not speak 1.3 yet; anything below 1.2 is not negotiable.
		MinVersion: tls.VersionTLS12,
	}
	if c.ClientCAFile != "" {
		pem, err := os.ReadFile(c.ClientCAFile) // #nosec G304 -- the operator named this file
		if err != nil {
			return nil, fmt.Errorf("reading the dashboard client CA %q: %w", c.ClientCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("the dashboard client CA %q contains no certificates", c.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ContentSecurityPolicy is the policy sent with every response.
//
// It starts from default-src 'none' and names each thing the page actually
// needs, so a directive nobody thought about is denied rather than inherited.
// Two parts carry the weight:
//
//   - script-src 'self' with no 'unsafe-inline' and no 'unsafe-eval'. Every
//     line of JavaScript is a file served from this binary. An XSS that lands
//     markup in the page cannot execute it.
//   - No external origin anywhere. A dashboard that pulls a charting library
//     from a CDN at runtime has made every viewer's browser trust a third
//     party, which is not a trade a security tool gets to make on a user's
//     behalf. That is why the diagrams here are SVG this package generates and
//     vanilla JavaScript, and why there is no chart dependency to update.
//
// style-src has no 'unsafe-inline' either, which is why nothing this package
// emits uses a style attribute: SVG presentation attributes (fill, stroke, x)
// are not covered by CSP, so the diagrams stay styleable from app.css without
// weakening the policy.
const ContentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self'; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'"

// SecurityHeaders sets the response headers on every route, including errors
// and 404s. Putting them outermost is deliberate: a header set inside a
// handler is a header missing from every path that returns before reaching it,
// and the paths that return early are exactly the error paths.
func SecurityHeaders(tlsEnabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		// frame-ancestors above is the modern control; X-Frame-Options is
		// still what older browsers honour, and clickjacking a read-only
		// dashboard is how a viewer gets shown someone else's namespace.
		h.Set("X-Frame-Options", "DENY")
		// Without nosniff a browser may decide a JSON response full of paths
		// and command lines is HTML and render it.
		h.Set("X-Content-Type-Options", "nosniff")
		// The URL path carries namespace and workload names. Those must not
		// travel to anywhere the viewer happens to click through to.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// Every response body is scoped to the viewer's own RBAC, so a cache
		// that kept one would serve one viewer's namespaces to the next.
		h.Set("Cache-Control", "no-store")
		if tlsEnabled {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// contentTypeFor maps an asset path to its type. Serving JavaScript as
// text/plain leaves the browser refusing to run it under nosniff, which turns
// into a blank page and a console message nobody connects to the header.
func contentTypeFor(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
