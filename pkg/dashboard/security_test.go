package dashboard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// A plaintext listener is refused because every request to this dashboard
// carries a Kubernetes bearer token, and in plaintext that token is published
// to anything on the path.
func TestPlaintextStartupIsRefusedWithoutInsecure(t *testing.T) {
	reader := fixtureReader(t)
	kube := k8sfake.NewSimpleClientset()

	_, err := New(Options{Addr: "127.0.0.1:0", Reader: reader, Kube: kube})
	if err == nil {
		t.Fatal("New started a plaintext dashboard without --insecure")
	}
	for _, want := range []string{"plaintext", "bearer token", "--tls-cert", "--insecure"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal %q does not mention %q, so it does not say what to do", err, want)
		}
	}

	if _, err := New(Options{Addr: "127.0.0.1:0", Reader: reader, Kube: kube, AllowInsecure: true}); err != nil {
		t.Fatalf("New refused an explicitly insecure listener: %v", err)
	}
}

func TestOptionsValidate(t *testing.T) {
	reader := fixtureReader(t)
	kube := k8sfake.NewSimpleClientset()

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "certificate without a key",
			opts:    Options{Reader: reader, Kube: kube, TLS: TLSConfig{CertFile: "tls.crt"}},
			wantErr: "both a certificate and a key",
		},
		{
			name:    "key without a certificate",
			opts:    Options{Reader: reader, Kube: kube, TLS: TLSConfig{KeyFile: "tls.key"}},
			wantErr: "both a certificate and a key",
		},
		{
			name:    "client CA without a server certificate",
			opts:    Options{Reader: reader, Kube: kube, TLS: TLSConfig{ClientCAFile: "ca.crt"}},
			wantErr: "client certificates cannot be required",
		},
		{
			name:    "no reader",
			opts:    Options{Kube: kube, AllowInsecure: true},
			wantErr: "no Kubernetes reader",
		},
		{
			name:    "no clientset",
			opts:    Options{Reader: reader, AllowInsecure: true},
			wantErr: "TokenReview",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate returned %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestDescribeNamesThePosture(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)
	// An operator has to be able to read the posture out of the startup log
	// rather than infer it from which flags they think they set.
	if got := server.Describe(); !strings.Contains(got, "PLAINTEXT") {
		t.Fatalf("Describe reported %q for an insecure listener", got)
	}
}

// The headers have to be on every response, including the ones handlers return
// early: the early returns are the error paths, and an error page is still a
// page a browser will execute script in.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	cases := []struct {
		path   string
		token  string
		method string
	}{
		{path: "/", token: testToken, method: http.MethodGet},
		{path: "/app.css", token: testToken, method: http.MethodGet},
		{path: "/app.js", token: testToken, method: http.MethodGet},
		{path: "/nope", token: testToken, method: http.MethodGet},
		{path: "/healthz", method: http.MethodGet},
		{path: "/api/overview", method: http.MethodGet},
		{path: "/api/overview", token: testToken, method: http.MethodGet},
		{path: "/api/workloads/secret/Deployment/ledger", token: testToken, method: http.MethodGet},
		{path: "/api/overview", token: testToken, method: http.MethodPost},
	}
	for _, tc := range cases {
		name := fmt.Sprintf("%s %s", tc.method, tc.path)
		t.Run(name, func(t *testing.T) {
			rec := do(t, server, tc.method, tc.path, tc.token)
			h := rec.Header()
			for header, want := range map[string]string{
				"Content-Security-Policy": ContentSecurityPolicy,
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
				"Referrer-Policy":         "no-referrer",
				"Cache-Control":           "no-store",
			} {
				if got := h.Get(header); got != want {
					t.Fatalf("%s carried %s=%q, want %q", name, header, got, want)
				}
			}
		})
	}
}

// The policy is parsed rather than compared to a constant, because a policy
// that is merely present is not the same as a policy that forbids anything.
func TestContentSecurityPolicyForbidsInlineAndExternal(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)
	rec := get(t, server, "/")

	policy := rec.Header().Get("Content-Security-Policy")
	if policy == "" {
		t.Fatal("no Content-Security-Policy was sent with the page")
	}
	directives := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		directives[fields[0]] = fields[1:]
	}

	if got := directives["default-src"]; len(got) != 1 || got[0] != "'none'" {
		t.Fatalf("default-src is %v, want 'none' so an unlisted directive is denied rather than inherited", got)
	}
	for _, directive := range []string{"script-src", "style-src", "img-src", "font-src", "connect-src"} {
		sources, ok := directives[directive]
		if !ok {
			t.Fatalf("%s is not named, so it falls back to default-src; name it explicitly", directive)
		}
		for _, src := range sources {
			switch src {
			case "'unsafe-inline'", "'unsafe-eval'":
				t.Fatalf("%s allows %s", directive, src)
			case "'self'", "'none'":
			default:
				t.Fatalf("%s allows the external origin %q; every asset is served from the binary", directive, src)
			}
		}
	}
	if got := directives["frame-ancestors"]; len(got) != 1 || got[0] != "'none'" {
		t.Fatalf("frame-ancestors is %v, want 'none'", got)
	}
	if got := directives["base-uri"]; len(got) != 1 || got[0] != "'none'" {
		t.Fatalf("base-uri is %v, want 'none': a base element could redirect every relative asset", got)
	}
	if got := directives["form-action"]; len(got) != 1 || got[0] != "'none'" {
		t.Fatalf("form-action is %v, want 'none'", got)
	}
}

func TestStrictTransportSecurityOnlyUnderTLS(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	insecureServer := newTestServer(t, auth, nil)
	if got := get(t, insecureServer, "/").Header().Get("Strict-Transport-Security"); got != "" {
		// Sending HSTS from a plaintext listener would pin a browser to HTTPS
		// for a host that does not serve it.
		t.Fatalf("a plaintext listener sent Strict-Transport-Security: %q", got)
	}

	certFile, keyFile, _ := writeTestCertificate(t)
	tlsServer, err := New(Options{
		Addr:   "127.0.0.1:0",
		TLS:    TLSConfig{CertFile: certFile, KeyFile: keyFile},
		Reader: fixtureReader(t),
		Kube:   auth.clientset,
	})
	if err != nil {
		t.Fatalf("building a TLS server: %v", err)
	}
	if got := get(t, tlsServer, "/").Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("a TLS listener sent no Strict-Transport-Security")
	}
	if got := tlsServer.Describe(); !strings.Contains(got, "TLS") {
		t.Fatalf("Describe reported %q for a TLS listener", got)
	}
}

func TestTLSServerConfig(t *testing.T) {
	certFile, keyFile, caPEM := writeTestCertificate(t)
	cfg, err := TLSConfig{CertFile: certFile, KeyFile: keyFile}.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig returned %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("the listener would accept TLS below 1.2 (MinVersion=%x)", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("the listener loaded %d certificates", len(cfg.Certificates))
	}

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("writing the test CA: %v", err)
	}
	withCA, err := TLSConfig{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile}.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig with a client CA returned %v", err)
	}
	if withCA.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("a client CA was configured but client certificates are not required (%v)", withCA.ClientAuth)
	}

	badCA := filepath.Join(t.TempDir(), "empty.crt")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("writing the empty CA: %v", err)
	}
	if _, err := (TLSConfig{CertFile: certFile, KeyFile: keyFile, ClientCAFile: badCA}).ServerConfig(); err == nil {
		t.Fatal("a CA bundle with no certificates was accepted, which would leave client " +
			"authentication silently unenforced")
	}
}

// End to end over a real socket: a listener that says it is TLS has to
// actually negotiate TLS.
func TestListenAndServeOverTLS(t *testing.T) {
	certFile, keyFile, caPEM := writeTestCertificate(t)
	auth := newFakeAuth(true, allowNamespaces(visibleNS))

	addr := freeAddr(t)
	server, err := New(Options{
		Addr:   addr,
		TLS:    TLSConfig{CertFile: certFile, KeyFile: keyFile},
		Reader: fixtureReader(t),
		Kube:   auth.clientset,
	})
	if err != nil {
		t.Fatalf("building the server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx) }()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the test certificate could not be added to a pool")
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}

	var resp *http.Response
	for i := 0; i < 50 && resp == nil; i++ {
		answer, getErr := client.Get("https://" + addr + "/healthz")
		if getErr != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		resp = answer
	}
	if resp == nil {
		t.Fatal("the TLS listener never answered")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz over TLS = %d", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("the connection was not TLS")
	}

	// A plaintext request to a TLS listener must not be served. Go's TLS
	// server recognises a cleartext HTTP request and answers 400 in the clear
	// rather than failing the dial, so both outcomes are accepted and only a
	// successful read of a real page is not.
	plain, plainErr := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + addr + "/healthz")
	if plainErr == nil {
		defer func() { _ = plain.Body.Close() }()
		if plain.StatusCode < 400 {
			t.Fatalf("the TLS listener served a plaintext request with status %d", plain.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned %v on a cancelled context, want a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return after its context was cancelled, so the pod would " +
			"be killed rather than terminating")
	}
}

func TestListenAndServeReportsABusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("taking a port: %v", err)
	}
	defer func() { _ = ln.Close() }()

	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server, err := New(Options{
		Addr: ln.Addr().String(), AllowInsecure: true,
		Reader: fixtureReader(t), Kube: auth.clientset,
	})
	if err != nil {
		t.Fatalf("building the server: %v", err)
	}
	err = server.ListenAndServe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "could not listen") {
		t.Fatalf("ListenAndServe returned %v for a port already in use", err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing the test port: %v", err)
	}
	return addr
}

// writeTestCertificate returns paths to a self-signed certificate and key, and
// the PEM a client needs to trust it.
func writeTestCertificate(t *testing.T) (certFile, keyFile string, caPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a test key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pahlevan-dashboard-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a test certificate: %v", err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the test key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, caPEM, 0o600); err != nil {
		t.Fatalf("writing the test certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the test key: %v", err)
	}
	return certFile, keyFile, caPEM
}
