package grpcapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
)

// writeCert issues a self-signed certificate and returns the cert and key paths
// plus the PEM, so a test can also use it as a CA.
func writeCert(t *testing.T, dir, name string) (certPath, keyPath string, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	return certPath, keyPath, certPEM
}

// A cert without a key is a typo, and silently falling back to plaintext
// because of it is how a stream ends up unencrypted while its operator believes
// otherwise.
func TestTLSConfigRejectsHalfAConfiguration(t *testing.T) {
	assert.Error(t, TLSConfig{CertFile: "a.crt"}.Validate())
	assert.Error(t, TLSConfig{KeyFile: "a.key"}.Validate())
	assert.NoError(t, TLSConfig{}.Validate())
	assert.NoError(t, TLSConfig{CertFile: "a.crt", KeyFile: "a.key"}.Validate())
}

// mTLS without a server certificate cannot be enforced, so asking for it is an
// error rather than a setting that quietly does nothing.
func TestClientCAWithoutAServerCertIsAnError(t *testing.T) {
	err := TLSConfig{ClientCAFile: "ca.crt"}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS cannot be enforced")
}

// A bearer token on an unencrypted connection is sent in cleartext on every
// call, to anyone on the path. Accepting that would be offering a control that
// provides no protection.
func TestTokenWithoutTLSIsRefused(t *testing.T) {
	err := AuthConfig{Token: "secret"}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires TLS")

	dir := t.TempDir()
	cert, key, _ := writeCert(t, dir, "server")
	assert.NoError(t, AuthConfig{
		TLS:   TLSConfig{CertFile: cert, KeyFile: key},
		Token: "secret",
	}.Validate())
}

func TestCredentialsAreNilForPlaintext(t *testing.T) {
	creds, err := TLSConfig{}.Credentials()
	require.NoError(t, err)
	assert.Nil(t, creds, "no certificate configured means no transport credentials")
}

func TestCredentialsLoadTheCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := writeCert(t, dir, "server")
	creds, err := TLSConfig{CertFile: cert, KeyFile: key}.Credentials()
	require.NoError(t, err)
	assert.NotNil(t, creds)
}

func TestCredentialsRejectAnUnreadableCA(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := writeCert(t, dir, "server")

	_, err := TLSConfig{CertFile: cert, KeyFile: key, ClientCAFile: "/nope"}.Credentials()
	assert.Error(t, err)

	junk := filepath.Join(dir, "junk.pem")
	require.NoError(t, os.WriteFile(junk, []byte("not a certificate"), 0o600))
	_, err = TLSConfig{CertFile: cert, KeyFile: key, ClientCAFile: junk}.Credentials()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates")
}

// The description goes in the startup log, so an operator can see the posture
// rather than infer it. The plaintext case has to be unmissable.
func TestAuthDescribe(t *testing.T) {
	assert.Contains(t, AuthConfig{}.Describe(), "PLAINTEXT AND UNAUTHENTICATED")
	assert.Equal(t, "TLS, no client authentication",
		AuthConfig{TLS: TLSConfig{CertFile: "c", KeyFile: "k"}}.Describe())
	assert.Equal(t, "TLS + bearer token",
		AuthConfig{TLS: TLSConfig{CertFile: "c", KeyFile: "k"}, Token: "t"}.Describe())
	assert.Equal(t, "mTLS",
		AuthConfig{TLS: TLSConfig{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}}.Describe())
	assert.Equal(t, "mTLS + bearer token",
		AuthConfig{TLS: TLSConfig{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}, Token: "t"}.Describe())
}

// serveWithAuth runs a server over bufconn so the interceptors are exercised
// end to end rather than called directly.
func serveWithAuth(t *testing.T, auth AuthConfig) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := New(Options{Auth: auth})

	opts, err := auth.ServerOptions()
	require.NoError(t, err)
	gs := grpc.NewServer(opts...)
	apiv1alpha1.RegisterEventServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The unary call and the stream both have to be protected. Protecting only one
// leaves the other open, and the one people forget is the stream - which is the
// one that carries every event.
func TestTokenIsRequiredOnBothCallTypes(t *testing.T) {
	// Validate() refuses a token without TLS, but ServerOptions is what builds
	// the interceptors; construct the interceptors directly so the transport is
	// not what this test depends on.
	unary, stream := tokenAuth("s3cret")
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(unary), grpc.StreamInterceptor(stream))
	apiv1alpha1.RegisterEventServiceServer(gs, New(Options{}))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := apiv1alpha1.NewEventServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("unary without a token", func(t *testing.T) {
		_, err := client.GetStatus(ctx, &apiv1alpha1.StatusRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("stream without a token", func(t *testing.T) {
		s, err := client.Subscribe(ctx, &apiv1alpha1.SubscribeRequest{})
		require.NoError(t, err, "the stream opens; the first Recv is what fails")
		_, err = s.Recv()
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("the wrong token", func(t *testing.T) {
		md := metadata.Pairs("authorization", "Bearer wrong")
		_, err := client.GetStatus(metadata.NewOutgoingContext(ctx, md),
			&apiv1alpha1.StatusRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("the right token", func(t *testing.T) {
		md := metadata.Pairs("authorization", "Bearer s3cret")
		resp, err := client.GetStatus(metadata.NewOutgoingContext(ctx, md),
			&apiv1alpha1.StatusRequest{})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("a bare token without the Bearer prefix", func(t *testing.T) {
		md := metadata.Pairs("authorization", "s3cret")
		_, err := client.GetStatus(metadata.NewOutgoingContext(ctx, md),
			&apiv1alpha1.StatusRequest{})
		assert.NoError(t, err, "the prefix is optional, so a plain token works")
	})
}

// Without a token configured, nothing is required - the server must not start
// refusing calls because the field is empty.
func TestNoTokenMeansNoAuthentication(t *testing.T) {
	conn := serveWithAuth(t, AuthConfig{})
	client := apiv1alpha1.NewEventServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetStatus(ctx, &apiv1alpha1.StatusRequest{})
	assert.NoError(t, err)
}

// A real TLS handshake, so the credentials are proven to work rather than just
// to construct.
func TestTLSHandshakeSucceeds(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, certPEM := writeCert(t, dir, "server")

	auth := AuthConfig{TLS: TLSConfig{CertFile: certPath, KeyFile: keyPath}}
	opts, err := auth.ServerOptions()
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer(opts...)
	apiv1alpha1.RegisterEventServiceServer(gs, New(Options{}))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "localhost")))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = apiv1alpha1.NewEventServiceClient(conn).GetStatus(ctx, &apiv1alpha1.StatusRequest{})
	assert.NoError(t, err)
}

// A plaintext client must not be able to talk to a TLS listener. If it could,
// the encryption would be optional in practice.
func TestPlaintextClientCannotReachATLSListener(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeCert(t, dir, "server")

	opts, err := AuthConfig{TLS: TLSConfig{CertFile: certPath, KeyFile: keyPath}}.ServerOptions()
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer(opts...)
	apiv1alpha1.RegisterEventServiceServer(gs, New(Options{}))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = apiv1alpha1.NewEventServiceClient(conn).GetStatus(ctx, &apiv1alpha1.StatusRequest{})
	assert.Error(t, err, "a plaintext client must not reach a TLS listener")
}

// mTLS: a client with no certificate is refused.
func TestMTLSRejectsAClientWithNoCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, certPEM := writeCert(t, dir, "server")
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	opts, err := AuthConfig{TLS: TLSConfig{
		CertFile: certPath, KeyFile: keyPath, ClientCAFile: caPath,
	}}.ServerOptions()
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer(opts...)
	apiv1alpha1.RegisterEventServiceServer(gs, New(Options{}))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "localhost")))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = apiv1alpha1.NewEventServiceClient(conn).GetStatus(ctx, &apiv1alpha1.StatusRequest{})
	assert.Error(t, err, "mTLS must refuse a client that presents no certificate")
}

func BenchmarkTokenInterceptor(b *testing.B) {
	unary, _ := tokenAuth("s3cret")
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer s3cret"))
	handler := func(context.Context, any) (any, error) { return nil, nil }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := unary(ctx, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
			b.Fatal(err)
		}
	}
}
