package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apiv1alpha1 "github.com/obsernetics/pahlevan/api/v1alpha1"
	"github.com/obsernetics/pahlevan/pkg/export"
	"github.com/obsernetics/pahlevan/pkg/grpcapi"
)

func TestAgentSourceValidate(t *testing.T) {
	tests := []struct {
		name    string
		source  AgentSource
		wantErr string
	}{
		{name: "no endpoint", source: AgentSource{}, wantErr: "needs an endpoint"},
		{
			// A token on an unencrypted connection is a token you have
			// published, so this is a startup error rather than a warning.
			name:    "token over plaintext",
			source:  AgentSource{Endpoint: "agent:9090", Token: "t", Insecure: true},
			wantErr: "cleartext",
		},
		{name: "token over TLS", source: AgentSource{Endpoint: "agent:9090", Token: "t"}},
		{name: "plaintext without a token", source: AgentSource{Endpoint: "agent:9090", Insecure: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.source.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate returned %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate returned %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestAgentSourceRejectsAnUnreadableCA(t *testing.T) {
	source := AgentSource{Endpoint: "agent:9090", CAFile: "/nonexistent/ca.crt"}
	if _, err := source.dialOptions(); err == nil {
		t.Fatal("a missing CA file was accepted, so the dashboard would fall back to the system " +
			"roots and trust the wrong agent")
	}
}

// gRPC itself refuses to attach per-RPC credentials to a plaintext connection.
// That is the last line of defence behind Validate, for a source built in code
// rather than from flags.
func TestBearerCredentialsRequireTransportSecurity(t *testing.T) {
	if !bearerCredentials("t").RequireTransportSecurity() {
		t.Fatal("the agent token would be attached to a plaintext connection")
	}
	md, err := bearerCredentials("t").GetRequestMetadata(context.Background())
	if err != nil || md["authorization"] != "Bearer t" {
		t.Fatalf("GetRequestMetadata = %v, %v", md, err)
	}
}

func TestEventFromProtoRoundTrip(t *testing.T) {
	// The fields asserted here are exactly the ones the dashboard renders: the
	// verdict, the subject of the denial and the ancestry behind it.
	original := &export.Event{
		Version:   export.SchemaVersion,
		Timestamp: export.Timestamp(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
		Type:      export.EventTypeProcess,
		Action:    export.ActionDeny,
		CgroupID:  4242,
		Process:   export.ProcessInfo{PID: 11, Comm: "curl", ParentComm: "sh"},
		Kubernetes: &export.KubernetesRef{
			Namespace: "prod", Pod: "api-0", Container: "api", Node: "node-1",
			WorkloadKind: "Deployment", WorkloadName: "api", Image: "nginx:1.27",
		},
		Exec: &export.ExecInfo{
			Binary:        "/usr/bin/curl",
			AncestryChain: "nginx -> sh -> curl",
			Ancestry:      []export.AncestorInfo{{PID: 2, Comm: "sh"}, {PID: 1, Comm: "nginx"}},
		},
	}

	got := EventFromProto(grpcapi.ToProto(original))

	if !got.Denied() {
		t.Fatal("a denied event came back as an observation, so the page would show an attack as normal traffic")
	}
	if got.Type != export.EventTypeProcess || got.CgroupID != 4242 {
		t.Fatalf("the envelope came back as %+v", got)
	}
	if got.Kubernetes == nil || got.Kubernetes.Namespace != "prod" || got.Kubernetes.WorkloadName != "api" {
		t.Fatalf("attribution came back as %+v", got.Kubernetes)
	}
	if got.Exec == nil || got.Exec.Binary != "/usr/bin/curl" || len(got.Exec.Ancestry) != 2 {
		t.Fatalf("the exec detail came back as %+v", got.Exec)
	}
	if got.Exec.Ancestry[0].Comm != "sh" {
		t.Fatalf("ancestry order changed: %+v", got.Exec.Ancestry)
	}
	if !got.Timestamp.Time().Equal(original.Timestamp.Time()) {
		t.Fatalf("the timestamp came back as %s", got.Timestamp)
	}
}

func TestEventFromProtoDetails(t *testing.T) {
	tests := []struct {
		name   string
		event  *export.Event
		assert func(t *testing.T, got export.Event)
	}{
		{
			name: "file read and write are distinct",
			event: &export.Event{
				Type: export.EventTypeFile,
				File: &export.FileInfo{Path: "/etc/shadow", Flags: 0x40000000},
			},
			assert: func(t *testing.T, got export.Event) {
				if got.File == nil || got.File.SyscallName != "write" {
					t.Fatalf("a write open came back as %+v", got.File)
				}
			},
		},
		{
			name: "network keeps both the name and the address",
			event: &export.Event{
				Type: export.EventTypeNetwork,
				Network: &export.NetworkInfo{
					DestinationIP: "10.0.0.5", DestinationPort: 5432,
					DestinationName: "prod/postgres", DestinationKind: "service", Protocol: "tcp",
				},
			},
			assert: func(t *testing.T, got export.Event) {
				// Both, not one: the name is what an operator recognises and
				// the address is what they grep the firewall logs for.
				if got.Network.DestinationIP != "10.0.0.5" || got.Network.DestinationName != "prod/postgres" {
					t.Fatalf("the destination came back as %+v", got.Network)
				}
			},
		},
		{
			name:  "capability",
			event: &export.Event{Type: export.EventTypeCapability, Capability: &export.CapabilityInfo{Name: "SYS_ADMIN", Number: 21}},
			assert: func(t *testing.T, got export.Event) {
				if got.Capability == nil || got.Capability.Name != "SYS_ADMIN" {
					t.Fatalf("the capability came back as %+v", got.Capability)
				}
			},
		},
		{
			name:  "syscall",
			event: &export.Event{Type: export.EventTypeSyscall, Syscall: &export.SyscallInfo{Name: "ptrace", Number: 101}},
			assert: func(t *testing.T, got export.Event) {
				if got.Syscall == nil || got.Syscall.Number != 101 {
					t.Fatalf("the syscall came back as %+v", got.Syscall)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, EventFromProto(grpcapi.ToProto(tc.event)))
		})
	}
}

func TestEventFromProtoHandlesNilAndBadTimestamps(t *testing.T) {
	if got := EventFromProto(nil); got.Type != "" {
		t.Fatalf("a nil message produced %+v", got)
	}
	// A stamp that will not parse is not worth discarding the event over: the
	// rest of it is still true, and the denial still belongs in the list.
	got := EventFromProto(&apiv1alpha1.Event{
		Timestamp: "not a timestamp",
		Type:      apiv1alpha1.EventType_EVENT_TYPE_FILE,
		Action:    apiv1alpha1.Action_ACTION_DENY,
	})
	if got.Timestamp.Time().IsZero() {
		t.Fatal("an unparseable timestamp produced a zero time, which sorts to the bottom of every list")
	}
	if !got.Denied() {
		t.Fatal("the verdict was lost with the timestamp")
	}
}

// An unrecognised action must render as an observation. An imaginary incident
// in front of an operator is the more expensive mistake.
func TestUnknownActionIsNotADenial(t *testing.T) {
	got := EventFromProto(&apiv1alpha1.Event{Action: apiv1alpha1.Action_ACTION_UNSPECIFIED})
	if got.Denied() {
		t.Fatal("an unspecified action was rendered as a denial")
	}
}

// End to end against the real agent server: subscribe, receive, and land in
// the store with attribution intact.
func TestAgentSourceStreamsIntoTheStore(t *testing.T) {
	agent := grpcapi.New(grpcapi.Options{Auth: grpcapi.AuthConfig{AllowInsecure: true}})
	addr := freeAddr(t)

	serveCtx, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	served := make(chan error, 1)
	go func() { served <- agent.Serve(serveCtx, addr) }()

	store := NewStore(StoreOptions{})
	source := AgentSource{Endpoint: addr, Insecure: true}
	sourceCtx, stopSource := context.WithCancel(context.Background())
	defer stopSource()
	go func() { _ = source.Run(sourceCtx, store) }()

	// Wait for the subscription before publishing: an event enqueued with no
	// subscriber attached is dropped by design, and the test would then be
	// asserting on a race rather than on the stream.
	deadline := time.Now().Add(10 * time.Second)
	for agent.Subscribers() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the source never subscribed to the agent")
		}
		time.Sleep(10 * time.Millisecond)
	}

	agent.Enqueue(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))

	key := WorkloadKey{Namespace: visibleNS, Kind: "Deployment", Name: "api"}
	for time.Now().Before(deadline) {
		if act, ok := store.Activity(key); ok && act.Counts.Denials == 1 {
			if len(act.Denials) != 1 || act.Denials[0].Subject != "/usr/bin/curl" {
				t.Fatalf("the denial arrived as %+v", act.Denials)
			}
			if act.Denials[0].Ancestry != "" && !strings.Contains(act.Denials[0].Ancestry, "nginx") {
				t.Fatalf("the ancestry arrived as %q", act.Denials[0].Ancestry)
			}
			if len(act.Processes) == 0 || act.Processes[0].Comm != "nginx" {
				t.Fatalf("the process tree arrived as %+v", act.Processes)
			}
			stopSource()
			stopAgent()
			<-served
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the event never reached the store")
}

func TestAgentSourceRunRejectsABadConfiguration(t *testing.T) {
	source := AgentSource{Endpoint: "agent:9090", Token: "t", Insecure: true}
	if err := source.Run(context.Background(), NewStore(StoreOptions{})); err == nil {
		t.Fatal("Run started a source that would publish its token in cleartext")
	}
}

func TestAgentSourceDialOptions(t *testing.T) {
	// Three shapes, each of which has to produce credentials rather than
	// silently dialling something weaker than the operator asked for.
	t.Run("plaintext", func(t *testing.T) {
		opts, err := (&AgentSource{Endpoint: "agent:9090", Insecure: true}).dialOptions()
		if err != nil || len(opts) != 1 {
			t.Fatalf("dialOptions = %d options, %v", len(opts), err)
		}
	})

	t.Run("system roots", func(t *testing.T) {
		opts, err := (&AgentSource{Endpoint: "agent:9090"}).dialOptions()
		if err != nil || len(opts) != 1 {
			t.Fatalf("dialOptions = %d options, %v", len(opts), err)
		}
	})

	t.Run("pinned CA and a token", func(t *testing.T) {
		_, _, caPEM := writeTestCertificate(t)
		caFile := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
			t.Fatalf("writing the CA: %v", err)
		}
		opts, err := (&AgentSource{Endpoint: "agent:9090", CAFile: caFile, Token: "t"}).dialOptions()
		if err != nil {
			t.Fatalf("dialOptions returned %v", err)
		}
		if len(opts) != 2 {
			t.Fatalf("dialOptions produced %d options, want transport credentials and the token", len(opts))
		}
	})

	t.Run("a CA with no certificates", func(t *testing.T) {
		caFile := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(caFile, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("writing the CA: %v", err)
		}
		if _, err := (&AgentSource{Endpoint: "agent:9090", CAFile: caFile}).dialOptions(); err == nil {
			t.Fatal("an empty CA bundle was accepted, so the dashboard would trust the system roots " +
				"while its operator believed it was pinned")
		}
	})
}

func TestAgentSourceStopsWithItsContext(t *testing.T) {
	// A dashboard whose agent connection dropped is still a useful dashboard,
	// so Run retries rather than failing - but it has to stop when told to.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&AgentSource{Endpoint: "127.0.0.1:1", Insecure: true}).Run(ctx, NewStore(StoreOptions{}))
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on a cancelled context, want a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run ignored its cancelled context")
	}
}
