package export

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/ebpf"
)

func TestNewPipelineWithoutSinks(t *testing.T) {
	p, err := New(Config{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if p != nil {
		t.Fatal("no sink configured should yield a nil pipeline")
	}
	// A nil pipeline is safe to use.
	if p.Dropped() != 0 {
		t.Error("Dropped on a nil pipeline")
	}
	if err := p.Flush(context.Background()); err != nil {
		t.Errorf("Flush on a nil pipeline: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close on a nil pipeline: %v", err)
	}
}

func TestNewPipelineEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	var posted atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := New(Config{
		FilePath:      path,
		WebhookURL:    srv.URL,
		QueueCapacity: 64,
		BatchSize:     2,
		FlushInterval: 5 * time.Millisecond,
		Types:         []string{"file", "process"},
		DenialsOnly:   true,
		Source:        "node-a",
		Attribution: func(id uint64) (KubernetesRef, bool) {
			return KubernetesRef{Namespace: "prod", Pod: "api-0"}, true
		},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if p == nil {
		t.Fatal("expected a pipeline")
	}

	// Denied file event: exported. Observed file event and any network event:
	// filtered out.
	if err := p.Handler.HandleFileEvent(&ebpf.FileEvent{Path: "/etc/shadow", Flags: DeniedFlag, CgroupID: 1}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := p.Handler.HandleFileEvent(&ebpf.FileEvent{Path: "/tmp/ok", CgroupID: 1}); err != nil {
		t.Fatalf("file: %v", err)
	}
	if err := p.Handler.HandleProcessEvent(&ebpf.ProcessEvent{Filename: "/bin/nc", Flags: DeniedFlag, CgroupID: 1}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if err := p.Handler.HandleNetworkEvent(&ebpf.NetworkEvent{DstIP: 1, Direction: DeniedDirection, CgroupID: 1}); err != nil {
		t.Fatalf("network: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if p.Dropped() != 0 {
		t.Errorf("dropped = %d", p.Dropped())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events := decodeLines(t, string(data))
	if len(events) != 2 {
		t.Fatalf("file holds %d events, want 2: %s", len(events), data)
	}
	for _, e := range events {
		if !e.Denied() {
			t.Errorf("event %q is not a denial", e.Type)
		}
		if e.Kubernetes == nil || e.Kubernetes.Pod != "api-0" {
			t.Errorf("attribution missing on %q", e.Type)
		}
	}
	if posted.Load() == 0 {
		t.Error("the webhook sink received nothing")
	}
}

func TestNewPipelineValidatesConfig(t *testing.T) {
	if _, err := New(Config{Stdout: true, Types: []string{"bogus"}}); err == nil {
		t.Error("expected an error for an unknown event type")
	}
	if _, err := New(Config{FilePath: string([]byte{0})}); err == nil {
		t.Error("expected an error for an unusable file path")
	}
	if !(Config{Stdout: true}).Enabled() || !(Config{FilePath: "/x"}).Enabled() ||
		!(Config{WebhookURL: "http://x"}).Enabled() || (Config{}).Enabled() {
		t.Error("Enabled does not reflect the configured sinks")
	}
}

func TestNewPipelineStdoutOnly(t *testing.T) {
	p, err := New(Config{Stdout: true, FlushInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = p.Close() }()

	multi, ok := p.Exporter.(*Multi)
	if !ok {
		t.Fatalf("exporter = %T", p.Exporter)
	}
	if got := multi.Exporters(); len(got) != 1 || got[0].Name() != "stdout" {
		t.Fatalf("sinks = %+v", got)
	}
}

func TestPipelineFlushAndDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	p, err := New(Config{FilePath: path, QueueCapacity: 8, BatchSize: 1, FlushInterval: time.Millisecond})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.Handler.HandleSyscallEvent(&ebpf.SyscallEvent{SyscallNr: 1}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if p.Dropped() != 0 {
		t.Errorf("dropped = %d", p.Dropped())
	}
}
