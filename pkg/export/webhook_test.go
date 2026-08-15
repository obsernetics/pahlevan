package export

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestWebhook builds a sink whose backoff does not actually sleep.
func newTestWebhook(t *testing.T, opts WebhookOptions) *WebhookExporter {
	t.Helper()
	e, err := NewWebhookExporter(opts)
	if err != nil {
		t.Fatalf("new webhook: %v", err)
	}
	e.sleep = func(context.Context, time.Duration) {}
	return e
}

func TestWebhookExporterPostsBatch(t *testing.T) {
	var (
		mu       sync.Mutex
		payloads []WebhookPayload
		headers  http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p WebhookPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("server got invalid JSON: %v", err)
		}
		mu.Lock()
		payloads = append(payloads, p)
		headers = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{
		URL:     srv.URL,
		Source:  "node-1",
		Headers: map[string]string{"Authorization": "Bearer secret"},
	})
	defer func() { _ = e.Close() }()

	if e.Name() != "webhook" || e.URL() != srv.URL {
		t.Errorf("name/url = %q/%q", e.Name(), e.URL())
	}
	if err := e.Export(context.Background(), nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	events := []*Event{testEvent(EventTypeFile), testEvent(EventTypeNetwork)}
	if err := e.Export(context.Background(), events); err != nil {
		t.Fatalf("export: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(payloads) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(payloads))
	}
	p := payloads[0]
	if p.Count != 2 || len(p.Events) != 2 || p.Version != SchemaVersion || p.Source != "node-1" {
		t.Fatalf("payload = %+v", p)
	}
	if got := headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type = %q", got)
	}
	if got := headers.Get("Authorization"); got != "Bearer secret" {
		t.Errorf("custom header = %q", got)
	}
	if got := headers.Get("User-Agent"); !strings.HasPrefix(got, "pahlevan-exporter/") {
		t.Errorf("user agent = %q", got)
	}
}

func TestWebhookExporterSplitsBatches(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL, BatchSize: 2})
	defer func() { _ = e.Close() }()

	events := make([]*Event, 5)
	for i := range events {
		events[i] = testEvent(EventTypeSyscall)
	}
	if err := e.Export(context.Background(), events); err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("made %d requests for 5 events with batch size 2, want 3", got)
	}
}

func TestWebhookExporterRetriesThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL, MaxRetries: 3})
	defer func() { _ = e.Close() }()

	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err != nil {
		t.Fatalf("export should have recovered: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestWebhookExporterDropsAfterRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL, MaxRetries: 2})
	defer func() { _ = e.Close() }()

	err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)})
	if err == nil {
		t.Fatal("expected the batch to be dropped with an error")
	}
	if !strings.Contains(err.Error(), "dropping 1 events") {
		t.Errorf("error should say the batch was dropped, got %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want the first try plus 2 retries", got)
	}
}

func TestWebhookExporterDoesNotRetryClientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL, MaxRetries: 5})
	defer func() { _ = e.Close() }()

	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, a 400 must not be retried", got)
	}
}

func TestWebhookExporterRetriesRateLimits(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL})
	defer func() { _ = e.Close() }()

	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); err != nil {
		t.Fatalf("429 should be retried: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d", got)
	}
}

func TestWebhookExporterDeadServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening any more

	e := newTestWebhook(t, WebhookOptions{URL: url, MaxRetries: 1, Timeout: 200 * time.Millisecond})
	defer func() { _ = e.Close() }()

	err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)})
	if err == nil {
		t.Fatal("expected an error against a dead server")
	}
	if !strings.Contains(err.Error(), "failed after 2 attempts") {
		t.Errorf("error = %v", err)
	}
}

func TestWebhookExporterHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e, err := NewWebhookExporter(WebhookOptions{URL: srv.URL, MaxRetries: 5, Backoff: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = e.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Export(ctx, []*Event{testEvent(EventTypeFile)}); err == nil {
		t.Fatal("expected an error once the context is canceled")
	}
}

func TestWebhookExporterClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL})
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := e.Export(context.Background(), []*Event{testEvent(EventTypeFile)}); !errors.Is(err, ErrClosed) {
		t.Errorf("export after close = %v", err)
	}
}

func TestNewWebhookExporterValidation(t *testing.T) {
	if _, err := NewWebhookExporter(WebhookOptions{}); err == nil {
		t.Fatal("expected an error without a URL")
	}
	e, err := NewWebhookExporter(WebhookOptions{URL: "http://example.invalid", MaxRetries: -1})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if e.opts.MaxRetries != 0 {
		t.Errorf("a negative MaxRetries should disable retries, got %d", e.opts.MaxRetries)
	}
	if e.opts.Timeout != DefaultWebhookTimeout || e.opts.BatchSize != DefaultWebhookBatchSize {
		t.Errorf("defaults not applied: %+v", e.opts)
	}
}

func TestWebhookBackoffGrowsAndIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	e, err := NewWebhookExporter(WebhookOptions{
		URL:        srv.URL,
		MaxRetries: 4,
		Backoff:    10 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer func() { _ = e.Close() }()

	var delays []time.Duration
	e.sleep = func(_ context.Context, d time.Duration) { delays = append(delays, d) }

	_ = e.Export(context.Background(), []*Event{testEvent(EventTypeFile)})
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
	if len(delays) != len(want) {
		t.Fatalf("delays = %v, want %v", delays, want)
	}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("delays = %v, want %v", delays, want)
		}
	}
}

func TestPermanentErrorWrapping(t *testing.T) {
	inner := errors.New("bad request")
	p := permanentError{inner}
	if p.Error() != "bad request" {
		t.Errorf("Error() = %q", p.Error())
	}
	if !errors.Is(p, inner) {
		t.Error("permanentError must unwrap to the cause")
	}
	if retryable(p) {
		t.Error("a permanent error is not retryable")
	}
	if !retryable(inner) {
		t.Error("an ordinary error is retryable")
	}
}

func TestWebhookThroughQueueCountsDrops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := newTestWebhook(t, WebhookOptions{URL: srv.URL, MaxRetries: 1})
	q := NewQueue(e, QueueOptions{Capacity: 8, BatchSize: 2, FlushInterval: time.Millisecond})

	for i := 0; i < 2; i++ {
		q.Enqueue(testEvent(EventTypeNetwork))
	}
	waitFor(t, func() bool { return q.Dropped() >= 2 })
	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
