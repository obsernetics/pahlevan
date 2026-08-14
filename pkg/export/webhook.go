package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Webhook sink defaults.
const (
	DefaultWebhookTimeout    = 5 * time.Second
	DefaultWebhookMaxRetries = 3
	DefaultWebhookBackoff    = 100 * time.Millisecond
	DefaultWebhookMaxBackoff = 2 * time.Second
	DefaultWebhookBatchSize  = 256
)

// WebhookPayload is the body POSTed to the webhook URL. Keeping the events
// inside an object (rather than a bare array) leaves room for future top level
// fields without breaking consumers.
type WebhookPayload struct {
	Version string   `json:"version"`
	Source  string   `json:"source,omitempty"`
	Count   int      `json:"count"`
	Events  []*Event `json:"events"`
}

// WebhookOptions configures the webhook sink.
type WebhookOptions struct {
	// URL is the endpoint that receives the POSTs. Required.
	URL string
	// Timeout bounds a single HTTP attempt. Zero uses DefaultWebhookTimeout.
	Timeout time.Duration
	// MaxRetries is how many times a failed POST is retried before the batch
	// is dropped. Zero uses DefaultWebhookMaxRetries; a negative value means
	// no retry at all.
	MaxRetries int
	// Backoff is the initial retry delay, doubled on each attempt up to
	// MaxBackoff. Zero uses DefaultWebhookBackoff.
	Backoff time.Duration
	// MaxBackoff caps the retry delay. Zero uses DefaultWebhookMaxBackoff.
	MaxBackoff time.Duration
	// BatchSize splits a large Export into several POSTs. Zero uses
	// DefaultWebhookBatchSize.
	BatchSize int
	// Headers are added to every request (for example an auth token).
	Headers map[string]string
	// Source is copied into the payload so a shared collector can tell agents
	// apart. The agent should set it to the node name.
	Source string
	// Client overrides the HTTP client. When nil a client with Timeout is
	// created.
	Client *http.Client
}

func (o WebhookOptions) withDefaults() WebhookOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultWebhookTimeout
	}
	if o.MaxRetries == 0 {
		o.MaxRetries = DefaultWebhookMaxRetries
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	if o.Backoff <= 0 {
		o.Backoff = DefaultWebhookBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultWebhookMaxBackoff
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultWebhookBatchSize
	}
	return o
}

// WebhookExporter POSTs batches of events to an HTTP endpoint with a bounded
// retry and exponential backoff. A batch that still fails after the last
// attempt is dropped rather than retried forever, so a dead collector cannot
// build an unbounded backlog.
type WebhookExporter struct {
	opts   WebhookOptions
	client *http.Client

	mu     sync.Mutex
	closed bool
	// sleep is swapped out in tests to keep backoff instant.
	sleep func(context.Context, time.Duration)
}

// NewWebhookExporter validates opts and returns the sink.
func NewWebhookExporter(opts WebhookOptions) (*WebhookExporter, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("export: webhook sink needs a URL")
	}
	RegisterMetrics()
	opts = opts.withDefaults()
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}
	return &WebhookExporter{
		opts:   opts,
		client: client,
		sleep:  sleepCtx,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (e *WebhookExporter) Name() string { return "webhook" }

// URL returns the configured endpoint.
func (e *WebhookExporter) URL() string { return e.opts.URL }

func (e *WebhookExporter) Export(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	for start := 0; start < len(events); start += e.opts.BatchSize {
		end := start + e.opts.BatchSize
		if end > len(events) {
			end = len(events)
		}
		chunk := events[start:end]
		if err := e.postWithRetry(ctx, chunk); err != nil {
			// The chunk is dropped rather than retried forever. Drop
			// accounting belongs to the Queue, which sees the error and
			// increments pahlevan_export_dropped_total for the whole batch.
			return err
		}
	}
	return nil
}

func (e *WebhookExporter) postWithRetry(ctx context.Context, events []*Event) error {
	body, err := json.Marshal(WebhookPayload{
		Version: SchemaVersion,
		Source:  e.opts.Source,
		Count:   len(events),
		Events:  events,
	})
	if err != nil {
		return fmt.Errorf("export: marshal webhook payload: %w", err)
	}

	backoff := e.opts.Backoff
	var lastErr error
	for attempt := 0; attempt <= e.opts.MaxRetries; attempt++ {
		if attempt > 0 {
			e.sleep(ctx, backoff)
			if ctx.Err() != nil {
				return fmt.Errorf("export: webhook aborted after %d attempts: %w", attempt, ctx.Err())
			}
			backoff *= 2
			if backoff > e.opts.MaxBackoff {
				backoff = e.opts.MaxBackoff
			}
		}
		lastErr = e.post(ctx, body)
		if lastErr == nil {
			return nil
		}
		if !retryable(lastErr) {
			return lastErr
		}
	}
	return fmt.Errorf("export: webhook %s failed after %d attempts, dropping %d events: %w",
		e.opts.URL, e.opts.MaxRetries+1, len(events), lastErr)
}

func (e *WebhookExporter) post(ctx context.Context, body []byte) error {
	reqCtx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, e.opts.URL, bytes.NewReader(body))
	if err != nil {
		return permanentError{fmt.Errorf("export: build webhook request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pahlevan-exporter/"+SchemaVersion)
	for k, v := range e.opts.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("export: post to %s: %w", e.opts.URL, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= 500:
		return fmt.Errorf("export: webhook %s returned %s", e.opts.URL, resp.Status)
	default:
		// 4xx other than 408/429 will not get better by retrying.
		return permanentError{fmt.Errorf("export: webhook %s returned %s", e.opts.URL, resp.Status)}
	}
}

// permanentError marks a failure that retrying cannot fix.
type permanentError struct{ err error }

func (p permanentError) Error() string { return p.err.Error() }
func (p permanentError) Unwrap() error { return p.err }

func retryable(err error) bool {
	var p permanentError
	return !errors.As(err, &p)
}

func (e *WebhookExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	if e.opts.Client == nil {
		e.client.CloseIdleConnections()
	}
	return nil
}
