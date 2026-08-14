package export

import (
	"context"
	"fmt"
	"time"
)

// Config describes a complete export pipeline: which sinks to build, how to
// buffer, and what to filter. It is the single entry point the agent needs.
type Config struct {
	// Stdout enables the JSON-lines stdout sink.
	Stdout bool

	// FilePath enables the JSON-lines file sink when non-empty. Use
	// DefaultEventLogPath to match what `pahlevan events` reads by default.
	FilePath string
	// FileMaxSizeBytes is the rotation threshold. Zero uses
	// DefaultMaxFileSizeBytes.
	FileMaxSizeBytes int64
	// FileMaxBackups is how many rotated files are kept. Zero uses
	// DefaultMaxBackups.
	FileMaxBackups int

	// WebhookURL enables the webhook sink when non-empty.
	WebhookURL string
	// WebhookTimeout bounds a single POST. Zero uses DefaultWebhookTimeout.
	WebhookTimeout time.Duration
	// WebhookMaxRetries bounds the retries per batch. Zero uses
	// DefaultWebhookMaxRetries; negative means no retry.
	WebhookMaxRetries int
	// WebhookBatchSize splits a queue batch into several POSTs. Zero uses
	// DefaultWebhookBatchSize.
	WebhookBatchSize int
	// WebhookHeaders are added to every POST.
	WebhookHeaders map[string]string
	// Source identifies this agent in the webhook payload (use the node name).
	Source string

	// QueueCapacity is the bounded buffer size. Zero uses
	// DefaultQueueCapacity.
	QueueCapacity int
	// BatchSize caps a single Export. Zero uses DefaultBatchSize.
	BatchSize int
	// FlushInterval bounds how long a partial batch waits. Zero uses
	// DefaultFlushInterval.
	FlushInterval time.Duration
	// ExportTimeout bounds a single Export call.
	ExportTimeout time.Duration

	// Types selects which event types are exported. Empty means all of them.
	Types []string
	// DenialsOnly exports only in-kernel denials (enforcement only mode).
	DenialsOnly bool

	// Attribution fills in pod metadata from a cgroup id. Optional.
	Attribution AttributionFunc
	// OnError, when set, receives every sink failure. It must not block.
	OnError func(err error)
}

// Enabled reports whether any sink is configured.
func (c Config) Enabled() bool {
	return c.Stdout || c.FilePath != "" || c.WebhookURL != ""
}

// Pipeline holds the constructed sinks, the bounded queue and the
// ebpf.EventHandler adapter. Close it to flush and release everything.
type Pipeline struct {
	Handler  *Handler
	Queue    *Queue
	Exporter Exporter
}

// New builds the pipeline described by cfg. It returns a nil Pipeline and a
// nil error when no sink is enabled, so a caller can write:
//
//	p, err := export.New(cfg)
//	if err != nil { return err }
//	if p != nil {
//		defer p.Close()
//		manager.AddEventHandler(p.Handler)
//	}
func New(cfg Config) (*Pipeline, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	RegisterMetrics()

	filter, err := NewFilter(cfg.Types, cfg.DenialsOnly)
	if err != nil {
		return nil, err
	}

	var sinks, built []Exporter
	closeBuilt := func() {
		for _, s := range built {
			_ = s.Close()
		}
	}

	if cfg.Stdout {
		s := NewStdoutExporter()
		sinks = append(sinks, s)
		built = append(built, s)
	}
	if cfg.FilePath != "" {
		s, err := NewFileExporter(FileOptions{
			Path:         cfg.FilePath,
			MaxSizeBytes: cfg.FileMaxSizeBytes,
			MaxBackups:   cfg.FileMaxBackups,
		})
		if err != nil {
			closeBuilt()
			return nil, err
		}
		sinks = append(sinks, s)
		built = append(built, s)
	}
	if cfg.WebhookURL != "" {
		s, err := NewWebhookExporter(WebhookOptions{
			URL:        cfg.WebhookURL,
			Timeout:    cfg.WebhookTimeout,
			MaxRetries: cfg.WebhookMaxRetries,
			BatchSize:  cfg.WebhookBatchSize,
			Headers:    cfg.WebhookHeaders,
			Source:     cfg.Source,
		})
		if err != nil {
			closeBuilt()
			return nil, err
		}
		sinks = append(sinks, s)
		built = append(built, s)
	}
	exporter := Exporter(NewMulti(sinks...))
	queue := NewQueue(exporter, QueueOptions{
		Capacity:      cfg.QueueCapacity,
		BatchSize:     cfg.BatchSize,
		FlushInterval: cfg.FlushInterval,
		ExportTimeout: cfg.ExportTimeout,
		OnError:       cfg.OnError,
	})
	handler := NewHandler(queue, HandlerOptions{
		Filter:      filter,
		Attribution: cfg.Attribution,
	})

	return &Pipeline{Handler: handler, Queue: queue, Exporter: exporter}, nil
}

// Dropped returns how many events the pipeline discarded.
func (p *Pipeline) Dropped() uint64 {
	if p == nil || p.Queue == nil {
		return 0
	}
	return p.Queue.Dropped()
}

// Flush waits for the buffered events to reach the sinks.
func (p *Pipeline) Flush(ctx context.Context) error {
	if p == nil || p.Queue == nil {
		return nil
	}
	return p.Queue.Flush(ctx)
}

// Close flushes the queue and closes every sink. It is safe on a nil Pipeline.
func (p *Pipeline) Close() error {
	if p == nil || p.Queue == nil {
		return nil
	}
	if err := p.Queue.Close(); err != nil {
		return fmt.Errorf("export: close pipeline: %w", err)
	}
	return nil
}
