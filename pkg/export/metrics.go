package export

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	metricsOnce sync.Once

	// eventsTotal counts envelopes accepted for export, by event type.
	eventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_export_events_total",
		Help: "Total number of events accepted for export, by event type.",
	}, []string{"type"})

	// droppedTotal counts envelopes discarded because the queue was full or a
	// sink permanently failed.
	droppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_export_dropped_total",
		Help: "Total number of events dropped instead of exported, by reason.",
	}, []string{"reason"})

	// signalsTotal counts post-exploitation signals recognised on the export
	// path, by signal. Separate from eventsTotal because the question an
	// operator asks of it is different: eventsTotal is volume, this is "did a
	// server process spawn a shell on this node today", and the answer is
	// wanted whether or not enforcement was on to deny it.
	signalsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pahlevan_postex_signals_total",
		Help: "Total number of post-exploitation signals recognised, by signal.",
	}, []string{"signal"})
)

// Drop reasons used as the label value of pahlevan_export_dropped_total.
const (
	dropReasonQueueFull = "queue_full"
	dropReasonSinkError = "sink_error"
	dropReasonClosed    = "closed"
)

// RegisterMetrics registers the export metrics on the controller-runtime
// registry. It is safe to call more than once and from several goroutines;
// only the first call registers. Constructing any exporter calls it, so
// callers rarely need to.
func RegisterMetrics() {
	metricsOnce.Do(func() {
		register(eventsTotal)
		register(droppedTotal)
		register(signalsTotal)
	})
}

// register tolerates a collector that is already present and never panics: a
// missing metric must not take down the agent.
func register(c prometheus.Collector) {
	err := ctrlmetrics.Registry.Register(c)
	if err == nil {
		return
	}
	var already prometheus.AlreadyRegisteredError
	_ = errors.As(err, &already)
}

func countExported(t EventType) {
	eventsTotal.WithLabelValues(string(t)).Inc()
}

func countSignal(s Signal) {
	signalsTotal.WithLabelValues(string(s)).Inc()
}

func countDropped(reason string, n int) {
	if n <= 0 {
		return
	}
	droppedTotal.WithLabelValues(reason).Add(float64(n))
}
