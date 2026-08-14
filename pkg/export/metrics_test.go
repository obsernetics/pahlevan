package export

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestMetricsAreRegistered(t *testing.T) {
	RegisterMetrics()
	RegisterMetrics() // idempotent

	// Produce at least one sample of each so the families show up.
	countExported(EventTypeFile)
	countDropped(dropReasonQueueFull, 1)
	countDropped(dropReasonQueueFull, 0) // no-op

	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{"pahlevan_export_events_total", "pahlevan_export_dropped_total"} {
		if !names[want] {
			t.Errorf("metric %s is not registered (have %d families)", want, len(families))
		}
	}
}

func TestRegisterToleratesConflict(t *testing.T) {
	// Registering a different collector under an existing name must not panic.
	conflicting := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pahlevan_export_events_total",
		Help: "conflicting collector",
	})
	register(conflicting)
}

func TestDefaultEventLogPath(t *testing.T) {
	if !strings.HasSuffix(DefaultEventLogPath, ".json") {
		t.Errorf("default path = %q", DefaultEventLogPath)
	}
}
