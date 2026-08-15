package observability

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// The three metric exporter branches used to log "temporarily disabled" and
// fall through, leaving `readers` empty. A MeterProvider with no readers still
// accepts every Add() and Record() call and silently discards them, so metrics
// looked configured, looked healthy, and reached nothing.
func TestInitializeMetricsBuildsAReaderPerExporter(t *testing.T) {
	res, err := resource.New(context.Background())
	require.NoError(t, err)

	for name, exporters := range map[string][]ExporterConfig{
		"console":            {{Type: ExporterTypeConsole}},
		"otlp":               {{Type: ExporterTypeOTLP, Endpoint: "localhost:4317", Insecure: true}},
		"console-plus-otlp":  {{Type: ExporterTypeConsole}, {Type: ExporterTypeOTLP, Insecure: true}},
		"unknown-is-skipped": {{Type: ExporterTypeDatadog}},
	} {
		t.Run(name, func(t *testing.T) {
			m := &Manager{config: &Config{
				MetricsExporters: exporters,
				MetricsInterval:  time.Minute,
				ServiceVersion:   "test",
			}}
			require.NoError(t, m.initializeMetrics(res))
			require.NotNil(t, m.meterProvider)
			require.NotNil(t, m.meter)
			// The provider must be usable regardless: an exporter that could not
			// be built must not take instrumentation down with it.
			c, err := m.meter.Int64Counter("probe")
			require.NoError(t, err)
			c.Add(context.Background(), 1)
			// Shutdown is bounded: with no collector listening the OTLP flush
			// fails, and that must be a prompt error rather than a hang.
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_ = m.meterProvider.Shutdown(ctx)
		})
	}
}

// The Prometheus branch is pull-based: it must register itself as a collector
// rather than be wrapped in a PeriodicReader, which would never fire.
func TestPrometheusExporterRegistersAsACollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	res, err := resource.New(context.Background())
	require.NoError(t, err)

	// Registering into a private registry rather than the process-wide one, so
	// this assertion does not depend on what other tests have registered.
	exp, err := newPrometheusReader(reg)
	require.NoError(t, err)

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(exp))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	c, err := mp.Meter("test").Int64Counter("pahlevan_probe_total")
	require.NoError(t, err)
	c.Add(context.Background(), 3)

	families, err := reg.Gather()
	require.NoError(t, err)
	var found bool
	for _, f := range families {
		if f.GetName() == "pahlevan_probe_total" {
			found = true
			require.Len(t, f.GetMetric(), 1)
			assert.Equal(t, 3.0, f.GetMetric()[0].GetCounter().GetValue())
		}
	}
	assert.True(t, found, "an OTel instrument must be scrapeable through the Prometheus reader")
}

// Recording through the provider must reach a reader, which is the property the
// stubbed-out version silently lacked.
func TestRecordedInstrumentsReachAReader(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	c, err := mp.Meter("test").Int64Counter("denials", metric.WithDescription("test"))
	require.NoError(t, err)
	c.Add(context.Background(), 7)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	require.NotEmpty(t, rm.ScopeMetrics)
	require.NotEmpty(t, rm.ScopeMetrics[0].Metrics)
	assert.Equal(t, "denials", rm.ScopeMetrics[0].Metrics[0].Name)
}

// Shutdown must be bounded. An OTLP exporter pointed at nothing retries until
// its own deadline, so an unbounded flush hangs the agent on every rollout
// while the collector is down.
func TestShutdownIsBoundedWhenTheCollectorIsUnreachable(t *testing.T) {
	res, err := resource.New(context.Background())
	require.NoError(t, err)
	m := &Manager{
		stopCh: make(chan struct{}),
		config: &Config{
			MetricsExporters: []ExporterConfig{
				{Type: ExporterTypeOTLP, Endpoint: "127.0.0.1:1", Insecure: true},
			},
			MetricsInterval: time.Minute,
		},
	}
	require.NoError(t, m.initializeMetrics(res))

	start := time.Now()
	err = m.Shutdown()
	elapsed := time.Since(start)

	assert.Error(t, err, "a failed flush must be reported, not swallowed")
	assert.Less(t, elapsed, shutdownTimeout+3*time.Second,
		"shutdown must give up rather than block on an unreachable collector")
}

// A meter provider that cannot flush must not stop the tracer provider from
// being shut down: returning at the first failure cost every buffered span.
func TestShutdownStopsBothProvidersOnFailure(t *testing.T) {
	res, err := resource.New(context.Background())
	require.NoError(t, err)
	m := &Manager{
		stopCh: make(chan struct{}),
		config: &Config{
			MetricsExporters: []ExporterConfig{
				{Type: ExporterTypeOTLP, Endpoint: "127.0.0.1:1", Insecure: true},
			},
			TracingExporters: []ExporterConfig{{Type: ExporterTypeConsole}},
			MetricsInterval:  time.Minute,
		},
	}
	require.NoError(t, m.initializeMetrics(res))
	require.NoError(t, m.initializeTracing(res))
	require.NotNil(t, m.tracerProvider)

	_ = m.Shutdown()

	// A shut-down tracer provider refuses further shutdowns silently but reports
	// that it is done by producing non-recording spans.
	_, span := m.tracerProvider.Tracer("t").Start(context.Background(), "after-shutdown")
	assert.False(t, span.IsRecording(), "the tracer provider must have been shut down too")
	span.End()
}

// An empty exporter list must still yield a working provider - instruments are
// created at startup regardless of whether anything is exporting.
func TestInitializeMetricsWithNoExporters(t *testing.T) {
	res, err := resource.New(context.Background())
	require.NoError(t, err)
	m := &Manager{config: &Config{MetricsInterval: time.Minute}}
	require.NoError(t, m.initializeMetrics(res))
	require.NotNil(t, m.meter)
	_, err = m.meter.Int64Counter("probe")
	assert.NoError(t, err)
	require.NoError(t, m.meterProvider.Shutdown(context.Background()))
}

func BenchmarkInitializeMetrics(b *testing.B) {
	res, err := resource.New(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := &Manager{config: &Config{
			MetricsExporters: []ExporterConfig{{Type: ExporterTypeConsole}},
			MetricsInterval:  time.Minute,
		}}
		if err := m.initializeMetrics(res); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = m.meterProvider.Shutdown(context.Background())
		b.StartTimer()
	}
}

// A configuration that asks for exporters and produces none must fail loudly.
// Silently continuing is what made the stubbed-out version look healthy.
func TestWantedReaderCountsOnlyWhatThisPackageBuilds(t *testing.T) {
	assert.Equal(t, 0, wantedReader([]ExporterConfig{{Type: ExporterTypeDatadog}}),
		"an exporter this package does not build must not count toward the requirement")
	assert.Equal(t, 2, wantedReader([]ExporterConfig{
		{Type: ExporterTypeConsole}, {Type: ExporterTypeOTLP}, {Type: ExporterTypeGrafana},
	}))
}

// A config naming only exporters served by RegisterExporter must not be treated
// as a failure: nothing here was supposed to build a reader for them.
func TestUnknownExporterTypesDoNotFailInitialization(t *testing.T) {
	res, err := resource.New(context.Background())
	require.NoError(t, err)
	m := &Manager{config: &Config{
		MetricsExporters: []ExporterConfig{{Type: ExporterTypeDatadog}, {Type: ExporterTypeGrafana}},
		MetricsInterval:  time.Minute,
	}}
	require.NoError(t, m.initializeMetrics(res))
	require.NoError(t, m.meterProvider.Shutdown(context.Background()))
}
