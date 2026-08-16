package observability

import (
	"context"
	"fmt"
)

// MockExporter is a test double for the Exporter interface.
//
// It lived in types.go, which means it shipped in every binary: a type whose
// only purpose is to be substituted for a real one, compiled into the agent an
// operator runs. Test doubles belong in _test.go files, where the compiler
// leaves them out of the build.
// MockExporter implements the Exporter interface for testing
type MockExporter struct {
	Type   ExporterType
	Config map[string]interface{}
}

func (e *MockExporter) Start(ctx context.Context) error {
	return nil
}

func (e *MockExporter) Stop(ctx context.Context) error {
	return nil
}

func (e *MockExporter) Export(data *ObservabilityData) error {
	switch e.Type {
	case ExporterTypePrometheus:
		return fmt.Errorf("prometheus endpoint not available")
	case ExporterTypeJaeger:
		return fmt.Errorf("jaeger endpoint not available")
	default:
		return fmt.Errorf("unknown exporter type: %s", e.Type)
	}
}

func (e *MockExporter) GetType() ExporterType {
	return e.Type
}

func (e *MockExporter) GetMetadata() *ExporterMetadata {
	return &ExporterMetadata{
		Name:         string(e.Type),
		Version:      "1.0.0",
		Description:  "Mock exporter for testing",
		Capabilities: []string{"metrics", "logs"},
	}
}
