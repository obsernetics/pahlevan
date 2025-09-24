/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/obsernetics/pahlevan/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// EventType represents the type of event
type EventType string

const (
	EventTypePolicyViolation      EventType = "PolicyViolation"
	EventTypeContainerCreated     EventType = "ContainerCreated"
	EventTypeContainerUpdated     EventType = "ContainerUpdated"
	EventTypeContainerDeleted     EventType = "ContainerDeleted"
	EventTypePolicyTransition     EventType = "PolicyTransition"
	EventTypeEnforcementAction    EventType = "EnforcementAction"
	EventTypeSelfHealing          EventType = "SelfHealing"
	EventTypeAttackSurfaceChanged EventType = "AttackSurfaceChanged"
	EventTypeSelfHealingTriggered EventType = "SelfHealingTriggered"
	EventTypeAttackDetected       EventType = "AttackDetected"
	EventTypeSystemError          EventType = "SystemError"
	EventTypePolicyCreated        EventType = "PolicyCreated"
	EventTypePolicyUpdated        EventType = "PolicyUpdated"
	EventTypePolicyDeleted        EventType = "PolicyDeleted"
	EventTypeSuspiciousActivity   EventType = "SuspiciousActivity"
	EventTypeSecurityAlert        EventType = "SecurityAlert"
)

const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityError    = "error"
	SeverityCritical = "critical"
)

// Event represents a system event
type Event struct {
	ID        string                  `json:"id"`
	Type      EventType               `json:"type"`
	Source    string                  `json:"source"`
	Subject   *corev1.ObjectReference `json:"subject,omitempty"`
	Object    runtime.Object          `json:"object,omitempty"`
	Timestamp metav1.Time             `json:"timestamp"`
	Message   string                  `json:"message"`
	Reason    string                  `json:"reason"`
	Data      map[string]interface{}  `json:"data,omitempty"`
	Severity  string                  `json:"severity"`
}

// EventHandler defines a function that handles events
type EventHandler func(context.Context, *Event) error

// EventProcessor processes events of a specific type
type EventProcessor struct {
	EventType EventType
	Handler   EventHandler
	Config    *ProcessorConfig
}

// ProcessorConfig holds configuration for event processors
type ProcessorConfig struct {
	Enabled        bool
	MaxRetries     int
	RetryDelay     time.Duration
	Timeout        time.Duration
	ConcurrentJobs int
}

// EventManager provides centralized event handling and coordination
type EventManager struct {
	recorder       record.EventRecorder
	metricsManager *metrics.Manager
	handlers       map[EventType][]EventHandler
	processors     map[string]*EventProcessor
	mu             sync.RWMutex
	eventQueue     chan *Event
	stopCh         chan struct{}
	config         *EventManagerConfig
	logger         logr.Logger
}

// EventManagerConfig holds configuration for the event manager
type EventManagerConfig struct {
	QueueSize      int
	WorkerCount    int
	ProcessTimeout time.Duration
	RetryAttempts  int
	RetryDelay     time.Duration
	MetricsEnabled bool
	AuditEnabled   bool
	BufferSize     int
}

// DefaultEventManagerConfig returns default configuration
func DefaultEventManagerConfig() *EventManagerConfig {
	return &EventManagerConfig{
		QueueSize:      10000,
		WorkerCount:    5,
		ProcessTimeout: 30 * time.Second,
		RetryAttempts:  3,
		RetryDelay:     1 * time.Second,
		MetricsEnabled: true,
		AuditEnabled:   true,
		BufferSize:     1000,
	}
}

// NewEventManager creates a new event manager
func NewEventManager(recorder record.EventRecorder, metricsManager *metrics.Manager, config *EventManagerConfig) *EventManager {
	if config == nil {
		config = DefaultEventManagerConfig()
	}

	return &EventManager{
		recorder:       recorder,
		metricsManager: metricsManager,
		handlers:       make(map[EventType][]EventHandler),
		processors:     make(map[string]*EventProcessor),
		eventQueue:     make(chan *Event, config.QueueSize),
		stopCh:         make(chan struct{}),
		config:         config,
		logger:         log.Log.WithName("event-manager"),
	}
}

// Start starts the event manager
func (em *EventManager) Start(ctx context.Context) error {
	em.logger.Info("Starting event manager", "workers", em.config.WorkerCount)

	// Start worker goroutines
	for i := 0; i < em.config.WorkerCount; i++ {
		go em.worker(ctx, i)
	}

	// Start metrics collection if enabled
	if em.config.MetricsEnabled && em.metricsManager != nil {
		go em.collectMetrics(ctx)
	}

	return nil
}

// Stop stops the event manager
func (em *EventManager) Stop() error {
	em.logger.Info("Stopping event manager")
	close(em.stopCh)
	close(em.eventQueue)
	return nil
}

// RegisterHandler registers an event handler for a specific event type
func (em *EventManager) RegisterHandler(eventType EventType, handler EventHandler) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.handlers[eventType] == nil {
		em.handlers[eventType] = make([]EventHandler, 0)
	}
	em.handlers[eventType] = append(em.handlers[eventType], handler)

	em.logger.Info("Registered event handler", "eventType", eventType)
}

// RegisterProcessor registers an event processor
func (em *EventManager) RegisterProcessor(name string, processor *EventProcessor) {
	em.mu.Lock()
	defer em.mu.Unlock()

	em.processors[name] = processor
	em.logger.Info("Registered event processor", "processor", name)
}

// EmitEvent emits an event to be processed
func (em *EventManager) EmitEvent(event *Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = metav1.NewTime(time.Now())
	}

	// Validate event
	if err := em.validateEvent(event); err != nil {
		return fmt.Errorf("invalid event: %v", err)
	}

	// Queue event for processing
	select {
	case em.eventQueue <- event:
		if em.metricsManager != nil {
			em.metricsManager.RecordProcessingLatency("event", "emitted", time.Since(time.Now()))
		}
		return nil
	default:
		// Queue is full
		if em.metricsManager != nil {
			em.metricsManager.RecordProcessingLatency("event", "dropped", time.Since(time.Now()))
		}
		return fmt.Errorf("event queue is full")
	}
}

// worker processes events from the queue
func (em *EventManager) worker(ctx context.Context, workerID int) {
	logger := em.logger.WithValues("worker", workerID)
	logger.Info("Starting event worker")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled, stopping worker")
			return
		case <-em.stopCh:
			logger.Info("Stop signal received, stopping worker")
			return
		case event, ok := <-em.eventQueue:
			if !ok {
				logger.Info("Event queue closed, stopping worker")
				return
			}

			if err := em.processEvent(ctx, event); err != nil {
				logger.Error(err, "Failed to process event",
					"eventType", event.Type,
					"eventID", event.ID,
					"source", event.Source)

				if em.metricsManager != nil {
					em.metricsManager.RecordProcessingLatency("event", "error", time.Since(time.Now()))
				}
			}
		}
	}
}

// processEvent processes a single event
func (em *EventManager) processEvent(ctx context.Context, event *Event) error {
	startTime := time.Now()

	// Create processing context with timeout
	procCtx, cancel := context.WithTimeout(ctx, em.config.ProcessTimeout)
	defer cancel()

	// Get handlers for this event type
	em.mu.RLock()
	handlers := em.handlers[event.Type]
	em.mu.RUnlock()

	// Process event with each handler
	var lastError error
	for _, handler := range handlers {
		if err := em.executeHandlerWithRetry(procCtx, handler, event); err != nil {
			lastError = err
			em.logger.Error(err, "Handler failed to process event",
				"eventType", event.Type,
				"eventID", event.ID)
		}
	}

	// Record processing metrics
	if em.metricsManager != nil {
		duration := time.Since(startTime)
		em.metricsManager.RecordProcessingLatency("event", "processing", duration)
	}

	// Create Kubernetes event if configured
	if em.shouldCreateKubernetesEvent(event) {
		em.createKubernetesEvent(event)
	}

	return lastError
}

// executeHandlerWithRetry executes a handler with retry logic
func (em *EventManager) executeHandlerWithRetry(ctx context.Context, handler EventHandler, event *Event) error {
	var lastError error

	for attempt := 1; attempt <= em.config.RetryAttempts; attempt++ {
		if err := handler(ctx, event); err != nil {
			lastError = err
			if attempt < em.config.RetryAttempts {
				em.logger.Info("Handler failed, retrying",
					"attempt", attempt,
					"eventType", event.Type,
					"error", err)

				// Wait before retry
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(em.config.RetryDelay):
					continue
				}
			}
		} else {
			return nil // Success
		}
	}

	return fmt.Errorf("handler failed after %d attempts: %v", em.config.RetryAttempts, lastError)
}

// validateEvent validates an event before processing
func (em *EventManager) validateEvent(event *Event) error {
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if event.Source == "" {
		return fmt.Errorf("event source is required")
	}
	if event.ID == "" {
		event.ID = generateEventID()
	}
	return nil
}

// shouldCreateKubernetesEvent determines if a Kubernetes event should be created
func (em *EventManager) shouldCreateKubernetesEvent(event *Event) bool {
	// Create Kubernetes events for important events
	switch event.Type {
	case EventTypePolicyViolation,
		EventTypePolicyTransition,
		EventTypeSelfHealingTriggered,
		EventTypeAttackDetected,
		EventTypeSystemError:
		return true
	default:
		return false
	}
}

// createKubernetesEvent creates a Kubernetes event
func (em *EventManager) createKubernetesEvent(event *Event) {
	if em.recorder == nil {
		return
	}

	// Determine event type
	eventType := corev1.EventTypeNormal
	if event.Severity == SeverityError || event.Severity == SeverityCritical {
		eventType = corev1.EventTypeWarning
	}

	// Create object reference if available
	var objRef *corev1.ObjectReference
	if event.Subject != nil {
		objRef = event.Subject
	} else if event.Object != nil {
		// Try to extract basic info from runtime.Object
		objRef = &corev1.ObjectReference{
			Kind: event.Object.GetObjectKind().GroupVersionKind().Kind,
			// Name and Namespace need proper type assertion
		}
	}

	// Record the event
	em.recorder.Event(objRef, eventType, string(event.Type), event.Message)
}

// collectMetrics collects and reports event processing metrics
func (em *EventManager) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-em.stopCh:
			return
		case <-ticker.C:
			em.reportMetrics()
		}
	}
}

// reportMetrics reports current metrics
func (em *EventManager) reportMetrics() {
	if em.metricsManager == nil {
		return
	}

	// Collect and record metrics
	queueSize := len(em.eventQueue)

	// Report handler count
	em.mu.RLock()
	handlerCount := 0
	for _, handlers := range em.handlers {
		handlerCount += len(handlers)
	}
	processorCount := len(em.processors)
	em.mu.RUnlock()

	// Log current metrics
	em.logger.V(1).Info("Event manager metrics",
		"queueSize", queueSize,
		"handlerCount", handlerCount,
		"processorCount", processorCount)
}

// GetStats returns event manager statistics
func (em *EventManager) GetStats() map[string]interface{} {
	em.mu.RLock()
	defer em.mu.RUnlock()

	handlerCount := 0
	handlersByType := make(map[string]int)
	for eventType, handlers := range em.handlers {
		count := len(handlers)
		handlerCount += count
		handlersByType[string(eventType)] = count
	}

	return map[string]interface{}{
		"queue_size":       len(em.eventQueue),
		"queue_capacity":   cap(em.eventQueue),
		"handler_count":    handlerCount,
		"handlers_by_type": handlersByType,
		"processor_count":  len(em.processors),
		"worker_count":     em.config.WorkerCount,
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}

// SpecializedEventProcessor represents a specialized event processor
type SpecializedEventProcessor struct {
	Name        string
	Description string
	Filter      EventFilter
	Processor   ProcessorFunc
	Config      map[string]interface{}
}

// ProcessorFunc is the function signature for event processors
type ProcessorFunc func(ctx context.Context, event *Event) error

// EventFilter determines if an event should be processed by a processor
type EventFilter func(event *Event) bool

// NewEventProcessor creates a new event processor
func NewEventProcessor(eventType EventType, handler EventHandler) *EventProcessor {
	return &EventProcessor{
		EventType: eventType,
		Handler:   handler,
		Config: &ProcessorConfig{
			Enabled:        true,
			MaxRetries:     3,
			RetryDelay:     1 * time.Second,
			Timeout:        30 * time.Second,
			ConcurrentJobs: 1,
		},
	}
}

// Process processes an event if it matches the event type
func (ep *EventProcessor) Process(ctx context.Context, event *Event) error {
	if event.Type != ep.EventType {
		return nil // Event doesn't match processor type
	}

	return ep.Handler(ctx, event)
}

// Common event filters

// PolicyEventFilter filters for policy-related events
func PolicyEventFilter(event *Event) bool {
	switch event.Type {
	case EventTypePolicyCreated,
		EventTypePolicyUpdated,
		EventTypePolicyDeleted,
		EventTypePolicyViolation,
		EventTypePolicyTransition:
		return true
	default:
		return false
	}
}

// SecurityEventFilter filters for security-related events
func SecurityEventFilter(event *Event) bool {
	switch event.Type {
	case EventTypePolicyViolation,
		EventTypeAttackDetected,
		EventTypeSuspiciousActivity,
		EventTypeSecurityAlert:
		return true
	default:
		return false
	}
}

// CriticalEventFilter filters for critical events
func CriticalEventFilter(event *Event) bool {
	return event.Severity == SeverityCritical
}

// NamespaceEventFilter creates a filter for events in specific namespaces
func NamespaceEventFilter(namespaces ...string) EventFilter {
	nsMap := make(map[string]bool)
	for _, ns := range namespaces {
		nsMap[ns] = true
	}

	return func(event *Event) bool {
		if event.Subject == nil {
			return false
		}
		return nsMap[event.Subject.Namespace]
	}
}

// TypeEventFilter creates a filter for specific event types
func TypeEventFilter(types ...EventType) EventFilter {
	typeMap := make(map[EventType]bool)
	for _, t := range types {
		typeMap[t] = true
	}

	return func(event *Event) bool {
		return typeMap[event.Type]
	}
}
