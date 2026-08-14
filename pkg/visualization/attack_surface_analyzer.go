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

package visualization

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/policies"
	"go.opentelemetry.io/otel/metric"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// AttackSurfaceAnalyzer provides cluster-wide attack surface analysis and visualization
type AttackSurfaceAnalyzer struct {
	mu                sync.RWMutex
	client            client.Client
	ebpfManager       *ebpf.Manager
	enforcementEngine *policies.EnforcementEngine

	// Analysis data
	clusterGraph         *ClusterAttackSurfaceGraph
	workloadProfiles     map[string]*WorkloadAttackSurface
	networkTopology      *NetworkTopology
	systemCallMatrix     *SystemCallMatrix
	exposureAnalysis     *ExposureAnalysis
	vulnerabilityScanner *VulnerabilityScanner
	threatModel          *ThreatModel

	// Configuration
	analysisInterval   time.Duration
	retentionPeriod    time.Duration
	enableDeepAnalysis bool
	riskThresholds     *RiskThresholds

	// Export channels
	grafanaExporter *GrafanaExporter
	datadogExporter *DatadogExporter
	otelExporter    *OTelExporter
	customExporters []CustomExporter

	// Metrics
	analysisCounter    metric.Int64Counter
	riskScoreGauge     metric.Float64Gauge
	exposureCounter    metric.Int64Counter
	vulnerabilityGauge metric.Int64Gauge

	stopCh chan struct{}
}

// ClusterAttackSurfaceGraph represents the complete attack surface of the cluster
type ClusterAttackSurfaceGraph struct {
	Timestamp          time.Time
	Nodes              map[string]*AttackSurfaceNode
	Edges              map[string]*AttackSurfaceEdge
	RiskAggregation    *RiskAggregation
	TopologyAnalysis   *TopologyAnalysis
	ExposurePaths      []*ExposurePath
	CriticalPaths      []*CriticalPath
	WeakPoints         []*WeakPoint
	RecommendedActions []*RecommendedAction
}

// AttackSurfaceNode represents a component in the attack surface
type AttackSurfaceNode struct {
	ID          string
	Type        NodeType
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string

	// Attack surface properties
	ExposedPorts      []*ExposedPort
	SyscallProfile    *SyscallProfile
	NetworkProfile    *NetworkProfile
	FileSystemProfile *FileSystemProfile
	Capabilities      []string
	Privileges        *PrivilegeProfile

	// Risk assessment
	RiskScore          float64
	RiskFactors        []*RiskFactor
	VulnerabilityCount int
	CriticalityLevel   CriticalityLevel

	// Relationships
	IncomingEdges []string
	OutgoingEdges []string
	Dependencies  []string
	Dependents    []string

	// Metadata
	CreationTime time.Time
	LastUpdate   time.Time
	Tags         []string
}

// AttackSurfaceEdge represents a connection/relationship in the attack surface
type AttackSurfaceEdge struct {
	ID               string
	Source           string
	Target           string
	Type             EdgeType
	Direction        EdgeDirection
	Protocol         string
	Ports            []*PortRange
	Weight           float64
	RiskContribution float64

	// Traffic analysis
	TrafficVolume      *TrafficMetrics
	ConnectionPattern  *ConnectionPattern
	SecurityProperties *SecurityProperties

	// Metadata
	FirstSeen time.Time
	LastSeen  time.Time
	Frequency float64
}

// Node and edge types
type NodeType string

const (
	NodeTypePod             NodeType = "Pod"
	NodeTypeService         NodeType = "Service"
	NodeTypeIngress         NodeType = "Ingress"
	NodeTypeNode            NodeType = "Node"
	NodeTypeNamespace       NodeType = "Namespace"
	NodeTypeExternalService NodeType = "ExternalService"
	NodeTypeLoadBalancer    NodeType = "LoadBalancer"
	NodeTypeDatabase        NodeType = "Database"
	NodeTypeAPI             NodeType = "API"
)

type EdgeType string

const (
	EdgeTypeNetworkConnection EdgeType = "NetworkConnection"
	EdgeTypeServiceDependency EdgeType = "ServiceDependency"
	EdgeTypeVolumeMount       EdgeType = "VolumeMount"
	EdgeTypeConfigMap         EdgeType = "ConfigMap"
	EdgeTypeSecret            EdgeType = "Secret"
	EdgeTypeRBAC              EdgeType = "RBAC"
	EdgeTypeNetworkPolicy     EdgeType = "NetworkPolicy"
)

type EdgeDirection string

const (
	EdgeDirectionInbound       EdgeDirection = "Inbound"
	EdgeDirectionOutbound      EdgeDirection = "Outbound"
	EdgeDirectionBidirectional EdgeDirection = "Bidirectional"
)

// WorkloadAttackSurface represents attack surface for a specific workload
type WorkloadAttackSurface struct {
	WorkloadRef     learner.WorkloadReference
	Containers      map[string]*ContainerAttackSurface
	PodTemplate     *PodAttackSurface
	ServiceExposure *ServiceExposure
	NetworkPolicies []*NetworkPolicyAnalysis
	RBACAnalysis    *RBACAnalysis

	// Risk metrics
	OverallRiskScore float64
	RiskDistribution *RiskDistribution
	TopRisks         []*RiskFactor
	Recommendations  []*SecurityRecommendation

	// Compliance and standards
	ComplianceStatus *ComplianceStatus
	BenchmarkScores  map[string]float64

	LastAnalysis time.Time
}

// ContainerAttackSurface represents attack surface for a container
type ContainerAttackSurface struct {
	ContainerID   string
	Name          string
	Image         string
	ImageAnalysis *ImageSecurityAnalysis

	// Runtime analysis
	RuntimeProfile     *RuntimeSecurityProfile
	SyscallExposure    *SyscallExposureAnalysis
	NetworkExposure    *NetworkExposureAnalysis
	FileSystemExposure *FileSystemExposureAnalysis

	// Configuration analysis
	SecurityContext    *SecurityContextAnalysis
	ResourceLimits     *ResourceLimitsAnalysis
	CapabilityAnalysis *CapabilityAnalysis

	// Policy compliance
	PolicyCompliance *PolicyComplianceAnalysis

	RiskScore  float64
	LastUpdate time.Time
}

// Analysis structures
type SyscallProfile struct {
	AllowedSyscalls    []uint64
	DeniedSyscalls     []uint64
	UnusedSyscalls     []uint64
	RiskySyscalls      []uint64
	SyscallFrequency   map[uint64]float64
	CriticalityMapping map[uint64]CriticalityLevel
}

type NetworkProfile struct {
	ExposedPorts        []*ExposedPort
	ListeningServices   []*ListeningService
	OutboundConnections []*OutboundConnection
	NetworkPolicies     []*AppliedNetworkPolicy
	TLSConfiguration    *TLSAnalysis
}

type FileSystemProfile struct {
	MountPoints     []*MountPoint
	WritablePaths   []string
	ExecutablePaths []string
	SensitiveFiles  []*SensitiveFile
	VolumeAnalysis  *VolumeSecurityAnalysis
}

type PrivilegeProfile struct {
	RunAsUser                  *int64
	RunAsGroup                 *int64
	FSGroup                    *int64
	Capabilities               *CapabilitySet
	Privileged                 bool
	AllowPrivilegeEscalation   bool
	ReadOnlyRootFilesystem     bool
	SecurityContextConstraints []string
}

// Risk analysis structures
type RiskAggregation struct {
	TotalRiskScore     float64
	RiskDistribution   map[RiskCategory]float64
	HighRiskComponents []*RiskComponent
	RiskTrends         *RiskTrends
	ClusterRiskProfile *ClusterRiskProfile
}

type RiskCategory string

const (
	RiskCategoryNetwork       RiskCategory = "Network"
	RiskCategoryPrivilege     RiskCategory = "Privilege"
	RiskCategoryCompliance    RiskCategory = "Compliance"
	RiskCategoryVulnerability RiskCategory = "Vulnerability"
	RiskCategoryConfiguration RiskCategory = "Configuration"
	RiskCategoryRuntime       RiskCategory = "Runtime"
)

type RiskComponent struct {
	ID          string
	Name        string
	Type        string
	RiskScore   float64
	RiskFactors []*RiskFactor
	Impact      ImpactLevel
	Likelihood  LikelihoodLevel
	Mitigation  []*MitigationAction
}

type RiskFactor struct {
	Type        RiskFactorType
	Severity    Severity
	Description string
	Evidence    []string
	CVSS        *CVSSScore
	CWE         []string
	MITRE       []string
	Remediation *RemediationGuidance
}

type RiskFactorType string

const (
	RiskFactorTypeExposedService       RiskFactorType = "ExposedService"
	RiskFactorTypePrivilegedAccess     RiskFactorType = "PrivilegedAccess"
	RiskFactorTypeVulnerability        RiskFactorType = "Vulnerability"
	RiskFactorTypeMisconfiguration     RiskFactorType = "Misconfiguration"
	RiskFactorTypeWeakCredentials      RiskFactorType = "WeakCredentials"
	RiskFactorTypeUnencryptedTraffic   RiskFactorType = "UnencryptedTraffic"
	RiskFactorTypeExcessivePermissions RiskFactorType = "ExcessivePermissions"
)

type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

type CriticalityLevel string

const (
	CriticalityInfo     CriticalityLevel = "Info"
	CriticalityLow      CriticalityLevel = "Low"
	CriticalityMedium   CriticalityLevel = "Medium"
	CriticalityHigh     CriticalityLevel = "High"
	CriticalityCritical CriticalityLevel = "Critical"
)

// Exposure analysis
type ExposurePath struct {
	ID            string
	StartNode     string
	EndNode       string
	Path          []string
	ExposureType  ExposureType
	RiskScore     float64
	AttackVectors []*AttackVector
	Defenses      []*Defense
}

type ExposureType string

const (
	ExposureTypeNetworkIngress      ExposureType = "NetworkIngress"
	ExposureTypeNetworkEgress       ExposureType = "NetworkEgress"
	ExposureTypePrivilegeEscalation ExposureType = "PrivilegeEscalation"
	ExposureTypeDataAccess          ExposureType = "DataAccess"
	ExposureTypeLateralMovement     ExposureType = "LateralMovement"
)

type AttackVector struct {
	Type            AttackVectorType
	Technique       string
	Probability     float64
	Impact          ImpactLevel
	Prerequisites   []string
	Indicators      []string
	Countermeasures []*Countermeasure
}

type AttackVectorType string

const (
	AttackVectorTypeRemoteExploit       AttackVectorType = "RemoteExploit"
	AttackVectorTypeCredentialAccess    AttackVectorType = "CredentialAccess"
	AttackVectorTypePrivilegeEscalation AttackVectorType = "PrivilegeEscalation"
	AttackVectorTypeLateralMovement     AttackVectorType = "LateralMovement"
	AttackVectorTypeDataExfiltration    AttackVectorType = "DataExfiltration"
)

type ImpactLevel string

const (
	ImpactLevelLow      ImpactLevel = "Low"
	ImpactLevelMedium   ImpactLevel = "Medium"
	ImpactLevelHigh     ImpactLevel = "High"
	ImpactLevelCritical ImpactLevel = "Critical"
)

type LikelihoodLevel string

const (
	LikelihoodLevelLow    LikelihoodLevel = "Low"
	LikelihoodLevelMedium LikelihoodLevel = "Medium"
	LikelihoodLevelHigh   LikelihoodLevel = "High"
)

// Threat modeling
type ThreatModel struct {
	ModelVersion   string
	Timestamp      time.Time
	ThreatActors   []*ThreatActor
	AttackChains   []*AttackChain
	AssetInventory *AssetInventory
	ThrustSurface  *ThrustSurface
	DefenseInDepth *DefenseAnalysis
	ResidualRisk   *ResidualRiskAssessment
}

type ThreatActor struct {
	Name           string
	Type           ThreatActorType
	Sophistication SophisticationLevel
	Motivation     []string
	Capabilities   []string
	TTPs           []string // Tactics, Techniques, Procedures
	TargetAssets   []string
}

type ThreatActorType string

const (
	ThreatActorTypeNationState ThreatActorType = "NationState"
	ThreatActorTypeCriminal    ThreatActorType = "Criminal"
	ThreatActorTypeHacktivism  ThreatActorType = "Hacktivism"
	ThreatActorTypeInsider     ThreatActorType = "Insider"
	ThreatActorTypeScript      ThreatActorType = "ScriptKiddie"
)

type SophisticationLevel string

const (
	SophisticationMinimal      SophisticationLevel = "Minimal"
	SophisticationLimited      SophisticationLevel = "Limited"
	SophisticationIntermediate SophisticationLevel = "Intermediate"
	SophisticationAdvanced     SophisticationLevel = "Advanced"
	SophisticationExpert       SophisticationLevel = "Expert"
)

// Export interfaces and implementations
type Exporter interface {
	Export(data *AttackSurfaceData) error
	GetFormat() ExportFormat
	Configure(config map[string]interface{}) error
}

type ExportFormat string

const (
	ExportFormatJSON       ExportFormat = "JSON"
	ExportFormatGraphQL    ExportFormat = "GraphQL"
	ExportFormatPrometheus ExportFormat = "Prometheus"
	ExportFormatGrafana    ExportFormat = "Grafana"
	ExportFormatSIEM       ExportFormat = "SIEM"
	ExportFormatCytoscape  ExportFormat = "Cytoscape"
	ExportFormatMermaid    ExportFormat = "Mermaid"
)

type AttackSurfaceData struct {
	ClusterGraph     *ClusterAttackSurfaceGraph
	WorkloadProfiles map[string]*WorkloadAttackSurface
	NetworkTopology  *NetworkTopology
	ThreatModel      *ThreatModel
	Timestamp        time.Time
	Metadata         map[string]interface{}
}

// Vulnerability scanning integration
type VulnerabilityScanner struct {
	scanners           map[string]VulnerabilityProvider
	scanResults        map[string]*ScanResult
	aggregatedFindings *AggregatedVulnerabilities
}

type VulnerabilityProvider interface {
	ScanImage(image string) (*ImageScanResult, error)
	ScanRuntime(containerID string) (*RuntimeScanResult, error)
	GetVulnerabilityDatabase() (*VulnerabilityDatabase, error)
}

type ScanResult struct {
	ScanID          string
	Target          string
	ScanType        ScanType
	Timestamp       time.Time
	Vulnerabilities []*Vulnerability
	Summary         *ScanSummary
}

type ScanType string

const (
	ScanTypeImage      ScanType = "Image"
	ScanTypeRuntime    ScanType = "Runtime"
	ScanTypeConfig     ScanType = "Configuration"
	ScanTypeNetwork    ScanType = "Network"
	ScanTypeCompliance ScanType = "Compliance"
)

type Vulnerability struct {
	ID               string
	CVE              string
	CVSS             *CVSSScore
	Severity         Severity
	Title            string
	Description      string
	AffectedPackage  string
	FixedVersion     string
	References       []string
	ExploitAvailable bool
	PatchAvailable   bool
}

type CVSSScore struct {
	Version            string
	BaseScore          float64
	TemporalScore      float64
	EnvironmentalScore float64
	Vector             string
}

func NewAttackSurfaceAnalyzer(
	client client.Client,
	ebpfManager *ebpf.Manager,
	enforcementEngine *policies.EnforcementEngine,
) *AttackSurfaceAnalyzer {
	return &AttackSurfaceAnalyzer{
		client:             client,
		ebpfManager:        ebpfManager,
		enforcementEngine:  enforcementEngine,
		workloadProfiles:   make(map[string]*WorkloadAttackSurface),
		analysisInterval:   5 * time.Minute,
		retentionPeriod:    24 * time.Hour,
		enableDeepAnalysis: true,
		riskThresholds: &RiskThresholds{
			Low:      3.0,
			Medium:   5.0,
			High:     7.0,
			Critical: 9.0,
		},
		stopCh: make(chan struct{}),
	}
}

type RiskThresholds struct {
	Low      float64
	Medium   float64
	High     float64
	Critical float64
}

func (asa *AttackSurfaceAnalyzer) Start(ctx context.Context) error {
	log.Log.Info("Starting attack surface analyzer")

	// Initialize components
	if err := asa.initializeComponents(); err != nil {
		return fmt.Errorf("failed to initialize components: %v", err)
	}

	// Start analysis workers
	go asa.analysisWorker(ctx)
	go asa.exportWorker(ctx)
	go asa.vulnerabilityScanWorker(ctx)
	go asa.threatModelingWorker(ctx)

	return nil
}

func (asa *AttackSurfaceAnalyzer) Stop() {
	close(asa.stopCh)
}

func (asa *AttackSurfaceAnalyzer) AnalyzeClusterAttackSurface() (*ClusterAttackSurfaceGraph, error) {
	asa.mu.Lock()
	defer asa.mu.Unlock()

	log.Log.Info("Analyzing cluster attack surface")

	graph := &ClusterAttackSurfaceGraph{
		Timestamp: time.Now(),
		Nodes:     make(map[string]*AttackSurfaceNode),
		Edges:     make(map[string]*AttackSurfaceEdge),
	}

	// Discover and analyze all workloads
	if err := asa.discoverWorkloads(graph); err != nil {
		return nil, fmt.Errorf("failed to discover workloads: %v", err)
	}

	// Analyze network topology
	if err := asa.analyzeNetworkTopology(graph); err != nil {
		return nil, fmt.Errorf("failed to analyze network topology: %v", err)
	}

	// Perform risk analysis
	if err := asa.performRiskAnalysis(graph); err != nil {
		return nil, fmt.Errorf("failed to perform risk analysis: %v", err)
	}

	// Find exposure paths
	if err := asa.identifyExposurePaths(graph); err != nil {
		return nil, fmt.Errorf("failed to identify exposure paths: %v", err)
	}

	// Generate recommendations
	if err := asa.generateRecommendations(graph); err != nil {
		return nil, fmt.Errorf("failed to generate recommendations: %v", err)
	}

	asa.clusterGraph = graph

	// Update metrics
	if asa.analysisCounter != nil {
		asa.analysisCounter.Add(context.Background(), 1)
	}

	if asa.riskScoreGauge != nil {
		asa.riskScoreGauge.Record(context.Background(), graph.RiskAggregation.TotalRiskScore)
	}

	return graph, nil
}

func (asa *AttackSurfaceAnalyzer) AnalyzeWorkloadAttackSurface(
	workloadRef learner.WorkloadReference,
) (*WorkloadAttackSurface, error) {
	asa.mu.Lock()
	defer asa.mu.Unlock()

	key := asa.getWorkloadKey(workloadRef)

	surface := &WorkloadAttackSurface{
		WorkloadRef:  workloadRef,
		Containers:   make(map[string]*ContainerAttackSurface),
		LastAnalysis: time.Now(),
	}

	// Analyze containers
	if err := asa.analyzeWorkloadContainers(surface); err != nil {
		return nil, fmt.Errorf("failed to analyze containers: %v", err)
	}

	// Analyze service exposure
	if err := asa.analyzeServiceExposure(surface); err != nil {
		return nil, fmt.Errorf("failed to analyze service exposure: %v", err)
	}

	// Analyze network policies
	if err := asa.analyzeNetworkPolicies(surface); err != nil {
		return nil, fmt.Errorf("failed to analyze network policies: %v", err)
	}

	// Analyze RBAC
	if err := asa.analyzeRBAC(surface); err != nil {
		return nil, fmt.Errorf("failed to analyze RBAC: %v", err)
	}

	// Calculate risk metrics
	if err := asa.calculateWorkloadRisk(surface); err != nil {
		return nil, fmt.Errorf("failed to calculate risk: %v", err)
	}

	asa.workloadProfiles[key] = surface

	return surface, nil
}

func (asa *AttackSurfaceAnalyzer) GetAttackSurfaceData() (*AttackSurfaceData, error) {
	asa.mu.RLock()
	defer asa.mu.RUnlock()

	return &AttackSurfaceData{
		ClusterGraph:     asa.clusterGraph,
		WorkloadProfiles: asa.workloadProfiles,
		NetworkTopology:  asa.networkTopology,
		ThreatModel:      asa.threatModel,
		Timestamp:        time.Now(),
		Metadata: map[string]interface{}{
			"analyzer_version": "1.0.0",
			"analysis_mode":    "comprehensive",
		},
	}, nil
}

func (asa *AttackSurfaceAnalyzer) ExportToFormat(format ExportFormat) ([]byte, error) {
	data, err := asa.GetAttackSurfaceData()
	if err != nil {
		return nil, err
	}

	switch format {
	case ExportFormatJSON:
		return json.MarshalIndent(data, "", "  ")
	case ExportFormatGraphQL:
		return asa.exportToGraphQL(data)
	case ExportFormatMermaid:
		return asa.exportToMermaid(data)
	case ExportFormatCytoscape:
		return asa.exportToCytoscape(data)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

func (asa *AttackSurfaceAnalyzer) RegisterExporter(exporter Exporter) {
	asa.mu.Lock()
	defer asa.mu.Unlock()

	// CustomExporter is a value type, so record the interface's format/enabled
	// state as a CustomExporter entry keyed by the exporter's format.
	customExporter := CustomExporter{
		Name:     fmt.Sprintf("custom-exporter-%s", exporter.GetFormat()),
		Endpoint: "configured-by-interface",
		Config:   make(map[string]string),
		Enabled:  true,
	}

	// Check if exporter already registered by comparing names
	for i, existing := range asa.customExporters {
		if existing.Name == customExporter.Name {
			// Update existing
			asa.customExporters[i] = customExporter
			return
		}
	}

	// Add the new exporter
	asa.customExporters = append(asa.customExporters, customExporter)
}

// Worker functions
func (asa *AttackSurfaceAnalyzer) analysisWorker(ctx context.Context) {
	ticker := time.NewTicker(asa.analysisInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-asa.stopCh:
			return
		case <-ticker.C:
			_, err := asa.AnalyzeClusterAttackSurface()
			if err != nil {
				log.Log.Error(err, "Failed to analyze cluster attack surface")
			}
		}
	}
}

func (asa *AttackSurfaceAnalyzer) exportWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-asa.stopCh:
			return
		case <-ticker.C:
			asa.performExports()
		}
	}
}

func (asa *AttackSurfaceAnalyzer) vulnerabilityScanWorker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-asa.stopCh:
			return
		case <-ticker.C:
			asa.performVulnerabilityScans()
		}
	}
}

func (asa *AttackSurfaceAnalyzer) threatModelingWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-asa.stopCh:
			return
		case <-ticker.C:
			asa.updateThreatModel()
		}
	}
}

// Implementation methods
func (asa *AttackSurfaceAnalyzer) initializeComponents() error {
	// Initialize vulnerability scanner
	asa.vulnerabilityScanner = &VulnerabilityScanner{
		scanners:    make(map[string]VulnerabilityProvider),
		scanResults: make(map[string]*ScanResult),
	}

	// Initialize network topology
	asa.networkTopology = &NetworkTopology{}

	// Initialize threat model
	asa.threatModel = &ThreatModel{
		ModelVersion: "1.0",
		Timestamp:    time.Now(),
	}

	return nil
}

func (asa *AttackSurfaceAnalyzer) discoverWorkloads(graph *ClusterAttackSurfaceGraph) error {
	log.Log.Info("Discovering workloads for attack surface analysis")

	// Discover Pods
	pods := &v1.PodList{}
	if err := asa.client.List(context.Background(), pods); err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase != v1.PodRunning {
			continue
		}

		nodeID := fmt.Sprintf("pod-%s-%s", pod.Namespace, pod.Name)
		node := &AttackSurfaceNode{
			ID:           nodeID,
			Type:         NodeTypePod,
			Name:         pod.Name,
			Namespace:    pod.Namespace,
			Labels:       pod.Labels,
			Annotations:  pod.Annotations,
			ExposedPorts: asa.extractPodPorts(&pod),
			Capabilities: asa.extractPodCapabilities(&pod),
			Privileges:   asa.analyzePodPrivileges(&pod),
			CreationTime: pod.CreationTimestamp.Time,
			LastUpdate:   time.Now(),
			Tags:         []string{"discovered", "pod"},
		}

		// Analyze pod-specific attack surface
		node.SyscallProfile = asa.getPodSyscallProfile(&pod)
		node.NetworkProfile = asa.getPodNetworkProfile(&pod)
		node.FileSystemProfile = asa.getPodFilesystemProfile(&pod)

		graph.Nodes[nodeID] = node
	}

	// Discover Services
	services := &v1.ServiceList{}
	if err := asa.client.List(context.Background(), services); err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}

	for _, service := range services.Items {
		nodeID := fmt.Sprintf("service-%s-%s", service.Namespace, service.Name)
		node := &AttackSurfaceNode{
			ID:           nodeID,
			Type:         NodeTypeService,
			Name:         service.Name,
			Namespace:    service.Namespace,
			Labels:       service.Labels,
			Annotations:  service.Annotations,
			ExposedPorts: asa.extractServicePorts(&service),
			CreationTime: service.CreationTimestamp.Time,
			LastUpdate:   time.Now(),
			Tags:         []string{"discovered", "service"},
		}

		graph.Nodes[nodeID] = node

		// Create edges between services and their target pods
		asa.createServicePodEdges(graph, &service)
	}

	// Discover Ingresses
	ingresses := &netv1.IngressList{}
	if err := asa.client.List(context.Background(), ingresses); err != nil {
		log.Log.Error(err, "Failed to list ingresses (continuing without ingress analysis)")
	} else {
		for _, ingress := range ingresses.Items {
			nodeID := fmt.Sprintf("ingress-%s-%s", ingress.Namespace, ingress.Name)
			node := &AttackSurfaceNode{
				ID:           nodeID,
				Type:         NodeTypeIngress,
				Name:         ingress.Name,
				Namespace:    ingress.Namespace,
				Labels:       ingress.Labels,
				Annotations:  ingress.Annotations,
				ExposedPorts: asa.extractIngressPorts(&ingress),
				CreationTime: ingress.CreationTimestamp.Time,
				LastUpdate:   time.Now(),
				Tags:         []string{"discovered", "ingress", "external-facing"},
			}

			graph.Nodes[nodeID] = node

			// Create edges between ingresses and their target services
			asa.createIngressServiceEdges(graph, &ingress)
		}
	}

	log.Log.Info("Workload discovery completed", "nodes", len(graph.Nodes))
	return nil
}

func (asa *AttackSurfaceAnalyzer) analyzeNetworkTopology(graph *ClusterAttackSurfaceGraph) error {
	log.Log.Info("Analyzing network topology")

	topology := &NetworkTopology{
		Subnets:       []*Subnet{},
		Gateways:      []*Gateway{},
		Firewall:      []*FirewallRule{},
		LoadBalancers: []*LoadBalancer{},
	}

	// Basic network topology analysis
	// This would be expanded to analyze cluster networking, policies, and service mesh
	log.Log.Info("Basic network topology analysis completed")

	// Store topology in the graph
	asa.networkTopology = topology

	return nil
}

func (asa *AttackSurfaceAnalyzer) performRiskAnalysis(graph *ClusterAttackSurfaceGraph) error {
	log.Log.Info("Performing risk analysis")

	// Calculate risk scores for each node
	var totalRiskScore float64
	var highRiskNodes int
	var criticalVulnerabilities int

	for _, node := range graph.Nodes {
		nodeRisk := asa.calculateNodeRisk(node)
		node.RiskScore = nodeRisk
		totalRiskScore += nodeRisk

		if nodeRisk > 7.0 {
			highRiskNodes++
		}

		if node.CriticalityLevel == CriticalityCritical {
			criticalVulnerabilities += node.VulnerabilityCount
		}
	}

	// Calculate edge risk contributions
	for _, edge := range graph.Edges {
		edge.RiskContribution = asa.calculateEdgeRisk(edge, graph)
	}

	// Aggregate overall risk. Guard against an empty graph.
	var averageRiskScore float64
	if len(graph.Nodes) > 0 {
		averageRiskScore = totalRiskScore / float64(len(graph.Nodes))
	}

	// Build the high-risk component list from the nodes that actually exceeded
	// the configured High threshold, carrying their real risk scores.
	lowThreshold, highThreshold, criticalThreshold := 3.0, 7.0, 9.0
	if asa.riskThresholds != nil {
		lowThreshold = asa.riskThresholds.Low
		highThreshold = asa.riskThresholds.High
		criticalThreshold = asa.riskThresholds.Critical
	}
	var highRiskComponents []*RiskComponent
	for _, node := range graph.Nodes {
		if node.RiskScore >= highThreshold {
			highRiskComponents = append(highRiskComponents, &RiskComponent{
				ID:         node.ID,
				Name:       node.Name,
				Type:       string(node.Type),
				RiskScore:  node.RiskScore,
				Impact:     asa.scoreToImpact(node.RiskScore),
				Likelihood: asa.scoreToLikelihood(node.RiskScore),
			})
		}
	}
	sort.Slice(highRiskComponents, func(i, j int) bool {
		return highRiskComponents[i].RiskScore > highRiskComponents[j].RiskScore
	})

	graph.RiskAggregation = &RiskAggregation{
		TotalRiskScore:     totalRiskScore,
		HighRiskComponents: highRiskComponents,
		// Distribution counts nodes falling in each severity band, derived from
		// the real per-node scores rather than a fixed split.
		RiskDistribution: map[RiskCategory]float64{
			RiskCategoryNetwork:       float64(asa.countNodesByRiskRange(graph.Nodes, 0.0, lowThreshold)),
			RiskCategoryPrivilege:     float64(asa.countNodesByRiskRange(graph.Nodes, lowThreshold, highThreshold)),
			RiskCategoryCompliance:    float64(asa.countNodesByRiskRange(graph.Nodes, highThreshold, criticalThreshold)),
			RiskCategoryVulnerability: float64(asa.countNodesByRiskRange(graph.Nodes, criticalThreshold, 10.01)),
		},
		ClusterRiskProfile: &ClusterRiskProfile{
			OverallScore: averageRiskScore,
			TopRisks:     asa.identifyTopRiskFactors(graph.Nodes),
		},
	}

	log.Log.Info("Risk analysis completed",
		"averageRisk", averageRiskScore,
		"highRiskNodes", highRiskNodes,
		"criticalVulns", criticalVulnerabilities)

	return nil
}

func (asa *AttackSurfaceAnalyzer) identifyExposurePaths(graph *ClusterAttackSurfaceGraph) error {
	log.Log.Info("Identifying exposure paths")

	var exposurePaths []*ExposurePath
	var criticalPaths []*CriticalPath

	// Find externally accessible entry points
	entryPoints := asa.findExternalEntryPoints(graph)

	for _, entryPoint := range entryPoints {
		// Trace paths from entry points to sensitive resources
		paths := asa.tracePathsFromEntry(graph, entryPoint)

		for _, path := range paths {
			endNode := path.Nodes[len(path.Nodes)-1]
			exposurePath := &ExposurePath{
				ID:            fmt.Sprintf("exposure-%s-%d", entryPoint, len(exposurePaths)),
				StartNode:     entryPoint,
				EndNode:       endNode,
				Path:          path.Nodes,
				ExposureType:  asa.classifyExposureType(graph, endNode),
				RiskScore:     asa.calculatePathRisk(path, graph),
				AttackVectors: asa.identifyAttackVectors(path, graph),
				Defenses:      asa.pathDefenses(path, graph),
			}

			exposurePaths = append(exposurePaths, exposurePath)

			// Identify critical paths (those whose real risk score clears the
			// configured High threshold).
			if exposurePath.RiskScore >= asa.highRiskThreshold() {
				criticalPath := &CriticalPath{
					ID:          exposurePath.ID + "-critical",
					Description: fmt.Sprintf("Exposure path from %s to %s crossing %d hops", entryPoint, endNode, len(path.Nodes)),
					Steps:       path.Nodes,
					RiskScore:   exposurePath.RiskScore,
					Likelihood:  asa.calculatePathProbability(path, graph),
					Impact:      asa.calculatePathImpact(path, graph),
				}
				criticalPaths = append(criticalPaths, criticalPath)
			}
		}
	}

	// Prioritize both collections: the exposure paths an operator should look at
	// first are those with the highest attacker priority (risk tempered by how
	// reachable the endpoint is), and the critical paths by combined
	// risk*likelihood*impact so the most dangerous, most-achievable chains lead.
	sort.SliceStable(exposurePaths, func(i, j int) bool {
		return asa.calculatePriority(exposurePaths[i]) > asa.calculatePriority(exposurePaths[j])
	})
	sort.SliceStable(criticalPaths, func(i, j int) bool {
		li := criticalPaths[i].RiskScore * criticalPaths[i].Likelihood * criticalPaths[i].Impact
		lj := criticalPaths[j].RiskScore * criticalPaths[j].Likelihood * criticalPaths[j].Impact
		return li > lj
	})

	graph.ExposurePaths = exposurePaths
	graph.CriticalPaths = criticalPaths

	log.Log.Info("Exposure path analysis completed",
		"exposurePaths", len(exposurePaths),
		"criticalPaths", len(criticalPaths))

	return nil
}

func (asa *AttackSurfaceAnalyzer) generateRecommendations(graph *ClusterAttackSurfaceGraph) error {
	log.Log.Info("Generating security recommendations")

	var recommendations []*RecommendedAction

	// Analyze high-risk nodes for recommendations
	for _, node := range graph.Nodes {
		if node.RiskScore >= asa.highRiskThreshold() {
			nodeRecommendations := asa.generateNodeRecommendations(node)
			recommendations = append(recommendations, nodeRecommendations...)
		}
	}

	// Analyze critical paths for recommendations
	for _, criticalPath := range graph.CriticalPaths {
		pathRecommendations := asa.generatePathRecommendations(criticalPath)
		recommendations = append(recommendations, pathRecommendations...)
	}

	// Generate general security recommendations
	generalRecommendations := asa.generateGeneralRecommendations(graph)
	recommendations = append(recommendations, generalRecommendations...)

	// Prioritize recommendations
	asa.prioritizeRecommendations(recommendations)

	graph.RecommendedActions = recommendations

	log.Log.Info("Generated security recommendations", "count", len(recommendations))

	return nil
}

func (asa *AttackSurfaceAnalyzer) getWorkloadKey(workloadRef learner.WorkloadReference) string {
	return fmt.Sprintf("%s/%s/%s", workloadRef.Namespace, workloadRef.Kind, workloadRef.Name)
}

func (asa *AttackSurfaceAnalyzer) analyzeWorkloadContainers(surface *WorkloadAttackSurface) error {
	log.Log.Info("Analyzing workload containers", "workload", surface.WorkloadRef.Name)

	// Get pods for this workload
	pods := &v1.PodList{}
	if err := asa.client.List(context.Background(), pods, client.InNamespace(surface.WorkloadRef.Namespace)); err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	for _, pod := range pods.Items {
		if !asa.podBelongsToWorkload(&pod, surface.WorkloadRef) {
			continue
		}

		for _, container := range pod.Spec.Containers {
			containerSurface := &ContainerAttackSurface{
				ContainerID: fmt.Sprintf("%s-%s", pod.Name, container.Name),
				Name:        container.Name,
				Image:       container.Image,
				LastUpdate:  time.Now(),
			}

			// Analyze container image
			containerSurface.ImageAnalysis = asa.analyzeContainerImage(container.Image)

			// Analyze runtime security profile
			containerSurface.RuntimeProfile = asa.analyzeRuntimeProfile(&pod, &container)

			// Analyze syscall exposure
			containerSurface.SyscallExposure = asa.analyzeSyscallExposure(&pod, &container)

			// Analyze network exposure
			containerSurface.NetworkExposure = asa.analyzeContainerNetworkExposure(&pod, &container)

			// Analyze filesystem exposure
			containerSurface.FileSystemExposure = asa.analyzeFilesystemExposure(&pod, &container)

			// Analyze security context
			containerSurface.SecurityContext = asa.analyzeContainerSecurityContext(&container)

			// Analyze resource limits
			containerSurface.ResourceLimits = asa.analyzeResourceLimits(&container)

			// Analyze capabilities
			containerSurface.CapabilityAnalysis = asa.analyzeContainerCapabilities(&container)

			// Analyze policy compliance
			containerSurface.PolicyCompliance = asa.analyzePolicyCompliance(&pod, &container)

			// Calculate container risk score
			containerSurface.RiskScore = asa.calculateContainerRisk(containerSurface)

			surface.Containers[containerSurface.ContainerID] = containerSurface
		}
	}

	log.Log.Info("Container analysis completed", "containers", len(surface.Containers))
	return nil
}

func (asa *AttackSurfaceAnalyzer) analyzeServiceExposure(surface *WorkloadAttackSurface) error {
	log.Log.Info("Analyzing service exposure", "workload", surface.WorkloadRef.Name)

	// Find services that expose this workload
	services := &v1.ServiceList{}
	if err := asa.client.List(context.Background(), services, client.InNamespace(surface.WorkloadRef.Namespace)); err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}

	for _, service := range services.Items {
		if asa.serviceExposesWorkload(&service, surface.WorkloadRef) {
			ports := asa.extractServicePorts(&service)
			exposedPorts := make([]ExposedPort, len(ports))
			for i, port := range ports {
				exposedPorts[i] = *port
			}

			exposure := &ServiceExposure{
				Name:         service.Name,
				Namespace:    service.Namespace,
				Type:         string(service.Spec.Type),
				Ports:        exposedPorts,
				LoadBalancer: service.Spec.Type == v1.ServiceTypeLoadBalancer,
			}

			// Check for external IP
			if len(service.Status.LoadBalancer.Ingress) > 0 {
				exposure.ExternalIP = service.Status.LoadBalancer.Ingress[0].IP
			}

			// Calculate exposure risk
			exposure.RiskScore = asa.calculateServiceExposureRisk(&service)

			surface.ServiceExposure = exposure
			break // Assuming one primary service per workload
		}
	}

	return nil
}

func (asa *AttackSurfaceAnalyzer) analyzeNetworkPolicies(surface *WorkloadAttackSurface) error {
	log.Log.Info("Analyzing network policies", "workload", surface.WorkloadRef.Name)

	// Find network policies that apply to this workload
	policies := &netv1.NetworkPolicyList{}
	if err := asa.client.List(context.Background(), policies, client.InNamespace(surface.WorkloadRef.Namespace)); err != nil {
		return fmt.Errorf("failed to list network policies: %v", err)
	}

	var applicablePolicies []*NetworkPolicyAnalysis

	for _, policy := range policies.Items {
		if asa.networkPolicyAppliesTo(&policy, surface.WorkloadRef) {
			analysis := &NetworkPolicyAnalysis{
				Name:      policy.Name,
				Namespace: policy.Namespace,
				Applied:   true,
			}

			// Analyze ingress rules
			for _, rule := range policy.Spec.Ingress {
				ruleDesc := fmt.Sprintf("Allow from %d peers on %d ports", len(rule.From), len(rule.Ports))
				analysis.IngressRules = append(analysis.IngressRules, ruleDesc)
			}

			// Analyze egress rules
			for _, rule := range policy.Spec.Egress {
				ruleDesc := fmt.Sprintf("Allow to %d peers on %d ports", len(rule.To), len(rule.Ports))
				analysis.EgressRules = append(analysis.EgressRules, ruleDesc)
			}

			// Calculate effectiveness and coverage
			analysis.Effectiveness = asa.calculatePolicyEffectiveness(&policy)
			analysis.Coverage = asa.calculatePolicyCoverage(&policy, surface.WorkloadRef)

			applicablePolicies = append(applicablePolicies, analysis)
		}
	}

	surface.NetworkPolicies = applicablePolicies

	log.Log.Info("Network policy analysis completed", "policies", len(applicablePolicies))
	return nil
}

func (asa *AttackSurfaceAnalyzer) analyzeRBAC(surface *WorkloadAttackSurface) error {
	log.Log.Info("Analyzing RBAC configuration", "workload", surface.WorkloadRef.Name)

	// Get pods for this workload to find service accounts
	pods := &v1.PodList{}
	if err := asa.client.List(context.Background(), pods, client.InNamespace(surface.WorkloadRef.Namespace)); err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	serviceAccountName := "default"
	var workloadPod *v1.Pod
	for i := range pods.Items {
		if asa.podBelongsToWorkload(&pods.Items[i], surface.WorkloadRef) {
			workloadPod = &pods.Items[i]
			if workloadPod.Spec.ServiceAccountName != "" {
				serviceAccountName = workloadPod.Spec.ServiceAccountName
			}
			break
		}
	}

	rbacAnalysis := &RBACAnalysis{
		ServiceAccount: serviceAccountName,
		Roles:          []string{},
		ClusterRoles:   []string{},
		Permissions:    []string{},
		Privileged:     false,
	}

	// Resolve the actual role/cluster-role bindings for this service account
	// (best-effort: if RBAC objects are not readable this returns empty sets and
	// the score falls back to pod-level signals).
	binding := asa.resolveServiceAccountBindings(surface.WorkloadRef.Namespace, serviceAccountName)
	rbacAnalysis.Roles = binding.roles
	rbacAnalysis.ClusterRoles = binding.clusterRoles
	rbacAnalysis.Privileged = binding.privileged
	rbacAnalysis.Permissions = binding.permissions

	// Risk score derived from real signals rather than the SA name alone:
	//   base                     1.0
	//   custom (non-default) SA  +1.5
	//   token auto-mounted       +1.0
	//   bound to any ClusterRole +2.0 (cluster-scoped reach)
	//   privileged binding       +4.0 (cluster-admin or wildcard verbs/resources)
	//   host namespace usage     +1.0
	risk := 1.0
	if serviceAccountName != "default" {
		risk += 1.5
	}
	if tokenAutomounted(workloadPod) {
		risk += 1.0
		rbacAnalysis.Permissions = appendUniqueString(rbacAnalysis.Permissions, "service account token auto-mounted")
	}
	if len(binding.clusterRoles) > 0 {
		risk += 2.0
	}
	if binding.privileged {
		risk += 4.0
	}
	if workloadPod != nil && (workloadPod.Spec.HostNetwork || workloadPod.Spec.HostPID || workloadPod.Spec.HostIPC) {
		risk += 1.0
	}
	if risk > 10.0 {
		risk = 10.0
	}
	rbacAnalysis.RiskScore = risk

	surface.RBACAnalysis = rbacAnalysis

	return nil
}

// saBindings holds the resolved RBAC picture for a service account.
type saBindings struct {
	roles        []string
	clusterRoles []string
	permissions  []string
	privileged   bool
}

// resolveServiceAccountBindings enumerates the RoleBindings and
// ClusterRoleBindings that reference the given service account and inspects the
// referenced roles for cluster-admin / wildcard grants. It is best-effort: any
// listing error (e.g. RBAC types not registered in the client scheme) yields the
// zero result so callers degrade gracefully to pod-level signals.
func (asa *AttackSurfaceAnalyzer) resolveServiceAccountBindings(namespace, serviceAccount string) saBindings {
	result := saBindings{roles: []string{}, clusterRoles: []string{}, permissions: []string{}}
	if asa.client == nil {
		return result
	}
	ctx := context.Background()

	subjectMatches := func(subjects []rbacv1.Subject) bool {
		for _, s := range subjects {
			if s.Kind == rbacv1.ServiceAccountKind && s.Name == serviceAccount &&
				(s.Namespace == "" || s.Namespace == namespace) {
				return true
			}
		}
		return false
	}

	// Namespaced RoleBindings.
	rbList := &rbacv1.RoleBindingList{}
	if err := asa.client.List(ctx, rbList, client.InNamespace(namespace)); err == nil {
		for i := range rbList.Items {
			rb := &rbList.Items[i]
			if !subjectMatches(rb.Subjects) {
				continue
			}
			if rb.RoleRef.Kind == "ClusterRole" {
				result.clusterRoles = appendUniqueString(result.clusterRoles, rb.RoleRef.Name)
				if asa.roleRefIsPrivileged(ctx, namespace, rb.RoleRef) {
					result.privileged = true
				}
			} else {
				result.roles = appendUniqueString(result.roles, rb.RoleRef.Name)
				if asa.roleRefIsPrivileged(ctx, namespace, rb.RoleRef) {
					result.privileged = true
				}
			}
		}
	}

	// Cluster-wide ClusterRoleBindings.
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := asa.client.List(ctx, crbList); err == nil {
		for i := range crbList.Items {
			crb := &crbList.Items[i]
			if !subjectMatches(crb.Subjects) {
				continue
			}
			result.clusterRoles = appendUniqueString(result.clusterRoles, crb.RoleRef.Name)
			if asa.roleRefIsPrivileged(ctx, namespace, crb.RoleRef) {
				result.privileged = true
			}
		}
	}

	for _, r := range result.roles {
		result.permissions = appendUniqueString(result.permissions, "role/"+r)
	}
	for _, r := range result.clusterRoles {
		result.permissions = appendUniqueString(result.permissions, "clusterrole/"+r)
	}
	return result
}

// roleRefIsPrivileged reports whether the referenced (cluster)role grants
// effectively unrestricted access - the well-known "cluster-admin" role, or any
// rule with a wildcard verb and a wildcard resource/API group.
func (asa *AttackSurfaceAnalyzer) roleRefIsPrivileged(ctx context.Context, namespace string, ref rbacv1.RoleRef) bool {
	if ref.Name == "cluster-admin" {
		return true
	}
	var rules []rbacv1.PolicyRule
	switch ref.Kind {
	case "ClusterRole":
		cr := &rbacv1.ClusterRole{}
		if err := asa.client.Get(ctx, client.ObjectKey{Name: ref.Name}, cr); err != nil {
			return false
		}
		rules = cr.Rules
	case "Role":
		role := &rbacv1.Role{}
		if err := asa.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, role); err != nil {
			return false
		}
		rules = role.Rules
	default:
		return false
	}
	for _, rule := range rules {
		if stringsContains(rule.Verbs, "*") &&
			(stringsContains(rule.Resources, "*") || stringsContains(rule.APIGroups, "*")) {
			return true
		}
	}
	return false
}

func (asa *AttackSurfaceAnalyzer) calculateWorkloadRisk(surface *WorkloadAttackSurface) error {
	log.Log.Info("Calculating workload risk score", "workload", surface.WorkloadRef.Name)

	var totalRisk float64
	var riskFactors []*RiskFactor
	riskDistribution := &RiskDistribution{
		Categories: make(map[string]float64),
	}

	// Container risk contribution
	var containerRisk float64
	for _, container := range surface.Containers {
		containerRisk += container.RiskScore
	}
	if len(surface.Containers) > 0 {
		containerRisk = containerRisk / float64(len(surface.Containers))
	}
	riskDistribution.Categories["containers"] = containerRisk
	totalRisk += containerRisk * 0.4 // 40% weight

	// Service exposure risk contribution
	var exposureRisk float64
	if surface.ServiceExposure != nil {
		exposureRisk = surface.ServiceExposure.RiskScore
		if exposureRisk > 7.0 {
			riskFactors = append(riskFactors, &RiskFactor{
				Type:        RiskFactorTypeExposedService,
				Severity:    SeverityHigh,
				Description: "Workload has high-risk service exposure",
			})
		}
	}
	riskDistribution.Categories["exposure"] = exposureRisk
	totalRisk += exposureRisk * 0.3 // 30% weight

	// Network policy risk contribution
	var networkRisk float64
	if len(surface.NetworkPolicies) == 0 {
		networkRisk = 6.0 // High risk if no network policies
		riskFactors = append(riskFactors, &RiskFactor{
			Type:        RiskFactorTypeMisconfiguration,
			Severity:    SeverityMedium,
			Description: "No network policies applied to workload",
		})
	} else {
		// Calculate average effectiveness
		var totalEffectiveness float64
		for _, policy := range surface.NetworkPolicies {
			totalEffectiveness += policy.Effectiveness
		}
		avgEffectiveness := totalEffectiveness / float64(len(surface.NetworkPolicies))
		networkRisk = (10.0 - avgEffectiveness) // Inverse of effectiveness
	}
	riskDistribution.Categories["network"] = networkRisk
	totalRisk += networkRisk * 0.2 // 20% weight

	// RBAC risk contribution
	var rbacRisk float64
	if surface.RBACAnalysis != nil {
		rbacRisk = surface.RBACAnalysis.RiskScore
		if surface.RBACAnalysis.Privileged {
			riskFactors = append(riskFactors, &RiskFactor{
				Type:        RiskFactorTypePrivilegedAccess,
				Severity:    SeverityCritical,
				Description: "Workload has privileged RBAC access",
			})
		}
	} else {
		rbacRisk = 5.0 // Medium risk if no RBAC analysis
	}
	riskDistribution.Categories["rbac"] = rbacRisk
	totalRisk += rbacRisk * 0.1 // 10% weight

	// Cap at 10.0
	if totalRisk > 10.0 {
		totalRisk = 10.0
	}

	surface.OverallRiskScore = totalRisk
	surface.TopRisks = riskFactors
	surface.RiskDistribution = riskDistribution

	// Count risk levels
	riskDistribution.Total = totalRisk
	if totalRisk >= 9.0 {
		riskDistribution.Critical = 1
	} else if totalRisk >= 7.0 {
		riskDistribution.High = 1
	} else if totalRisk >= 4.0 {
		riskDistribution.Medium = 1
	} else {
		riskDistribution.Low = 1
	}

	// Generate recommendations based on risk factors
	var recommendations []*SecurityRecommendation
	for _, factor := range riskFactors {
		recommendation := asa.generateRecommendationForRiskFactor(factor)
		recommendations = append(recommendations, recommendation)
	}
	surface.Recommendations = recommendations

	log.Log.Info("Workload risk calculation completed",
		"riskScore", totalRisk,
		"riskFactors", len(riskFactors),
		"recommendations", len(recommendations))

	return nil
}

func (asa *AttackSurfaceAnalyzer) performExports() {
	asa.mu.RLock()
	defer asa.mu.RUnlock()

	// Gather current attack surface data
	data := &AttackSurfaceData{
		Timestamp:        time.Now(),
		ClusterGraph:     asa.clusterGraph,
		WorkloadProfiles: asa.workloadProfiles,
		NetworkTopology:  asa.networkTopology,
		ThreatModel:      asa.threatModel,
		Metadata:         make(map[string]interface{}),
	}

	// Export to Grafana if configured
	if asa.grafanaExporter != nil && asa.grafanaExporter.Enabled {
		if err := asa.exportToGrafana(data); err != nil {
			log.Log.Error(err, "Failed to export to Grafana")
		}
	}

	// Export to Datadog if configured
	if asa.datadogExporter != nil && asa.datadogExporter.Enabled {
		if err := asa.exportToDatadog(data); err != nil {
			log.Log.Error(err, "Failed to export to Datadog")
		}
	}

	// Export to OpenTelemetry if configured
	if asa.otelExporter != nil && asa.otelExporter.Enabled {
		if err := asa.exportToOTel(data); err != nil {
			log.Log.Error(err, "Failed to export to OpenTelemetry")
		}
	}

	// Export to custom exporters
	for _, exporter := range asa.customExporters {
		if exporter.Enabled {
			if err := asa.exportToCustom(data, &exporter); err != nil {
				log.Log.Error(err, "Failed to export to custom exporter",
					"exporter", exporter.Name)
			}
		}
	}
}

func (asa *AttackSurfaceAnalyzer) performVulnerabilityScans() {
	// Implementation would perform vulnerability scans
}

func (asa *AttackSurfaceAnalyzer) updateThreatModel() {
	// Implementation would update threat model
}

func (asa *AttackSurfaceAnalyzer) exportToGraphQL(data *AttackSurfaceData) ([]byte, error) {
	// Implementation would export to GraphQL format
	return []byte("{}"), nil
}

func (asa *AttackSurfaceAnalyzer) exportToMermaid(data *AttackSurfaceData) ([]byte, error) {
	// Implementation would export to Mermaid diagram format
	return []byte("graph TD"), nil
}

func (asa *AttackSurfaceAnalyzer) exportToCytoscape(data *AttackSurfaceData) ([]byte, error) {
	// Implementation would export to Cytoscape.js format
	return []byte("{}"), nil
}

// Helper methods for workload discovery
func (asa *AttackSurfaceAnalyzer) extractPodPorts(pod *v1.Pod) []*ExposedPort {
	var ports []*ExposedPort
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			exposedPort := &ExposedPort{
				Port:     port.ContainerPort,
				Protocol: string(port.Protocol),
				Service:  port.Name,
				Public:   false, // Determined later based on service exposure
			}
			ports = append(ports, exposedPort)
		}
	}
	return ports
}

func (asa *AttackSurfaceAnalyzer) extractPodCapabilities(pod *v1.Pod) []string {
	var capabilities []string
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				capabilities = append(capabilities, string(cap))
			}
		}
	}
	return capabilities
}

func (asa *AttackSurfaceAnalyzer) analyzePodPrivileges(pod *v1.Pod) *PrivilegeProfile {
	profile := &PrivilegeProfile{
		Privileged: false,
	}

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil {
			if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
				profile.RunAsUser = container.SecurityContext.RunAsUser
			}
			if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				profile.Privileged = true
			}
		}
	}

	return profile
}

// getPodSyscallProfile derives the syscall attack surface of a pod from its
// real security posture. When the enforcement engine holds a learned/enforced
// policy for one of the pod's containers, that observed+enforced surface is used
// directly. Otherwise the surface is reconstructed from the pod's declared Linux
// capabilities and privilege level, because each capability unlocks a concrete,
// well-known set of (frequently sensitive) syscalls.
func (asa *AttackSurfaceAnalyzer) getPodSyscallProfile(pod *v1.Pod) *SyscallProfile {
	profile := &SyscallProfile{
		SyscallFrequency:   make(map[uint64]float64),
		CriticalityMapping: make(map[uint64]CriticalityLevel),
	}

	// Prefer real enforcement/learning data when it exists for this pod.
	if gp := asa.resolvePodPolicy(pod); gp != nil && gp.SyscallPolicy != nil {
		for nr, rule := range gp.SyscallPolicy.AllowedSyscalls {
			profile.AllowedSyscalls = append(profile.AllowedSyscalls, nr)
			if rule != nil {
				profile.CriticalityMapping[nr] = mapLearnerCriticality(rule.Criticality)
			}
			if isSensitiveSyscall(nr) {
				profile.RiskySyscalls = append(profile.RiskySyscalls, nr)
			}
		}
		for nr := range gp.SyscallPolicy.DeniedSyscalls {
			profile.DeniedSyscalls = append(profile.DeniedSyscalls, nr)
		}
		if bp := gp.BasedOnProfile; bp != nil {
			for nr, sp := range bp.AllowedSyscalls {
				if sp != nil {
					profile.SyscallFrequency[nr] = sp.Frequency
				}
			}
		}
		sort.Slice(profile.AllowedSyscalls, func(i, j int) bool { return profile.AllowedSyscalls[i] < profile.AllowedSyscalls[j] })
		sort.Slice(profile.RiskySyscalls, func(i, j int) bool { return profile.RiskySyscalls[i] < profile.RiskySyscalls[j] })
		sort.Slice(profile.DeniedSyscalls, func(i, j int) bool { return profile.DeniedSyscalls[i] < profile.DeniedSyscalls[j] })
		return profile
	}

	// Fallback: reconstruct from the declared security context. Start from the
	// baseline every container needs, then widen by the syscalls each granted
	// capability unlocks; a privileged container is treated as having every
	// sensitive syscall available.
	allowed := make(map[uint64]bool, len(baselineContainerSyscalls))
	for _, nr := range baselineContainerSyscalls {
		allowed[nr] = true
	}
	risky := make(map[uint64]bool)

	privileged := false
	for i := range pod.Spec.Containers {
		sc := pod.Spec.Containers[i].SecurityContext
		if sc == nil {
			continue
		}
		if sc.Privileged != nil && *sc.Privileged {
			privileged = true
		}
		if sc.Capabilities != nil {
			for _, c := range sc.Capabilities.Add {
				for _, nr := range capabilitySyscalls[string(c)] {
					allowed[nr] = true
					risky[nr] = true
				}
			}
		}
	}
	if privileged {
		for _, nr := range sensitiveSyscallList {
			allowed[nr] = true
			risky[nr] = true
		}
	}

	for nr := range allowed {
		profile.AllowedSyscalls = append(profile.AllowedSyscalls, nr)
	}
	for nr := range risky {
		profile.RiskySyscalls = append(profile.RiskySyscalls, nr)
		if isCriticalSyscall(nr) {
			profile.CriticalityMapping[nr] = CriticalityCritical
		} else {
			profile.CriticalityMapping[nr] = CriticalityHigh
		}
	}
	sort.Slice(profile.AllowedSyscalls, func(i, j int) bool { return profile.AllowedSyscalls[i] < profile.AllowedSyscalls[j] })
	sort.Slice(profile.RiskySyscalls, func(i, j int) bool { return profile.RiskySyscalls[i] < profile.RiskySyscalls[j] })
	return profile
}

// getPodNetworkProfile derives the network attack surface from the pod's real
// container port declarations, enriched with any learned outbound flows.
func (asa *AttackSurfaceAnalyzer) getPodNetworkProfile(pod *v1.Pod) *NetworkProfile {
	profile := &NetworkProfile{}

	for i := range pod.Spec.Containers {
		for _, p := range pod.Spec.Containers[i].Ports {
			profile.ExposedPorts = append(profile.ExposedPorts, &ExposedPort{
				Port:     p.ContainerPort,
				Protocol: string(p.Protocol),
				Service:  p.Name,
			})
			profile.ListeningServices = append(profile.ListeningServices, &ListeningService{
				Port:        p.ContainerPort,
				Protocol:    string(p.Protocol),
				ServiceName: p.Name,
			})
		}
	}

	if gp := asa.resolvePodPolicy(pod); gp != nil && gp.BasedOnProfile != nil {
		for _, flow := range gp.BasedOnProfile.AllowedNetworkFlows {
			if flow == nil {
				continue
			}
			if strings.EqualFold(flow.Direction, "egress") || strings.EqualFold(flow.Direction, "outbound") {
				for _, ep := range flow.RemoteEndpoints {
					profile.OutboundConnections = append(profile.OutboundConnections, &OutboundConnection{
						DestinationIP: ep,
						Protocol:      flow.Protocol,
						LastSeen:      time.Now(),
					})
				}
			}
		}
	}

	return profile
}

// getPodFilesystemProfile derives the filesystem attack surface from the pod's
// real volume mounts and root-filesystem posture, plus any learned/enforced
// allowed paths.
func (asa *AttackSurfaceAnalyzer) getPodFilesystemProfile(pod *v1.Pod) *FileSystemProfile {
	profile := &FileSystemProfile{}

	sensitiveVols := make(map[string]string)
	for _, v := range pod.Spec.Volumes {
		switch {
		case v.Secret != nil:
			sensitiveVols[v.Name] = "secret"
		case v.ConfigMap != nil:
			sensitiveVols[v.Name] = "config"
		}
	}

	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		roRoot := c.SecurityContext != nil &&
			c.SecurityContext.ReadOnlyRootFilesystem != nil &&
			*c.SecurityContext.ReadOnlyRootFilesystem
		if !roRoot {
			profile.WritablePaths = appendUniqueString(profile.WritablePaths, "/")
		}
		for _, m := range c.VolumeMounts {
			mp := &MountPoint{
				Source:      m.Name,
				Destination: m.MountPath,
				ReadOnly:    m.ReadOnly,
			}
			if t, ok := sensitiveVols[m.Name]; ok {
				mp.Sensitive = true
				profile.SensitiveFiles = append(profile.SensitiveFiles, &SensitiveFile{
					Path: m.MountPath,
					Type: t,
					Risk: "high",
				})
			}
			profile.MountPoints = append(profile.MountPoints, mp)
			if !m.ReadOnly {
				profile.WritablePaths = appendUniqueString(profile.WritablePaths, m.MountPath)
			}
		}
	}

	if gp := asa.resolvePodPolicy(pod); gp != nil && gp.FilePolicy != nil {
		for p := range gp.FilePolicy.AllowedPaths {
			profile.ExecutablePaths = appendUniqueString(profile.ExecutablePaths, p)
		}
		sort.Strings(profile.ExecutablePaths)
	}

	return profile
}

// resolvePodPolicy returns the first generated enforcement policy the engine
// holds for any of the pod's running containers, or nil when none is available
// (e.g. the engine has not learned this workload yet).
func (asa *AttackSurfaceAnalyzer) resolvePodPolicy(pod *v1.Pod) *policies.GeneratedPolicy {
	if asa.enforcementEngine == nil || pod == nil {
		return nil
	}
	var ids []string
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ContainerID == "" {
			continue
		}
		ids = append(ids, cs.ContainerID)
		// Container IDs are typically "<runtime>://<hash>"; the engine may key
		// by either the full reference or the bare hash.
		if i := strings.LastIndex(cs.ContainerID, "/"); i >= 0 && i+1 < len(cs.ContainerID) {
			ids = append(ids, cs.ContainerID[i+1:])
		}
	}
	for _, id := range ids {
		if state, err := asa.enforcementEngine.GetPolicyState(id); err == nil && state != nil && state.GeneratedPolicy != nil {
			return state.GeneratedPolicy
		}
	}
	return nil
}

func (asa *AttackSurfaceAnalyzer) extractServicePorts(service *v1.Service) []*ExposedPort {
	var ports []*ExposedPort
	for _, port := range service.Spec.Ports {
		exposedPort := &ExposedPort{
			Port:     port.Port,
			Protocol: string(port.Protocol),
			Service:  port.Name,
			Public:   service.Spec.Type == v1.ServiceTypeLoadBalancer || service.Spec.Type == v1.ServiceTypeNodePort,
		}
		ports = append(ports, exposedPort)
	}
	return ports
}

func (asa *AttackSurfaceAnalyzer) extractIngressPorts(ingress *netv1.Ingress) []*ExposedPort {
	var ports []*ExposedPort
	// Ingresses typically expose HTTP/HTTPS
	ports = append(ports, &ExposedPort{
		Port:     80,
		Protocol: "TCP",
		Service:  "http",
		Public:   true,
	})

	// Check for TLS configuration
	if len(ingress.Spec.TLS) > 0 {
		ports = append(ports, &ExposedPort{
			Port:     443,
			Protocol: "TCP",
			Service:  "https",
			Public:   true,
		})
	}

	return ports
}

func (asa *AttackSurfaceAnalyzer) createServicePodEdges(graph *ClusterAttackSurfaceGraph, service *v1.Service) {
	serviceNodeID := fmt.Sprintf("service-%s-%s", service.Namespace, service.Name)

	// Find pods that match the service selector
	pods := &v1.PodList{}
	if err := asa.client.List(context.Background(), pods, client.InNamespace(service.Namespace)); err != nil {
		return
	}

	for _, pod := range pods.Items {
		if asa.podMatchesSelector(&pod, service.Spec.Selector) {
			podNodeID := fmt.Sprintf("pod-%s-%s", pod.Namespace, pod.Name)
			edgeID := fmt.Sprintf("%s->%s", serviceNodeID, podNodeID)

			edge := &AttackSurfaceEdge{
				ID:               edgeID,
				Source:           serviceNodeID,
				Target:           podNodeID,
				Type:             EdgeTypeServiceDependency,
				Direction:        EdgeDirectionBidirectional,
				Protocol:         "TCP",
				Weight:           1.0,
				RiskContribution: 0.1,
				FirstSeen:        time.Now(),
				LastSeen:         time.Now(),
				Frequency:        1.0,
			}

			graph.Edges[edgeID] = edge
		}
	}
}

func (asa *AttackSurfaceAnalyzer) createIngressServiceEdges(graph *ClusterAttackSurfaceGraph, ingress *netv1.Ingress) {
	ingressNodeID := fmt.Sprintf("ingress-%s-%s", ingress.Namespace, ingress.Name)

	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				serviceNodeID := fmt.Sprintf("service-%s-%s", ingress.Namespace, path.Backend.Service.Name)
				edgeID := fmt.Sprintf("%s->%s", ingressNodeID, serviceNodeID)

				edge := &AttackSurfaceEdge{
					ID:               edgeID,
					Source:           ingressNodeID,
					Target:           serviceNodeID,
					Type:             EdgeTypeNetworkConnection,
					Direction:        EdgeDirectionOutbound,
					Protocol:         "HTTP",
					Weight:           1.0,
					RiskContribution: 0.3, // Higher risk as it's externally accessible
					FirstSeen:        time.Now(),
					LastSeen:         time.Now(),
					Frequency:        1.0,
				}

				graph.Edges[edgeID] = edge
			}
		}
	}
}

func (asa *AttackSurfaceAnalyzer) podMatchesSelector(pod *v1.Pod, selector map[string]string) bool {
	if selector == nil {
		return false
	}

	for key, value := range selector {
		if podValue, exists := pod.Labels[key]; !exists || podValue != value {
			return false
		}
	}

	return true
}

// Risk calculation helper methods
//
// calculateNodeRisk turns a node's concrete attack-surface factors into a
// bounded 0..10 risk score. The score is the sum of independently weighted
// contributions, each derived from real observed/declared data on the node:
//
//	base(type)          external-facing components start higher (ingress > service > pod)
//	exposed ports       +1.2 per public port, +0.3 per internal port, +1.0 per high-risk port
//	writable paths      +0.4 per writable path (a writable "/" is a full-fs escape primitive)
//	allowed syscalls    +0.02 per allowed syscall (broader surface = more reachable code paths)
//	sensitive syscalls  +0.8 per risky syscall (ptrace/mount/module-load/etc.)
//	capabilities        +0.7 per risky Linux capability held
//	privilege level     +3.0 privileged, +2.0 runs-as-root, +1.0 privilege-escalation allowed
//	vulnerabilities     +0.8 per known vulnerability
//
// The weights are chosen so that a single dominant primitive (privileged, or a
// sensitive syscall backed by a matching capability) drives the score into the
// high band, while an otherwise-clean node with only a couple of internal ports
// stays low. The result is clamped to [0, 10].
func (asa *AttackSurfaceAnalyzer) calculateNodeRisk(node *AttackSurfaceNode) float64 {
	riskScore := 0.0

	// Base risk from node type (external reachability).
	switch node.Type {
	case NodeTypeIngress:
		riskScore += 3.0
	case NodeTypeLoadBalancer:
		riskScore += 2.5
	case NodeTypeService:
		riskScore += 2.0
	case NodeTypePod:
		riskScore += 1.0
	}

	// Risk from exposed ports.
	for _, port := range node.ExposedPorts {
		if port.Public {
			riskScore += 1.2
		} else {
			riskScore += 0.3
		}
		if asa.isHighRiskPort(port.Port) {
			riskScore += 1.0
		}
	}

	// Risk from writable filesystem surface.
	if node.FileSystemProfile != nil {
		for _, p := range node.FileSystemProfile.WritablePaths {
			if p == "/" {
				riskScore += 1.5 // writable root filesystem
			} else {
				riskScore += 0.4
			}
		}
		// Sensitive files reachable in the container add direct data-access risk.
		riskScore += float64(len(node.FileSystemProfile.SensitiveFiles)) * 0.6
	}

	// Risk from syscall surface: breadth (allowed) plus sensitivity (risky).
	if node.SyscallProfile != nil {
		riskScore += float64(len(node.SyscallProfile.AllowedSyscalls)) * 0.02
		riskScore += float64(len(node.SyscallProfile.RiskySyscalls)) * 0.8
	}

	// Risk from held Linux capabilities.
	for _, c := range node.Capabilities {
		if asa.isRiskyCapability(c) {
			riskScore += 0.7
		}
	}

	// Risk from privilege level.
	if node.Privileges != nil {
		if node.Privileges.RunAsUser != nil && *node.Privileges.RunAsUser == 0 {
			riskScore += 2.0
		}
		if node.Privileges.Privileged {
			riskScore += 3.0
		}
		if node.Privileges.AllowPrivilegeEscalation {
			riskScore += 1.0
		}
	}

	// Vulnerability contribution.
	riskScore += float64(node.VulnerabilityCount) * 0.8

	if riskScore > 10.0 {
		riskScore = 10.0
	}
	if riskScore < 0 {
		riskScore = 0
	}

	// Record the criticality band implied by the score so downstream consumers
	// (exposure typing, aggregation) reflect real risk rather than a default.
	node.CriticalityLevel = asa.riskToCriticality(riskScore)

	return riskScore
}

// riskToCriticality maps a 0..10 risk score onto the analyzer's configured
// risk-threshold bands.
func (asa *AttackSurfaceAnalyzer) riskToCriticality(score float64) CriticalityLevel {
	t := asa.riskThresholds
	switch {
	case t != nil && score >= t.Critical:
		return CriticalityCritical
	case t != nil && score >= t.High:
		return CriticalityHigh
	case t != nil && score >= t.Medium:
		return CriticalityMedium
	case t != nil && score >= t.Low:
		return CriticalityLow
	default:
		return CriticalityInfo
	}
}

func (asa *AttackSurfaceAnalyzer) calculateEdgeRisk(edge *AttackSurfaceEdge, graph *ClusterAttackSurfaceGraph) float64 {
	// Risk based on edge type and connectivity
	riskScore := 0.1

	switch edge.Type {
	case EdgeTypeNetworkConnection:
		riskScore = 0.8 // Higher risk for external connections
	case EdgeTypeServiceDependency:
		riskScore = 0.3
	default:
		riskScore = 0.2
	}

	// Increase risk if connecting high-risk nodes
	if sourceNode, exists := graph.Nodes[edge.Source]; exists {
		if sourceNode.RiskScore > 7.0 {
			riskScore += 0.2
		}
	}

	if targetNode, exists := graph.Nodes[edge.Target]; exists {
		if targetNode.RiskScore > 7.0 {
			riskScore += 0.2
		}
	}

	return riskScore
}

func (asa *AttackSurfaceAnalyzer) countNodesByRiskRange(nodes map[string]*AttackSurfaceNode, min, max float64) int {
	count := 0
	for _, node := range nodes {
		if node.RiskScore >= min && node.RiskScore < max {
			count++
		}
	}
	return count
}

func (asa *AttackSurfaceAnalyzer) identifyTopRiskFactors(nodes map[string]*AttackSurfaceNode) []string {
	factors := []string{}

	// Count common risk factors
	privilegedCount := 0
	externalCount := 0
	vulnerabilityCount := 0

	for _, node := range nodes {
		if node.Privileges != nil && node.Privileges.Privileged {
			privilegedCount++
		}
		for _, port := range node.ExposedPorts {
			if port.Public {
				externalCount++
				break
			}
		}
		if node.VulnerabilityCount > 0 {
			vulnerabilityCount++
		}
	}

	if privilegedCount > 0 {
		factors = append(factors, "Privileged containers")
	}
	if externalCount > 0 {
		factors = append(factors, "External exposure")
	}
	if vulnerabilityCount > 0 {
		factors = append(factors, "Known vulnerabilities")
	}

	return factors
}

// Exposure path analysis methods
func (asa *AttackSurfaceAnalyzer) findExternalEntryPoints(graph *ClusterAttackSurfaceGraph) []string {
	var entryPoints []string

	for _, node := range graph.Nodes {
		// Check if node is externally accessible
		if node.Type == NodeTypeIngress {
			entryPoints = append(entryPoints, node.ID)
		} else if node.Type == NodeTypeService {
			for _, port := range node.ExposedPorts {
				if port.Public {
					entryPoints = append(entryPoints, node.ID)
					break
				}
			}
		}
	}

	return entryPoints
}

func (asa *AttackSurfaceAnalyzer) tracePathsFromEntry(graph *ClusterAttackSurfaceGraph, entryPoint string) []*PathAnalysis {
	paths := []*PathAnalysis{}

	// Bounded depth-first traversal that enumerates every distinct path reachable
	// from the entry point along the graph's edges, up to a maximum depth.
	visited := make(map[string]bool)
	currentPath := &PathAnalysis{
		Nodes: []string{entryPoint},
	}

	asa.tracePathsRecursive(graph, entryPoint, currentPath, visited, &paths, 0, 5) // Max depth 5

	return paths
}

func (asa *AttackSurfaceAnalyzer) tracePathsRecursive(graph *ClusterAttackSurfaceGraph, currentNode string, currentPath *PathAnalysis, visited map[string]bool, paths *[]*PathAnalysis, depth, maxDepth int) {
	if depth >= maxDepth {
		return
	}

	visited[currentNode] = true

	// Find outgoing edges
	for _, edge := range graph.Edges {
		if edge.Source == currentNode && !visited[edge.Target] {
			newPath := &PathAnalysis{
				Nodes: append([]string{}, currentPath.Nodes...),
			}
			newPath.Nodes = append(newPath.Nodes, edge.Target)
			*paths = append(*paths, newPath)

			// Continue tracing
			asa.tracePathsRecursive(graph, edge.Target, newPath, visited, paths, depth+1, maxDepth)
		}
	}

	visited[currentNode] = false
}

// calculatePathRisk scores what an attacker gains by traversing an exposure
// path end-to-end. It is derived entirely from the real per-node risk scores
// and per-edge risk contributions along the path:
//
//	risk = (0.5*endpointRisk + 0.5*avgHopRisk) * reachabilityDiscount + edgeRiskSum
//
// endpointRisk is the risk of the asset finally reached (what the attacker
// walks away with), avgHopRisk is the mean risk of every node on the path,
// edgeRiskSum sums the traversed edges' risk contributions, and
// reachabilityDiscount = 1/(1 + 0.2*extraHops) shrinks the score for longer
// chains, which require more successful steps. The result is clamped to [0, 10].
func (asa *AttackSurfaceAnalyzer) calculatePathRisk(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) float64 {
	if path == nil || len(path.Nodes) == 0 {
		return 0
	}

	var sumHop float64
	for _, id := range path.Nodes {
		if n, ok := graph.Nodes[id]; ok {
			sumHop += n.RiskScore
		}
	}
	avgHop := sumHop / float64(len(path.Nodes))

	var endpointRisk float64
	if n, ok := graph.Nodes[path.Nodes[len(path.Nodes)-1]]; ok {
		endpointRisk = n.RiskScore
	}

	edgeRiskSum := asa.pathEdgeRisk(path, graph)

	extraHops := float64(len(path.Nodes) - 2)
	if extraHops < 0 {
		extraHops = 0
	}
	reachabilityDiscount := 1.0 / (1.0 + 0.2*extraHops)

	risk := (0.5*endpointRisk+0.5*avgHop)*reachabilityDiscount + edgeRiskSum
	if risk > 10.0 {
		risk = 10.0
	}
	if risk < 0 {
		risk = 0
	}
	return risk
}

// calculatePathProbability estimates the likelihood (0..1) that an attacker can
// complete the whole path. It multiplies per-hop compromise probabilities,
// where each hop's probability grows with the target node's real risk score
// (a riskier node is easier to pivot into): perHop = clamp(0.4 + 0.05*targetRisk, 0, 0.98).
func (asa *AttackSurfaceAnalyzer) calculatePathProbability(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) float64 {
	if path == nil || len(path.Nodes) < 2 {
		return 1.0
	}
	prob := 1.0
	for _, id := range path.Nodes[1:] {
		targetRisk := 0.0
		if n, ok := graph.Nodes[id]; ok {
			targetRisk = n.RiskScore
		}
		perHop := 0.4 + 0.05*targetRisk
		if perHop > 0.98 {
			perHop = 0.98
		}
		if perHop < 0 {
			perHop = 0
		}
		prob *= perHop
	}
	return prob
}

// calculatePathImpact scores the blast radius (0..10) of the asset the path
// reaches, using the endpoint node's real risk score plus a bonus for
// high-value asset types (databases, APIs) and for endpoints exposing sensitive
// files.
func (asa *AttackSurfaceAnalyzer) calculatePathImpact(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) float64 {
	if path == nil || len(path.Nodes) == 0 {
		return 0
	}
	end, ok := graph.Nodes[path.Nodes[len(path.Nodes)-1]]
	if !ok {
		return 0
	}
	impact := end.RiskScore
	switch end.Type {
	case NodeTypeDatabase:
		impact += 3.0
	case NodeTypeAPI:
		impact += 2.0
	}
	if end.FileSystemProfile != nil && len(end.FileSystemProfile.SensitiveFiles) > 0 {
		impact += 1.5
	}
	if impact > 10.0 {
		impact = 10.0
	}
	return impact
}

// identifyAttackVectors derives the concrete attacker techniques a path enables
// from the real properties of the nodes it crosses.
func (asa *AttackSurfaceAnalyzer) identifyAttackVectors(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) []*AttackVector {
	var vectors []*AttackVector
	seen := make(map[AttackVectorType]bool)

	add := func(t AttackVectorType, technique string, prob float64, impact ImpactLevel, prereq string) {
		if seen[t] {
			return
		}
		seen[t] = true
		v := &AttackVector{Type: t, Technique: technique, Probability: prob, Impact: impact}
		if prereq != "" {
			v.Prerequisites = []string{prereq}
		}
		vectors = append(vectors, v)
	}

	// The entry hop is, by construction, externally reachable.
	if len(path.Nodes) > 0 {
		if entry, ok := graph.Nodes[path.Nodes[0]]; ok {
			for _, p := range entry.ExposedPorts {
				if p.Public {
					add(AttackVectorTypeRemoteExploit, "Exploitation of a public-facing endpoint", 0.6, asa.scoreToImpact(entry.RiskScore), "Network reachability to exposed port")
					break
				}
			}
		}
	}

	// More than one hop means the attacker moves laterally through the cluster.
	if len(path.Nodes) > 1 {
		add(AttackVectorTypeLateralMovement, "Lateral movement across connected workloads", asa.calculatePathProbability(path, graph), ImpactLevelMedium, "Foothold on the entry node")
	}

	for _, id := range path.Nodes {
		n, ok := graph.Nodes[id]
		if !ok {
			continue
		}
		if n.Privileges != nil && (n.Privileges.Privileged || (n.Privileges.RunAsUser != nil && *n.Privileges.RunAsUser == 0) || n.Privileges.AllowPrivilegeEscalation) {
			add(AttackVectorTypePrivilegeEscalation, "Privilege escalation via over-privileged container", 0.5, ImpactLevelHigh, "Code execution inside the container")
		}
		if n.SyscallProfile != nil && len(n.SyscallProfile.RiskySyscalls) > 0 {
			add(AttackVectorTypePrivilegeEscalation, "Abuse of sensitive syscalls (e.g. ptrace/mount/module load)", 0.45, ImpactLevelHigh, "Access to a granted sensitive capability")
		}
		if n.FileSystemProfile != nil && len(n.FileSystemProfile.SensitiveFiles) > 0 {
			add(AttackVectorTypeCredentialAccess, "Reading secret/credential material mounted in the container", 0.55, ImpactLevelHigh, "Filesystem read access")
			add(AttackVectorTypeDataExfiltration, "Exfiltration of sensitive mounted data", 0.4, ImpactLevelHigh, "Outbound network access")
		}
	}

	return vectors
}

// generateMitigationSteps derives targeted remediation steps for a path from the
// weaknesses actually present on its nodes.
func (asa *AttackSurfaceAnalyzer) generateMitigationSteps(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) []string {
	var steps []string
	seen := make(map[string]bool)
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			steps = append(steps, s)
		}
	}

	if len(path.Nodes) > 1 {
		add("Restrict east-west traffic with NetworkPolicies to break this path")
	}
	for _, id := range path.Nodes {
		n, ok := graph.Nodes[id]
		if !ok {
			continue
		}
		if n.Privileges != nil && (n.Privileges.Privileged || (n.Privileges.RunAsUser != nil && *n.Privileges.RunAsUser == 0)) {
			add(fmt.Sprintf("Drop privileged/root execution on %s and run as a non-root user", n.Name))
		}
		if n.SyscallProfile != nil && len(n.SyscallProfile.RiskySyscalls) > 0 {
			add(fmt.Sprintf("Remove unneeded capabilities/sensitive syscalls from %s", n.Name))
		}
		if n.FileSystemProfile != nil {
			for _, p := range n.FileSystemProfile.WritablePaths {
				if p == "/" {
					add(fmt.Sprintf("Set readOnlyRootFilesystem on %s", n.Name))
					break
				}
			}
			if len(n.FileSystemProfile.SensitiveFiles) > 0 {
				add(fmt.Sprintf("Limit and encrypt secret mounts on %s", n.Name))
			}
		}
		for _, port := range n.ExposedPorts {
			if port.Public {
				add(fmt.Sprintf("Reduce the public exposure of %s", n.Name))
				break
			}
		}
	}
	if len(steps) == 0 {
		add("Enable runtime security monitoring on the workloads along this path")
	}
	return steps
}

// calculatePriority ranks an exposure path for operator attention. It combines
// the path's real risk score with how reachable its endpoint is (shorter paths
// to the same risk are more urgent) and how many distinct attack vectors it
// unlocks: priority = riskScore * (1 + 0.15*len(vectors)) / (1 + 0.1*extraHops).
func (asa *AttackSurfaceAnalyzer) calculatePriority(exposurePath *ExposurePath) float64 {
	if exposurePath == nil {
		return 0
	}
	extraHops := float64(len(exposurePath.Path) - 2)
	if extraHops < 0 {
		extraHops = 0
	}
	vectorBoost := 1.0 + 0.15*float64(len(exposurePath.AttackVectors))
	reachability := 1.0 / (1.0 + 0.1*extraHops)
	return exposurePath.RiskScore * vectorBoost * reachability
}

// Recommendation generation methods
func (asa *AttackSurfaceAnalyzer) generateNodeRecommendations(node *AttackSurfaceNode) []*RecommendedAction {
	var recommendations []*RecommendedAction

	if node.Privileges != nil && node.Privileges.RunAsUser != nil && *node.Privileges.RunAsUser == 0 {
		recommendations = append(recommendations, &RecommendedAction{
			ID:          fmt.Sprintf("rec-root-%s", node.ID),
			Category:    "Security Configuration",
			Priority:    "High",
			Title:       "Remove root privileges",
			Description: fmt.Sprintf("Container %s is running as root user", node.Name),
			Impact:      "Reduces container escape risk",
			Effort:      "Low",
		})
	}

	if len(node.ExposedPorts) > 0 {
		hasPublic := false
		for _, port := range node.ExposedPorts {
			if port.Public {
				hasPublic = true
				break
			}
		}
		if hasPublic {
			recommendations = append(recommendations, &RecommendedAction{
				ID:          fmt.Sprintf("rec-exposure-%s", node.ID),
				Category:    "Network Security",
				Priority:    "High",
				Title:       "Review external exposure",
				Description: fmt.Sprintf("Service %s has publicly exposed ports", node.Name),
				Impact:      "Reduces attack surface",
				Effort:      "Medium",
			})
		}
	}

	return recommendations
}

func (asa *AttackSurfaceAnalyzer) generatePathRecommendations(criticalPath *CriticalPath) []*RecommendedAction {
	// The recommendation priority tracks the path's real, computed criticality
	// band rather than a fixed "Critical".
	priority := string(asa.riskToCriticality(criticalPath.RiskScore))
	hops := len(criticalPath.Steps)
	entry, target := "entry", "target"
	if hops > 0 {
		entry = criticalPath.Steps[0]
		target = criticalPath.Steps[hops-1]
	}
	return []*RecommendedAction{
		{
			ID:       fmt.Sprintf("rec-path-%s", criticalPath.ID),
			Category: "Network Segmentation",
			Priority: priority,
			Title:    "Segment the exposure path with NetworkPolicies",
			Description: fmt.Sprintf(
				"Exposure path from %s to %s (%d hops, risk %.1f, likelihood %.2f, impact %.1f) should be broken with network segmentation",
				entry, target, hops, criticalPath.RiskScore, criticalPath.Likelihood, criticalPath.Impact),
			Impact: "Blocks attacker traversal along this path",
			Effort: "High",
		},
	}
}

func (asa *AttackSurfaceAnalyzer) generateGeneralRecommendations(graph *ClusterAttackSurfaceGraph) []*RecommendedAction {
	return []*RecommendedAction{
		{
			ID:          "rec-general-monitoring",
			Category:    "Monitoring",
			Priority:    "Medium",
			Title:       "Enable security monitoring",
			Description: "Implement comprehensive security monitoring for the cluster",
			Impact:      "Improves detection capabilities",
			Effort:      "Medium",
		},
	}
}

// prioritizeRecommendations sorts recommendations in place so the highest-value
// actions come first. The rank is severity-dominant (Critical > High > Medium >
// Low) and, within the same severity, favours quick wins by ordering lower
// effort ahead of higher effort. The slice is mutated in place, so the caller's
// backing array reflects the new order.
func (asa *AttackSurfaceAnalyzer) prioritizeRecommendations(recommendations []*RecommendedAction) {
	sort.SliceStable(recommendations, func(i, j int) bool {
		pi := priorityRank(recommendations[i].Priority)
		pj := priorityRank(recommendations[j].Priority)
		if pi != pj {
			return pi > pj
		}
		// Same severity: cheaper (lower effort) first.
		return effortRank(recommendations[i].Effort) < effortRank(recommendations[j].Effort)
	})
	log.Log.Info("Prioritized recommendations", "count", len(recommendations))
}

// priorityRank maps a textual priority to a numeric weight (higher = more urgent).
func priorityRank(priority string) int {
	switch strings.ToLower(priority) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// effortRank maps a textual effort estimate to a numeric weight (lower = cheaper).
func effortRank(effort string) int {
	switch strings.ToLower(effort) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 2
	}
}

// Helper methods for container analysis
func (asa *AttackSurfaceAnalyzer) podBelongsToWorkload(pod *v1.Pod, workloadRef learner.WorkloadReference) bool {
	// Match by namespace plus either an app label or an owner reference.
	if pod.Namespace != workloadRef.Namespace {
		return false
	}

	// Check if pod has labels matching the workload
	for key, value := range pod.Labels {
		if key == "app" && value == workloadRef.Name {
			return true
		}
		if key == "app.kubernetes.io/name" && value == workloadRef.Name {
			return true
		}
	}

	// Check owner references
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == workloadRef.Kind && owner.Name == workloadRef.Name {
			return true
		}
	}

	return false
}

// analyzeContainerImage derives an image risk score from the concrete image
// reference. A digest-pinned image is the most trustworthy (immutable); a
// mutable or missing tag (":latest" or no tag) is the least, and an image
// pulled from an implicit public registry adds a small amount of supply-chain
// risk. The score is bounded to [0, 10].
func (asa *AttackSurfaceAnalyzer) analyzeContainerImage(image string) *ImageSecurityAnalysis {
	risk := 2.0 // pinned, well-qualified images start low

	digestPinned := strings.Contains(image, "@sha256:")
	tag := imageTag(image)
	switch {
	case digestPinned:
		// immutable reference, keep baseline
	case tag == "" || tag == "latest":
		risk += 3.0 // mutable/unpinned image
	default:
		risk += 1.0 // fixed tag but still mutable at the registry
	}

	// Implicit public registry (no registry host segment) adds supply-chain risk.
	if !digestPinned && !imageHasRegistryHost(image) {
		risk += 1.0
	}

	if risk > 10.0 {
		risk = 10.0
	}

	return &ImageSecurityAnalysis{
		BaseImage:       image,
		Vulnerabilities: []Vulnerability{},
		Layers:          []string{},
		ScanResults:     []ScanResult{},
		RiskScore:       risk,
	}
}

// analyzeRuntimeProfile reconstructs the container's runtime profile from its
// real spec (entrypoint, declared capabilities, listening ports, mounts).
func (asa *AttackSurfaceAnalyzer) analyzeRuntimeProfile(pod *v1.Pod, container *v1.Container) *RuntimeSecurityProfile {
	profile := &RuntimeSecurityProfile{
		ProcessList:    []string{},
		NetworkAccess:  []string{},
		FileAccess:     []string{},
		Capabilities:   []string{},
		SecurityEvents: []string{},
	}

	if len(container.Command) > 0 {
		profile.ProcessList = append(profile.ProcessList, container.Command[0])
	} else {
		profile.ProcessList = append(profile.ProcessList, container.Name)
	}

	for _, p := range container.Ports {
		profile.NetworkAccess = append(profile.NetworkAccess, fmt.Sprintf("%s/%d", strings.ToLower(string(p.Protocol)), p.ContainerPort))
	}

	for _, m := range container.VolumeMounts {
		profile.FileAccess = append(profile.FileAccess, m.MountPath)
	}

	if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
		for _, c := range container.SecurityContext.Capabilities.Add {
			profile.Capabilities = append(profile.Capabilities, string(c))
		}
	}

	return profile
}

// analyzeSyscallExposure computes the container's syscall exposure. When a
// learned/enforced policy exists it uses the real allowed/denied sets; otherwise
// it reconstructs the sensitive syscalls unlocked by the container's granted
// capabilities and privilege level. The exposure score scales with the breadth
// of the allowed set and, more heavily, with the number of sensitive syscalls.
func (asa *AttackSurfaceAnalyzer) analyzeSyscallExposure(pod *v1.Pod, container *v1.Container) *SyscallExposureAnalysis {
	analysis := &SyscallExposureAnalysis{}

	if gp := asa.resolvePodPolicy(pod); gp != nil && gp.SyscallPolicy != nil {
		for nr := range gp.SyscallPolicy.AllowedSyscalls {
			analysis.AllowedSyscalls = append(analysis.AllowedSyscalls, syscallName(nr))
			if isSensitiveSyscall(nr) {
				analysis.RiskySyscalls = append(analysis.RiskySyscalls, syscallName(nr))
			}
		}
		for nr := range gp.SyscallPolicy.DeniedSyscalls {
			analysis.BlockedSyscalls = append(analysis.BlockedSyscalls, syscallName(nr))
		}
	} else {
		risky := make(map[uint64]bool)
		privileged := container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, c := range container.SecurityContext.Capabilities.Add {
				for _, nr := range capabilitySyscalls[string(c)] {
					risky[nr] = true
				}
			}
			// Explicitly blocked syscalls: those a dropped capability would gate.
			for _, c := range container.SecurityContext.Capabilities.Drop {
				name := string(c)
				if name == "ALL" {
					for _, nr := range sensitiveSyscallList {
						analysis.BlockedSyscalls = append(analysis.BlockedSyscalls, syscallName(nr))
					}
				} else {
					for _, nr := range capabilitySyscalls[name] {
						analysis.BlockedSyscalls = append(analysis.BlockedSyscalls, syscallName(nr))
					}
				}
			}
		}
		if privileged {
			for _, nr := range sensitiveSyscallList {
				risky[nr] = true
			}
		}
		for _, nr := range baselineContainerSyscalls {
			analysis.AllowedSyscalls = append(analysis.AllowedSyscalls, syscallName(nr))
		}
		for nr := range risky {
			analysis.AllowedSyscalls = append(analysis.AllowedSyscalls, syscallName(nr))
			analysis.RiskySyscalls = append(analysis.RiskySyscalls, syscallName(nr))
		}
	}
	sort.Strings(analysis.AllowedSyscalls)
	sort.Strings(analysis.RiskySyscalls)
	sort.Strings(analysis.BlockedSyscalls)

	// Exposure score: breadth (allowed) plus weighted sensitivity, clamped 0..10.
	score := float64(len(analysis.AllowedSyscalls))*0.05 + float64(len(analysis.RiskySyscalls))*1.2
	if score > 10.0 {
		score = 10.0
	}
	analysis.ExposureScore = score
	return analysis
}

// analyzeContainerNetworkExposure derives the container's network exposure from
// its declared ports, marking ports the fronting service publishes as public,
// and scores it by port count and the presence of high-risk ports.
func (asa *AttackSurfaceAnalyzer) analyzeContainerNetworkExposure(pod *v1.Pod, container *v1.Container) *NetworkExposureAnalysis {
	var publicPorts, internalPorts []ExposedPort

	publicSet := asa.publicContainerPorts(pod)

	for _, port := range container.Ports {
		exposedPort := ExposedPort{
			Port:     port.ContainerPort,
			Protocol: string(port.Protocol),
			Service:  port.Name,
			Public:   publicSet[port.ContainerPort],
		}
		if exposedPort.Public {
			publicPorts = append(publicPorts, exposedPort)
		} else {
			internalPorts = append(internalPorts, exposedPort)
		}
	}

	// Score: public ports weigh more than internal, high-risk ports add extra.
	score := float64(len(publicPorts))*2.0 + float64(len(internalPorts))*0.5
	for _, p := range container.Ports {
		if asa.isHighRiskPort(p.ContainerPort) {
			score += 1.0
		}
	}
	if score > 10.0 {
		score = 10.0
	}

	return &NetworkExposureAnalysis{
		PublicPorts:     publicPorts,
		InternalPorts:   internalPorts,
		OutboundTraffic: []OutboundConnection{},
		NetworkPolicies: []AppliedNetworkPolicy{},
		ExposureScore:   score,
	}
}

// analyzeFilesystemExposure derives the container's filesystem exposure from its
// real volume mounts and root-filesystem posture, flagging secret/configmap and
// hostPath mounts as sensitive, and scores it accordingly.
func (asa *AttackSurfaceAnalyzer) analyzeFilesystemExposure(pod *v1.Pod, container *v1.Container) *FileSystemExposureAnalysis {
	var writablePaths []string
	var mountPoints []MountPoint
	var sensitiveFiles []SensitiveFile

	// Classify volumes referenced by this pod.
	volType := make(map[string]string)
	for _, v := range pod.Spec.Volumes {
		switch {
		case v.Secret != nil:
			volType[v.Name] = "secret"
		case v.ConfigMap != nil:
			volType[v.Name] = "config"
		case v.HostPath != nil:
			volType[v.Name] = "hostPath"
		}
	}

	roRoot := container.SecurityContext != nil &&
		container.SecurityContext.ReadOnlyRootFilesystem != nil &&
		*container.SecurityContext.ReadOnlyRootFilesystem
	if !roRoot {
		writablePaths = append(writablePaths, "/")
	}

	for _, mount := range container.VolumeMounts {
		t := volType[mount.Name]
		sensitive := t == "secret" || t == "config" || t == "hostPath"
		mountPoint := MountPoint{
			Source:      mount.Name,
			Destination: mount.MountPath,
			Type:        t,
			ReadOnly:    mount.ReadOnly,
			Sensitive:   sensitive,
		}
		mountPoints = append(mountPoints, mountPoint)

		if sensitive {
			risk := "medium"
			if t == "secret" || t == "hostPath" {
				risk = "high"
			}
			sensitiveFiles = append(sensitiveFiles, SensitiveFile{
				Path: mount.MountPath,
				Type: t,
				Risk: risk,
			})
		}
		if !mount.ReadOnly {
			writablePaths = append(writablePaths, mount.MountPath)
		}
	}

	// Score: writable surface plus weighted sensitive mounts; a writable root
	// filesystem is the single largest contributor.
	score := 0.0
	for _, p := range writablePaths {
		if p == "/" {
			score += 3.0
		} else {
			score += 0.5
		}
	}
	for _, sf := range sensitiveFiles {
		if sf.Risk == "high" {
			score += 1.5
		} else {
			score += 0.75
		}
	}
	if score > 10.0 {
		score = 10.0
	}

	return &FileSystemExposureAnalysis{
		SensitiveFiles: sensitiveFiles,
		WritablePaths:  writablePaths,
		MountPoints:    mountPoints,
		Permissions:    map[string]string{},
		ExposureScore:  score,
	}
}

// analyzeContainerSecurityContext scores the container's security context. A
// missing security context is not "medium risk by default" - it means the
// container runs with every insecure default (privilege escalation permitted,
// writable root filesystem, non-root not enforced), so it is scored exactly as
// an empty context would be rather than with a magic constant.
func (asa *AttackSurfaceAnalyzer) analyzeContainerSecurityContext(container *v1.Container) *SecurityContextAnalysis {
	analysis := &SecurityContextAnalysis{}

	sc := container.SecurityContext
	if sc != nil {
		analysis.RunAsUser = sc.RunAsUser
		analysis.RunAsGroup = sc.RunAsGroup
		analysis.RunAsNonRoot = sc.RunAsNonRoot
		analysis.ReadOnlyRootFilesystem = sc.ReadOnlyRootFilesystem
		analysis.AllowPrivilegeEscalation = sc.AllowPrivilegeEscalation
		analysis.Privileged = sc.Privileged
	}

	// Score against the insecure-default posture. A nil field is treated as the
	// Kubernetes default, which for these controls is the insecure value.
	riskScore := 0.0
	if sc != nil && sc.RunAsUser != nil && *sc.RunAsUser == 0 {
		riskScore += 3.0 // running as root (explicitly)
	}
	if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		riskScore += 1.0 // non-root not enforced
	}
	if sc != nil && sc.Privileged != nil && *sc.Privileged {
		riskScore += 4.0 // privileged container
	}
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		riskScore += 2.0 // privilege escalation allowed
	}
	if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		riskScore += 1.0 // writable root filesystem
	}
	if riskScore > 10.0 {
		riskScore = 10.0
	}
	analysis.RiskScore = riskScore

	return analysis
}

// analyzeResourceLimits scores a container's resource-exhaustion (DoS) exposure
// from which limits are actually set: no limits is the highest risk, both CPU and
// memory limits the lowest, and a partial set in between.
func (asa *AttackSurfaceAnalyzer) analyzeResourceLimits(container *v1.Container) *ResourceLimitsAnalysis {
	analysis := &ResourceLimitsAnalysis{}

	_, hasCPU := container.Resources.Limits["cpu"]
	_, hasMem := container.Resources.Limits["memory"]
	analysis.HasLimits = len(container.Resources.Limits) > 0

	switch {
	case hasCPU && hasMem:
		analysis.RiskScore = 1.0 // both bounded
	case hasCPU || hasMem:
		analysis.RiskScore = 2.5 // only one dimension bounded
	default:
		analysis.RiskScore = 4.0 // unbounded: DoS / noisy-neighbour exposure
	}

	if container.Resources.Limits != nil {
		if cpu, ok := container.Resources.Limits["cpu"]; ok {
			analysis.CPULimit = cpu.String()
		}
		if memory, ok := container.Resources.Limits["memory"]; ok {
			analysis.MemoryLimit = memory.String()
		}
	}

	if container.Resources.Requests != nil {
		if cpu, ok := container.Resources.Requests["cpu"]; ok {
			analysis.CPURequest = cpu.String()
		}
		if memory, ok := container.Resources.Requests["memory"]; ok {
			analysis.MemoryRequest = memory.String()
		}
	}

	return analysis
}

// analyzeContainerCapabilities scores the container's capability posture from
// the actual capabilities it adds and drops. The score starts at 0 and rises
// per risky capability added; dropping ALL capabilities is credited as the
// most-hardened baseline.
func (asa *AttackSurfaceAnalyzer) analyzeContainerCapabilities(container *v1.Container) *CapabilityAnalysis {
	analysis := &CapabilityAnalysis{
		Added:    []string{},
		Dropped:  []string{},
		Risky:    []string{},
		Required: []string{},
	}

	riskScore := 0.0
	droppedAll := false

	if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
		caps := container.SecurityContext.Capabilities

		for _, cap := range caps.Add {
			capStr := string(cap)
			analysis.Added = append(analysis.Added, capStr)
			if asa.isRiskyCapability(capStr) {
				analysis.Risky = append(analysis.Risky, capStr)
				riskScore += 1.5
			} else {
				riskScore += 0.3
			}
		}

		for _, cap := range caps.Drop {
			analysis.Dropped = append(analysis.Dropped, string(cap))
			if string(cap) == "ALL" {
				droppedAll = true
			}
		}
	}

	// A container that adds nothing and drops ALL is the hardened baseline.
	if droppedAll && len(analysis.Added) == 0 {
		riskScore = 0.0
	} else if !droppedAll && len(analysis.Added) == 0 {
		// Neither hardened nor extended: it keeps the runtime's default set.
		riskScore = 1.0
	}
	if riskScore > 10.0 {
		riskScore = 10.0
	}
	analysis.RiskScore = riskScore

	return analysis
}

func (asa *AttackSurfaceAnalyzer) isRiskyCapability(capability string) bool {
	riskyCapabilities := []string{
		"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
		"SYS_PACCT", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE",
		"SYS_TIME", "SYS_TTY_CONFIG", "DAC_OVERRIDE", "DAC_READ_SEARCH",
		"FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
		"LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST",
		"NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER", "SYS_CHROOT",
		"AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE", "BLOCK_SUSPEND",
		"CHOWN", "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD", "SETFCAP",
		"SYSLOG", "WAKE_ALARM",
	}

	for _, risky := range riskyCapabilities {
		if capability == risky {
			return true
		}
	}
	return false
}

// analyzePolicyCompliance checks the container's real security context against
// the Pod Security "restricted" baseline. Each control the container fails to
// satisfy is recorded as a violation and lowers the compliance score from a
// perfect 10 by a per-control weight; the container is compliant only when no
// control is violated.
func (asa *AttackSurfaceAnalyzer) analyzePolicyCompliance(pod *v1.Pod, container *v1.Container) *PolicyComplianceAnalysis {
	analysis := &PolicyComplianceAnalysis{
		Compliant:        true,
		PolicyViolations: []string{},
		RequiredPolicies: []string{"restricted-pod-security", "resource-limits", "capability-drop-all"},
		MissingPolicies:  []string{},
		ComplianceScore:  10.0,
	}

	sc := container.SecurityContext

	// privileged: -4
	if sc != nil && sc.Privileged != nil && *sc.Privileged {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "container runs in privileged mode")
		analysis.ComplianceScore -= 4.0
	}
	// runs as root / not enforced non-root: -2
	runsAsRoot := sc != nil && sc.RunAsUser != nil && *sc.RunAsUser == 0
	enforcesNonRoot := sc != nil && sc.RunAsNonRoot != nil && *sc.RunAsNonRoot
	if runsAsRoot || !enforcesNonRoot {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "container may run as root (runAsNonRoot not enforced)")
		analysis.ComplianceScore -= 2.0
	}
	// allowPrivilegeEscalation not disabled: -2
	if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "allowPrivilegeEscalation is not set to false")
		analysis.ComplianceScore -= 2.0
	}
	// writable root filesystem: -1
	if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "readOnlyRootFilesystem is not enabled")
		analysis.ComplianceScore -= 1.0
	}
	// capabilities not dropped to ALL: -1, plus any risky added capability: -1 each
	if !capabilitiesDropAll(sc) {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "capabilities are not dropped to ALL")
		analysis.MissingPolicies = append(analysis.MissingPolicies, "capability-drop-all")
		analysis.ComplianceScore -= 1.0
	}
	if sc != nil && sc.Capabilities != nil {
		for _, c := range sc.Capabilities.Add {
			if asa.isRiskyCapability(string(c)) {
				analysis.PolicyViolations = append(analysis.PolicyViolations, fmt.Sprintf("risky capability added: %s", string(c)))
				analysis.ComplianceScore -= 1.0
			}
		}
	}
	// no resource limits: -1
	if len(container.Resources.Limits) == 0 {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "no resource limits set")
		analysis.MissingPolicies = append(analysis.MissingPolicies, "resource-limits")
		analysis.ComplianceScore -= 1.0
	}
	// hostNetwork / hostPID / hostIPC at the pod level: -2 each
	if pod.Spec.HostNetwork {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "pod uses host network namespace")
		analysis.ComplianceScore -= 2.0
	}
	if pod.Spec.HostPID {
		analysis.PolicyViolations = append(analysis.PolicyViolations, "pod uses host PID namespace")
		analysis.ComplianceScore -= 2.0
	}

	if analysis.ComplianceScore < 0 {
		analysis.ComplianceScore = 0
	}
	analysis.Compliant = len(analysis.PolicyViolations) == 0
	return analysis
}

func (asa *AttackSurfaceAnalyzer) calculateContainerRisk(containerSurface *ContainerAttackSurface) float64 {
	riskScore := 0.0

	// Image risk
	if containerSurface.ImageAnalysis != nil {
		riskScore += containerSurface.ImageAnalysis.RiskScore * 0.2
	}

	// Security context risk
	if containerSurface.SecurityContext != nil {
		riskScore += containerSurface.SecurityContext.RiskScore * 0.3
	}

	// Capability risk
	if containerSurface.CapabilityAnalysis != nil {
		riskScore += containerSurface.CapabilityAnalysis.RiskScore * 0.2
	}

	// Resource limits risk
	if containerSurface.ResourceLimits != nil {
		riskScore += containerSurface.ResourceLimits.RiskScore * 0.1
	}

	// Network exposure risk
	if containerSurface.NetworkExposure != nil {
		riskScore += containerSurface.NetworkExposure.ExposureScore * 0.1
	}

	// Filesystem exposure risk
	if containerSurface.FileSystemExposure != nil {
		riskScore += containerSurface.FileSystemExposure.ExposureScore * 0.1
	}

	// Cap at 10.0
	if riskScore > 10.0 {
		riskScore = 10.0
	}

	return riskScore
}

func (asa *AttackSurfaceAnalyzer) generateRecommendationForRiskFactor(factor *RiskFactor) *SecurityRecommendation {
	recommendation := &SecurityRecommendation{
		ID:       fmt.Sprintf("rec-%s-%d", factor.Type, time.Now().Unix()),
		Category: string(factor.Type),
		Priority: string(factor.Severity),
	}

	switch factor.Type {
	case RiskFactorTypeExposedService:
		recommendation.Title = "Review service exposure"
		recommendation.Description = "Service has public exposure that may not be necessary"
		recommendation.Impact = "Reduces external attack surface"
		recommendation.Effort = "Medium"
		recommendation.Steps = []string{
			"Review service configuration",
			"Implement network policies",
			"Consider internal-only exposure",
		}
	case RiskFactorTypePrivilegedAccess:
		recommendation.Title = "Remove privileged access"
		recommendation.Description = "Container or service has unnecessary privileged access"
		recommendation.Impact = "Reduces privilege escalation risk"
		recommendation.Effort = "High"
		recommendation.Steps = []string{
			"Review required privileges",
			"Apply principle of least privilege",
			"Test with reduced privileges",
		}
	case RiskFactorTypeMisconfiguration:
		recommendation.Title = "Fix security misconfiguration"
		recommendation.Description = "Security configuration does not follow best practices"
		recommendation.Impact = "Improves security posture"
		recommendation.Effort = "Low"
		recommendation.Steps = []string{
			"Review security configuration",
			"Apply security best practices",
			"Implement monitoring",
		}
	default:
		recommendation.Title = "Address security risk"
		recommendation.Description = factor.Description
		recommendation.Impact = "Improves overall security"
		recommendation.Effort = "Medium"
		recommendation.Steps = []string{
			"Investigate risk factor",
			"Implement mitigation",
			"Monitor for improvements",
		}
	}

	return recommendation
}

// Additional helper methods for service and network policy analysis
func (asa *AttackSurfaceAnalyzer) serviceExposesWorkload(service *v1.Service, workloadRef learner.WorkloadReference) bool {
	// Check if service selector matches workload labels
	if service.Spec.Selector == nil {
		return false
	}

	// Match the service selector against the workload's app identity labels.
	for key, value := range service.Spec.Selector {
		if key == "app" && value == workloadRef.Name {
			return true
		}
		if key == "app.kubernetes.io/name" && value == workloadRef.Name {
			return true
		}
	}

	return false
}

func (asa *AttackSurfaceAnalyzer) calculateServiceExposureRisk(service *v1.Service) float64 {
	risk := 2.0 // Base risk

	// Increase risk for external exposure
	switch service.Spec.Type {
	case v1.ServiceTypeLoadBalancer:
		risk += 4.0
	case v1.ServiceTypeNodePort:
		risk += 3.0
	case v1.ServiceTypeClusterIP:
		risk += 1.0
	}

	// Increase risk for multiple exposed ports
	risk += float64(len(service.Spec.Ports)) * 0.5

	// Check for common high-risk ports
	for _, port := range service.Spec.Ports {
		if asa.isHighRiskPort(port.Port) {
			risk += 2.0
		}
	}

	// Cap at 10.0
	if risk > 10.0 {
		risk = 10.0
	}

	return risk
}

func (asa *AttackSurfaceAnalyzer) isHighRiskPort(port int32) bool {
	highRiskPorts := []int32{
		22,   // SSH
		23,   // Telnet
		135,  // RPC
		139,  // NetBIOS
		445,  // SMB
		1433, // SQL Server
		1521, // Oracle
		3306, // MySQL
		3389, // RDP
		5432, // PostgreSQL
		6379, // Redis
		8080, // HTTP Alt
		9200, // Elasticsearch
	}

	for _, riskPort := range highRiskPorts {
		if port == riskPort {
			return true
		}
	}
	return false
}

func (asa *AttackSurfaceAnalyzer) networkPolicyAppliesTo(policy *netv1.NetworkPolicy, workloadRef learner.WorkloadReference) bool {
	// Check if policy selector matches workload
	if policy.Spec.PodSelector.MatchLabels == nil {
		return true // Empty selector matches all pods
	}

	// Match the policy pod-selector against the workload's app identity labels.
	for key, value := range policy.Spec.PodSelector.MatchLabels {
		if key == "app" && value == workloadRef.Name {
			return true
		}
		if key == "app.kubernetes.io/name" && value == workloadRef.Name {
			return true
		}
	}

	return false
}

func (asa *AttackSurfaceAnalyzer) calculatePolicyEffectiveness(policy *netv1.NetworkPolicy) float64 {
	effectiveness := 5.0 // Base effectiveness

	// Increase effectiveness for specific rules
	if len(policy.Spec.Ingress) > 0 {
		effectiveness += 2.0
	}
	if len(policy.Spec.Egress) > 0 {
		effectiveness += 2.0
	}

	// Decrease effectiveness for overly permissive rules
	for _, rule := range policy.Spec.Ingress {
		if len(rule.From) == 0 && len(rule.Ports) == 0 {
			effectiveness -= 3.0 // Very permissive
		}
	}

	for _, rule := range policy.Spec.Egress {
		if len(rule.To) == 0 && len(rule.Ports) == 0 {
			effectiveness -= 3.0 // Very permissive
		}
	}

	// Cap between 0 and 10
	if effectiveness < 0 {
		effectiveness = 0
	}
	if effectiveness > 10.0 {
		effectiveness = 10.0
	}

	return effectiveness
}

// calculatePolicyCoverage measures how much of a workload's observed network
// attack surface a NetworkPolicy actually governs, on a 0..10 scale. Coverage is
// the mean of two real signals:
//
//	directionCoverage = (policyTypes the policy declares among Ingress/Egress) / 2
//	portCoverage      = fraction of the workload's observed container ports that
//	                    appear in the policy's port rules
//
// The observed surface is derived from the actual container ports of the pods
// that make up the workload; the enforced surface is the set of ports named in
// the policy's ingress/egress rules. An "allow-all" rule (no peers and no ports)
// asserts a direction is handled but constrains nothing, so it contributes to
// directionCoverage but not to portCoverage. Coverage collapses to 0 when the
// policy has no rules at all.
func (asa *AttackSurfaceAnalyzer) calculatePolicyCoverage(policy *netv1.NetworkPolicy, workloadRef learner.WorkloadReference) float64 {
	hasIngress := len(policy.Spec.Ingress) > 0
	hasEgress := len(policy.Spec.Egress) > 0
	if !hasIngress && !hasEgress {
		return 0.0
	}

	// Direction coverage: how many of the two traffic directions are addressed.
	// Prefer the declared PolicyTypes when present, else infer from the rules.
	directions := 0.0
	if len(policy.Spec.PolicyTypes) > 0 {
		for _, pt := range policy.Spec.PolicyTypes {
			if pt == netv1.PolicyTypeIngress || pt == netv1.PolicyTypeEgress {
				directions++
			}
		}
	} else {
		if hasIngress {
			directions++
		}
		if hasEgress {
			directions++
		}
	}
	directionCoverage := directions / 2.0
	if directionCoverage > 1.0 {
		directionCoverage = 1.0
	}

	// Observed surface: the distinct container ports the workload exposes.
	observedPorts := asa.observedWorkloadPorts(workloadRef)

	// Enforced surface: ports named across the policy's ingress/egress rules.
	enforcedPorts := make(map[int32]bool)
	collect := func(ports []netv1.NetworkPolicyPort) {
		for _, p := range ports {
			if p.Port != nil && p.Port.Type == 0 { // Int-typed port
				enforcedPorts[int32(p.Port.IntValue())] = true
			}
		}
	}
	for _, r := range policy.Spec.Ingress {
		collect(r.Ports)
	}
	for _, r := range policy.Spec.Egress {
		collect(r.Ports)
	}

	// Port coverage: fraction of observed ports that the policy actually names.
	var portCoverage float64
	switch {
	case len(observedPorts) == 0:
		// Nothing observed to constrain; direction coverage alone is meaningful.
		portCoverage = directionCoverage
	case len(enforcedPorts) == 0:
		// Rules exist but pin no specific ports (allow-all style): no port-level
		// restriction of the observed surface.
		portCoverage = 0.0
	default:
		matched := 0
		for p := range observedPorts {
			if enforcedPorts[p] {
				matched++
			}
		}
		portCoverage = float64(matched) / float64(len(observedPorts))
	}

	coverage := 10.0 * (0.5*directionCoverage + 0.5*portCoverage)
	if coverage > 10.0 {
		coverage = 10.0
	}
	if coverage < 0 {
		coverage = 0
	}
	return coverage
}

// observedWorkloadPorts returns the distinct container ports declared by the
// pods that belong to the given workload - the workload's observed network
// attack surface.
func (asa *AttackSurfaceAnalyzer) observedWorkloadPorts(workloadRef learner.WorkloadReference) map[int32]bool {
	ports := make(map[int32]bool)
	if asa.client == nil {
		return ports
	}
	pods := &v1.PodList{}
	if err := asa.client.List(context.Background(), pods, client.InNamespace(workloadRef.Namespace)); err != nil {
		return ports
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !asa.podBelongsToWorkload(pod, workloadRef) {
			continue
		}
		for _, c := range pod.Spec.Containers {
			for _, p := range c.Ports {
				ports[p.ContainerPort] = true
			}
		}
	}
	return ports
}

// Additional type definitions
type PathAnalysis struct {
	Nodes []string
}

// IsolationLevel is already defined earlier in the file

// Supporting type definitions
type NetworkTopology struct {
	Subnets       []*Subnet
	Gateways      []*Gateway
	Firewall      []*FirewallRule
	LoadBalancers []*LoadBalancer
}

type Subnet struct {
	CIDR      string
	Name      string
	Isolation IsolationLevel
	Workloads []string
}

type IsolationLevel string

const (
	IsolationNone     IsolationLevel = "None"
	IsolationPartial  IsolationLevel = "Partial"
	IsolationComplete IsolationLevel = "Complete"
)

type Gateway struct {
	Name      string
	Type      string
	Endpoints []string
	TLS       *TLSConfiguration
}

type TLSConfiguration struct {
	Enabled     bool
	Version     string
	CipherSuite []string
	Certificate *CertificateInfo
}

type CertificateInfo struct {
	Issuer    string
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
	KeySize   int
	Algorithm string
}

// ExposedPort represents a network port exposed by a container
type ExposedPort struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Public   bool   `json:"public"`
}

// ListeningService represents a service listening on a port
type ListeningService struct {
	Port        int32  `json:"port"`
	Protocol    string `json:"protocol"`
	ServiceName string `json:"serviceName"`
	ProcessName string `json:"processName"`
	PID         int32  `json:"pid"`
}

// OutboundConnection represents an outbound network connection
type OutboundConnection struct {
	DestinationIP   string    `json:"destinationIP"`
	DestinationPort int32     `json:"destinationPort"`
	Protocol        string    `json:"protocol"`
	Count           int       `json:"count"`
	LastSeen        time.Time `json:"lastSeen"`
}

// AppliedNetworkPolicy represents a network policy applied to a workload
type AppliedNetworkPolicy struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Rules     []string `json:"rules"`
	Ingress   bool     `json:"ingress"`
	Egress    bool     `json:"egress"`
}

// TLSAnalysis contains TLS/SSL configuration analysis
type TLSAnalysis struct {
	Enabled         bool             `json:"enabled"`
	Version         string           `json:"version"`
	CipherSuite     string           `json:"cipherSuite"`
	Certificate     *CertificateInfo `json:"certificate,omitempty"`
	Vulnerabilities []string         `json:"vulnerabilities"`
}

// MountPoint represents a filesystem mount point
type MountPoint struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Options     []string `json:"options"`
	ReadOnly    bool     `json:"readOnly"`
	Sensitive   bool     `json:"sensitive"`
}

// SensitiveFile represents a file with sensitive content
type SensitiveFile struct {
	Path        string `json:"path"`
	Type        string `json:"type"` // secret, config, credential, etc.
	Permissions string `json:"permissions"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	Risk        string `json:"risk"` // low, medium, high, critical
}

// VolumeSecurityAnalysis contains security analysis of mounted volumes
type VolumeSecurityAnalysis struct {
	HostMounts    []MountPoint      `json:"hostMounts"`
	SensitiveData []SensitiveFile   `json:"sensitiveData"`
	Permissions   map[string]string `json:"permissions"`
	RiskScore     float64           `json:"riskScore"`
}

// CapabilitySet represents Linux capabilities
type CapabilitySet struct {
	Effective   []string `json:"effective"`
	Permitted   []string `json:"permitted"`
	Inheritable []string `json:"inheritable"`
	Bounding    []string `json:"bounding"`
	Ambient     []string `json:"ambient"`
}

// TopologyAnalysis represents network topology analysis results
type TopologyAnalysis struct {
	Subnets     []Subnet            `json:"subnets"`
	Gateways    []Gateway           `json:"gateways"`
	Connections []NetworkConnection `json:"connections"`
	Isolation   map[string]string   `json:"isolation"`
}

// NetworkConnection represents a network connection between components
type NetworkConnection struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        int32  `json:"port"`
	Encrypted   bool   `json:"encrypted"`
}

// PortRange represents a range of ports
type PortRange struct {
	Start int32 `json:"start"`
	End   int32 `json:"end"`
}

// TrafficMetrics represents network traffic metrics
type TrafficMetrics struct {
	BytesIn     int64 `json:"bytesIn"`
	BytesOut    int64 `json:"bytesOut"`
	PacketsIn   int64 `json:"packetsIn"`
	PacketsOut  int64 `json:"packetsOut"`
	Connections int32 `json:"connections"`
}

// ConnectionPattern represents network connection patterns
type ConnectionPattern struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Frequency   int    `json:"frequency"`
	Protocol    string `json:"protocol"`
	Encrypted   bool   `json:"encrypted"`
}

// SecurityProperties represents security properties of a connection
type SecurityProperties struct {
	Encrypted     bool     `json:"encrypted"`
	Authenticated bool     `json:"authenticated"`
	Protocols     []string `json:"protocols"`
	Certificates  []string `json:"certificates"`
}

// RiskTrends represents risk trends over time
type RiskTrends struct {
	Historical []RiskDataPoint `json:"historical"`
	Current    float64         `json:"current"`
	Predicted  []RiskDataPoint `json:"predicted"`
	Trend      string          `json:"trend"` // increasing, decreasing, stable
}

// RiskDataPoint represents a single risk measurement
type RiskDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Factors   []string  `json:"factors"`
}

// ClusterRiskProfile represents the overall cluster risk profile
type ClusterRiskProfile struct {
	OverallScore float64            `json:"overallScore"`
	Categories   map[string]float64 `json:"categories"`
	TopRisks     []string           `json:"topRisks"`
	Trends       *RiskTrends        `json:"trends"`
}

// MitigationAction represents an action to mitigate risk
type MitigationAction struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Effort      string    `json:"effort"`
	Impact      float64   `json:"impact"`
	Status      string    `json:"status"`
	DueDate     time.Time `json:"dueDate"`
}

// RemediationGuidance provides guidance on how to fix issues
type RemediationGuidance struct {
	Issue      string             `json:"issue"`
	Severity   string             `json:"severity"`
	Steps      []string           `json:"steps"`
	References []string           `json:"references"`
	Actions    []MitigationAction `json:"actions"`
	Timeline   string             `json:"timeline"`
}

// Countermeasure represents a security countermeasure
type Countermeasure struct {
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Description   string  `json:"description"`
	Implemented   bool    `json:"implemented"`
	Effectiveness float64 `json:"effectiveness"`
	Cost          string  `json:"cost"`
}

// CriticalPath represents a critical attack path in the system
type CriticalPath struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	RiskScore   float64  `json:"riskScore"`
	Likelihood  float64  `json:"likelihood"`
	Impact      float64  `json:"impact"`
}

// WeakPoint represents a security weak point
type WeakPoint struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Location    string `json:"location"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Exploitable bool   `json:"exploitable"`
}

// RecommendedAction represents a recommended security action
type RecommendedAction struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Effort      string `json:"effort"`
	Impact      string `json:"impact"`
}

// ImageSecurityAnalysis contains security analysis of container images
type ImageSecurityAnalysis struct {
	BaseImage       string          `json:"baseImage"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Layers          []string        `json:"layers"`
	ScanResults     []ScanResult    `json:"scanResults"`
	RiskScore       float64         `json:"riskScore"`
}

// RuntimeSecurityProfile contains runtime security profile information
type RuntimeSecurityProfile struct {
	ProcessList    []string `json:"processList"`
	NetworkAccess  []string `json:"networkAccess"`
	FileAccess     []string `json:"fileAccess"`
	Capabilities   []string `json:"capabilities"`
	SecurityEvents []string `json:"securityEvents"`
}

// SyscallExposureAnalysis contains syscall exposure analysis
type SyscallExposureAnalysis struct {
	AllowedSyscalls []string `json:"allowedSyscalls"`
	BlockedSyscalls []string `json:"blockedSyscalls"`
	RiskySyscalls   []string `json:"riskySyscalls"`
	UnusedSyscalls  []string `json:"unusedSyscalls"`
	ExposureScore   float64  `json:"exposureScore"`
}

// NetworkExposureAnalysis contains network exposure analysis
type NetworkExposureAnalysis struct {
	PublicPorts     []ExposedPort          `json:"publicPorts"`
	InternalPorts   []ExposedPort          `json:"internalPorts"`
	OutboundTraffic []OutboundConnection   `json:"outboundTraffic"`
	NetworkPolicies []AppliedNetworkPolicy `json:"networkPolicies"`
	ExposureScore   float64                `json:"exposureScore"`
}

// FileSystemExposureAnalysis contains filesystem exposure analysis
type FileSystemExposureAnalysis struct {
	SensitiveFiles []SensitiveFile   `json:"sensitiveFiles"`
	WritablePaths  []string          `json:"writablePaths"`
	MountPoints    []MountPoint      `json:"mountPoints"`
	Permissions    map[string]string `json:"permissions"`
	ExposureScore  float64           `json:"exposureScore"`
}

// SecurityContextAnalysis contains security context analysis
type SecurityContextAnalysis struct {
	RunAsUser                *int64            `json:"runAsUser,omitempty"`
	RunAsGroup               *int64            `json:"runAsGroup,omitempty"`
	RunAsNonRoot             *bool             `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem   *bool             `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool             `json:"allowPrivilegeEscalation,omitempty"`
	Privileged               *bool             `json:"privileged,omitempty"`
	Capabilities             *CapabilitySet    `json:"capabilities,omitempty"`
	SELinuxOptions           map[string]string `json:"selinuxOptions,omitempty"`
	WindowsOptions           map[string]string `json:"windowsOptions,omitempty"`
	RiskScore                float64           `json:"riskScore"`
}

// PodAttackSurface represents the attack surface of a pod
type PodAttackSurface struct {
	Name       string                   `json:"name"`
	Namespace  string                   `json:"namespace"`
	Containers []ContainerAttackSurface `json:"containers"`
	Network    *NetworkExposureAnalysis `json:"network"`
	RiskScore  float64                  `json:"riskScore"`
}

// ServiceExposure represents service exposure information
type ServiceExposure struct {
	Name         string        `json:"name"`
	Namespace    string        `json:"namespace"`
	Type         string        `json:"type"`
	Ports        []ExposedPort `json:"ports"`
	ExternalIP   string        `json:"externalIP,omitempty"`
	LoadBalancer bool          `json:"loadBalancer"`
	RiskScore    float64       `json:"riskScore"`
}

// NetworkPolicyAnalysis contains network policy analysis
type NetworkPolicyAnalysis struct {
	Name          string   `json:"name"`
	Namespace     string   `json:"namespace"`
	Applied       bool     `json:"applied"`
	IngressRules  []string `json:"ingressRules"`
	EgressRules   []string `json:"egressRules"`
	Effectiveness float64  `json:"effectiveness"`
	Coverage      float64  `json:"coverage"`
}

// RBACAnalysis contains RBAC analysis information
type RBACAnalysis struct {
	ServiceAccount string   `json:"serviceAccount"`
	Roles          []string `json:"roles"`
	ClusterRoles   []string `json:"clusterRoles"`
	Permissions    []string `json:"permissions"`
	RiskScore      float64  `json:"riskScore"`
	Privileged     bool     `json:"privileged"`
}

// RiskDistribution represents risk distribution across different categories
type RiskDistribution struct {
	Categories map[string]float64 `json:"categories"`
	Total      float64            `json:"total"`
	Critical   int                `json:"critical"`
	High       int                `json:"high"`
	Medium     int                `json:"medium"`
	Low        int                `json:"low"`
}

// ResourceLimitsAnalysis contains resource limits analysis
type ResourceLimitsAnalysis struct {
	CPURequest    string  `json:"cpuRequest,omitempty"`
	CPULimit      string  `json:"cpuLimit,omitempty"`
	MemoryRequest string  `json:"memoryRequest,omitempty"`
	MemoryLimit   string  `json:"memoryLimit,omitempty"`
	HasLimits     bool    `json:"hasLimits"`
	RiskScore     float64 `json:"riskScore"`
}

// CapabilityAnalysis contains capability analysis
type CapabilityAnalysis struct {
	Added     []string `json:"added"`
	Dropped   []string `json:"dropped"`
	Risky     []string `json:"risky"`
	Required  []string `json:"required"`
	RiskScore float64  `json:"riskScore"`
}

// PolicyComplianceAnalysis contains policy compliance analysis
type PolicyComplianceAnalysis struct {
	Compliant        bool     `json:"compliant"`
	PolicyViolations []string `json:"policyViolations"`
	RequiredPolicies []string `json:"requiredPolicies"`
	MissingPolicies  []string `json:"missingPolicies"`
	ComplianceScore  float64  `json:"complianceScore"`
}

// Defense represents a security defense mechanism
type Defense struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Active        bool     `json:"active"`
	Effectiveness float64  `json:"effectiveness"`
	Coverage      []string `json:"coverage"`
	Gaps          []string `json:"gaps"`
}

// ScanSummary provides a summary of security scans
type ScanSummary struct {
	TotalScanned    int       `json:"totalScanned"`
	Vulnerabilities int       `json:"vulnerabilities"`
	Critical        int       `json:"critical"`
	High            int       `json:"high"`
	Medium          int       `json:"medium"`
	Low             int       `json:"low"`
	LastScan        time.Time `json:"lastScan"`
	RiskScore       float64   `json:"riskScore"`
}

// SystemCallMatrix represents a matrix of system call usage patterns
type SystemCallMatrix struct {
	Syscalls   []string                  `json:"syscalls"`
	Containers []string                  `json:"containers"`
	Usage      map[string]map[string]int `json:"usage"`
	RiskScores map[string]float64        `json:"riskScores"`
}

// ExposureAnalysis contains detailed exposure analysis
type ExposureAnalysis struct {
	TotalExposures  int                 `json:"totalExposures"`
	CriticalPaths   []CriticalPath      `json:"criticalPaths"`
	WeakPoints      []WeakPoint         `json:"weakPoints"`
	Recommendations []RecommendedAction `json:"recommendations"`
	RiskScore       float64             `json:"riskScore"`
}

// SecurityRecommendation contains security recommendations
type SecurityRecommendation struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Impact      string   `json:"impact"`
	Effort      string   `json:"effort"`
	Steps       []string `json:"steps"`
}

// ComplianceStatus represents compliance status information
type ComplianceStatus struct {
	Framework  string            `json:"framework"`
	Version    string            `json:"version"`
	Score      float64           `json:"score"`
	Compliant  bool              `json:"compliant"`
	Violations []string          `json:"violations"`
	Controls   map[string]string `json:"controls"`
}

// AggregatedVulnerabilities contains aggregated vulnerability information
type AggregatedVulnerabilities struct {
	Total      int             `json:"total"`
	BySeverity map[string]int  `json:"bySeverity"`
	ByType     map[string]int  `json:"byType"`
	Recent     []Vulnerability `json:"recent"`
	Trending   []string        `json:"trending"`
}

// ImageScanResult contains container image scan results
type ImageScanResult struct {
	ImageName       string          `json:"imageName"`
	Tag             string          `json:"tag"`
	ScanTime        time.Time       `json:"scanTime"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	RiskScore       float64         `json:"riskScore"`
}

// RuntimeScanResult contains runtime security scan results
type RuntimeScanResult struct {
	ContainerID      string    `json:"containerID"`
	PodName          string    `json:"podName"`
	Namespace        string    `json:"namespace"`
	ScanTime         time.Time `json:"scanTime"`
	SecurityEvents   []string  `json:"securityEvents"`
	PolicyViolations []string  `json:"policyViolations"`
	RiskScore        float64   `json:"riskScore"`
}

// VulnerabilityDatabase contains vulnerability database information
type VulnerabilityDatabase struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	LastUpdated time.Time `json:"lastUpdated"`
	TotalCVEs   int       `json:"totalCVEs"`
	Sources     []string  `json:"sources"`
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        string `json:"port"`
	Enabled     bool   `json:"enabled"`
}

// LoadBalancer represents a load balancer configuration
type LoadBalancer struct {
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	ExternalIP     string  `json:"externalIP"`
	InternalIP     string  `json:"internalIP"`
	Ports          []int32 `json:"ports"`
	HealthCheck    bool    `json:"healthCheck"`
	SSLTermination bool    `json:"sslTermination"`
}

// GrafanaExporter exports data to Grafana
type GrafanaExporter struct {
	URL     string `json:"url"`
	APIKey  string `json:"apiKey"`
	Enabled bool   `json:"enabled"`
}

// DatadogExporter exports data to Datadog
type DatadogExporter struct {
	APIKey  string `json:"apiKey"`
	AppKey  string `json:"appKey"`
	Enabled bool   `json:"enabled"`
}

// OTelExporter exports data using OpenTelemetry
type OTelExporter struct {
	Endpoint string            `json:"endpoint"`
	Headers  map[string]string `json:"headers"`
	Enabled  bool              `json:"enabled"`
}

// CustomExporter allows custom export configurations
type CustomExporter struct {
	Name     string            `json:"name"`
	Endpoint string            `json:"endpoint"`
	Config   map[string]string `json:"config"`
	Enabled  bool              `json:"enabled"`
}

// AttackChain represents a chain of attack steps
type AttackChain struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Steps      []string `json:"steps"`
	Likelihood float64  `json:"likelihood"`
	Impact     float64  `json:"impact"`
	RiskScore  float64  `json:"riskScore"`
}

// AssetInventory contains inventory of security assets
type AssetInventory struct {
	Containers      int `json:"containers"`
	Pods            int `json:"pods"`
	Services        int `json:"services"`
	NetworkPolicies int `json:"networkPolicies"`
	Secrets         int `json:"secrets"`
	ConfigMaps      int `json:"configMaps"`
}

// ThrustSurface represents trusted computing surface
type ThrustSurface struct {
	TrustedComponents   []string `json:"trustedComponents"`
	TrustBoundaries     []string `json:"trustBoundaries"`
	TrustLevel          float64  `json:"trustLevel"`
	VerificationMethods []string `json:"verificationMethods"`
}

// DefenseAnalysis contains analysis of defense mechanisms
type DefenseAnalysis struct {
	Active        []Defense `json:"active"`
	Passive       []Defense `json:"passive"`
	Missing       []string  `json:"missing"`
	Effectiveness float64   `json:"effectiveness"`
	Coverage      float64   `json:"coverage"`
}

// ResidualRiskAssessment contains residual risk assessment
type ResidualRiskAssessment struct {
	TotalRisk       float64                  `json:"totalRisk"`
	MitigatedRisk   float64                  `json:"mitigatedRisk"`
	ResidualRisk    float64                  `json:"residualRisk"`
	RiskFactors     []RiskFactor             `json:"riskFactors"`
	Recommendations []SecurityRecommendation `json:"recommendations"`
}

// Export method implementations
func (asa *AttackSurfaceAnalyzer) exportToGrafana(data *AttackSurfaceData) error {
	// Implementation would export data to Grafana dashboard
	// This would typically involve:
	// - Converting attack surface data to Grafana-compatible format
	// - Creating/updating dashboard panels
	// - Sending metrics to Grafana's API
	return nil
}

func (asa *AttackSurfaceAnalyzer) exportToDatadog(data *AttackSurfaceData) error {
	// Implementation would export data to Datadog
	// This would typically involve:
	// - Converting attack surface data to Datadog metrics
	// - Sending custom metrics via Datadog API
	// - Creating/updating dashboards and alerts
	return nil
}

func (asa *AttackSurfaceAnalyzer) exportToOTel(data *AttackSurfaceData) error {
	// Implementation would export data to OpenTelemetry
	// This would typically involve:
	// - Converting attack surface data to OTEL metrics/traces
	// - Publishing via OTEL collector
	// - Structured logging with attack surface context
	return nil
}

func (asa *AttackSurfaceAnalyzer) exportToCustom(data *AttackSurfaceData, exporter *CustomExporter) error {
	// Implementation would export data to custom endpoint
	// This would typically involve:
	// - Formatting data according to exporter config
	// - Making HTTP requests to custom endpoint
	// - Handling authentication and retry logic
	return nil
}

// ---------------------------------------------------------------------------
// Attack-surface computation helpers and lookup tables.
//
// The syscall numbers below are the Linux x86_64 ABI numbers. They back the
// capability->syscall reconstruction used when no learned/enforced policy is
// available, so that a pod's syscall attack surface is derived from what its
// declared capabilities actually unlock rather than from a fixed list.
// ---------------------------------------------------------------------------

// baselineContainerSyscalls is the set every ordinary container needs to run.
// It is the floor of the "allowed" surface; capability-gated syscalls widen it.
var baselineContainerSyscalls = []uint64{
	0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 21, 22, 23, 32, 35,
	39, 41, 42, 43, 44, 45, 49, 50, 56, 59, 60, 61, 72, 202, 217, 218, 231,
	232, 233, 257, 262, 273, 291,
}

// capabilitySyscalls maps a Linux capability (as spelled in a Kubernetes
// SecurityContext, i.e. without the "CAP_" prefix) to the sensitive syscalls it
// unlocks.
var capabilitySyscalls = map[string][]uint64{
	"SYS_PTRACE": {101, 310, 311},
	"SYS_ADMIN":  {165, 166, 155, 167, 168, 161, 308, 272, 321, 298, 246},
	"SYS_MODULE": {175, 176, 313},
	"SYS_BOOT":   {169, 246},
	"SYS_TIME":   {164, 227, 159},
	"SYS_RAWIO":  {172, 173},
	"SYS_CHROOT": {161},
	"SETUID":     {105, 117},
	"SETGID":     {106, 119},
}

// sensitiveSyscallList enumerates every syscall considered a security-relevant
// (escape/tamper) primitive. sensitiveSyscalls is its set form.
var sensitiveSyscallList = []uint64{
	101, 310, 311, 165, 166, 155, 167, 168, 161, 308, 272, 321, 298,
	175, 176, 313, 169, 246, 164, 227, 159, 172, 173, 105, 117, 106, 119,
	248, 250,
}

var sensitiveSyscalls = func() map[uint64]bool {
	m := make(map[uint64]bool, len(sensitiveSyscallList))
	for _, nr := range sensitiveSyscallList {
		m[nr] = true
	}
	return m
}()

// criticalSyscalls are the subset of sensitive syscalls that grant kernel-level
// or container-escape power (as opposed to merely elevated in-container power).
var criticalSyscalls = map[uint64]bool{
	101: true, 165: true, 155: true, 175: true, 176: true, 313: true,
	321: true, 169: true, 246: true, 172: true, 173: true, 308: true,
	272: true, 161: true,
}

// syscallNames maps the syscall numbers referenced by this analyzer to their
// canonical names for human-readable exposure reports.
var syscallNames = map[uint64]string{
	0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
	8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
	13: "rt_sigaction", 14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl",
	21: "access", 22: "pipe", 23: "select", 32: "dup", 35: "nanosleep",
	39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
	45: "recvfrom", 49: "bind", 50: "listen", 56: "clone", 59: "execve",
	60: "exit", 61: "wait4", 72: "fcntl", 105: "setuid", 106: "setgid",
	117: "setresuid", 119: "setresgid", 155: "pivot_root", 159: "adjtimex",
	161: "chroot", 164: "settimeofday", 165: "mount", 166: "umount2",
	167: "swapon", 168: "swapoff", 169: "reboot", 172: "iopl", 173: "ioperm",
	175: "init_module", 176: "delete_module", 202: "futex", 217: "getdents64",
	218: "set_tid_address", 227: "clock_settime", 231: "exit_group",
	232: "epoll_wait", 233: "epoll_ctl", 246: "kexec_load", 248: "add_key",
	250: "keyctl", 257: "openat", 262: "newfstatat", 272: "unshare",
	273: "set_robust_list", 291: "epoll_create1", 298: "perf_event_open",
	308: "setns", 310: "process_vm_readv", 311: "process_vm_writev",
	313: "finit_module", 321: "bpf",
}

func syscallName(nr uint64) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

func isSensitiveSyscall(nr uint64) bool { return sensitiveSyscalls[nr] }

func isCriticalSyscall(nr uint64) bool { return criticalSyscalls[nr] }

// mapLearnerCriticality translates a learner criticality level into the
// visualization package's own criticality scale.
func mapLearnerCriticality(c learner.CriticalityLevel) CriticalityLevel {
	switch strings.ToLower(string(c)) {
	case "critical":
		return CriticalityCritical
	case "high":
		return CriticalityHigh
	case "medium":
		return CriticalityMedium
	case "low":
		return CriticalityLow
	default:
		return CriticalityInfo
	}
}

// appendUniqueString appends s to slice only if it is not already present.
func appendUniqueString(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// stringsContains reports whether target appears in slice.
func stringsContains(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// imageTag extracts the tag from a container image reference, or "" if the
// reference is digest-pinned or untagged.
func imageTag(image string) string {
	if strings.Contains(image, "@") {
		return ""
	}
	// Strip any registry host:port before looking for the tag separator so that
	// the port colon is not mistaken for a tag.
	name := image
	if i := strings.LastIndex(name, "/"); i >= 0 {
		if j := strings.LastIndex(name[i+1:], ":"); j >= 0 {
			return name[i+1+j+1:]
		}
		return ""
	}
	if j := strings.LastIndex(name, ":"); j >= 0 {
		return name[j+1:]
	}
	return ""
}

// imageHasRegistryHost reports whether the image reference names an explicit
// registry host (contains a "/" whose first segment looks like a host).
func imageHasRegistryHost(image string) bool {
	i := strings.Index(image, "/")
	if i < 0 {
		return false
	}
	first := image[:i]
	return strings.ContainsAny(first, ".:") || first == "localhost"
}

// capabilitiesDropAll reports whether the security context drops all Linux
// capabilities.
func capabilitiesDropAll(sc *v1.SecurityContext) bool {
	if sc == nil || sc.Capabilities == nil {
		return false
	}
	for _, c := range sc.Capabilities.Drop {
		if string(c) == "ALL" {
			return true
		}
	}
	return false
}

// tokenAutomounted reports whether the pod's service-account token is mounted
// into its containers. Kubernetes defaults this to true when unset.
func tokenAutomounted(pod *v1.Pod) bool {
	if pod == nil {
		return true
	}
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	return true
}

// scoreToImpact maps a 0..10 risk score to an impact level using the configured
// thresholds.
func (asa *AttackSurfaceAnalyzer) scoreToImpact(score float64) ImpactLevel {
	switch asa.riskToCriticality(score) {
	case CriticalityCritical:
		return ImpactLevelCritical
	case CriticalityHigh:
		return ImpactLevelHigh
	case CriticalityMedium:
		return ImpactLevelMedium
	default:
		return ImpactLevelLow
	}
}

// scoreToLikelihood maps a 0..10 risk score to a likelihood level.
func (asa *AttackSurfaceAnalyzer) scoreToLikelihood(score float64) LikelihoodLevel {
	switch {
	case score >= asa.highRiskThreshold():
		return LikelihoodLevelHigh
	case asa.riskThresholds != nil && score >= asa.riskThresholds.Medium:
		return LikelihoodLevelMedium
	default:
		return LikelihoodLevelLow
	}
}

// highRiskThreshold returns the configured High risk threshold (default 7.0).
func (asa *AttackSurfaceAnalyzer) highRiskThreshold() float64 {
	if asa.riskThresholds != nil {
		return asa.riskThresholds.High
	}
	return 7.0
}

// classifyExposureType infers the dominant exposure type of a path from the real
// properties of the asset it reaches.
func (asa *AttackSurfaceAnalyzer) classifyExposureType(graph *ClusterAttackSurfaceGraph, endNodeID string) ExposureType {
	end, ok := graph.Nodes[endNodeID]
	if !ok {
		return ExposureTypeNetworkIngress
	}
	if end.Privileges != nil && (end.Privileges.Privileged ||
		(end.Privileges.RunAsUser != nil && *end.Privileges.RunAsUser == 0) ||
		end.Privileges.AllowPrivilegeEscalation) {
		return ExposureTypePrivilegeEscalation
	}
	if end.FileSystemProfile != nil && len(end.FileSystemProfile.SensitiveFiles) > 0 {
		return ExposureTypeDataAccess
	}
	if end.Type == NodeTypeDatabase || end.Type == NodeTypeAPI {
		return ExposureTypeDataAccess
	}
	return ExposureTypeLateralMovement
}

// pathEdgeRisk sums the risk contributions of the edges traversed along a path.
func (asa *AttackSurfaceAnalyzer) pathEdgeRisk(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) float64 {
	var sum float64
	for i := 0; i+1 < len(path.Nodes); i++ {
		edgeID := fmt.Sprintf("%s->%s", path.Nodes[i], path.Nodes[i+1])
		if e, ok := graph.Edges[edgeID]; ok {
			sum += e.RiskContribution
		}
	}
	return sum
}

// pathDefenses expresses the mitigation steps for a path as recommended (not yet
// active) defenses.
func (asa *AttackSurfaceAnalyzer) pathDefenses(path *PathAnalysis, graph *ClusterAttackSurfaceGraph) []*Defense {
	var defenses []*Defense
	for _, step := range asa.generateMitigationSteps(path, graph) {
		defenses = append(defenses, &Defense{
			Name:   step,
			Type:   "Mitigation",
			Active: false,
		})
	}
	return defenses
}

// publicContainerPorts returns the set of container ports fronted by a service
// of type NodePort or LoadBalancer, i.e. the ports that are actually externally
// reachable.
func (asa *AttackSurfaceAnalyzer) publicContainerPorts(pod *v1.Pod) map[int32]bool {
	public := make(map[int32]bool)
	if asa.client == nil || pod == nil {
		return public
	}
	services := &v1.ServiceList{}
	if err := asa.client.List(context.Background(), services, client.InNamespace(pod.Namespace)); err != nil {
		return public
	}
	for i := range services.Items {
		svc := &services.Items[i]
		if svc.Spec.Type != v1.ServiceTypeNodePort && svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !asa.podMatchesSelector(pod, svc.Spec.Selector) {
			continue
		}
		for _, sp := range svc.Spec.Ports {
			// TargetPort resolves to a container port; when it is an int use it,
			// otherwise fall back to the service port number.
			if sp.TargetPort.Type == 0 && sp.TargetPort.IntVal != 0 {
				public[sp.TargetPort.IntVal] = true
			} else {
				public[sp.Port] = true
			}
		}
	}
	return public
}
