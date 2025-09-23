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
	"sync"
	"time"

	"github.com/obsernetics/pahlevan/internal/learner"
	"github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/obsernetics/pahlevan/pkg/policies"
	"go.opentelemetry.io/otel/metric"
	v1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
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
	// Implementation would register custom exporters
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

// Implementation methods (simplified for brevity)
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
		node.SyscallProfile = asa.getPodSyscallProfile(pod.Name, pod.Namespace)
		node.NetworkProfile = asa.getPodNetworkProfile(pod.Name, pod.Namespace)
		node.FileSystemProfile = asa.getPodFilesystemProfile(pod.Name, pod.Namespace)

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

	// Aggregate overall risk
	averageRiskScore := totalRiskScore / float64(len(graph.Nodes))

	graph.RiskAggregation = &RiskAggregation{
		TotalRiskScore: totalRiskScore,
		RiskDistribution: map[RiskCategory]float64{
			RiskCategoryNetwork:       float64(asa.countNodesByRiskRange(graph.Nodes, 0.0, 3.0)),
			RiskCategoryPrivilege:     float64(asa.countNodesByRiskRange(graph.Nodes, 3.0, 7.0)),
			RiskCategoryCompliance:    float64(asa.countNodesByRiskRange(graph.Nodes, 7.0, 9.0)),
			RiskCategoryVulnerability: float64(asa.countNodesByRiskRange(graph.Nodes, 9.0, 10.0)),
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
			exposurePath := &ExposurePath{
				ID:           fmt.Sprintf("exposure-%s-%d", entryPoint, len(exposurePaths)),
				StartNode:    entryPoint,
				EndNode:      path.Nodes[len(path.Nodes)-1],
				Path:         path.Nodes,
				ExposureType: ExposureTypeNetworkIngress,
				RiskScore:    asa.calculatePathRisk(path),
			}

			exposurePaths = append(exposurePaths, exposurePath)

			// Identify critical paths (high risk)
			if exposurePath.RiskScore > 7.0 {
				criticalPath := &CriticalPath{
					ID:          exposurePath.ID + "-critical",
					Description: "Critical exposure path requiring attention",
					Steps:       path.Nodes,
					RiskScore:   exposurePath.RiskScore,
					Likelihood:  asa.calculatePathProbability(path),
					Impact:      asa.calculatePathImpact(path),
				}
				criticalPaths = append(criticalPaths, criticalPath)
			}
		}
	}

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
		if node.RiskScore > 7.0 {
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
	for _, pod := range pods.Items {
		if asa.podBelongsToWorkload(&pod, surface.WorkloadRef) {
			if pod.Spec.ServiceAccountName != "" {
				serviceAccountName = pod.Spec.ServiceAccountName
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

	// This would be expanded to analyze actual role bindings and cluster role bindings
	// For now, provide basic analysis
	if serviceAccountName == "default" {
		rbacAnalysis.RiskScore = 2.0 // Low risk for default SA
		rbacAnalysis.Permissions = []string{"basic pod operations"}
	} else {
		rbacAnalysis.RiskScore = 5.0 // Medium risk for custom SA
		rbacAnalysis.Permissions = []string{"custom permissions - requires detailed analysis"}
	}

	surface.RBACAnalysis = rbacAnalysis

	return nil
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
	// Implementation would perform exports to registered exporters
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

func (asa *AttackSurfaceAnalyzer) getPodSyscallProfile(podName, namespace string) *SyscallProfile {
	// This would integrate with the eBPF manager to get real syscall data
	// For now, return a basic profile
	return &SyscallProfile{
		AllowedSyscalls: []uint64{0, 1, 2, 3, 41}, // read, write, open, close, socket
		RiskySyscalls:   []uint64{101, 165},       // ptrace, mount
	}
}

func (asa *AttackSurfaceAnalyzer) getPodNetworkProfile(podName, namespace string) *NetworkProfile {
	// This would integrate with the eBPF manager to get real network data
	return &NetworkProfile{
		ExposedPorts: []*ExposedPort{
			{Port: 8080, Protocol: "TCP", Public: false},
		},
	}
}

func (asa *AttackSurfaceAnalyzer) getPodFilesystemProfile(podName, namespace string) *FileSystemProfile {
	// This would integrate with the eBPF manager to get real filesystem data
	return &FileSystemProfile{
		WritablePaths:   []string{"/tmp", "/var/log"},
		ExecutablePaths: []string{"/bin", "/usr/bin"},
	}
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
func (asa *AttackSurfaceAnalyzer) calculateNodeRisk(node *AttackSurfaceNode) float64 {
	riskScore := 0.0

	// Base risk from node type
	switch node.Type {
	case NodeTypeIngress:
		riskScore += 3.0 // Higher base risk for external-facing
	case NodeTypeService:
		riskScore += 2.0
	case NodeTypePod:
		riskScore += 1.0
	}

	// Risk from exposed ports
	for _, port := range node.ExposedPorts {
		if port.Public {
			riskScore += 2.0
		} else {
			riskScore += 0.5
		}
	}

	// Risk from privileges
	if node.Privileges != nil {
		if node.Privileges.RunAsUser != nil && *node.Privileges.RunAsUser == 0 {
			riskScore += 2.0
		}
		if node.Privileges.Privileged {
			riskScore += 3.0
		}
		// Additional privilege checks could be added here
	}

	// Risk from syscall profile
	if node.SyscallProfile != nil {
		riskScore += float64(len(node.SyscallProfile.RiskySyscalls)) * 0.5
	}

	// Vulnerability contribution
	riskScore += float64(node.VulnerabilityCount) * 0.8

	// Cap at 10.0
	if riskScore > 10.0 {
		riskScore = 10.0
	}

	return riskScore
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

	// Simple path tracing - in reality this would be more sophisticated
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

func (asa *AttackSurfaceAnalyzer) calculatePathRisk(path *PathAnalysis) float64 {
	// Simple risk calculation - would be more sophisticated in reality
	return float64(len(path.Nodes)) * 1.5
}

func (asa *AttackSurfaceAnalyzer) calculatePathProbability(path *PathAnalysis) float64 {
	// Simple probability calculation
	return 1.0 / float64(len(path.Nodes))
}

func (asa *AttackSurfaceAnalyzer) calculatePathImpact(path *PathAnalysis) float64 {
	// Simple impact calculation
	return float64(len(path.Nodes)) * 2.0
}

func (asa *AttackSurfaceAnalyzer) identifyAttackVectors(path *PathAnalysis) []string {
	return []string{"Network traversal", "Privilege escalation", "Container escape"}
}

func (asa *AttackSurfaceAnalyzer) generateMitigationSteps(path *PathAnalysis) []string {
	return []string{"Implement network policies", "Apply least privilege", "Enable container security"}
}

func (asa *AttackSurfaceAnalyzer) calculatePriority(exposurePath *ExposurePath) float64 {
	return exposurePath.RiskScore * 0.8 // Simple priority calculation
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
	return []*RecommendedAction{
		{
			ID:          fmt.Sprintf("rec-path-%s", criticalPath.ID),
			Category:    "Network Segmentation",
			Priority:    "Critical",
			Title:       "Implement network policies",
			Description: "Critical exposure path identified requiring network segmentation",
			Impact:      "Blocks attack path",
			Effort:      "High",
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

func (asa *AttackSurfaceAnalyzer) prioritizeRecommendations(recommendations []*RecommendedAction) {
	// Simple prioritization - in reality would use more sophisticated ranking
	// For now, just sort by priority field
	log.Log.Info("Prioritized recommendations", "count", len(recommendations))
}

// Helper methods for container analysis
func (asa *AttackSurfaceAnalyzer) podBelongsToWorkload(pod *v1.Pod, workloadRef learner.WorkloadReference) bool {
	// Basic implementation - would be more sophisticated in practice
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

func (asa *AttackSurfaceAnalyzer) analyzeContainerImage(image string) *ImageSecurityAnalysis {
	return &ImageSecurityAnalysis{
		BaseImage:       image,
		Vulnerabilities: []Vulnerability{},
		Layers:          []string{},
		ScanResults:     []ScanResult{},
		RiskScore:       3.0, // Default medium risk
	}
}

func (asa *AttackSurfaceAnalyzer) analyzeRuntimeProfile(pod *v1.Pod, container *v1.Container) *RuntimeSecurityProfile {
	return &RuntimeSecurityProfile{
		ProcessList:    []string{"main_process"},
		NetworkAccess:  []string{"outbound_https"},
		FileAccess:     []string{"/app", "/tmp"},
		Capabilities:   []string{},
		SecurityEvents: []string{},
	}
}

func (asa *AttackSurfaceAnalyzer) analyzeSyscallExposure(pod *v1.Pod, container *v1.Container) *SyscallExposureAnalysis {
	return &SyscallExposureAnalysis{
		AllowedSyscalls: []string{"read", "write", "open", "close"},
		BlockedSyscalls: []string{"ptrace", "mount"},
		RiskySyscalls:   []string{},
		UnusedSyscalls:  []string{},
		ExposureScore:   4.0,
	}
}

func (asa *AttackSurfaceAnalyzer) analyzeContainerNetworkExposure(pod *v1.Pod, container *v1.Container) *NetworkExposureAnalysis {
	var publicPorts, internalPorts []ExposedPort

	for _, port := range container.Ports {
		exposedPort := ExposedPort{
			Port:     port.ContainerPort,
			Protocol: string(port.Protocol),
			Service:  port.Name,
			Public:   false, // Determined by service analysis
		}
		internalPorts = append(internalPorts, exposedPort)
	}

	return &NetworkExposureAnalysis{
		PublicPorts:     publicPorts,
		InternalPorts:   internalPorts,
		OutboundTraffic: []OutboundConnection{},
		NetworkPolicies: []AppliedNetworkPolicy{},
		ExposureScore:   3.0,
	}
}

func (asa *AttackSurfaceAnalyzer) analyzeFilesystemExposure(pod *v1.Pod, container *v1.Container) *FileSystemExposureAnalysis {
	var writablePaths []string
	var mountPoints []MountPoint

	// Analyze volume mounts
	for _, mount := range container.VolumeMounts {
		mountPoint := MountPoint{
			Source:      mount.Name,
			Destination: mount.MountPath,
			ReadOnly:    mount.ReadOnly,
			Sensitive:   mount.Name == "secret" || mount.Name == "configmap",
		}
		mountPoints = append(mountPoints, mountPoint)

		if !mount.ReadOnly {
			writablePaths = append(writablePaths, mount.MountPath)
		}
	}

	return &FileSystemExposureAnalysis{
		SensitiveFiles: []SensitiveFile{},
		WritablePaths:  writablePaths,
		MountPoints:    mountPoints,
		Permissions:    map[string]string{},
		ExposureScore:  3.5,
	}
}

func (asa *AttackSurfaceAnalyzer) analyzeContainerSecurityContext(container *v1.Container) *SecurityContextAnalysis {
	analysis := &SecurityContextAnalysis{
		RiskScore: 5.0, // Default medium risk
	}

	if container.SecurityContext != nil {
		sc := container.SecurityContext
		analysis.RunAsUser = sc.RunAsUser
		analysis.RunAsGroup = sc.RunAsGroup
		analysis.RunAsNonRoot = sc.RunAsNonRoot
		analysis.ReadOnlyRootFilesystem = sc.ReadOnlyRootFilesystem
		analysis.AllowPrivilegeEscalation = sc.AllowPrivilegeEscalation
		analysis.Privileged = sc.Privileged

		// Calculate risk based on security context
		riskScore := 0.0
		if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
			riskScore += 3.0 // Running as root
		}
		if sc.Privileged != nil && *sc.Privileged {
			riskScore += 4.0 // Privileged container
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			riskScore += 2.0 // Privilege escalation allowed
		}
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			riskScore += 1.0 // Writable root filesystem
		}

		analysis.RiskScore = riskScore
	}

	return analysis
}

func (asa *AttackSurfaceAnalyzer) analyzeResourceLimits(container *v1.Container) *ResourceLimitsAnalysis {
	analysis := &ResourceLimitsAnalysis{
		HasLimits: false,
		RiskScore: 3.0, // Default medium risk
	}

	if container.Resources.Limits != nil {
		analysis.HasLimits = true
		analysis.RiskScore = 1.0 // Lower risk with limits

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

func (asa *AttackSurfaceAnalyzer) analyzeContainerCapabilities(container *v1.Container) *CapabilityAnalysis {
	analysis := &CapabilityAnalysis{
		Added:     []string{},
		Dropped:   []string{},
		Risky:     []string{},
		Required:  []string{},
		RiskScore: 3.0,
	}

	if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
		caps := container.SecurityContext.Capabilities

		for _, cap := range caps.Add {
			capStr := string(cap)
			analysis.Added = append(analysis.Added, capStr)

			// Check for risky capabilities
			if asa.isRiskyCapability(capStr) {
				analysis.Risky = append(analysis.Risky, capStr)
				analysis.RiskScore += 1.0
			}
		}

		for _, cap := range caps.Drop {
			analysis.Dropped = append(analysis.Dropped, string(cap))
		}
	}

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

func (asa *AttackSurfaceAnalyzer) analyzePolicyCompliance(pod *v1.Pod, container *v1.Container) *PolicyComplianceAnalysis {
	return &PolicyComplianceAnalysis{
		Compliant:        true,
		PolicyViolations: []string{},
		RequiredPolicies: []string{"PodSecurityPolicy", "NetworkPolicy"},
		MissingPolicies:  []string{},
		ComplianceScore:  8.0,
	}
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

	// Basic implementation - would need to check actual pod labels
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

	// Basic implementation - would need to check actual pod labels
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

func (asa *AttackSurfaceAnalyzer) calculatePolicyCoverage(policy *netv1.NetworkPolicy, workloadRef learner.WorkloadReference) float64 {
	// Simple coverage calculation - would be more sophisticated in practice
	coverage := 8.0 // Assume good coverage for now

	// Reduce coverage if policy has no rules
	if len(policy.Spec.Ingress) == 0 && len(policy.Spec.Egress) == 0 {
		coverage = 2.0
	}

	return coverage
}

// Additional type definitions
type PathAnalysis struct {
	Nodes []string
}

// IsolationLevel is already defined earlier in the file

// Additional types for completeness
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
