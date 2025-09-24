package policies

import (
	"time"

	"github.com/obsernetics/pahlevan/pkg/learner"
)

// Note: Self-healing types are defined in their respective implementation files:
// - SelfHealingManager: defined in self_healing.go
// - SelfHealingState: defined in enforcement_engine.go
// - RollbackAction: defined in lifecycle_manager.go
// - RollbackActionType: defined in self_healing.go
// - RollbackCondition: defined in self_healing.go
// - EmergencyAction: defined in self_healing.go

type SelfHealingMetrics struct {
	TotalRollbacks      int
	SuccessfulRollbacks int
	FailedRollbacks     int
	AverageRecoveryTime time.Duration
	LastRecoveryTime    time.Time
}

// Attack surface analysis types
type AttackSurfaceAnalyzer struct {
	riskFactors          map[RiskType]*RiskFactor
	mitigationStrategies map[MitigationType]*MitigationStrategy
}

type AttackSurfaceAnalysis struct {
	ContainerID            string
	TotalRiskScore         float64
	RiskFactors            []*RiskFactor
	Dimensions             []*AttackSurfaceDimension
	RecommendedMitigations []*MitigationStrategy
	ComplianceResults      []*ComplianceResult
	ThreatVectors          []*ThreatVector
}

type RiskFactor struct {
	Type        RiskType
	Severity    RiskSeverity
	Impact      float64
	Likelihood  float64
	Description string
	Evidence    []string
}

type RiskType string

const (
	RiskTypePrivilegedAccess RiskType = "PrivilegedAccess"
	RiskTypeNetworkExposure  RiskType = "NetworkExposure"
	RiskTypeFileAccess       RiskType = "FileAccess"
	RiskTypeProcessElevation RiskType = "ProcessElevation"
)

type RiskSeverity string

const (
	RiskSeverityLow      RiskSeverity = "Low"
	RiskSeverityMedium   RiskSeverity = "Medium"
	RiskSeverityHigh     RiskSeverity = "High"
	RiskSeverityCritical RiskSeverity = "Critical"
)

type AttackSurfaceDimension struct {
	Name        string
	Weight      float64
	RiskFactors []*RiskFactor
}

type MitigationStrategy struct {
	Type            MitigationType
	TargetRiskTypes []RiskType
	Effectiveness   float64
	Priority        MitigationPriority
	Implementation  string
	Cost            float64
}

type MitigationType string

const (
	MitigationTypeNetworkPolicy MitigationType = "NetworkPolicy"
	MitigationTypeSyscallFilter MitigationType = "SyscallFilter"
	MitigationTypeFilePolicy    MitigationType = "FilePolicy"
)

type MitigationPriority string

const (
	MitigationPriorityLow      MitigationPriority = "Low"
	MitigationPriorityMedium   MitigationPriority = "Medium"
	MitigationPriorityHigh     MitigationPriority = "High"
	MitigationPriorityCritical MitigationPriority = "Critical"
)

type ThreatVector struct {
	Type         ThreatVectorType
	Likelihood   float64
	Impact       float64
	Complexity   ThreatComplexity
	Prerequisites []string
}

type ThreatVectorType string

const (
	ThreatVectorPrivilegeEscalation ThreatVectorType = "PrivilegeEscalation"
	ThreatVectorDataExfiltration    ThreatVectorType = "DataExfiltration"
	ThreatVectorLateralMovement     ThreatVectorType = "LateralMovement"
)

type ThreatComplexity string

const (
	ThreatComplexityLow    ThreatComplexity = "Low"
	ThreatComplexityMedium ThreatComplexity = "Medium"
	ThreatComplexityHigh   ThreatComplexity = "High"
)

type ComplianceFramework struct {
	Name     string
	Version  string
	Controls []*ComplianceControl
}

type ComplianceControl struct {
	ID          string
	Title       string
	Description string
	Level       ComplianceLevel
	Automated   bool
}

type ComplianceLevel string

const (
	ComplianceLevelLevel1 ComplianceLevel = "Level1"
	ComplianceLevelLevel2 ComplianceLevel = "Level2"
)

type ComplianceResult struct {
	Framework       string
	OverallCompliant bool
	PassedControls  []*ComplianceControl
	FailedControls  []*ComplianceControl
}

// Note: Core policy types are defined in their respective implementation files:
// - ContainerPolicyState: defined in enforcement_engine.go
// - GlobalEnforcementConfig: defined in enforcement_engine.go
// - EnforcementAction: defined in enforcement_engine.go
// - ActionType: defined in enforcement_engine.go
// - ActionPriority: defined in enforcement_engine.go

// Note: Policy implementation types are defined in enforcement_engine.go:
// - GeneratedPolicy, SyscallEnforcementPolicy, NetworkEnforcementPolicy, FileEnforcementPolicy
// - SyscallRule, NetworkRule, FileRule, PortRule
// - PathPattern, AccessModeRule, SizeRestriction, RuleCondition, RateLimit
// - PolicyAction, PolicyViolation, ViolationType, ViolationSeverity
// - EnforcementStatistics, EnforcementMode, WorkloadLifecyclePhase

// Note: Constructor functions and methods are defined in their respective implementation files:
// - NewSelfHealingManager: defined in self_healing.go
// - NewAttackSurfaceAnalyzer: defined in attack_surface_analyzer.go (if exists)
// - All methods are defined alongside their type definitions

// Constructor for AttackSurfaceAnalyzer (only defined in this file)
func NewAttackSurfaceAnalyzer() *AttackSurfaceAnalyzer {
	return &AttackSurfaceAnalyzer{
		riskFactors:          make(map[RiskType]*RiskFactor),
		mitigationStrategies: make(map[MitigationType]*MitigationStrategy),
	}
}

// Note: All other methods are defined in their respective implementation files alongside the types

func (shm *SelfHealingMetrics) UpdateSuccess(recoveryTime time.Duration) {
	shm.TotalRollbacks++
	shm.SuccessfulRollbacks++

	// Update average recovery time
	if shm.SuccessfulRollbacks == 1 {
		shm.AverageRecoveryTime = recoveryTime
	} else {
		total := shm.AverageRecoveryTime * time.Duration(shm.SuccessfulRollbacks-1)
		shm.AverageRecoveryTime = (total + recoveryTime) / time.Duration(shm.SuccessfulRollbacks)
	}

	shm.LastRecoveryTime = time.Now()
}

func (shm *SelfHealingMetrics) UpdateFailure() {
	shm.TotalRollbacks++
	shm.FailedRollbacks++
}

func (shm *SelfHealingMetrics) SuccessRate() float64 {
	if shm.TotalRollbacks == 0 {
		return 0.0
	}
	return float64(shm.SuccessfulRollbacks) / float64(shm.TotalRollbacks)
}

func (asa *AttackSurfaceAnalyzer) AnalyzeContainer(profile *learner.LearningProfile) *AttackSurfaceAnalysis {
	analysis := &AttackSurfaceAnalysis{
		ContainerID: profile.ContainerID,
		RiskFactors: make([]*RiskFactor, 0),
		Dimensions:  make([]*AttackSurfaceDimension, 0),
	}

	// Analyze syscalls for privileged access
	for _, stats := range profile.ObservedSyscalls {
		if stats.SyscallNumber == 136 { // setuid
			risk := &RiskFactor{
				Type:        RiskTypePrivilegedAccess,
				Severity:    RiskSeverityHigh,
				Impact:      8.5,
				Likelihood:  0.7,
				Description: "Container uses setuid syscall",
			}
			analysis.RiskFactors = append(analysis.RiskFactors, risk)
		}
	}

	// Analyze network connections
	if len(profile.NetworkConnections) > 0 {
		risk := &RiskFactor{
			Type:        RiskTypeNetworkExposure,
			Severity:    RiskSeverityMedium,
			Impact:      6.0,
			Likelihood:  0.5,
			Description: "Container has network exposure",
		}
		analysis.RiskFactors = append(analysis.RiskFactors, risk)
	}

	// Create attack surface dimensions
	if len(analysis.RiskFactors) > 0 {
		dimensions := make(map[RiskType][]*RiskFactor)
		for _, factor := range analysis.RiskFactors {
			dimensions[factor.Type] = append(dimensions[factor.Type], factor)
		}

		for riskType, factors := range dimensions {
			dimension := &AttackSurfaceDimension{
				Name:        string(riskType),
				Weight:      1.0,
				RiskFactors: factors,
			}
			analysis.Dimensions = append(analysis.Dimensions, dimension)
		}
	}

	// Calculate total risk score
	totalScore := 0.0
	for _, factor := range analysis.RiskFactors {
		totalScore += factor.CalculateScore()
	}
	analysis.TotalRiskScore = totalScore

	return analysis
}

func (rf *RiskFactor) CalculateScore() float64 {
	return rf.Impact * rf.Likelihood
}

func (asd *AttackSurfaceDimension) CalculateScore() float64 {
	if len(asd.RiskFactors) == 0 {
		return 0.0
	}

	total := 0.0
	for _, factor := range asd.RiskFactors {
		total += factor.CalculateScore()
	}
	return (total / float64(len(asd.RiskFactors))) * asd.Weight
}

func (ms *MitigationStrategy) IsApplicable(factor *RiskFactor) bool {
	for _, riskType := range ms.TargetRiskTypes {
		if riskType == factor.Type {
			return true
		}
	}
	return false
}

func (asa *AttackSurfaceAnalysis) GetHighRiskFactors() []*RiskFactor {
	var highRisk []*RiskFactor
	for _, factor := range asa.RiskFactors {
		if factor.Severity == RiskSeverityHigh || factor.Severity == RiskSeverityCritical {
			highRisk = append(highRisk, factor)
		}
	}
	return highRisk
}

func (asa *AttackSurfaceAnalysis) GetRecommendedMitigations() []*MitigationStrategy {
	return asa.RecommendedMitigations
}

func (tv *ThreatVector) CalculateRisk() float64 {
	complexityMultiplier := map[ThreatComplexity]float64{
		ThreatComplexityLow:    1.0,
		ThreatComplexityMedium: 0.7,
		ThreatComplexityHigh:   0.4,
	}

	multiplier := complexityMultiplier[tv.Complexity]
	return tv.Impact * tv.Likelihood * multiplier
}

func (cf *ComplianceFramework) CheckCompliance(analysis *AttackSurfaceAnalysis) *ComplianceResult {
	result := &ComplianceResult{
		Framework:      cf.Name,
		PassedControls: make([]*ComplianceControl, 0),
		FailedControls: make([]*ComplianceControl, 0),
	}

	// Check privileged access control
	hasPrivilegedRisk := false
	for _, factor := range analysis.RiskFactors {
		if factor.Type == RiskTypePrivilegedAccess {
			hasPrivilegedRisk = true
			break
		}
	}

	for _, control := range cf.Controls {
		if control.ID == "5.1.1" { // Privileged containers control
			if hasPrivilegedRisk {
				result.FailedControls = append(result.FailedControls, control)
			} else {
				result.PassedControls = append(result.PassedControls, control)
			}
		}
	}

	result.OverallCompliant = len(result.FailedControls) == 0
	return result
}