package policies

import (
	"testing"
	"time"

	"github.com/obsernetics/pahlevan/pkg/learner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackSurfaceAnalyzer_NewAttackSurfaceAnalyzer(t *testing.T) {
	analyzer := NewAttackSurfaceAnalyzer()

	require.NotNil(t, analyzer)
	assert.NotNil(t, analyzer.riskFactors)
	assert.NotNil(t, analyzer.mitigationStrategies)
}

func TestAttackSurfaceAnalyzer_AnalyzeContainer(t *testing.T) {
	analyzer := NewAttackSurfaceAnalyzer()

	profile := &learner.LearningProfile{
		ContainerID: "test-container",
		ObservedSyscalls: map[uint64]*learner.SyscallStatistics{
			1: {SyscallNumber: 1, TotalCalls: 100, UniquePids: 1},
			2: {SyscallNumber: 2, TotalCalls: 50, UniquePids: 1},
		},
		NetworkConnections: []*learner.NetworkConnection{
			{
				Protocol:    "tcp",
				LocalPort:   8080,
				RemoteAddr:  "192.168.1.1",
				RemotePort:  80,
				State:       "ESTABLISHED",
				ProcessInfo: &learner.ProcessInfo{PID: 1234, Command: "nginx"},
			},
		},
		FileAccesses: []*learner.FileAccess{
			{
				Path:        "/tmp/test.txt",
				Mode:        "write",
				ProcessInfo: &learner.ProcessInfo{PID: 1234, Command: "nginx"},
				Timestamp:   time.Now(),
			},
		},
		ProcessHierarchy: []*learner.ProcessInfo{
			{PID: 1, PPID: 0, Command: "init", User: "root"},
			{PID: 1234, PPID: 1, Command: "nginx", User: "www-data"},
		},
	}

	analysis := analyzer.AnalyzeContainer(profile)

	require.NotNil(t, analysis)
	assert.Equal(t, "test-container", analysis.ContainerID)
	assert.True(t, analysis.TotalRiskScore >= 0)
	assert.NotEmpty(t, analysis.RiskFactors)
	assert.NotEmpty(t, analysis.Dimensions)
}

func TestRiskFactor_CalculateScore(t *testing.T) {
	tests := []struct {
		name       string
		factor     *RiskFactor
		minScore   float64
		maxScore   float64
	}{
		{
			name: "privileged container",
			factor: &RiskFactor{
				Type:        RiskTypePrivilegedAccess,
				Severity:    RiskSeverityHigh,
				Impact:      8.5,
				Likelihood:  0.7,
				Description: "Container runs with privileged access",
			},
			minScore: 5.0,
			maxScore: 10.0,
		},
		{
			name: "network exposure",
			factor: &RiskFactor{
				Type:        RiskTypeNetworkExposure,
				Severity:    RiskSeverityMedium,
				Impact:      6.0,
				Likelihood:  0.5,
				Description: "Container exposes network ports",
			},
			minScore: 0.0,
			maxScore: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.factor.CalculateScore()
			assert.GreaterOrEqual(t, score, tt.minScore)
			assert.LessOrEqual(t, score, tt.maxScore)
		})
	}
}

func TestAttackSurfaceDimension_CalculateScore(t *testing.T) {
	dimension := &AttackSurfaceDimension{
		Name:        "Network",
		Weight:      0.3,
		RiskFactors: []*RiskFactor{
			{
				Type:       RiskTypeNetworkExposure,
				Severity:   RiskSeverityHigh,
				Impact:     8.0,
				Likelihood: 0.8,
			},
			{
				Type:       RiskTypeNetworkExposure,
				Severity:   RiskSeverityMedium,
				Impact:     5.0,
				Likelihood: 0.6,
			},
		},
	}

	score := dimension.CalculateScore()
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 10.0)
}

func TestMitigationStrategy_IsApplicable(t *testing.T) {
	tests := []struct {
		name       string
		strategy   *MitigationStrategy
		factor     *RiskFactor
		applicable bool
	}{
		{
			name: "network policy for network risk",
			strategy: &MitigationStrategy{
				Type:            MitigationTypeNetworkPolicy,
				TargetRiskTypes: []RiskType{RiskTypeNetworkExposure},
				Effectiveness:   0.8,
			},
			factor: &RiskFactor{
				Type: RiskTypeNetworkExposure,
			},
			applicable: true,
		},
		{
			name: "syscall filter for file access risk",
			strategy: &MitigationStrategy{
				Type:            MitigationTypeSyscallFilter,
				TargetRiskTypes: []RiskType{RiskTypeFileAccess},
				Effectiveness:   0.7,
			},
			factor: &RiskFactor{
				Type: RiskTypeNetworkExposure,
			},
			applicable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applicable := tt.strategy.IsApplicable(tt.factor)
			assert.Equal(t, tt.applicable, applicable)
		})
	}
}

func TestAttackSurfaceAnalysis_GetHighRiskFactors(t *testing.T) {
	analysis := &AttackSurfaceAnalysis{
		ContainerID: "test-container",
		RiskFactors: []*RiskFactor{
			{
				Type:     RiskTypePrivilegedAccess,
				Severity: RiskSeverityHigh,
				Impact:   9.0,
			},
			{
				Type:     RiskTypeFileAccess,
				Severity: RiskSeverityMedium,
				Impact:   5.0,
			},
			{
				Type:     RiskTypeNetworkExposure,
				Severity: RiskSeverityHigh,
				Impact:   8.0,
			},
		},
	}

	highRiskFactors := analysis.GetHighRiskFactors()
	assert.Len(t, highRiskFactors, 2)

	for _, factor := range highRiskFactors {
		assert.Equal(t, RiskSeverityHigh, factor.Severity)
	}
}

func TestAttackSurfaceAnalysis_GetRecommendedMitigations(t *testing.T) {
	analysis := &AttackSurfaceAnalysis{
		ContainerID: "test-container",
		RiskFactors: []*RiskFactor{
			{
				Type:     RiskTypeNetworkExposure,
				Severity: RiskSeverityHigh,
				Impact:   8.0,
			},
		},
		RecommendedMitigations: []*MitigationStrategy{
			{
				Type:            MitigationTypeNetworkPolicy,
				TargetRiskTypes: []RiskType{RiskTypeNetworkExposure},
				Effectiveness:   0.8,
				Priority:        MitigationPriorityHigh,
			},
		},
	}

	mitigations := analysis.GetRecommendedMitigations()
	assert.Len(t, mitigations, 1)
	assert.Equal(t, MitigationTypeNetworkPolicy, mitigations[0].Type)
}

func TestThreatVector_CalculateRisk(t *testing.T) {
	vector := &ThreatVector{
		Type:         ThreatVectorPrivilegeEscalation,
		Likelihood:   0.7,
		Impact:       8.5,
		Complexity:   ThreatComplexityMedium,
		Prerequisites: []string{"container_privileged", "writable_host_mount"},
	}

	risk := vector.CalculateRisk()
	assert.GreaterOrEqual(t, risk, 0.0)
	assert.LessOrEqual(t, risk, 10.0)
}

func TestComplianceFramework_CheckCompliance(t *testing.T) {
	framework := &ComplianceFramework{
		Name:     "CIS Kubernetes Benchmark",
		Version:  "1.6.0",
		Controls: []*ComplianceControl{
			{
				ID:          "5.1.1",
				Title:       "Minimize the admission of privileged containers",
				Description: "Do not generally permit containers to be run with the privileged flag set to true",
				Level:       ComplianceLevelLevel1,
				Automated:   true,
			},
		},
	}

	analysis := &AttackSurfaceAnalysis{
		RiskFactors: []*RiskFactor{
			{
				Type:     RiskTypePrivilegedAccess,
				Severity: RiskSeverityHigh,
			},
		},
	}

	result := framework.CheckCompliance(analysis)
	require.NotNil(t, result)
	assert.Equal(t, "CIS Kubernetes Benchmark", result.Framework)
	assert.False(t, result.OverallCompliant)
	assert.NotEmpty(t, result.FailedControls)
}

func TestBenchmarkTest_AttackSurfaceAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	analyzer := NewAttackSurfaceAnalyzer()
	profile := &learner.LearningProfile{
		ContainerID: "benchmark-container",
		ObservedSyscalls: make(map[uint64]*learner.SyscallStatistics),
		NetworkConnections: make([]*learner.NetworkConnection, 0),
		FileAccesses: make([]*learner.FileAccess, 0),
		ProcessHierarchy: make([]*learner.ProcessInfo, 0),
	}

	// Add many syscalls for realistic benchmark
	for i := uint64(1); i <= 300; i++ {
		profile.ObservedSyscalls[i] = &learner.SyscallStatistics{
			SyscallNumber: i,
			TotalCalls:    100,
			UniquePids:    1,
		}
	}

	start := time.Now()
	analysis := analyzer.AnalyzeContainer(profile)
	duration := time.Since(start)

	require.NotNil(t, analysis)
	assert.Less(t, duration, 100*time.Millisecond, "Analysis should complete quickly")
	t.Logf("Attack surface analysis took %v", duration)
}