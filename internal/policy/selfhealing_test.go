package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/obsernetics/pahlevan/internal/adaptive"
	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

func TestSelfHealingTranslation(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		SelfHealing: policyv1alpha1.SelfHealingConfig{
			Enabled:           true,
			RollbackThreshold: 25,
			RollbackWindow:    &metav1.Duration{Duration: 10 * time.Minute},
		},
	}, now)
	assert.Empty(t, warnings)
	assert.Equal(t, adaptive.SelfHealingDecision{
		Enabled: true, Threshold: 25, Window: 10 * time.Minute,
	}, d.SelfHealing)
}

// An absent block means self-healing off, which is the API's zero value and
// what an operator who never mentioned it should get.
func TestSelfHealingDefaultsToDisabled(t *testing.T) {
	d, _ := Translate("p", policyv1alpha1.PahlevanPolicySpec{}, now)
	assert.False(t, d.SelfHealing.Enabled)
	assert.Zero(t, d.SelfHealing.Threshold)
	assert.Zero(t, d.SelfHealing.Window)
}

// Zero threshold and window mean "use the controller default", not "disable".
func TestSelfHealingZeroesMeanDefault(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		SelfHealing: policyv1alpha1.SelfHealingConfig{Enabled: true},
	}, now)
	assert.Empty(t, warnings)
	assert.True(t, d.SelfHealing.Enabled)
	assert.Zero(t, d.SelfHealing.Threshold)
	assert.Zero(t, d.SelfHealing.Window)
}

func TestSelfHealingNegativesAreClamped(t *testing.T) {
	d, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		SelfHealing: policyv1alpha1.SelfHealingConfig{
			Enabled:           true,
			RollbackThreshold: -5,
			RollbackWindow:    &metav1.Duration{Duration: -time.Minute},
		},
	}, now)
	assert.Zero(t, d.SelfHealing.Threshold)
	assert.Zero(t, d.SelfHealing.Window)
	assert.True(t, hasWarning(warnings, "rollbackThreshold is negative"))
	assert.True(t, hasWarning(warnings, "rollbackWindow is negative"))
}

// Only Rollback is implemented; the other strategies are accepted by the API
// and do nothing, so say so rather than let an operator believe otherwise.
func TestUnimplementedRecoveryStrategyIsFlagged(t *testing.T) {
	for _, strategy := range []policyv1alpha1.RecoveryStrategy{
		policyv1alpha1.RecoveryStrategyRelax,
		policyv1alpha1.RecoveryStrategyMaintenance,
	} {
		t.Run(string(strategy), func(t *testing.T) {
			_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
				SelfHealing: policyv1alpha1.SelfHealingConfig{
					Enabled: true, RecoveryStrategy: strategy,
				},
			}, now)
			assert.True(t, hasWarning(warnings, "is not implemented"), "warnings were %v", warnings)
		})
	}

	_, warnings := Translate("p", policyv1alpha1.PahlevanPolicySpec{
		SelfHealing: policyv1alpha1.SelfHealingConfig{
			Enabled: true, RecoveryStrategy: policyv1alpha1.RecoveryStrategyRollback,
		},
	}, now)
	assert.False(t, hasWarning(warnings, "is not implemented"),
		"Rollback is the implemented strategy and must not warn")
}
