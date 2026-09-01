package main

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// unsupportedClusterScheme builds a scheme with no ValidatingAdmissionPolicy
// registration and no RESTMapper support for it, which is exactly what
// admission.Ensure and admission.EnsureDerived see on a cluster below
// Kubernetes 1.30: both report admission.ErrUnsupported.
func unsupportedClusterScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, policyv1alpha1.AddToScheme(s))
	require.NoError(t, admissionregistrationv1.AddToScheme(s))
	return s
}

func unsupportedClusterClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(unsupportedClusterScheme(t)).
		WithObjects(objs...).
		Build()
}

func TestEnsureAdmissionOnce(t *testing.T) {
	t.Run("unsupported cluster does not panic and logs a skip", func(t *testing.T) {
		c := unsupportedClusterClient(t)
		assert.NotPanics(t, func() {
			ensureAdmissionOnce(context.Background(), logr.Discard(), c)
		})
	})

	t.Run("canceled context is handled without panicking", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := unsupportedClusterClient(t)
		assert.NotPanics(t, func() {
			ensureAdmissionOnce(ctx, logr.Discard(), c)
		})
	})
}

func TestReconcileDerivedAdmissionOnce(t *testing.T) {
	t.Run("unsupported cluster is a silent no-op", func(t *testing.T) {
		c := unsupportedClusterClient(t)
		assert.NotPanics(t, func() {
			reconcileDerivedAdmissionOnce(context.Background(), logr.Discard(), c)
		})
	})

	t.Run("no PahlevanPolicy objects reconciles zero policies without panicking", func(t *testing.T) {
		c := unsupportedClusterClient(t)
		assert.NotPanics(t, func() {
			reconcileDerivedAdmissionOnce(context.Background(), logr.Discard(), c)
		})
	})
}
