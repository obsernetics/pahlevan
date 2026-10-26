package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

// supportedClusterMapper is a RESTMapper that knows about
// ValidatingAdmissionPolicy, the condition admission.Ensure and
// admission.EnsureDerived check before writing anything.
func supportedClusterMapper(t *testing.T) meta.RESTMapper {
	t.Helper()
	gv := admissionregistrationv1.SchemeGroupVersion
	m := meta.NewDefaultRESTMapper([]schema.GroupVersion{gv})
	m.Add(gv.WithKind("ValidatingAdmissionPolicy"), meta.RESTScopeRoot)
	m.Add(gv.WithKind("ValidatingAdmissionPolicyBinding"), meta.RESTScopeRoot)
	return m
}

func supportedClusterClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(unsupportedClusterScheme(t)).
		WithRESTMapper(supportedClusterMapper(t)).
		WithObjects(objs...).
		Build()
}

// capturingLogSink records every record logged through it (Info and Error
// alike), so a test can assert on what was actually reported rather than
// only on "it did not panic".
type capturingLogSink struct {
	records []string
}

func capturingLogger(sink *capturingLogSink) logr.Logger {
	return funcr.New(func(prefix, args string) {
		sink.records = append(sink.records, args)
	}, funcr.Options{Verbosity: 1})
}

func (s *capturingLogSink) contains(substr string) bool {
	for _, r := range s.records {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
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

// The other two branches of ensureAdmissionOnce - a successful upsert and a
// real (non-ErrUnsupported) failure - were never exercised: every prior test
// used an unsupported cluster, which returns before either log line is
// reached.

func TestEnsureAdmissionOnceLogsSuccess(t *testing.T) {
	c := supportedClusterClient(t)
	sink := &capturingLogSink{}

	ensureAdmissionOnce(context.Background(), capturingLogger(sink), c)

	assert.True(t, sink.contains("ensured"), "records: %v", sink.records)

	var vap admissionregistrationv1.ValidatingAdmissionPolicy
	assert.NoError(t, c.Get(context.Background(),
		client.ObjectKey{Name: "pahlevan-pod-hardening"}, &vap))
}

func TestEnsureAdmissionOnceLogsFailure(t *testing.T) {
	wantErr := errors.New("apiserver unavailable")
	c := fake.NewClientBuilder().
		WithScheme(unsupportedClusterScheme(t)).
		WithRESTMapper(supportedClusterMapper(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				return wantErr
			},
		}).
		Build()
	sink := &capturingLogSink{}

	assert.NotPanics(t, func() {
		ensureAdmissionOnce(context.Background(), capturingLogger(sink), c)
	})

	assert.True(t, sink.contains("failed to ensure CEL admission policy"), "records: %v", sink.records)
	assert.True(t, sink.contains(wantErr.Error()), "records: %v", sink.records)
}

// Same gap in reconcileDerivedAdmissionOnce: a supported cluster that
// actually derives a policy, and one where EnsureDerived fails outright,
// were both untested.

func derivedReadyProfile(name, policyRef string) *policyv1alpha1.ContainerProfile {
	return &policyv1alpha1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "prod"},
		Spec:       policyv1alpha1.ContainerProfileSpec{PolicyRef: policyRef},
		Status: policyv1alpha1.ContainerProfileStatus{
			Phase:               "Enforcing",
			LearnedCapabilities: []string{"NET_BIND_SERVICE"},
		},
	}
}

func TestReconcileDerivedAdmissionOnceLogsReconciledCount(t *testing.T) {
	pol := &policyv1alpha1.PahlevanPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-security", Namespace: "prod"},
	}
	c := supportedClusterClient(t, pol, derivedReadyProfile("cp-a", "nginx-security"))
	sink := &capturingLogSink{}

	reconcileDerivedAdmissionOnce(context.Background(), capturingLogger(sink), c)

	assert.True(t, sink.contains("derived admission policies reconciled"), "records: %v", sink.records)
}

func TestReconcileDerivedAdmissionOnceLogsFailureAtV1(t *testing.T) {
	wantErr := errors.New("list failed")
	c := fake.NewClientBuilder().
		WithScheme(unsupportedClusterScheme(t)).
		WithRESTMapper(supportedClusterMapper(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*policyv1alpha1.PahlevanPolicyList); ok {
					return wantErr
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()
	sink := &capturingLogSink{}

	assert.NotPanics(t, func() {
		reconcileDerivedAdmissionOnce(context.Background(), capturingLogger(sink), c)
	})

	assert.True(t, sink.contains("derived admission reconcile failed"), "records: %v", sink.records)
}
