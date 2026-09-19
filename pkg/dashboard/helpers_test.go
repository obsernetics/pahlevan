package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// The test fixtures model the situation the whole package exists to get right:
// two namespaces, one of which the viewer may read and one of which they may
// not, with data in both. Every authorisation test asserts on the second one.

const (
	visibleNS = "prod"
	hiddenNS  = "secret"
	testUser  = "alice@example.com"
	testToken = "a-kubernetes-token"
)

// fakeAuth builds a clientset whose TokenReview and SubjectAccessReview
// answers are under the test's control, and which counts the reviews it was
// asked for so a test can assert that a decision was actually taken rather
// than assumed.
type fakeAuth struct {
	clientset  *k8sfake.Clientset
	tokenCalls atomic.Int64
	sarCalls   atomic.Int64
}

// allowFunc decides one SubjectAccessReview.
type allowFunc func(res Resource, namespace string) bool

// allowNamespaces allows every resource in the listed namespaces.
func allowNamespaces(namespaces ...string) allowFunc {
	set := map[string]struct{}{}
	for _, ns := range namespaces {
		set[ns] = struct{}{}
	}
	return func(_ Resource, namespace string) bool {
		_, ok := set[namespace]
		return ok
	}
}

func newFakeAuth(authenticated bool, allow allowFunc) *fakeAuth {
	f := &fakeAuth{clientset: k8sfake.NewSimpleClientset()}
	f.clientset.PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			f.tokenCalls.Add(1)
			review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
			out := review.DeepCopy()
			out.Status = authenticationv1.TokenReviewStatus{
				Authenticated: authenticated,
				Audiences:     review.Spec.Audiences,
				User: authenticationv1.UserInfo{
					Username: testUser,
					UID:      "uid-1",
					Groups:   []string{"system:authenticated"},
				},
			}
			if !authenticated {
				out.Status.User = authenticationv1.UserInfo{}
				out.Status.Error = "the token could not be verified"
			}
			return true, out, nil
		})
	f.clientset.PrependReactor("create", "subjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			f.sarCalls.Add(1)
			review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
			out := review.DeepCopy()
			attrs := review.Spec.ResourceAttributes
			allowed := false
			if attrs != nil && allow != nil {
				allowed = allow(Resource(attrs.Resource), attrs.Namespace)
			}
			out.Status = authorizationv1.SubjectAccessReviewStatus{
				Allowed: allowed,
				Reason:  "decided by the test",
			}
			return true, out, nil
		})
	return f
}

func testScheme(t testing.TB) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := policyv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("registering the Pahlevan types in the test scheme: %v", err)
	}
	return s
}

func mustTime(t testing.TB, value string) metav1.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parsing the fixture timestamp %q: %v", value, err)
	}
	return metav1.NewTime(parsed)
}

func int32p(v int32) *int32 { return &v }

// fixtureObjects is the cluster every handler test reads: one workload the
// viewer may see and one they may not, each with a policy, a profile and an
// attack surface.
func fixtureObjects(t testing.TB) []runtime.Object {
	t.Helper()
	return []runtime.Object{
		&policyv1alpha1.PahlevanPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: visibleNS},
			Status:     policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseEnforcing},
		},
		&policyv1alpha1.PahlevanPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "ledger", Namespace: hiddenNS},
			Status:     policyv1alpha1.PahlevanPolicyStatus{Phase: policyv1alpha1.PolicyPhaseLearning},
		},
		&policyv1alpha1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "api-0-api", Namespace: visibleNS},
			Spec: policyv1alpha1.ContainerProfileSpec{
				PolicyRef: "api",
				Namespace: visibleNS,
				PodName:   "api-0",
				Node:      "node-1",
				Workload: &policyv1alpha1.WorkloadReference{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "api", Namespace: visibleNS,
				},
			},
			Status: policyv1alpha1.ContainerProfileStatus{
				Phase:                      "Enforcing",
				LearnedFiles:               []string{"/etc/passwd", "/usr/share/nginx/index.html"},
				LearnedNetworkDestinations: []string{"10.0.0.5:5432"},
				LearnedExecutables:         []string{"/usr/sbin/nginx"},
				LearnedCapabilities:        []string{"NET_BIND_SERVICE"},
				LearnedSyscalls:            []int64{0, 1, 257},
				FileCount:                  2,
				NetworkCount:               1,
				SyscallCount:               3,
				DenialCount:                4,
				DeniedFiles:                3,
				DeniedNetwork:              1,
				EnforcementAttempts:        2,
				RollbackCount:              1,
				LastRollbackReason:         "denial rate exceeded the rollback threshold during the first attempt",
				FirstSeen:                  ptrTime(mustTime(t, "2026-01-01T10:00:00Z")),
				EnforcingSince:             ptrTime(mustTime(t, "2026-01-01T10:30:00Z")),
				LastUpdated:                ptrTime(mustTime(t, "2026-01-01T11:00:00Z")),
				Seccomp: &policyv1alpha1.SeccompProfileRef{
					LocalhostProfile: "pahlevan/api.json", Node: "node-1",
					AllowedSyscalls: 42, TotalSyscalls: 400,
				},
			},
		},
		&policyv1alpha1.ContainerProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "ledger-0-ledger", Namespace: hiddenNS},
			Spec: policyv1alpha1.ContainerProfileSpec{
				PolicyRef: "ledger",
				Namespace: hiddenNS,
				PodName:   "ledger-0",
				Workload: &policyv1alpha1.WorkloadReference{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "ledger", Namespace: hiddenNS,
				},
			},
			Status: policyv1alpha1.ContainerProfileStatus{
				Phase:        "Learning",
				LearnedFiles: []string{"/var/lib/ledger/secrets.db"},
				DenialCount:  99,
				DeniedFiles:  99,
			},
		},
		&policyv1alpha1.AttackSurface{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: visibleNS},
			Spec: policyv1alpha1.AttackSurfaceSpec{
				Namespace: visibleNS,
				Workload: &policyv1alpha1.WorkloadReference{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "api", Namespace: visibleNS,
				},
			},
			Status: policyv1alpha1.AttackSurfaceStatus{
				RiskScore:       int32p(37),
				ExposedSyscalls: []string{"execve"},
				ExposedPorts:    []int32{8080},
			},
		},
		&policyv1alpha1.AttackSurface{
			ObjectMeta: metav1.ObjectMeta{Name: "ledger", Namespace: hiddenNS},
			Spec: policyv1alpha1.AttackSurfaceSpec{
				Namespace: hiddenNS,
				Workload: &policyv1alpha1.WorkloadReference{
					APIVersion: "apps/v1", Kind: "Deployment", Name: "ledger", Namespace: hiddenNS,
				},
			},
			Status: policyv1alpha1.AttackSurfaceStatus{RiskScore: int32p(91)},
		},
	}
}

func ptrTime(t metav1.Time) *metav1.Time { return &t }

// newTestServer wires a Server over the fixtures with the given access
// decision. It uses --insecure because a unit test is exactly the case that
// flag exists for.
func newTestServer(t testing.TB, auth *fakeAuth, store *Store) *Server {
	t.Helper()
	reader := ctrlfake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithRuntimeObjects(fixtureObjects(t)...).
		Build()
	server, err := New(Options{
		Addr:          "127.0.0.1:0",
		AllowInsecure: true,
		Reader:        reader,
		Kube:          auth.clientset,
		Store:         store,
	})
	if err != nil {
		t.Fatalf("building the test server: %v", err)
	}
	return server
}

// get performs an authenticated request against the fully wrapped handler, so
// every test sees the headers and the method guard a browser would.
func get(t testing.TB, server *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, server, http.MethodGet, path, testToken)
}

func do(t testing.TB, server *Server, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the response body %q: %v", rec.Body.String(), err)
	}
	return out
}
