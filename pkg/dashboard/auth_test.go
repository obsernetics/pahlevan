package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{name: "absent", header: "", ok: false},
		{name: "bearer", header: "Bearer abc", want: "abc", ok: true},
		{name: "lowercase scheme is still a bearer token", header: "bearer abc", want: "abc", ok: true},
		{name: "padded", header: "Bearer   abc  ", want: "abc", ok: true},
		{name: "empty token", header: "Bearer ", ok: false},
		{name: "basic auth is not a bearer token", header: "Basic dXNlcjpwYXNz", ok: false},
		{name: "scheme only", header: "Bearer", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/overview", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got, ok := BearerToken(req)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("BearerToken(%q) = %q, %v; want %q, %v", tc.header, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// A token must never be read from a cookie or a query parameter: a cookie is
// attached by the browser automatically, which is what makes cross-site
// request forgery possible against a read-only API too, and a token in a URL
// lands in every proxy log on the way.
func TestBearerTokenIgnoresCookieAndQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/overview?token=leaked", nil)
	req.AddCookie(&http.Cookie{Name: "authorization", Value: "leaked"})
	if _, ok := BearerToken(req); ok {
		t.Fatal("BearerToken accepted a token that was not in the Authorization header")
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()

	t.Run("authenticated", func(t *testing.T) {
		auth := newFakeAuth(true, allowNamespaces(visibleNS))
		id, err := NewAuthenticator(auth.clientset, nil).Authenticate(ctx, testToken)
		if err != nil {
			t.Fatalf("Authenticate returned %v", err)
		}
		if id.User != testUser {
			t.Fatalf("Authenticate identified %q, want %q", id.User, testUser)
		}
		if auth.tokenCalls.Load() != 1 {
			t.Fatalf("Authenticate made %d TokenReview calls, want exactly 1", auth.tokenCalls.Load())
		}
	})

	t.Run("rejected by the API server", func(t *testing.T) {
		auth := newFakeAuth(false, nil)
		_, err := NewAuthenticator(auth.clientset, nil).Authenticate(ctx, testToken)
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authenticate returned %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("empty token never reaches the API server", func(t *testing.T) {
		auth := newFakeAuth(true, nil)
		_, err := NewAuthenticator(auth.clientset, nil).Authenticate(ctx, "")
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authenticate returned %v, want ErrUnauthenticated", err)
		}
		if auth.tokenCalls.Load() != 0 {
			t.Fatal("an empty token was sent to the API server for review")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		// A token minted for another service is a valid token the API server
		// will happily identify. Accepting it here would make the dashboard a
		// relay for credentials that were never meant for it.
		clientset := k8sfake.NewSimpleClientset()
		clientset.PrependReactor("create", "tokenreviews",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
				review.Status = authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{"some-other-service"},
					User:          authenticationv1.UserInfo{Username: testUser},
				}
				return true, review, nil
			})
		_, err := NewAuthenticator(clientset, []string{"pahlevan-dashboard"}).Authenticate(ctx, testToken)
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authenticate accepted a token for another audience: %v", err)
		}
	})

	t.Run("authenticated but unnamed", func(t *testing.T) {
		clientset := k8sfake.NewSimpleClientset()
		clientset.PrependReactor("create", "tokenreviews",
			func(action k8stesting.Action) (bool, runtime.Object, error) {
				review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
				review.Status = authenticationv1.TokenReviewStatus{Authenticated: true}
				return true, review, nil
			})
		_, err := NewAuthenticator(clientset, nil).Authenticate(ctx, testToken)
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authenticate accepted an identity with no username: %v", err)
		}
	})

	t.Run("API server unreachable is not a rejection", func(t *testing.T) {
		clientset := k8sfake.NewSimpleClientset()
		clientset.PrependReactor("create", "tokenreviews",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("connection refused")
			})
		_, err := NewAuthenticator(clientset, nil).Authenticate(ctx, testToken)
		if err == nil {
			t.Fatal("Authenticate returned no error when the API server was unreachable")
		}
		if errors.Is(err, ErrUnauthenticated) {
			t.Fatal("an unreachable API server was reported as a rejected token, which would tell " +
				"the viewer to fix their credential instead of the operator to fix the cluster")
		}
	})
}

func TestAuthorizerAllowed(t *testing.T) {
	ctx := context.Background()
	id := &Identity{User: testUser, Groups: []string{"system:authenticated"}}

	tests := []struct {
		name      string
		allowed   bool
		denied    bool
		want      bool
		namespace string
	}{
		{name: "allowed", allowed: true, want: true, namespace: visibleNS},
		{name: "not allowed", allowed: false, want: false, namespace: hiddenNS},
		{name: "explicitly denied", allowed: false, denied: true, want: false, namespace: hiddenNS},
		{name: "contradiction resolves to denied", allowed: true, denied: true, want: false, namespace: hiddenNS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientset := k8sfake.NewSimpleClientset()
			var seen *authorizationv1.SubjectAccessReviewSpec
			clientset.PrependReactor("create", "subjectaccessreviews",
				func(action k8stesting.Action) (bool, runtime.Object, error) {
					review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
					seen = &review.Spec
					review.Status = authorizationv1.SubjectAccessReviewStatus{
						Allowed: tc.allowed, Denied: tc.denied,
					}
					return true, review, nil
				})
			got, _, err := NewAuthorizer(clientset).Allowed(ctx, id, ResourceProfiles, tc.namespace)
			if err != nil {
				t.Fatalf("Allowed returned %v", err)
			}
			if got != tc.want {
				t.Fatalf("Allowed = %v, want %v", got, tc.want)
			}
			if seen == nil || seen.ResourceAttributes == nil {
				t.Fatal("the SubjectAccessReview carried no resource attributes")
			}
			// The review has to name the resource, group, namespace and verb
			// the read will actually perform. A review of something else is a
			// check that passes while the read it stands for is unauthorised.
			attrs := seen.ResourceAttributes
			if attrs.Group != APIGroup || attrs.Resource != string(ResourceProfiles) ||
				attrs.Namespace != tc.namespace || attrs.Verb != readVerb {
				t.Fatalf("the review asked about %+v, want group %q resource %q namespace %q verb %q",
					attrs, APIGroup, ResourceProfiles, tc.namespace, readVerb)
			}
			if seen.User != testUser {
				t.Fatalf("the review asked about user %q, want %q", seen.User, testUser)
			}
		})
	}
}

func TestAuthorizerReportsAPIFailureRatherThanDenying(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset()
	clientset.PrependReactor("create", "subjectaccessreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("etcd is unavailable")
		})
	_, _, err := NewAuthorizer(clientset).Allowed(context.Background(),
		&Identity{User: testUser}, ResourceProfiles, visibleNS)
	if err == nil {
		t.Fatal("Allowed swallowed an API server failure, which would render as an empty page " +
			"that looks exactly like a viewer with no access")
	}
}

func TestAccessCheckerMemoisesWithinOneRequest(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	checker := newAccessChecker(NewAuthorizer(auth.clientset), &Identity{User: testUser})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		allowed, err := checker.mayRead(ctx, ResourceProfiles, visibleNS)
		if err != nil || !allowed {
			t.Fatalf("mayRead = %v, %v; want true, nil", allowed, err)
		}
	}
	if got := auth.sarCalls.Load(); got != 1 {
		t.Fatalf("one request made %d SubjectAccessReviews for the same question, want 1", got)
	}
	// A different resource in the same namespace is a different question and
	// must be asked, or a viewer with profiles-only access would be shown
	// policies too.
	if _, err := checker.mayRead(ctx, ResourcePolicies, visibleNS); err != nil {
		t.Fatalf("mayRead returned %v", err)
	}
	if got := auth.sarCalls.Load(); got != 2 {
		t.Fatalf("a second resource reused the first resource's decision (%d reviews)", got)
	}
}

// The memo must not outlive the request, or a viewer whose RoleBinding was
// deleted keeps seeing the namespace until some cache expires.
func TestAccessDecisionsDoNotCrossRequests(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	az := NewAuthorizer(auth.clientset)
	id := &Identity{User: testUser}
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		checker := newAccessChecker(az, id)
		if _, err := checker.mayRead(ctx, ResourceProfiles, visibleNS); err != nil {
			t.Fatalf("mayRead returned %v", err)
		}
	}
	if got := auth.sarCalls.Load(); got != 3 {
		t.Fatalf("three requests made %d SubjectAccessReviews, want one each: a decision that "+
			"survives the response is a permission cache", got)
	}
}

func TestExtraIsCarriedIntoTheAccessReview(t *testing.T) {
	// Some clusters authorise on the extra fields an authenticator attaches
	// (a scope, a tenant). Dropping them instead of converting between the two
	// identically shaped named types would silently change the decision.
	clientset := k8sfake.NewSimpleClientset()
	var seen map[string]authorizationv1.ExtraValue
	clientset.PrependReactor("create", "subjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
			seen = review.Spec.Extra
			review.Status = authorizationv1.SubjectAccessReviewStatus{Allowed: true}
			return true, review, nil
		})

	id := &Identity{
		User:  testUser,
		Extra: map[string]authenticationv1.ExtraValue{"scope": {"read"}},
	}
	if _, _, err := NewAuthorizer(clientset).Allowed(context.Background(), id, ResourceProfiles, visibleNS); err != nil {
		t.Fatalf("Allowed returned %v", err)
	}
	if len(seen["scope"]) != 1 || seen["scope"][0] != "read" {
		t.Fatalf("the review carried extra %v, want the identity's scope", seen)
	}

	if got := extraForAuthorization(nil); got != nil {
		t.Fatalf("extraForAuthorization(nil) = %v, want nil so the field stays absent", got)
	}
}

func TestAllowedRefusesAnAbsentIdentity(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	_, _, err := NewAuthorizer(auth.clientset).Allowed(context.Background(), nil, ResourceProfiles, visibleNS)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Allowed with no identity returned %v, want ErrUnauthenticated", err)
	}
	if auth.sarCalls.Load() != 0 {
		t.Fatal("an absent identity was sent to the API server for review")
	}
}
