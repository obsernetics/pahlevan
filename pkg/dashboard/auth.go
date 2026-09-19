package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// APIGroup is the group the three Pahlevan CRDs live in. Every
// SubjectAccessReview the dashboard makes names it, so a viewer granted read
// on the CRDs and nothing else sees the dashboard work and nothing more.
const APIGroup = "policy.pahlevan.io"

// Resource is one of the three CRDs the dashboard reads. The list is closed on
// purpose: a dashboard that can be talked into reviewing access to an
// arbitrary resource is a probe for what its service account can reach.
type Resource string

const (
	ResourcePolicies Resource = "pahlevanpolicies"
	ResourceProfiles Resource = "containerprofiles"
	ResourceSurfaces Resource = "attacksurfaces"
)

// readVerb is the verb every SubjectAccessReview asks about.
//
// Every read this package performs is a namespace-scoped list, so authorizing
// "list" authorizes exactly what happens. Asking about "get" while performing
// a list would be a lie in the direction that matters: a viewer granted get on
// one named object would be shown every object in the namespace.
const readVerb = "list"

// ErrUnauthenticated means the request carried no usable identity. It is kept
// distinct from an authorisation failure because they are different answers:
// one says "tell me who you are", the other says "I know who you are and no".
var ErrUnauthenticated = errors.New("dashboard: the request carried no valid Kubernetes token")

// Identity is who the browser is, as the API server understands it. The
// dashboard never stores one: it is established per request from the presented
// token and discarded with the response.
type Identity struct {
	User   string
	UID    string
	Groups []string
	Extra  map[string]authenticationv1.ExtraValue
}

// Authenticator turns a bearer token into an Identity by asking Kubernetes.
//
// There is no user database and no session. The token the browser holds is a
// Kubernetes token, the answer about who it belongs to comes from the API
// server, and revoking it is done where every other Kubernetes credential is
// revoked. That is the whole point: there is no secret here worth stealing,
// because there is no secret here.
type Authenticator struct {
	client    kubernetes.Interface
	audiences []string
}

// NewAuthenticator builds an Authenticator. Audiences may be empty, in which
// case the API server's default audience applies.
func NewAuthenticator(client kubernetes.Interface, audiences []string) *Authenticator {
	return &Authenticator{client: client, audiences: audiences}
}

// BearerToken extracts the token from the Authorization header.
//
// Header only, never a cookie and never a query parameter: a cookie would be
// sent by the browser automatically, which is what makes cross-site request
// forgery possible, and a token in a URL ends up in every proxy log between
// here and the viewer.
func BearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	value := r.Header.Get("Authorization")
	if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(value[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// Authenticate resolves a token to an Identity.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, ErrUnauthenticated
	}
	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: a.audiences,
		},
	}
	result, err := a.client.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("asking the API server to review the presented token: %w", err)
	}
	if !result.Status.Authenticated {
		if msg := result.Status.Error; msg != "" {
			return nil, fmt.Errorf("%w: %s", ErrUnauthenticated, msg)
		}
		return nil, ErrUnauthenticated
	}
	// A token minted for a different audience - a projected service account
	// token for some other service, say - is a valid token the API server will
	// happily identify. Accepting one here would turn the dashboard into a
	// relay for credentials that were never meant for it, so the audience the
	// API server confirms has to be one we asked for.
	if len(a.audiences) > 0 && !intersects(a.audiences, result.Status.Audiences) {
		return nil, fmt.Errorf("%w: the token is valid but was issued for a different audience", ErrUnauthenticated)
	}
	user := result.Status.User
	if user.Username == "" {
		return nil, fmt.Errorf("%w: the API server authenticated the token but named no user", ErrUnauthenticated)
	}
	return &Identity{
		User:   user.Username,
		UID:    user.UID,
		Groups: user.Groups,
		Extra:  user.Extra,
	}, nil
}

func intersects(want, got []string) bool {
	for _, w := range want {
		for _, g := range got {
			if w == g {
				return true
			}
		}
	}
	return false
}

// Authorizer answers "may this identity read this resource in this namespace"
// by asking Kubernetes, once per read.
type Authorizer struct {
	client kubernetes.Interface
}

// NewAuthorizer builds an Authorizer.
func NewAuthorizer(client kubernetes.Interface) *Authorizer {
	return &Authorizer{client: client}
}

// Allowed runs one SubjectAccessReview. The returned reason is the API
// server's own explanation, which is worth surfacing in a log: "no RoleBinding
// found" and "denied by a webhook" are different problems for the operator who
// has to fix the viewer's access.
func (a *Authorizer) Allowed(ctx context.Context, id *Identity, res Resource, namespace string) (bool, string, error) {
	if id == nil {
		return false, "", ErrUnauthenticated
	}
	review := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   id.User,
			UID:    id.UID,
			Groups: id.Groups,
			Extra:  extraForAuthorization(id.Extra),
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      readVerb,
				Group:     APIGroup,
				Resource:  string(res),
			},
		},
	}
	result, err := a.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, "", fmt.Errorf(
			"asking the API server whether %s may list %s in namespace %q: %w",
			id.User, res, namespace, err)
	}
	// Denied wins over Allowed. An authorizer that says both is a
	// misconfiguration, and the safe reading of a contradiction is the
	// restrictive one.
	if result.Status.Denied {
		return false, result.Status.Reason, nil
	}
	return result.Status.Allowed, result.Status.Reason, nil
}

// extraForAuthorization converts the authentication package's ExtraValue to
// the authorization package's. They are the same shape and different named
// types, and dropping the field instead of converting it would silently change
// the decision for any cluster whose authorizer keys off it.
func extraForAuthorization(in map[string]authenticationv1.ExtraValue) map[string]authorizationv1.ExtraValue {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]authorizationv1.ExtraValue, len(in))
	for k, v := range in {
		out[k] = authorizationv1.ExtraValue(v)
	}
	return out
}

// accessChecker memoises one request's decisions.
//
// The scope is deliberately one request and not one process. A single overview
// asks about the same namespace for several resources, and re-asking the API
// server for an answer it just gave costs a round trip per namespace per
// resource on a page load. Carrying the answer past the response, though,
// would be a permission cache: a viewer whose RoleBinding was deleted would
// keep seeing the namespace until it expired, and "how long until the
// dashboard stops showing them that" is not a question a security tool should
// have an answer to.
type accessChecker struct {
	az     *Authorizer
	id     *Identity
	cached map[accessKey]bool
}

type accessKey struct {
	resource  Resource
	namespace string
}

func newAccessChecker(az *Authorizer, id *Identity) *accessChecker {
	return &accessChecker{az: az, id: id, cached: map[accessKey]bool{}}
}

// mayRead reports whether the identity may list res in namespace.
//
// An error is not a "no" that gets swallowed: it is returned, so a failing API
// server produces a 503 rather than an empty page that looks like a viewer
// with no access. Those two look identical to a user and mean opposite things.
func (c *accessChecker) mayRead(ctx context.Context, res Resource, namespace string) (bool, error) {
	key := accessKey{resource: res, namespace: namespace}
	if allowed, ok := c.cached[key]; ok {
		return allowed, nil
	}
	allowed, _, err := c.az.Allowed(ctx, c.id, res, namespace)
	if err != nil {
		return false, err
	}
	c.cached[key] = allowed
	return allowed, nil
}
