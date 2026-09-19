package clusterdata

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

// Reason is why a read failed, at the granularity that changes what the reader
// should do next.
//
// The distinction is the whole point: "the CRDs are not installed" sends an
// operator to `kubectl apply -f config/crd`, "you are not allowed to list
// policies" sends them to their RBAC, and "the API server is not reachable"
// sends them to their kubeconfig or their VPN. A console that prints the raw
// client error for all three sends them to none of those - the three messages
// look alike enough that the usual response is to re-run the command.
type Reason int

const (
	// ReasonUnknown is an error this package could not attribute. The
	// underlying message is still shown; it is simply not interpreted.
	ReasonUnknown Reason = iota

	// ReasonNoClient means no Kubernetes client was ever built, which in
	// practice means no kubeconfig was found or it could not be loaded.
	ReasonNoClient

	// ReasonCRDsMissing means the cluster is reachable but does not know the
	// Pahlevan kinds.
	ReasonCRDsMissing

	// ReasonSchemeMissing means the client itself was built without the
	// Pahlevan types registered. It looks like ReasonCRDsMissing from the
	// outside and is the opposite problem: the cluster is fine and the binary
	// is wrong. Kept separate because telling an operator to install CRDs that
	// are already installed is how an afternoon gets lost.
	ReasonSchemeMissing

	// ReasonForbidden means the credentials are valid and lack the list
	// permission.
	ReasonForbidden

	// ReasonUnauthorized means the credentials were rejected outright -
	// expired token, wrong cluster - as against accepted and under-privileged.
	ReasonUnauthorized

	// ReasonUnreachable means the API server could not be contacted or did not
	// answer in time.
	ReasonUnreachable

	// ReasonCanceled means the caller went away. Normal when an operator
	// switches views mid-list; never worth alarming them about.
	ReasonCanceled
)

func (r Reason) String() string {
	switch r {
	case ReasonNoClient:
		return "no-client"
	case ReasonCRDsMissing:
		return "crds-missing"
	case ReasonSchemeMissing:
		return "scheme-missing"
	case ReasonForbidden:
		return "forbidden"
	case ReasonUnauthorized:
		return "unauthorized"
	case ReasonUnreachable:
		return "unreachable"
	case ReasonCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// Error is a read failure with the reason attached and a message written for
// somebody sitting in front of a terminal rather than for a log aggregator.
type Error struct {
	Reason Reason

	// Resource is the plural kind being listed, e.g. "containerprofiles". It
	// is in the message because "you are not allowed to list policies" and
	// "you are not allowed to list profiles" are different RBAC fixes.
	Resource string

	// Err is the underlying client error, preserved for Unwrap so callers can
	// still use apierrors on it.
	Err error
}

func (e *Error) Error() string {
	res := e.Resource
	if res == "" {
		res = "Pahlevan resources"
	}
	switch e.Reason {
	case ReasonNoClient:
		return "no connection to a cluster: no kubeconfig was loaded, so there is nothing to read " +
			"(check KUBECONFIG, or pass --kubeconfig)"
	case ReasonCRDsMissing:
		return fmt.Sprintf("the Pahlevan CRDs are not installed in this cluster, so %s cannot be listed "+
			"(install them with: kubectl apply -f config/crd)", res)
	case ReasonSchemeMissing:
		return fmt.Sprintf("this build cannot decode %s: the Pahlevan API types are not registered in the "+
			"client's scheme (build the client with clusterdata.NewScheme)", res)
	case ReasonForbidden:
		return fmt.Sprintf("you are not allowed to list %s in this cluster: %v "+
			"(your credentials are valid; the RBAC for this resource is not)", res, e.Err)
	case ReasonUnauthorized:
		return fmt.Sprintf("your credentials were rejected while listing %s: %v "+
			"(the token or client certificate is expired or belongs to another cluster)", res, e.Err)
	case ReasonUnreachable:
		return fmt.Sprintf("the Kubernetes API server could not be reached while listing %s: %v", res, e.Err)
	case ReasonCanceled:
		return fmt.Sprintf("reading %s was canceled: %v", res, e.Err)
	default:
		if e.Err == nil {
			return fmt.Sprintf("failed to list %s", res)
		}
		return fmt.Sprintf("failed to list %s: %v", res, e.Err)
	}
}

func (e *Error) Unwrap() error { return e.Err }

// ReasonOf reports why err happened, for callers that want to branch on it -
// a console showing an install hint on one screen and an RBAC hint on another.
// It returns ReasonUnknown for a nil error, since nil is not a failure.
func ReasonOf(err error) Reason {
	if err == nil {
		return ReasonUnknown
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return classifyReason(err)
}

// classify wraps a client error with the reason it represents.
func classify(err error, resource string) error {
	if err == nil {
		return nil
	}
	return &Error{Reason: classifyReason(err), Resource: resource, Err: err}
}

func classifyReason(err error) Reason {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// A deadline is grouped with cancellation rather than with
		// unreachability: the caller set the deadline, so it is the caller's
		// budget that ran out, and telling an operator the cluster is down
		// because a 50ms timeout expired would be a lie.
		return ReasonCanceled

	case runtime.IsNotRegisteredError(err):
		return ReasonSchemeMissing

	case meta.IsNoMatchError(err):
		return ReasonCRDsMissing

	case apierrors.IsForbidden(err):
		return ReasonForbidden

	case apierrors.IsUnauthorized(err):
		return ReasonUnauthorized

	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), apierrors.IsServiceUnavailable(err),
		apierrors.IsInternalError(err), apierrors.IsTooManyRequests(err):
		return ReasonUnreachable
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return ReasonUnreachable
	}

	// String matching is the last resort, not the first: the typed checks
	// above cover a real API server, and these cover the shapes that arrive
	// as bare errors from the REST client and the discovery cache.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no matches for kind"),
		strings.Contains(msg, "could not find the requested resource"),
		strings.Contains(msg, "the server doesn't have a resource type"):
		return ReasonCRDsMissing
	case strings.Contains(msg, "no kind is registered"),
		strings.Contains(msg, "not registered in scheme"),
		strings.Contains(msg, "failed to get api group resources"):
		return ReasonSchemeMissing
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "tls handshake timeout"),
		strings.Contains(msg, "connection reset by peer"):
		return ReasonUnreachable
	case strings.Contains(msg, "no configuration has been provided"),
		strings.Contains(msg, "kubeconfig"),
		strings.Contains(msg, ".kube/config"):
		return ReasonNoClient
	}
	return ReasonUnknown
}
