package cycle

import (
	"context"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// maxOwnerHops bounds how far up an owner chain Find will walk.
//
// The chain this package exists for is two hops - Pod -> Job -> CronJob - and
// the longest real chain in a cluster is a rollout controller's, which adds a
// step or two above a ReplicaSet. Eight is comfortably past anything genuine
// while still being a number, which matters because this walk runs inside a
// reconcile: an unbounded walk over a corrupted owner graph would hang the
// worker, and a hung worker stops every policy in the cluster from updating,
// not just the one being reconciled.
const maxOwnerHops = 8

// cronJobGroup is the API group CronJob lives in. Only the group and kind are
// matched, not the version: a cluster old enough to still report
// batch/v1beta1 on an owner reference serves the same object at batch/v1, which
// is the version this package reads.
const cronJobGroup = "batch"

// cronJobKind is the owner reference kind that ends the walk.
const cronJobKind = "CronJob"

// Schedule is the outcome of an owner chain walk.
//
// Not finding a CronJob is the ordinary result, not a failure - the great
// majority of workloads are Deployments with no periodicity at all - so it is
// reported by Found being false rather than by an error. Callers that treat
// "no CronJob" as an error end up logging a line per reconcile per pod for the
// normal case, which is how a useful signal gets drowned.
type Schedule struct {
	// Found reports whether a CronJob was reached.
	Found bool
	// Expression is the CronJob's .spec.schedule, empty when Found is false.
	Expression string
	// CronJob names the object the expression came from, so an operator can be
	// told which schedule extended their learning window.
	CronJob types.NamespacedName
}

// Find walks up obj's owner references looking for a CronJob, and returns its
// .spec.schedule.
//
// A Job created by a CronJob carries the CronJob in its ownerReferences, and a
// Pod created by a Job carries the Job, so the schedule that governs a pod is
// two hops above it and is never visible on the pod itself. That is why this
// walks rather than reading a label: the CronJob controller sets no label on the
// pod that names the schedule, and the job-name label it does set is not the
// CronJob's name.
//
// Only controller references are followed. Kubernetes permits at most one
// controller reference per object, which is what makes the walk a chain rather
// than a graph, and it is the reference that describes what actually created
// the object - a non-controller owner is a lifecycle link, not a creator.
//
// An owner that has been deleted ends the walk with Found false rather than an
// error. A Job disappearing out from under its pod is routine under
// ttlSecondsAfterFinished, and failing the reconcile over it would block policy
// updates for a workload that is behaving perfectly normally.
func Find(ctx context.Context, c client.Client, obj client.Object) (Schedule, error) {
	if c == nil || obj == nil {
		return Schedule{}, fmt.Errorf("owner chain walk needs a client and an object")
	}

	namespace := obj.GetNamespace()
	owner := metav1.GetControllerOf(obj)

	// Owner references are namespace-local, so identity within the walk is
	// kind plus name. Visiting the same one twice means the chain loops, which
	// cannot happen in a healthy cluster but can after a restore from backup or
	// a hand-edited ownerReferences block - and a loop with no seen set is an
	// infinite reconcile, not a wrong answer.
	seen := make(map[string]struct{}, maxOwnerHops)

	for hop := 0; owner != nil && hop < maxOwnerHops; hop++ {
		gv, err := schema.ParseGroupVersion(owner.APIVersion)
		if err != nil {
			// An unparseable apiVersion is a malformed owner reference. There is
			// nothing above it to reach, so stop rather than fail the reconcile.
			return Schedule{}, nil
		}

		key := gv.Group + "/" + owner.Kind + "/" + owner.Name
		if _, loop := seen[key]; loop {
			return Schedule{}, nil
		}
		seen[key] = struct{}{}

		name := types.NamespacedName{Namespace: namespace, Name: owner.Name}

		if gv.Group == cronJobGroup && owner.Kind == cronJobKind {
			var cj batchv1.CronJob
			if err := c.Get(ctx, name, &cj); err != nil {
				if apierrors.IsNotFound(err) {
					return Schedule{}, nil
				}
				return Schedule{}, fmt.Errorf("get cronjob %s: %w", name, err)
			}
			return Schedule{Found: true, Expression: cj.Spec.Schedule, CronJob: name}, nil
		}

		// Intermediate owners are read unstructured deliberately. The chain
		// between a pod and its schedule is not a fixed set of kinds - a Job may
		// itself be owned by an operator's custom resource - and enumerating
		// kinds here would mean quietly giving up on any chain that contains one.
		var parent unstructured.Unstructured
		parent.SetGroupVersionKind(gv.WithKind(owner.Kind))
		if err := c.Get(ctx, name, &parent); err != nil {
			// Every failure to read an intermediate owner ends the walk with
			// "no cycle" rather than an error, and the two that happen are both
			// benign: the owner was garbage collected (a Job removed by
			// ttlSecondsAfterFinished), or its kind is one this client cannot
			// serve at all (an operator CRD with no informer). Neither says
			// anything about whether a schedule exists, and failing the
			// reconcile of every pod under that operator would be a far worse
			// outcome than a missed cycle. Only the CronJob read above, where a
			// wrong answer really does mean enforcing against a 3am job, is
			// allowed to fail the reconcile.
			return Schedule{}, nil
		}

		owner = metav1.GetControllerOf(&parent)
	}

	return Schedule{}, nil
}

// FindRequired combines the owner chain walk with Required: it discovers the
// schedule governing obj, if any, and resolves it against the operator's
// declared minimum.
//
// This is the call a controller wants. Discovery failing is not allowed to
// shorten a window - on error the declared minimum is returned alongside it, so
// a caller that logs and carries on gets the behaviour it had before rather
// than a zero window and immediate enforcement.
func FindRequired(ctx context.Context, c client.Client, obj client.Object, declared time.Duration) (Requirement, Schedule, error) {
	sched, err := Find(ctx, c, obj)
	if err != nil {
		req, _ := Required(declared, "")
		return req, Schedule{}, err
	}
	req, err := Required(declared, sched.Expression)
	return req, sched, err
}
