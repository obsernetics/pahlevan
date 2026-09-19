package cycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "batch-ns"

func testScheme(t testing.TB) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme,
		batchv1.AddToScheme,
		appsv1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatalf("build scheme: %v", err)
		}
	}
	return s
}

func clientWith(t testing.TB, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
}

// ownedBy builds the controller reference the garbage collector would set.
func ownedBy(apiVersion, kind, name string) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID(kind + "-" + name),
		Controller: &controller,
	}
}

func pod(name string, owners ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:            name,
		Namespace:       testNamespace,
		UID:             types.UID("Pod-" + name),
		OwnerReferences: owners,
	}}
}

func job(name string, owners ...metav1.OwnerReference) *batchv1.Job {
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name:            name,
		Namespace:       testNamespace,
		UID:             types.UID("Job-" + name),
		OwnerReferences: owners,
	}}
}

func cronJob(name, schedule string) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, UID: types.UID("CronJob-" + name)},
		Spec:       batchv1.CronJobSpec{Schedule: schedule},
	}
}

func replicaSet(name string, owners ...metav1.OwnerReference) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name:            name,
		Namespace:       testNamespace,
		UID:             types.UID("ReplicaSet-" + name),
		OwnerReferences: owners,
	}}
}

func deployment(name string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: testNamespace, UID: types.UID("Deployment-" + name),
	}}
}

func TestFindWalksPodToJobToCronJob(t *testing.T) {
	p := pod("nightly-batch-29081600-abcde", ownedBy("batch/v1", "Job", "nightly-batch-29081600"))
	c := clientWith(t,
		p,
		job("nightly-batch-29081600", ownedBy("batch/v1", "CronJob", "nightly-batch")),
		cronJob("nightly-batch", "0 3 * * *"),
	)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if !got.Found {
		t.Fatal("no CronJob found for a pod two hops below one")
	}
	if got.Expression != "0 3 * * *" {
		t.Fatalf("schedule = %q, want %q", got.Expression, "0 3 * * *")
	}
	if got.CronJob != (types.NamespacedName{Namespace: testNamespace, Name: "nightly-batch"}) {
		t.Fatalf("CronJob = %v, want batch-ns/nightly-batch", got.CronJob)
	}
}

func TestFindAcceptsAJobAsTheStartingObject(t *testing.T) {
	// The controller may reconcile a Job rather than a Pod, and starting one hop
	// up must not change the answer.
	j := job("weekly-renew-29081600", ownedBy("batch/v1", "CronJob", "weekly-renew"))
	c := clientWith(t, j, cronJob("weekly-renew", "0 2 * * 0"))

	got, err := Find(context.Background(), c, j)
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if !got.Found || got.Expression != "0 2 * * 0" {
		t.Fatalf("Find = %+v, want the weekly schedule", got)
	}
}

func TestFindReportsNoCronJobForADeploymentPod(t *testing.T) {
	// The ordinary case, and the one that must not be an error: a Deployment pod
	// has no periodicity, and a walk that logged or failed here would do so for
	// most pods in most clusters.
	p := pod("web-7d9f4-xyz", ownedBy("apps/v1", "ReplicaSet", "web-7d9f4"))
	c := clientWith(t,
		p,
		replicaSet("web-7d9f4", ownedBy("apps/v1", "Deployment", "web")),
		deployment("web"),
	)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("a pod with no CronJob must not be an error, got: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
	if got.Expression != "" {
		t.Fatalf("expression = %q, want empty when nothing was found", got.Expression)
	}
}

func TestFindReportsNoCronJobForAPodWithNoOwners(t *testing.T) {
	p := pod("static-pod")
	c := clientWith(t, p)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
}

func TestFindIgnoresOwnerReferencesThatAreNotControllers(t *testing.T) {
	// A non-controller owner is a lifecycle link, not the thing that created the
	// pod. Following one would attribute a schedule to a workload that a
	// CronJob merely happens to reference.
	ref := ownedBy("batch/v1", "CronJob", "unrelated")
	ref.Controller = nil
	p := pod("adopted", ref)
	c := clientWith(t, p, cronJob("unrelated", "0 3 * * *"))

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if got.Found {
		t.Fatalf("Find followed a non-controller owner reference: %+v", got)
	}
}

func TestFindStopsWhenAnOwnerHasBeenGarbageCollected(t *testing.T) {
	// A Job removed by ttlSecondsAfterFinished while its pod lingers is routine.
	// Failing the reconcile over it would block policy updates for a healthy
	// workload.
	p := pod("orphan-abcde", ownedBy("batch/v1", "Job", "already-deleted"))
	c := clientWith(t, p)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("a deleted owner must not be an error, got: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
}

func TestFindStopsWhenTheCronJobItselfHasBeenDeleted(t *testing.T) {
	p := pod("tail-abcde", ownedBy("batch/v1", "Job", "tail-29081600"))
	c := clientWith(t, p, job("tail-29081600", ownedBy("batch/v1", "CronJob", "gone")))

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("a deleted CronJob must not be an error, got: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
}

func TestFindStopsOnAMalformedOwnerReference(t *testing.T) {
	ref := ownedBy("not a group/version/at/all", "Job", "broken")
	p := pod("broken-owner", ref)
	c := clientWith(t, p)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("a malformed owner reference must not fail the reconcile, got: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
}

func TestFindTerminatesOnACyclicOwnerChain(t *testing.T) {
	// Two Jobs owning each other cannot happen in a healthy cluster, but it can
	// after a restore from backup or a hand-edited ownerReferences block. With
	// no seen set this walk would never return, and a reconcile worker that
	// never returns stops every policy in the cluster from updating.
	c := clientWith(t,
		job("ping", ownedBy("batch/v1", "Job", "pong")),
		job("pong", ownedBy("batch/v1", "Job", "ping")),
	)
	start := job("ping", ownedBy("batch/v1", "Job", "pong"))

	done := make(chan struct{})
	var got Schedule
	var err error
	go func() {
		defer close(done)
		got, err = Find(context.Background(), c, start)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Find did not terminate on a cyclic owner chain")
	}
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
}

func TestFindGivesUpOnAnAbsurdlyDeepOwnerChain(t *testing.T) {
	// A chain longer than any real controller builds is indistinguishable from a
	// corrupted one. Bounding it is what keeps a reconcile from becoming a walk
	// over an attacker-supplied graph.
	objs := []client.Object{}
	depth := maxOwnerHops + 4
	for i := 0; i < depth; i++ {
		objs = append(objs, job(jobName(i), ownedBy("batch/v1", "Job", jobName(i+1))))
	}
	objs = append(objs, cronJob("too-far", "0 3 * * *"))
	objs[len(objs)-2] = job(jobName(depth-1), ownedBy("batch/v1", "CronJob", "too-far"))
	c := clientWith(t, objs...)

	got, err := Find(context.Background(), c, job(jobName(0), ownedBy("batch/v1", "Job", jobName(1))))
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if got.Found {
		t.Fatalf("Find walked past the hop limit: %+v", got)
	}
}

func jobName(i int) string {
	return "link-" + string(rune('a'+i))
}

func TestFindWalksThroughAnOwnerKindItDoesNotKnow(t *testing.T) {
	// A Job owned by an operator's custom resource still has a CronJob above it
	// in some deployments. Reading intermediate owners unstructured is what lets
	// the walk cross a kind this package has never heard of - here simulated by
	// a Deployment sitting between the Job and nothing, which must terminate
	// cleanly rather than error.
	p := pod("odd-abcde", ownedBy("batch/v1", "Job", "odd-job"))
	c := clientWith(t,
		p,
		job("odd-job", ownedBy("apps/v1", "ReplicaSet", "odd-rs")),
		replicaSet("odd-rs", ownedBy("batch/v1", "CronJob", "odd-cron")),
		cronJob("odd-cron", "0 1 * * *"),
	)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("Find returned an error: %v", err)
	}
	if !got.Found || got.Expression != "0 1 * * *" {
		t.Fatalf("Find = %+v, want the schedule three hops up", got)
	}
}

func TestFindRejectsACallWithNothingToWalk(t *testing.T) {
	if _, err := Find(context.Background(), nil, pod("p")); err == nil {
		t.Fatal("Find with a nil client returned no error")
	}
	if _, err := Find(context.Background(), clientWith(t), nil); err == nil {
		t.Fatal("Find with a nil object returned no error")
	}
}

func TestFindRequiredRaisesTheWindowToTheDiscoveredCycle(t *testing.T) {
	p := pod("nightly-29081600-abcde", ownedBy("batch/v1", "Job", "nightly-29081600"))
	c := clientWith(t,
		p,
		job("nightly-29081600", ownedBy("batch/v1", "CronJob", "nightly")),
		cronJob("nightly", "0 3 * * *"),
	)

	req, sched, err := FindRequired(context.Background(), c, p, 50*time.Minute)
	if err != nil {
		t.Fatalf("FindRequired returned an error: %v", err)
	}
	if !sched.Found {
		t.Fatal("FindRequired did not report the schedule it used")
	}
	if want := 24 * time.Hour; req.Window != want {
		t.Fatalf("window = %v, want %v - fifty minutes never sees a 3am job", req.Window, want)
	}
	if req.Source != SourceCycle {
		t.Fatalf("source = %q, want %q", req.Source, SourceCycle)
	}
}

func TestFindRequiredLeavesTheDeclaredWindowAloneWithoutACronJob(t *testing.T) {
	p := pod("web-7d9f4-xyz", ownedBy("apps/v1", "ReplicaSet", "web-7d9f4"))
	c := clientWith(t, p, replicaSet("web-7d9f4", ownedBy("apps/v1", "Deployment", "web")), deployment("web"))

	req, sched, err := FindRequired(context.Background(), c, p, 50*time.Minute)
	if err != nil {
		t.Fatalf("FindRequired returned an error: %v", err)
	}
	if sched.Found {
		t.Fatalf("schedule = %+v, want none", sched)
	}
	if req.Window != 50*time.Minute || req.Source != SourceDeclared {
		t.Fatalf("requirement = %+v, want the declared fifty minutes", req)
	}
}

func TestFindRequiredKeepsTheDeclaredWindowWhenTheScheduleWillNotParse(t *testing.T) {
	// A CronJob cannot normally hold an unparseable schedule, but a CRD-managed
	// or mutated one can. The workload must keep the window it declared rather
	// than fall back to zero and enforce immediately.
	p := pod("bad-abcde", ownedBy("batch/v1", "Job", "bad-29081600"))
	c := clientWith(t,
		p,
		job("bad-29081600", ownedBy("batch/v1", "CronJob", "bad")),
		cronJob("bad", "not a schedule"),
	)

	req, sched, err := FindRequired(context.Background(), c, p, 50*time.Minute)
	if err == nil {
		t.Fatal("an unparseable schedule returned no error")
	}
	if !sched.Found {
		t.Fatal("the schedule that failed to parse should still be reported")
	}
	if req.Window != 50*time.Minute {
		t.Fatalf("window = %v, want the declared fifty minutes preserved", req.Window)
	}
}

func TestFindStopsOnAnOwnerKindTheClientCannotServe(t *testing.T) {
	// An operator's custom resource in the middle of the chain, with no CRD
	// installed and no informer for it. There is nothing above it this package
	// can reach, and failing the reconcile of every pod under that operator
	// would be a far worse outcome than reporting no cycle.
	p := pod("crd-owned", ownedBy("example.com/v1", "Widget", "widget-1"))
	c := clientWith(t, p)

	got, err := Find(context.Background(), c, p)
	if err != nil {
		t.Fatalf("an unservable owner kind must not fail the reconcile, got: %v", err)
	}
	if got.Found {
		t.Fatalf("Find = %+v, want the no-CronJob signal", got)
	}
}

func TestFindSurfacesARealFailureToReadTheCronJob(t *testing.T) {
	// The one case that is a genuine error: the CronJob is there, the read
	// failed for a reason that is not absence. Swallowing this would silently
	// give the workload a fifty minute window and enforce against a 3am job -
	// exactly the failure this package exists to stop - so the reconcile is
	// failed and retried instead.
	p := pod("nightly-abcde", ownedBy("batch/v1", "Job", "nightly-29081600"))
	base := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
		p,
		job("nightly-29081600", ownedBy("batch/v1", "CronJob", "nightly")),
		cronJob("nightly", "0 3 * * *"),
	).Build()
	c := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, isCronJob := obj.(*batchv1.CronJob); isCronJob {
				return apierrors.NewInternalError(errors.New("etcd is having a day"))
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})

	got, err := Find(context.Background(), c, p)
	if err == nil {
		t.Fatalf("Find = %+v, want the read failure surfaced", got)
	}
	if !strings.Contains(err.Error(), "nightly") {
		t.Fatalf("error %q does not name the cronjob it failed to read", err)
	}
}

func TestFindRequiredKeepsTheDeclaredWindowWhenDiscoveryFails(t *testing.T) {
	req, sched, err := FindRequired(context.Background(), nil, pod("p"), 50*time.Minute)
	if err == nil {
		t.Fatal("FindRequired with no client returned no error")
	}
	if sched.Found {
		t.Fatalf("schedule = %+v, want none", sched)
	}
	if req.Window != 50*time.Minute || req.Source != SourceDeclared {
		t.Fatalf("requirement = %+v, want the declared fifty minutes preserved", req)
	}
}
