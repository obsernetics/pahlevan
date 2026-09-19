package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// Every endpoint, with a viewer allowed in one namespace and refused in the
// other. The assertion that matters in all of them is the same: the refused
// namespace must be absent from the bytes, not merely absent from a field.

func TestEndpointsRequireAToken(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	for _, path := range []string{
		"/api/overview",
		"/api/workloads",
		"/api/workloads/prod/Deployment/api",
		"/api/denials",
		"/api/diagram/flow/prod/Deployment/api",
		"/api/diagram/surface/prod/Deployment/api",
		"/api/diagram/tree/prod/Deployment/api",
	} {
		t.Run(path, func(t *testing.T) {
			rec := do(t, server, http.MethodGet, path, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET %s without a token = %d, want 401", path, rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
				t.Fatalf("a 401 offered no Bearer challenge, got %q", got)
			}
			if strings.Contains(rec.Body.String(), hiddenNS) ||
				strings.Contains(rec.Body.String(), visibleNS) {
				t.Fatalf("an unauthenticated response carried cluster data: %s", rec.Body.String())
			}
		})
	}
}

func TestOverviewHidesNamespacesTheViewerMayNotRead(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/overview = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, hiddenNS) {
		t.Fatalf("the overview named a namespace the viewer may not read: %s", body)
	}

	out := decode[Overview](t, rec)
	if len(out.Namespaces) != 1 || out.Namespaces[0].Namespace != visibleNS {
		t.Fatalf("the overview listed %+v, want only %q", out.Namespaces, visibleNS)
	}
	// The hidden namespace's profile reports 99 denials. Leaking "there are 99
	// denials somewhere you cannot see" is still leaking.
	if out.Denials.Total != 4 {
		t.Fatalf("the overview totalled %d denials, want only the 4 from %q",
			out.Denials.Total, visibleNS)
	}
	if out.Policies.Total != 1 || out.Containers.Total != 1 || out.Workloads != 1 {
		t.Fatalf("the overview counted policies=%d containers=%d workloads=%d, want 1 of each",
			out.Policies.Total, out.Containers.Total, out.Workloads)
	}
	if out.Namespaces[0].MaxRisk != 37 {
		t.Fatalf("the visible namespace reported risk %d, want 37", out.Namespaces[0].MaxRisk)
	}
}

func TestOverviewWithNoAccessIsEmptyRatherThanForbidden(t *testing.T) {
	// A viewer with no access anywhere gets an honest empty document. A 403
	// here would be indistinguishable from the dashboard being broken, and the
	// page has a sentence for the empty case that says it is an RBAC answer.
	auth := newFakeAuth(true, allowNamespaces())
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/overview = %d: %s", rec.Code, rec.Body.String())
	}
	out := decode[Overview](t, rec)
	if len(out.Namespaces) != 0 || out.Workloads != 0 || out.Denials.Total != 0 {
		t.Fatalf("a viewer with no access saw %+v", out)
	}
	if strings.Contains(rec.Body.String(), visibleNS) {
		t.Fatalf("a viewer with no access saw a namespace name: %s", rec.Body.String())
	}
}

func TestWorkloadsListIsFilteredByAccess(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/workloads")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/workloads = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ledger") {
		t.Fatalf("the workload list named a workload in a namespace the viewer may not read: %s",
			rec.Body.String())
	}
	out := decode[struct {
		Workloads []WorkloadSummary `json:"workloads"`
	}](t, rec)
	if len(out.Workloads) != 1 {
		t.Fatalf("the viewer saw %d workloads, want 1", len(out.Workloads))
	}
	w := out.Workloads[0]
	if w.Namespace != visibleNS || w.Name != "api" || w.Kind != "Deployment" {
		t.Fatalf("the workload was %+v", w)
	}
	if w.Phase != "Enforcing" {
		t.Fatalf("the workload phase was %q, want Enforcing", w.Phase)
	}
	if w.Surface.FileCount != 2 || w.Surface.SyscallCount != 3 || w.Surface.NetworkCount != 1 {
		t.Fatalf("the learned surface was %+v", w.Surface)
	}
	if w.Denials.Total != 4 || w.Rollbacks != 1 {
		t.Fatalf("the workload reported %d denials and %d rollbacks, want 4 and 1",
			w.Denials.Total, w.Rollbacks)
	}
}

// The case the whole package exists for: a SubjectAccessReview that says no
// must produce a 403 and no data at all.
func TestWorkloadDetailForbiddenWhenAccessReviewSaysNo(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/workloads/"+hiddenNS+"/Deployment/ledger")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a refused viewer got %d, want 403: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leak := range []string{"/var/lib/ledger/secrets.db", "Learning", "99", "riskScore"} {
		if strings.Contains(body, leak) {
			t.Fatalf("the 403 body leaked %q: %s", leak, body)
		}
	}
}

func TestDiagramsAreForbiddenForTheSameViewer(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	// A diagram is a rendering of the detail, not a second way in. If the SVG
	// endpoints authorised differently they would be the hole.
	for _, kind := range []string{"flow", "surface", "tree"} {
		rec := get(t, server, "/api/diagram/"+kind+"/"+hiddenNS+"/Deployment/ledger")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("the %s diagram for a refused namespace returned %d, want 403", kind, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secrets.db") {
			t.Fatalf("the %s diagram leaked learned data on a 403", kind)
		}
	}
}

func TestWorkloadDetail(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	store := NewStore(StoreOptions{})
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))
	server := newTestServer(t, auth, store)

	rec := get(t, server, "/api/workloads/"+visibleNS+"/Deployment/api")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the workload detail = %d: %s", rec.Code, rec.Body.String())
	}
	detail := decode[WorkloadDetail](t, rec)

	if detail.Name != "api" || detail.Namespace != visibleNS {
		t.Fatalf("the detail was for %s/%s", detail.Namespace, detail.Name)
	}
	if len(detail.Flow) != 4 {
		t.Fatalf("the flow had %d stages, want 4", len(detail.Flow))
	}
	// Two attempts and one rollback is the single most useful thing to know
	// about a profile somebody is about to trust, so the flow has to say it.
	transition := detail.Flow[2]
	if transition.State != StateFailed || !strings.Contains(transition.Detail, "rollback") {
		t.Fatalf("the transition stage was %+v, want a failed stage naming the rollback", transition)
	}
	if detail.Flow[3].State != StateActive {
		t.Fatalf("the enforcing stage was %q, want active", detail.Flow[3].State)
	}
	if detail.AttackSurface == nil || detail.AttackSurface.Risk != 37 {
		t.Fatalf("the attack surface was %+v, want risk 37", detail.AttackSurface)
	}
	if len(detail.ContainerViews) != 1 || detail.ContainerViews[0].Seccomp == nil {
		t.Fatalf("the container views were %+v", detail.ContainerViews)
	}
	if len(detail.Denied) != 1 {
		t.Fatalf("the detail carried %d denials, want the one from the store", len(detail.Denied))
	}
	if !strings.Contains(detail.Denied[0].Reason, "learned executable allow-set") {
		t.Fatalf("the denial reason was %q, which does not say which allow-set refused it",
			detail.Denied[0].Reason)
	}
	if len(detail.Processes) == 0 {
		t.Fatal("the detail carried no process tree, so a denied exec has nothing behind it")
	}
	if detail.Processes[0].Comm != "nginx" {
		t.Fatalf("the process tree rooted at %q, want the ancestry's oldest entry", detail.Processes[0].Comm)
	}
}

func TestWorkloadDetailUnknownWorkload(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/workloads/"+visibleNS+"/Deployment/does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown workload returned %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestDenialsAreFilteredByAccess(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	store := NewStore(StoreOptions{})
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx"}))
	store.Add(execDenial(hiddenNS, "ledger", "/usr/bin/nc", []string{"ledger"}))
	server := newTestServer(t, auth, store)

	rec := get(t, server, "/api/denials")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/denials = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "/usr/bin/nc") || strings.Contains(body, hiddenNS) {
		t.Fatalf("the denial feed leaked a namespace the viewer may not read: %s", body)
	}
	out := decode[struct {
		Denials []map[string]any `json:"denials"`
		Totals  DenialTotals     `json:"totals"`
		Live    bool             `json:"live"`
	}](t, rec)
	if len(out.Denials) != 1 {
		t.Fatalf("the viewer saw %d denials, want 1", len(out.Denials))
	}
	if !out.Live {
		t.Fatal("the feed reported no live stream while a store was wired, so the page would tell " +
			"the reader the reasons are missing when they are not")
	}
	if out.Totals.Total != 4 {
		t.Fatalf("the totals were %+v, want only the visible namespace's 4", out.Totals)
	}
}

func TestDenialsWithoutAStoreSaysSo(t *testing.T) {
	// Without an event stream the counters are still real, but the individual
	// denials behind them were never seen. A page that did not distinguish the
	// two would read as "nothing was denied".
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/denials")
	out := decode[struct {
		Denials []map[string]any `json:"denials"`
		Totals  DenialTotals     `json:"totals"`
		Live    bool             `json:"live"`
	}](t, rec)
	if out.Live {
		t.Fatal("the feed claimed a live stream with no store wired")
	}
	if len(out.Denials) != 0 {
		t.Fatalf("the feed invented %d denials", len(out.Denials))
	}
	if out.Totals.Total != 4 {
		t.Fatalf("the reported totals were %+v, want the profile's 4", out.Totals)
	}
}

func TestDiagramsRenderForAnAllowedViewer(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	store := NewStore(StoreOptions{})
	store.Add(execDenial(visibleNS, "api", "/usr/bin/curl", []string{"nginx", "sh"}))
	server := newTestServer(t, auth, store)

	for _, kind := range []string{"flow", "surface", "tree"} {
		rec := get(t, server, "/api/diagram/"+kind+"/"+visibleNS+"/Deployment/api")
		if rec.Code != http.StatusOK {
			t.Fatalf("the %s diagram returned %d: %s", kind, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
			t.Fatalf("the %s diagram had content type %q", kind, ct)
		}
		if !strings.HasPrefix(rec.Body.String(), "<svg") {
			t.Fatalf("the %s diagram did not start with an svg element", kind)
		}
	}
}

func TestReadOnlyRejectsEveryWriteMethod(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions,
	} {
		for _, path := range []string{"/", "/api/overview", "/api/workloads/prod/Deployment/api"} {
			rec := do(t, server, method, path, testToken)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s = %d, want 405: the dashboard has no write path", method, path, rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
				t.Fatalf("%s %s advertised Allow: %q", method, path, allow)
			}
		}
	}
}

// The routing table itself is the read-only commitment. A handler added later
// under a non-GET pattern would pass every other test in this file.
func TestEveryRouteIsAGetRoute(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	for _, path := range []string{
		"/api/overview", "/api/workloads", "/api/denials",
		"/api/workloads/prod/Deployment/api",
		"/api/diagram/flow/prod/Deployment/api",
	} {
		if _, pattern := server.mux.Handler(httptest.NewRequest(http.MethodPost, path, nil)); pattern != "" {
			t.Fatalf("a non-GET route is registered for %s as %q", path, pattern)
		}
	}
}

func TestHealthNeedsNoTokenAndSaysNothing(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := do(t, server, http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 without a token", path, rec.Code)
		}
		if body := strings.TrimSpace(rec.Body.String()); body != "ok" {
			t.Fatalf("GET %s returned %q; a probe must not report cluster state to an "+
				"unauthenticated caller", path, body)
		}
	}
	if auth.tokenCalls.Load() != 0 || auth.sarCalls.Load() != 0 {
		t.Fatal("a probe caused a TokenReview or a SubjectAccessReview, which would make the " +
			"kubelet's liveness check depend on the API server")
	}
}

func TestAPIServerFailuresAreUnavailableNotEmpty(t *testing.T) {
	// A failing API server and a viewer with no access look identical on a
	// page unless the server distinguishes them. One is "ask your admin", the
	// other is "retry".
	t.Run("access review fails", func(t *testing.T) {
		clientset := k8sfake.NewSimpleClientset()
		clientset.PrependReactor("create", "tokenreviews", authenticatedReactor())
		clientset.PrependReactor("create", "subjectaccessreviews",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("the webhook authorizer timed out")
			})
		server := serverWithClients(t, clientset, fixtureReader(t))
		rec := get(t, server, "/api/overview")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("a failing access review returned %d, want 503", rec.Code)
		}
	})

	t.Run("crd read fails", func(t *testing.T) {
		auth := newFakeAuth(true, allowNamespaces(visibleNS))
		server := serverWithClients(t, auth.clientset, failingReader{})
		rec := get(t, server, "/api/overview")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("a failing CRD read returned %d, want 503: %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "etcd") {
			t.Fatal("the error body echoed the API server's message, which can name resources " +
				"the viewer is not allowed to know about")
		}
	})
}

func TestUnauthenticatedViewerNeverReachesTheAPIServer(t *testing.T) {
	// A rejected token must not cost a SubjectAccessReview: an unauthenticated
	// caller who can drive API server load has a denial of service.
	auth := newFakeAuth(false, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	rec := get(t, server, "/api/overview")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a rejected token returned %d, want 401", rec.Code)
	}
	if auth.sarCalls.Load() != 0 {
		t.Fatalf("a rejected token caused %d SubjectAccessReviews", auth.sarCalls.Load())
	}
}

func TestMalformedWorkloadPath(t *testing.T) {
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := newTestServer(t, auth, nil)

	// An empty namespace segment must not become a cluster-wide read.
	rec := get(t, server, "/api/workloads//Deployment/api")
	if rec.Code == http.StatusOK {
		t.Fatalf("a path with an empty namespace returned 200: %s", rec.Body.String())
	}
}

// failingReader stands in for an API server that will not answer.
type failingReader struct{ client.Reader }

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("etcd is unavailable")
}

func (failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("etcd is unavailable")
}

func fixtureReader(t testing.TB) client.Reader {
	t.Helper()
	return ctrlfake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithRuntimeObjects(fixtureObjects(t)...).
		Build()
}

func serverWithClients(t testing.TB, clientset *k8sfake.Clientset, reader client.Reader) *Server {
	t.Helper()
	server, err := New(Options{
		Addr:          "127.0.0.1:0",
		AllowInsecure: true,
		Reader:        reader,
		Kube:          clientset,
	})
	if err != nil {
		t.Fatalf("building the test server: %v", err)
	}
	return server
}

func TestListViewsReportTheAPIServerFailing(t *testing.T) {
	// Same reasoning as the overview: an empty list and an unreachable API
	// server must not look the same to the reader.
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	server := serverWithClients(t, auth.clientset, failingReader{})

	for _, path := range []string{"/api/workloads", "/api/denials", "/api/workloads/prod/Deployment/api"} {
		rec := get(t, server, path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET %s with a failing reader = %d, want 503: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestTokenReviewFailureIsUnavailableNotUnauthorized(t *testing.T) {
	// "your token is bad" and "the cluster is not answering" send a viewer to
	// two different people, so the status codes have to differ too.
	clientset := k8sfake.NewSimpleClientset()
	clientset.PrependReactor("create", "tokenreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("the API server is unreachable")
		})
	server := serverWithClients(t, clientset, fixtureReader(t))

	rec := get(t, server, "/api/overview")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a failed token review returned %d, want 503", rec.Code)
	}
}

func TestAttackSurfaceViewCarriesTheAnalysisTime(t *testing.T) {
	// A risk score with no analysis time is a number nobody can date, and a
	// stale surface is the one that gets acted on by mistake.
	auth := newFakeAuth(true, allowNamespaces(visibleNS))
	objects := fixtureObjects(t)
	for _, obj := range objects {
		if surface, ok := obj.(*policyv1alpha1.AttackSurface); ok && surface.Namespace == visibleNS {
			analysed := mustTime(t, "2026-01-01T09:00:00Z")
			surface.Status.LastAnalysis = &analysed
			surface.Status.WritableFiles = []string{"/var/cache/nginx"}
			surface.Status.Capabilities = []string{"NET_BIND_SERVICE"}
		}
	}
	reader := ctrlfake.NewClientBuilder().WithScheme(testScheme(t)).WithRuntimeObjects(objects...).Build()
	server := serverWithClients(t, auth.clientset, reader)

	detail := decode[WorkloadDetail](t, get(t, server, "/api/workloads/"+visibleNS+"/Deployment/api"))
	if detail.AttackSurface == nil || detail.AttackSurface.LastAnalysis == nil {
		t.Fatalf("the attack surface came back as %+v", detail.AttackSurface)
	}
	if len(detail.AttackSurface.WritableFiles) != 1 || len(detail.AttackSurface.Capabilities) != 1 {
		t.Fatalf("the attack surface lost its lists: %+v", detail.AttackSurface)
	}
}
