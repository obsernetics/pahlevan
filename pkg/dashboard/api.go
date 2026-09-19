package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/obsernetics/pahlevan/pkg/apis/policy/v1alpha1"
)

// routes registers every endpoint the dashboard serves.
//
// Every pattern begins with GET. That is the read-only commitment expressed
// where it can be checked rather than asserted: there is no handler here that
// writes, because there is no route here that would reach one.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /", s.assets())
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleHealth)

	mux.HandleFunc("GET /api/overview", s.authenticated(s.handleOverview))
	mux.HandleFunc("GET /api/workloads", s.authenticated(s.handleWorkloads))
	mux.HandleFunc("GET /api/workloads/{namespace}/{kind}/{name}", s.authenticated(s.handleWorkload))
	mux.HandleFunc("GET /api/denials", s.authenticated(s.handleDenials))
	mux.HandleFunc("GET /api/diagram/flow/{namespace}/{kind}/{name}", s.authenticated(s.handleFlowDiagram))
	mux.HandleFunc("GET /api/diagram/surface/{namespace}/{kind}/{name}", s.authenticated(s.handleSurfaceDiagram))
	mux.HandleFunc("GET /api/diagram/tree/{namespace}/{kind}/{name}", s.authenticated(s.handleTreeDiagram))

	return mux
}

// handleHealth answers the kubelet probes.
//
// Unauthenticated on purpose, and it says nothing but "ok": a probe that
// needed a token would need a token mounted into the kubelet, and a probe that
// reported how many workloads exist would be an unauthenticated read of the
// very thing the rest of this file protects.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// viewerHandler is a handler that has already been given an authenticated
// identity and the per-request access checker.
type viewerHandler func(w http.ResponseWriter, r *http.Request, access *accessChecker)

// authenticated establishes who the browser is before any handler runs.
//
// Identity is established once per request and never stored. There is no
// session to fixate, no cookie to steal, and no logout to implement: the
// browser holds a Kubernetes token and the API server decides what it means,
// every single time.
func (s *Server) authenticated(next viewerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(r)
		if !ok {
			unauthenticated(w, "this endpoint needs a Kubernetes bearer token in the Authorization header")
			return
		}
		id, err := s.auth.Authenticate(r.Context(), token)
		if err != nil {
			if errors.Is(err, ErrUnauthenticated) {
				unauthenticated(w, "the API server did not accept the presented token")
				return
			}
			s.log.Error(err, "token review failed")
			writeError(w, http.StatusServiceUnavailable,
				"the dashboard could not reach the Kubernetes API server to check the presented token; retry, and check the dashboard's own service account")
			return
		}
		next(w, r, newAccessChecker(s.access, id))
	}
}

func unauthenticated(w http.ResponseWriter, msg string) {
	// The challenge tells a browser client what kind of credential to send.
	// Without it a fetch that 401s looks like a server fault rather than a
	// missing token.
	w.Header().Set("WWW-Authenticate", `Bearer realm="pahlevan-dashboard"`)
	writeError(w, http.StatusUnauthorized, msg)
}

// handleOverview answers "what is Pahlevan doing", namespace by namespace.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	ctx := r.Context()

	policies, err := s.listPolicies(ctx, "")
	if err != nil {
		s.apiUnavailable(w, err, "policies")
		return
	}
	profiles, err := s.listProfiles(ctx, "")
	if err != nil {
		s.apiUnavailable(w, err, "container profiles")
		return
	}
	surfaces, err := s.listSurfaces(ctx, "")
	if err != nil {
		s.apiUnavailable(w, err, "attack surfaces")
		return
	}

	// The lists above were read with the dashboard's own service account,
	// which can read all three CRDs cluster-wide. Nothing from them reaches
	// the response until a SubjectAccessReview says this viewer may list that
	// resource in that namespace, and a namespace with no allowed resource is
	// absent from the document entirely - not present with zeroes, which would
	// itself disclose that the namespace exists.
	byNamespace := map[string]*NamespaceSummary{}
	summary := func(ns string) *NamespaceSummary {
		s := byNamespace[ns]
		if s == nil {
			s = &NamespaceSummary{Namespace: ns}
			byNamespace[ns] = s
		}
		return s
	}

	out := Overview{Generated: time.Now().UTC()}

	for i := range policies {
		p := &policies[i]
		allowed, err := access.mayRead(ctx, ResourcePolicies, p.Namespace)
		if err != nil {
			s.accessUnavailable(w, err)
			return
		}
		if !allowed {
			continue
		}
		ns := summary(p.Namespace)
		ns.Policies++
		out.Policies.addPhase(string(p.Status.Phase))
	}

	workloads := map[WorkloadKey]struct{}{}
	for i := range profiles {
		p := &profiles[i]
		key := workloadOf(p)
		allowed, err := access.mayRead(ctx, ResourceProfiles, key.Namespace)
		if err != nil {
			s.accessUnavailable(w, err)
			return
		}
		if !allowed {
			continue
		}
		ns := summary(key.Namespace)
		ns.Containers.addPhase(phaseOf(p.Status.Phase))
		ns.Rollbacks += int(p.Status.RollbackCount)
		ns.Denials.add(denialsOfProfile(&p.Status))
		out.Containers.addPhase(phaseOf(p.Status.Phase))
		out.Denials.add(denialsOfProfile(&p.Status))
		if _, seen := workloads[key]; !seen {
			workloads[key] = struct{}{}
			ns.Workloads++
		}
	}
	out.Workloads = len(workloads)

	for i := range surfaces {
		sf := &surfaces[i]
		ns := sf.Spec.Namespace
		if ns == "" {
			ns = sf.Namespace
		}
		allowed, err := access.mayRead(ctx, ResourceSurfaces, ns)
		if err != nil {
			s.accessUnavailable(w, err)
			return
		}
		if !allowed {
			continue
		}
		if risk := sf.Status.RiskScore; risk != nil && int(*risk) > summary(ns).MaxRisk {
			summary(ns).MaxRisk = int(*risk)
		}
	}

	out.Namespaces = make([]NamespaceSummary, 0, len(byNamespace))
	for _, ns := range byNamespace {
		out.Namespaces = append(out.Namespaces, *ns)
	}
	sort.Slice(out.Namespaces, func(i, j int) bool {
		return out.Namespaces[i].Namespace < out.Namespaces[j].Namespace
	})

	// Store statistics describe the dashboard's own process, not any
	// namespace's contents, so they are safe to report to any authenticated
	// viewer. They are what distinguishes "nothing was denied" from "the event
	// stream is not wired up".
	if s.opts.Store != nil {
		st := s.opts.Store.Stats()
		out.Live = &st
	}

	writeJSON(w, http.StatusOK, out)
}

// handleWorkloads lists every workload the viewer may see.
func (s *Server) handleWorkloads(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	ctx := r.Context()
	namespace := r.URL.Query().Get("namespace")

	summaries, err := s.workloadSummaries(ctx, access, namespace)
	if err != nil {
		s.writeLoadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workloads": summaries})
}

// handleWorkload is the per-workload view: the learned surface, the flow from
// learning to enforcement, what was denied and why, and the process tree
// behind it.
func (s *Server) handleWorkload(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	detail, ok := s.detailForRequest(w, r, access)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// handleDenials answers "what was denied and why" across everything visible.
func (s *Server) handleDenials(w http.ResponseWriter, r *http.Request, access *accessChecker) {
	ctx := r.Context()
	namespace := r.URL.Query().Get("namespace")

	type entry struct {
		Namespace string `json:"namespace"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Denial
	}
	out := []entry{}

	if s.opts.Store != nil {
		for _, act := range s.opts.Store.Snapshot() {
			if namespace != "" && act.Key.Namespace != namespace {
				continue
			}
			// Live denials are gated on the same resource as the profiles they
			// describe: a viewer who may not list container profiles in a
			// namespace may not read that namespace's denials either, however
			// they reached this process.
			allowed, err := access.mayRead(ctx, ResourceProfiles, act.Key.Namespace)
			if err != nil {
				s.accessUnavailable(w, err)
				return
			}
			if !allowed {
				continue
			}
			for _, d := range act.Denials {
				out = append(out, entry{
					Namespace: act.Key.Namespace, Kind: act.Key.Kind, Name: act.Key.Name, Denial: d,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })

	summaries, err := s.workloadSummaries(ctx, access, namespace)
	if err != nil {
		s.writeLoadError(w, err)
		return
	}
	totals := DenialTotals{}
	for i := range summaries {
		totals.add(summaries[i].Denials)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"denials": out,
		"totals":  totals,
		// live says whether the reason column can be trusted to be complete.
		// Without an event stream the counters are still real, but the
		// individual denials behind them were never seen by this process, and
		// a page that did not say so would read as "nothing was denied".
		"live": s.opts.Store != nil,
	})
}

// detailForRequest resolves and authorises the workload named in the path.
// It writes the response itself on every failure, so callers only handle the
// success case.
func (s *Server) detailForRequest(w http.ResponseWriter, r *http.Request, access *accessChecker) (*WorkloadDetail, bool) {
	ctx := r.Context()
	key := WorkloadKey{
		Namespace: r.PathValue("namespace"),
		Kind:      r.PathValue("kind"),
		Name:      r.PathValue("name"),
	}
	if key.Empty() {
		writeError(w, http.StatusBadRequest,
			"the path must name a namespace, a workload kind and a workload name, for example /api/workloads/prod/Deployment/api")
		return nil, false
	}

	// Authorise before reading. Checking after the read would work, but it
	// leaves a window in which a denied viewer's request has already pulled
	// the data into this process, and it makes the failure mode of a bug in
	// the filtering a disclosure rather than an empty page.
	allowed, err := access.mayRead(ctx, ResourceProfiles, key.Namespace)
	if err != nil {
		s.accessUnavailable(w, err)
		return nil, false
	}
	if !allowed {
		forbidden(w, key.Namespace)
		return nil, false
	}

	detail, found, err := s.workloadDetail(ctx, access, key)
	if err != nil {
		s.writeLoadError(w, err)
		return nil, false
	}
	if !found {
		writeError(w, http.StatusNotFound,
			"no container profile names that workload; check the namespace, kind and name, and that the agent has reported a profile for it")
		return nil, false
	}
	return detail, true
}

// forbidden is the one place a denial is rendered, so every route says the
// same thing and none of them accidentally says whether the namespace exists.
func forbidden(w http.ResponseWriter, namespace string) {
	writeError(w, http.StatusForbidden,
		"your Kubernetes account may not list Pahlevan resources in namespace "+namespace+
			"; ask a cluster administrator for a Role granting list on pahlevanpolicies, containerprofiles and attacksurfaces there")
}

// workloadSummaries builds the list view, filtered to what the viewer may see.
func (s *Server) workloadSummaries(ctx context.Context, access *accessChecker, namespace string) ([]WorkloadSummary, error) {
	profiles, err := s.listProfiles(ctx, namespace)
	if err != nil {
		return nil, err
	}

	grouped := map[WorkloadKey]*WorkloadSummary{}
	order := []WorkloadKey{}
	for i := range profiles {
		p := &profiles[i]
		key := workloadOf(p)
		allowed, err := access.mayRead(ctx, ResourceProfiles, key.Namespace)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		ws := grouped[key]
		if ws == nil {
			ws = &WorkloadSummary{Namespace: key.Namespace, Kind: key.Kind, Name: key.Name, Policy: p.Spec.PolicyRef}
			grouped[key] = ws
			order = append(order, key)
		}
		foldProfileIntoSummary(ws, p)
	}

	out := make([]WorkloadSummary, 0, len(order))
	for _, key := range order {
		ws := grouped[key]
		ws.Phase = summaryPhase(ws.Containers)
		if s.opts.Store != nil {
			if act, ok := s.opts.Store.Activity(key); ok {
				counts := act.Counts
				ws.Live = &counts
			}
		}
		out = append(out, *ws)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func foldProfileIntoSummary(ws *WorkloadSummary, p *policyv1alpha1.ContainerProfile) {
	ws.Containers.addPhase(phaseOf(p.Status.Phase))
	ws.Rollbacks += int(p.Status.RollbackCount)
	ws.Denials.add(denialsOfProfile(&p.Status))
	mergeSurface(&ws.Surface, surfaceOf(&p.Status))
	if p.Spec.Node != "" {
		ws.Node = p.Spec.Node
	}
	if ws.Policy == "" {
		ws.Policy = p.Spec.PolicyRef
	}
	if t := p.Status.LastUpdated; t != nil && (ws.LastUpdate == nil || t.Time.After(*ws.LastUpdate)) {
		when := t.Time
		ws.LastUpdate = &when
	}
}

// summaryPhase collapses a workload's containers into one word.
//
// Mixed is its own answer rather than a rounding to the majority: half a
// Deployment enforcing and half still learning is the state where a rollout is
// halfway through, and that is precisely when someone is looking.
func summaryPhase(c PhaseCounts) string {
	switch {
	case c.Total == 0:
		return "Unknown"
	case c.Failed > 0:
		return "Failed"
	case c.Enforcing == c.Total:
		return "Enforcing"
	case c.Learning == c.Total:
		return "Learning"
	case c.Enforcing > 0 && c.Learning > 0:
		return "Mixed"
	case c.Enforcing > 0:
		return "Enforcing"
	case c.Learning > 0:
		return "Learning"
	default:
		return "Initializing"
	}
}

// workloadDetail assembles the per-workload view. The caller has already
// authorised container profiles in this namespace; the attack surface and the
// policy are authorised separately here, because a viewer may hold read on one
// and not the others and must see exactly the part they hold.
func (s *Server) workloadDetail(ctx context.Context, access *accessChecker, key WorkloadKey) (*WorkloadDetail, bool, error) {
	profiles, err := s.listProfiles(ctx, key.Namespace)
	if err != nil {
		return nil, false, err
	}

	detail := &WorkloadDetail{}
	detail.Namespace, detail.Kind, detail.Name = key.Namespace, key.Kind, key.Name
	found := false

	for i := range profiles {
		p := &profiles[i]
		if workloadOf(p) != key {
			continue
		}
		found = true
		foldProfileIntoSummary(&detail.WorkloadSummary, p)
		detail.ContainerViews = append(detail.ContainerViews, containerViewOf(p))
	}
	if !found {
		return nil, false, nil
	}
	detail.Phase = summaryPhase(detail.Containers)
	detail.Flow = flowFor(detail.WorkloadSummary, detail.ContainerViews)

	allowedSurfaces, err := access.mayRead(ctx, ResourceSurfaces, key.Namespace)
	if err != nil {
		return nil, false, err
	}
	if allowedSurfaces {
		surfaces, err := s.listSurfaces(ctx, key.Namespace)
		if err != nil {
			return nil, false, err
		}
		for i := range surfaces {
			sf := &surfaces[i]
			if w := sf.Spec.Workload; w == nil || w.Kind != key.Kind || w.Name != key.Name {
				continue
			}
			view := attackSurfaceViewOf(sf)
			detail.AttackSurface = &view
			detail.Risk = view.Risk
			break
		}
	}

	if s.opts.Store != nil {
		if act, ok := s.opts.Store.Activity(key); ok {
			counts := act.Counts
			detail.Live = &counts
			detail.Denied = act.Denials
			detail.Processes = act.Processes
			detail.ProcessesTruncated = act.ProcessesTruncated
			if detail.Node == "" {
				detail.Node = act.Node
			}
		}
	}
	return detail, true, nil
}

func containerViewOf(p *policyv1alpha1.ContainerProfile) ContainerView {
	cv := ContainerView{
		Name:           p.Name,
		Pod:            p.Spec.PodName,
		Node:           p.Spec.Node,
		Phase:          phaseOf(p.Status.Phase),
		Attempts:       int(p.Status.EnforcementAttempts),
		Rollbacks:      int(p.Status.RollbackCount),
		RollbackReason: p.Status.LastRollbackReason,
		Denials:        denialsOfProfile(&p.Status),
	}
	if t := p.Status.FirstSeen; t != nil {
		when := t.Time
		cv.FirstSeen = &when
	}
	if t := p.Status.EnforcingSince; t != nil {
		when := t.Time
		cv.EnforcingSince = &when
	}
	if sp := p.Status.Seccomp; sp != nil {
		cv.Seccomp = &SeccompView{
			LocalhostProfile: sp.LocalhostProfile,
			Node:             sp.Node,
			Allowed:          int(sp.AllowedSyscalls),
			Total:            int(sp.TotalSyscalls),
			SkippedUnknown:   int(sp.SkippedUnknown),
		}
	}
	return cv
}

func attackSurfaceViewOf(sf *policyv1alpha1.AttackSurface) AttackSurfaceView {
	v := AttackSurfaceView{
		ExposedSyscalls: limitStrings(sf.Status.ExposedSyscalls),
		WritableFiles:   limitStrings(sf.Status.WritableFiles),
		Capabilities:    limitStrings(sf.Status.Capabilities),
		ExposedPorts:    sf.Status.ExposedPorts,
	}
	if sf.Status.RiskScore != nil {
		v.Risk = int(*sf.Status.RiskScore)
	}
	if t := sf.Status.LastAnalysis; t != nil {
		when := t.Time
		v.LastAnalysis = &when
	}
	return v
}

// The three CRD readers. Each one exists so the SubjectAccessReview above it
// names the same resource the read touches, which is the property that makes
// the authorisation mean anything.

func (s *Server) listPolicies(ctx context.Context, namespace string) ([]policyv1alpha1.PahlevanPolicy, error) {
	var list policyv1alpha1.PahlevanPolicyList
	if err := s.opts.Reader.List(ctx, &list, listOptions(namespace)...); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (s *Server) listProfiles(ctx context.Context, namespace string) ([]policyv1alpha1.ContainerProfile, error) {
	var list policyv1alpha1.ContainerProfileList
	if err := s.opts.Reader.List(ctx, &list, listOptions(namespace)...); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (s *Server) listSurfaces(ctx context.Context, namespace string) ([]policyv1alpha1.AttackSurface, error) {
	var list policyv1alpha1.AttackSurfaceList
	if err := s.opts.Reader.List(ctx, &list, listOptions(namespace)...); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func listOptions(namespace string) []client.ListOption {
	if namespace == "" {
		return nil
	}
	return []client.ListOption{client.InNamespace(namespace)}
}

// apiUnavailable reports a failed CRD read.
//
// 503 and not 500: the dashboard is fine, the API server did not answer, and
// the difference decides whether the reader retries or files a bug. The
// underlying error goes to the log rather than the response, because it can
// name resources the viewer is not allowed to know about.
func (s *Server) apiUnavailable(w http.ResponseWriter, err error, what string) {
	s.log.Error(err, "reading Pahlevan resources failed", "resource", what)
	writeError(w, http.StatusServiceUnavailable,
		"the dashboard could not read "+what+" from the Kubernetes API server; retry, and check that the dashboard's service account still has read on the Pahlevan CRDs")
}

func (s *Server) accessUnavailable(w http.ResponseWriter, err error) {
	s.log.Error(err, "subject access review failed")
	writeError(w, http.StatusServiceUnavailable,
		"the dashboard could not ask the Kubernetes API server what you are allowed to read; retry, and check that the dashboard's service account may create subjectaccessreviews")
}

// writeLoadError routes an error from the assembly helpers, which mix CRD
// reads and access reviews. Both are the API server failing to answer, which
// is one outcome for the reader.
func (s *Server) writeLoadError(w http.ResponseWriter, err error) {
	s.log.Error(err, "assembling the view failed")
	writeError(w, http.StatusServiceUnavailable,
		"the dashboard could not assemble this view from the Kubernetes API server; retry, and check the dashboard's own access to the Pahlevan CRDs")
}

// writeJSON renders a response.
func writeJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Marshalling cannot fail for the types here, but a silent empty 200
		// would be indistinguishable from "nothing to show", so it is reported
		// as the server fault it would be.
		writeError(w, http.StatusInternalServerError, "the dashboard could not encode its response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// writeError renders a failure. The message names what failed and what to do
// about it, because the reader is an operator in a browser with no log access.
func writeError(w http.ResponseWriter, code int, msg string) {
	body, _ := json.Marshal(map[string]string{"error": msg})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}
